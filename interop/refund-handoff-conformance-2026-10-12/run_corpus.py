"""Run every committed vector through the installed public CLI and retain bytes."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import selectors
import subprocess
import sys
import time
from typing import Any

from probity_observer.crypto import VerificationError, canonical, strict_loads
from probity_observer.refund_handoff import CONTRACT_ID, SCHEMA

CASE_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,99}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
MAX_STREAM_BYTES = 1_048_576


def _load(path: Path) -> Any:
    if path.is_symlink() or not path.is_file():
        raise VerificationError("corpus member is not a regular file: " + path.name)
    return strict_loads(path.read_bytes())


def _closed(value: Any, fields: set[str], reason: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise VerificationError(reason + " has fields outside the closed profile")
    return value


def _check_expected(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("exit") not in {0, 2, 3}:
        raise VerificationError("vector has an invalid expected result")
    if value["exit"] == 2:
        expected = _closed(value, {"exit", "refusal"}, "refusal expectation")
        if not isinstance(expected["refusal"], str) or not expected["refusal"].isascii():
            raise VerificationError("vector has an invalid refusal substring")
        return expected
    allowed = {
        "exit",
        "overall",
        "effect_coverage",
        "completion",
        "completion_value",
        "excluded_after_cutoff",
        "unique_handoffs",
    }
    if not {"exit", "overall"} <= set(value) or not set(value) <= allowed:
        raise VerificationError("classification expectation has invalid fields")
    states = {"ESTABLISHED", "CONTRADICTED", "NOT_ESTABLISHED"}
    for field in ("overall", "effect_coverage", "completion"):
        if field in value and value[field] not in states:
            raise VerificationError("classification expectation has an invalid state")
    if "completion_value" in value and value["completion_value"] not in {
        "effect_committed",
        "no_effect",
        "unknown",
    }:
        raise VerificationError("classification expectation has an invalid value")
    for field in ("excluded_after_cutoff", "unique_handoffs"):
        if field in value and (type(value[field]) is not int or value[field] < 0):
            raise VerificationError("classification expectation has an invalid count")
    return value


def _check_manifest(value: Any, trust_bytes: bytes) -> list[dict[str, Any]]:
    manifest = _closed(
        value,
        {
            "profile",
            "schema",
            "generator",
            "trust_snapshot_sha256",
            "vectors",
        },
        "vector manifest",
    )
    if manifest["profile"] != CONTRACT_ID or manifest["schema"] != SCHEMA:
        raise VerificationError("vector manifest selects a different profile")
    if manifest["generator"] != "generate_vectors.py":
        raise VerificationError("vector manifest selects an unknown generator")
    if manifest["trust_snapshot_sha256"] != hashlib.sha256(trust_bytes).hexdigest():
        raise VerificationError("trust snapshot digest differs from the manifest")
    if not isinstance(manifest["vectors"], list) or not manifest["vectors"]:
        raise VerificationError("vector manifest has no vectors")
    result = []
    cases: set[str] = set()
    files: set[str] = set()
    for value in manifest["vectors"]:
        item = _closed(value, {"case", "file", "sha256", "expected"}, "vector entry")
        case = item["case"]
        if not isinstance(case, str) or CASE_ID.fullmatch(case) is None:
            raise VerificationError("vector case is not a safe identifier")
        if item["file"] != case + ".json":
            raise VerificationError("vector file does not match its case identifier")
        if not isinstance(item["sha256"], str) or SHA256.fullmatch(item["sha256"]) is None:
            raise VerificationError("vector digest is invalid")
        if case in cases or item["file"] in files:
            raise VerificationError("vector manifest repeats a member")
        cases.add(case)
        files.add(item["file"])
        _check_expected(item["expected"])
        result.append(item)
    return result


def _run_bounded(command: list[str]) -> tuple[int, bytes, bytes]:
    """Run one verifier while bounding both retained output streams."""
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert process.stdout is not None and process.stderr is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + 30
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                process.kill()
                process.wait()
                raise subprocess.TimeoutExpired(command, 30)
            for key, _ in selector.select(remaining):
                chunk = os.read(key.fileobj.fileno(), 65_536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                stream = buffers[key.data]
                stream.extend(chunk)
                if len(stream) > MAX_STREAM_BYTES:
                    process.kill()
                    process.wait()
                    raise VerificationError("verifier output exceeds the retained byte limit")
        status = process.wait(timeout=max(0.1, deadline - time.monotonic()))
    finally:
        selector.close()
        if process.poll() is None:
            process.kill()
            process.wait()
    return status, bytes(buffers["stdout"]), bytes(buffers["stderr"])


def run(executable: Path, profile: Path, output: Path) -> dict[str, Any]:
    """Execute the installed verifier over the hash-selected finite corpus."""
    if output.exists():
        raise VerificationError("result path already exists")
    output.mkdir(parents=True)
    trust = profile / "fixtures/trust-snapshot.json"
    trust_bytes = trust.read_bytes() if not trust.is_symlink() and trust.is_file() else b""
    if not trust_bytes:
        raise VerificationError("trust snapshot is not a regular nonempty file")
    manifest = _load(profile / "fixtures/vector-manifest.json")
    vectors = _check_manifest(manifest, trust_bytes)
    vector_root = (profile / "fixtures/vectors").resolve(strict=True)
    actual_files = {
        path.name
        for path in vector_root.iterdir()
        if path.is_file() and not path.is_symlink()
    }
    selected_files = {item["file"] for item in vectors}
    if actual_files != selected_files:
        raise VerificationError("vector directory differs from the finite manifest")
    completed = []
    for item in vectors:
        source = vector_root / item["file"]
        if source.is_symlink() or not source.is_file() or source.parent != vector_root:
            raise VerificationError("vector is not a selected regular file: " + item["case"])
        raw = source.read_bytes()
        if hashlib.sha256(raw).hexdigest() != item["sha256"]:
            raise VerificationError("vector digest differs: " + item["case"])
        returncode, stdout, stderr = _run_bounded(
            [str(executable), "--bundle", str(source), "--trust-snapshot", str(trust)],
        )
        prefix = output / item["case"]
        prefix.with_suffix(".stdout").write_bytes(stdout)
        prefix.with_suffix(".stderr").write_bytes(stderr)
        prefix.with_suffix(".exit").write_text(str(returncode) + "\n", encoding="ascii")
        expected = item["expected"]
        if returncode != expected["exit"]:
            raise VerificationError("vector exit differs: " + item["case"])
        actual: dict[str, Any] = {"case": item["case"], "exit": returncode}
        if returncode == 2:
            if stdout or expected["refusal"].encode("ascii") not in stderr:
                raise VerificationError("vector refusal differs: " + item["case"])
            actual["refusal_matched"] = expected["refusal"]
        else:
            if not stdout.endswith(b"\n"):
                raise VerificationError("vector report lacks one terminal newline: " + item["case"])
            report = strict_loads(stdout[:-1])
            if report["overall"] != expected["overall"]:
                raise VerificationError("vector classification differs: " + item["case"])
            for field in ("effect_coverage", "completion"):
                if field in expected and report["claims"][field]["state"] != expected[field]:
                    raise VerificationError("vector claim differs: " + item["case"] + ":" + field)
            if "completion_value" in expected and report["claims"]["completion"]["value"] != expected["completion_value"]:
                raise VerificationError("vector completion value differs: " + item["case"])
            for field in ("excluded_after_cutoff", "unique_handoffs"):
                if field in expected and report["counts"][field] != expected[field]:
                    raise VerificationError("vector count differs: " + item["case"] + ":" + field)
            actual["overall"] = report["overall"]
            actual["report_sha256"] = hashlib.sha256(stdout).hexdigest()
        actual["stdout_sha256"] = hashlib.sha256(stdout).hexdigest()
        actual["stderr_sha256"] = hashlib.sha256(stderr).hexdigest()
        completed.append(actual)
    summary = {
        "profile": manifest["profile"],
        "schema": manifest["schema"],
        "manifest_sha256": hashlib.sha256(canonical(manifest)).hexdigest(),
        "trust_snapshot_sha256": hashlib.sha256(trust_bytes).hexdigest(),
        "vectors_run": len(completed),
        "results": completed,
    }
    (output / "summary.json").write_bytes(canonical(summary))
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--verifier", required=True, type=Path)
    parser.add_argument("--profile", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        run(args.verifier, args.profile, args.output)
    except (VerificationError, OSError, subprocess.SubprocessError, KeyError, TypeError) as error:
        print("Refund handoff corpus refused: " + str(error), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
