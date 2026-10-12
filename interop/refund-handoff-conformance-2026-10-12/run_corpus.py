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
from probity_observer.refund_handoff import (
    CONTRACT_ID,
    MAX_BUNDLE_RECORDS,
    SCHEMA,
    read_document_bytes,
)

CASE_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,99}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
MAX_STREAM_BYTES = 1_048_576
PROCESS_TIMEOUT_SECONDS = 30


def _load(path: Path) -> Any:
    return strict_loads(read_document_bytes(path))


def _closed(value: Any, fields: set[str], reason: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise VerificationError(reason + " has fields outside the closed profile")
    return value


def _check_expected(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("exit") not in {0, 2, 3}:
        raise VerificationError("vector has an invalid expected result")
    if value["exit"] == 2:
        expected = _closed(
            value,
            {"exit", "refusal", "stderr_sha256"},
            "refusal expectation",
        )
        if not isinstance(expected["refusal"], str) or not expected["refusal"].isascii():
            raise VerificationError("vector has an invalid refusal")
        if (
            not isinstance(expected["stderr_sha256"], str)
            or SHA256.fullmatch(expected["stderr_sha256"]) is None
        ):
            raise VerificationError("vector has an invalid refusal digest")
        return expected
    expected = _closed(
        value,
        {"exit", "overall", "claims", "report_sha256"},
        "classification expectation",
    )
    states = {"ESTABLISHED", "CONTRADICTED", "NOT_ESTABLISHED"}
    if expected["overall"] not in states or not isinstance(expected["claims"], dict):
        raise VerificationError("classification expectation has an invalid state")
    if (
        not isinstance(expected["report_sha256"], str)
        or SHA256.fullmatch(expected["report_sha256"]) is None
    ):
        raise VerificationError("classification expectation has an invalid report digest")
    return expected


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
    if (
        not isinstance(manifest["vectors"], list)
        or not manifest["vectors"]
        or len(manifest["vectors"]) > MAX_BUNDLE_RECORDS
    ):
        raise VerificationError("vector manifest has an invalid vector count")
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


def _run_bounded(command: list[str]) -> tuple[int, bytes, bytes, str | None]:
    """Run one verifier and return all bounded output, including failure output."""
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert process.stdout is not None and process.stderr is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + PROCESS_TIMEOUT_SECONDS
    problem: str | None = None
    try:
        while selector.get_map() and problem is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                problem = f"verifier exceeded {PROCESS_TIMEOUT_SECONDS} seconds"
                break
            for key, _ in selector.select(remaining):
                chunk = os.read(key.fileobj.fileno(), 65_536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                stream = buffers[key.data]
                stream.extend(chunk)
                if len(stream) > MAX_STREAM_BYTES:
                    problem = "verifier output exceeds the retained byte limit"
                    break
        if problem is not None and process.poll() is None:
            process.kill()
        status = process.wait(timeout=5)
    finally:
        selector.close()
        if process.poll() is None:
            process.kill()
            process.wait()
    return status, bytes(buffers["stdout"]), bytes(buffers["stderr"]), problem


def _classification_errors(
    stdout: bytes,
    stderr: bytes,
    expected: dict[str, Any],
) -> tuple[list[str], dict[str, Any]]:
    errors = []
    actual: dict[str, Any] = {}
    if stderr:
        errors.append("classified report wrote stderr")
    if not stdout.endswith(b"\n") or stdout.endswith(b"\n\n"):
        errors.append("vector report lacks exactly one terminal newline")
        return errors, actual
    try:
        report = strict_loads(stdout[:-1])
    except (VerificationError, RecursionError) as error:
        errors.append("vector report is not canonical JSON: " + str(error))
        return errors, actual
    try:
        report_sha256 = hashlib.sha256(stdout).hexdigest()
        if report["overall"] != expected["overall"]:
            errors.append("vector classification differs")
        if report["claims"] != expected["claims"]:
            errors.append("vector claims or exact reasons differ")
        if report_sha256 != expected["report_sha256"]:
            errors.append("vector report digest differs")
        actual["overall"] = report["overall"]
        actual["report_sha256"] = report_sha256
    except (KeyError, TypeError) as error:
        errors.append("vector report structure differs: " + str(error))
    return errors, actual


def _case_errors(
    returncode: int,
    stdout: bytes,
    stderr: bytes,
    runner_error: str | None,
    expected: dict[str, Any],
) -> tuple[list[str], dict[str, Any]]:
    errors = []
    actual: dict[str, Any] = {}
    if runner_error is not None:
        errors.append(runner_error)
    if returncode != expected["exit"]:
        errors.append("vector exit differs")
    if expected["exit"] == 2:
        if stdout:
            errors.append("refused vector wrote stdout")
        expected_stderr = (
            "Refund handoff bundle refused: " + expected["refusal"] + "\n"
        ).encode("ascii")
        if stderr != expected_stderr:
            errors.append("vector refusal differs")
        if hashlib.sha256(stderr).hexdigest() != expected["stderr_sha256"]:
            errors.append("vector refusal digest differs")
        actual["refusal_matched"] = expected["refusal"]
    else:
        classification_errors, classification_actual = _classification_errors(
            stdout, stderr, expected
        )
        errors.extend(classification_errors)
        actual.update(classification_actual)
    return errors, actual


def _write_failure_summary(
    output: Path,
    *,
    stage: str,
    error: Exception,
) -> None:
    summary = {
        "profile": CONTRACT_ID,
        "schema": SCHEMA,
        "status": "FAIL",
        "stage": stage,
        "error": type(error).__name__ + ": " + str(error),
        "vectors_run": 0,
        "results": [],
    }
    (output / "summary.json").write_bytes(canonical(summary))


def run(
    executable: Path,
    profile: Path,
    output: Path,
    provenance: Path,
) -> dict[str, Any]:
    """Run the installed verifier against immutable retained input snapshots."""
    if output.exists():
        raise VerificationError("result path already exists")
    output.mkdir(parents=True)
    retained = output / "inputs"
    retained_vectors = retained / "vectors"
    retained_vectors.mkdir(parents=True)
    try:
        provenance_bytes = read_document_bytes(provenance)
        strict_loads(provenance_bytes)
        (output / "provenance.json").write_bytes(provenance_bytes)

        trust_source = profile / "fixtures/trust-snapshot.json"
        manifest_source = profile / "fixtures/vector-manifest.json"
        trust_bytes = read_document_bytes(trust_source)
        if not trust_bytes:
            raise VerificationError("trust snapshot is empty")
        manifest_bytes = read_document_bytes(manifest_source)
        manifest = strict_loads(manifest_bytes)
        vectors = _check_manifest(manifest, trust_bytes)
        retained_trust = retained / "trust-snapshot.json"
        retained_manifest = retained / "vector-manifest.json"
        retained_trust.write_bytes(trust_bytes)
        retained_manifest.write_bytes(manifest_bytes)

        vector_root = (profile / "fixtures/vectors").resolve(strict=True)
        actual_files = {
            path.name
            for path in vector_root.iterdir()
            if path.is_file() and not path.is_symlink()
        }
        selected_files = {item["file"] for item in vectors}
        if actual_files != selected_files:
            raise VerificationError("vector directory differs from the finite manifest")
        for item in vectors:
            source = vector_root / item["file"]
            raw = read_document_bytes(source)
            if hashlib.sha256(raw).hexdigest() != item["sha256"]:
                raise VerificationError("vector digest differs: " + item["case"])
            (retained_vectors / item["file"]).write_bytes(raw)
    except Exception as error:
        _write_failure_summary(output, stage="preflight", error=error)
        raise

    completed = []
    failures = []
    for item in vectors:
        case = item["case"]
        source = retained_vectors / item["file"]
        try:
            returncode, stdout, stderr, runner_error = _run_bounded(
                [
                    str(executable),
                    "--bundle",
                    str(source),
                    "--trust-snapshot",
                    str(retained_trust),
                ]
            )
        except (OSError, subprocess.SubprocessError) as error:
            returncode = -1
            stdout = b""
            stderr = b""
            runner_error = type(error).__name__ + ": " + str(error)
        prefix = output / case
        prefix.with_suffix(".stdout").write_bytes(stdout)
        prefix.with_suffix(".stderr").write_bytes(stderr)
        prefix.with_suffix(".exit").write_text(str(returncode) + "\n", encoding="ascii")
        if runner_error is not None:
            prefix.with_suffix(".runner-error").write_text(
                runner_error + "\n", encoding="ascii"
            )
        errors, actual = _case_errors(
            returncode,
            stdout,
            stderr,
            runner_error,
            item["expected"],
        )
        actual.update(
            {
                "case": case,
                "exit": returncode,
                "status": "FAIL" if errors else "PASS",
                "errors": errors,
                "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
                "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
            }
        )
        completed.append(actual)
        if errors:
            failures.append(case)

    summary = {
        "profile": manifest["profile"],
        "schema": manifest["schema"],
        "status": "FAIL" if failures else "PASS",
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "trust_snapshot_sha256": hashlib.sha256(trust_bytes).hexdigest(),
        "provenance_sha256": hashlib.sha256(provenance_bytes).hexdigest(),
        "vectors_selected": len(vectors),
        "vectors_run": len(completed),
        "vectors_passed": len(completed) - len(failures),
        "vectors_failed": len(failures),
        "failed_cases": failures,
        "results": completed,
    }
    (output / "summary.json").write_bytes(canonical(summary))
    if failures:
        raise VerificationError(
            f"{len(failures)} vector results differed; complete results are retained"
        )
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--verifier", required=True, type=Path)
    parser.add_argument("--profile", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--provenance", required=True, type=Path)
    args = parser.parse_args()
    try:
        run(args.verifier, args.profile, args.output, args.provenance)
    except (
        VerificationError,
        OSError,
        subprocess.SubprocessError,
        KeyError,
        TypeError,
        RecursionError,
    ) as error:
        print("Refund handoff corpus refused: " + str(error), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
