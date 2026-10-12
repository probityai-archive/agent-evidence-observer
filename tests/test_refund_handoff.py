"""Conformance, mutation, and monotonicity tests for refund-handoff/0.1."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import queue
import re
import shutil
import sys
import threading
import time
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from jsonschema import Draft202012Validator, ValidationError
from referencing import Registry, Resource

from probity_observer.crypto import VerificationError, canonical, strict_loads
from probity_observer.refund_handoff import (
    MAX_DOCUMENT_BYTES,
    _IssueBook,
    assess,
    check_trust_snapshot,
    main,
    operation_id,
    read_document_bytes,
    reason_uri,
)
from probity_observer.refund_handoff_reasons import (
    REASON_CONTRACTS,
    build_reason_registry,
    lookup_reason_contract,
)

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "interop/refund-handoff-conformance-2026-10-12"
VECTORS = PROFILE / "fixtures/vectors"
TRUST_ROOT = PROFILE / "fixtures/trust"
TRUST_BYTES = {path.stem: path.read_bytes() for path in TRUST_ROOT.glob("*.json")}
TRUST = strict_loads(TRUST_BYTES["baseline"])
MANIFEST = strict_loads((PROFILE / "fixtures/vector-manifest.json").read_bytes())
CONTRACT_FILES = (
    "docs/contract/refund-handoff/0.1/contract.schema.json",
    "docs/contract/refund-handoff/0.1/reason-codes.json",
    "docs/contract/refund-handoff/0.1/reason-codes.schema.json",
    "docs/contract/refund-handoff/0.1/report.schema.json",
    "docs/contract/refund-handoff/0.1/run-provenance.schema.json",
)
CONTRACT_BYTES = {
    relative: (ROOT / relative).read_bytes() for relative in CONTRACT_FILES
}
CONTRACT_DOCUMENTS = {
    relative: json.loads(raw) for relative, raw in CONTRACT_BYTES.items()
}
CLAIM_NAMES = frozenset(
    claim for claims, _state in REASON_CONTRACTS.values() for claim in claims
)
EVIDENCE_STATES = ("CONTRADICTED", "NOT_ESTABLISHED")
REASON_NAMESPACE = (
    "https://probityai.github.io/agent-evidence-observer/contract/"
    "refund-handoff/0.1#reason-"
)


def _schema_validator(filename: str) -> Draft202012Validator:
    resources = [
        (document["$id"], Resource.from_contents(document))
        for document in CONTRACT_DOCUMENTS.values()
        if "$id" in document
    ]
    registry = Registry().with_resources(resources)
    return Draft202012Validator(CONTRACT_DOCUMENTS[filename], registry=registry)


def _reason_definition_name(claim: str, state: str) -> str:
    parts = claim.split("_")
    claim_name = parts[0] + "".join(part.title() for part in parts[1:])
    state_name = "Contradicted" if state == "CONTRADICTED" else "NotEstablished"
    return claim_name + state_name + "Reason"


def _reason_schema(claim: str, state: str) -> dict:
    report_schema = CONTRACT_DOCUMENTS[
        "docs/contract/refund-handoff/0.1/report.schema.json"
    ]
    return report_schema["$defs"][_reason_definition_name(claim, state)]


def _case(name: str) -> bytes:
    return (VECTORS / (name + ".json")).read_bytes()


def _report(name: str) -> dict:
    return assess(strict_loads(_case(name)), TRUST)


def _selected_report(name: str) -> dict:
    item = next(item for item in MANIFEST["vectors"] if item["case"] == name)
    trust = strict_loads(TRUST_BYTES[item["trust_snapshot"]])
    return assess(strict_loads(_case(name)), trust)


def _provenance_bytes() -> bytes:
    return canonical(
        {
            "schema": "probity-refund-handoff-run-provenance-v0.1",
            "profile": "https://probityai.github.io/agent-evidence-observer/contract/refund-handoff/0.1",
            "source": {
                "commit": "1" * 40,
                "dirty": False,
                "bundle_file": "source.bundle",
                "bundle_sha256": "2" * 64,
                "archive_file": "source-at-commit.tar",
                "archive_sha256": "3" * 64,
            },
            "wheel": {
                "file": "probity_observer-0.0.0-py3-none-any.whl",
                "sha256": "4" * 64,
                "size": 1,
            },
            "environment": {
                "python": "3.12.0",
                "python_implementation": "CPython",
                "python_sha256": "6" * 64,
                "platform": "test-platform",
                "uv": "uv 0.12.23",
                "uv_sha256": "7" * 64,
            },
            "locks": {
                "requirements_file": "requirements.lock",
                "requirements_sha256": "5" * 64,
            },
        }
    )


def _load_script(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, PROFILE / filename)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _disable_runner_preflights(runner, monkeypatch) -> None:
    """Keep runner behavior tests independent from retained build artifacts."""
    for name in (
        "_check_provenance_artifacts",
        "_check_selected_source_bytes",
        "_check_runtime_binding",
        "_check_runtime_environment",
        "_check_reproducible_wheel",
    ):
        if hasattr(runner, name):
            monkeypatch.setattr(runner, name, lambda *_args, **_kwargs: None)


def _capture_reader_result(reader, path, outcomes) -> None:
    try:
        outcomes.put(reader(path))
    except BaseException as error:  # noqa: BLE001 - retain any thread failure
        outcomes.put(error)


def _in_process_cli(command: list[str]) -> tuple[int, bytes, bytes, None]:
    bundle_path = Path(command[command.index("--bundle") + 1])
    trust_path = Path(command[command.index("--trust-snapshot") + 1])
    try:
        report = assess(
            strict_loads(bundle_path.read_bytes()),
            strict_loads(trust_path.read_bytes()),
        )
    except VerificationError as error:
        message = ("Refund handoff bundle refused: " + str(error) + "\n").encode(
            "ascii"
        )
        return 2, b"", message, None
    status = 0 if report["overall"] == "ESTABLISHED" else 3
    return status, canonical(report) + b"\n", b"", None


def test_manifest_selects_every_vector_byte_and_trust_snapshot():
    assert set(MANIFEST) == {
        "profile",
        "schema",
        "generator",
        "contract_artifacts",
        "trust_snapshots",
        "vectors",
    }
    selected_trust = {
        item["id"]: item["sha256"] for item in MANIFEST["trust_snapshots"]
    }
    assert selected_trust == {
        trust_id: hashlib.sha256(raw).hexdigest()
        for trust_id, raw in TRUST_BYTES.items()
    }
    selected_contract = {
        item["file"]: item["sha256"] for item in MANIFEST["contract_artifacts"]
    }
    assert selected_contract == {
        filename: hashlib.sha256(raw).hexdigest()
        for filename, raw in CONTRACT_BYTES.items()
    }
    selected = {item["file"]: item["sha256"] for item in MANIFEST["vectors"]}
    actual = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in VECTORS.glob("*.json")
    }
    assert selected == actual


@pytest.mark.parametrize(
    "filename",
    [name for name in CONTRACT_FILES if name.endswith(".schema.json")],
)
def test_each_published_json_schema_is_meta_valid(filename):
    Draft202012Validator.check_schema(CONTRACT_DOCUMENTS[filename])


def test_reason_registry_matches_the_immutable_python_contract():
    published = CONTRACT_DOCUMENTS["docs/contract/refund-handoff/0.1/reason-codes.json"]
    assert published == build_reason_registry()
    reasons = published["reasons"]
    assert len(reasons) == len(REASON_CONTRACTS) == 155
    assert len({item["code"] for item in reasons}) == len(reasons)
    assert len({item["uri"] for item in reasons}) == len(reasons)
    for item in reasons:
        assert item["claims"] == sorted(item["claims"])
        assert lookup_reason_contract(item["code"]) == (
            tuple(item["claims"]),
            item["default_evidence_state"],
        )
    assert set(REASON_CONTRACTS) == {item["code"] for item in reasons}
    _schema_validator(
        "docs/contract/refund-handoff/0.1/reason-codes.schema.json"
    ).validate(published)


def test_each_published_reason_uri_resolves_to_a_labelled_html_anchor():
    page = (ROOT / "docs/contract/refund-handoff/0.1/index.html").read_text()
    anchors = re.findall(
        r'<li id="reason-([a-z0-9_]+)"><code>([a-z0-9_]+)</code></li>',
        page,
    )
    expected = [item["code"] for item in build_reason_registry()["reasons"]]
    assert len(anchors) == page.count('id="reason-')
    assert anchors == [(code, code) for code in expected]
    assert 'href="reason-codes.json"' in page
    assert 'href="report.schema.json"' in page


def test_report_reason_partitions_exactly_match_the_registry():
    report_definitions = CONTRACT_DOCUMENTS[
        "docs/contract/refund-handoff/0.1/report.schema.json"
    ]["$defs"]
    expected_names = {
        _reason_definition_name(claim, state)
        for claim in CLAIM_NAMES
        for state in EVIDENCE_STATES
    }
    actual_names = {name for name in report_definitions if name.endswith("Reason")}
    assert actual_names == expected_names
    for claim in CLAIM_NAMES:
        for state in EVIDENCE_STATES:
            expected = {
                REASON_NAMESPACE + code
                for code, (claims, reason_state) in REASON_CONTRACTS.items()
                if claim in claims and reason_state == state
            }
            assert set(_reason_schema(claim, state)["enum"]) == expected


@pytest.mark.parametrize("code", sorted(REASON_CONTRACTS))
def test_each_reason_accepts_only_its_declared_claims_and_state(code):
    claims, state = REASON_CONTRACTS[code]
    uri = REASON_NAMESPACE + code
    opposite = "NOT_ESTABLISHED" if state == "CONTRADICTED" else "CONTRADICTED"
    for claim in claims:
        assert Draft202012Validator(_reason_schema(claim, state)).is_valid(uri)
        assert not Draft202012Validator(_reason_schema(claim, opposite)).is_valid(uri)

        book = _IssueBook()
        emitter = book.contradict if state == "CONTRADICTED" else book.miss
        emitter(claim, code)
        wrong_emitter = book.miss if state == "CONTRADICTED" else book.contradict
        with pytest.raises(AssertionError, match="reason contract mismatch"):
            wrong_emitter(claim, code)

    for claim in CLAIM_NAMES.difference(claims):
        for candidate_state in EVIDENCE_STATES:
            assert not Draft202012Validator(
                _reason_schema(claim, candidate_state)
            ).is_valid(uri)
        book = _IssueBook()
        emitter = book.contradict if state == "CONTRADICTED" else book.miss
        with pytest.raises(AssertionError, match="reason contract mismatch"):
            emitter(claim, code)


def test_corpus_reason_emission_matches_the_frozen_expectations():
    expected_uris: set[str] = set()
    actual_uris: set[str] = set()
    for item in MANIFEST["vectors"]:
        if item["expected"]["exit"] == 2:
            continue
        report = _selected_report(item["case"])
        for claim, result in report["claims"].items():
            for uri in result["reasons"]:
                assert uri.startswith(REASON_NAMESPACE)
                code = uri.removeprefix(REASON_NAMESPACE)
                claims, state = lookup_reason_contract(code)
                assert claim in claims
                assert result["state"] == state
                actual_uris.add(uri)
        for result in item["expected"]["claims"].values():
            expected_uris.update(result["reasons"])
    assert actual_uris == expected_uris
    assert actual_uris <= {REASON_NAMESPACE + code for code in REASON_CONTRACTS}


@pytest.mark.parametrize("trust_id", sorted(TRUST_BYTES))
def test_contract_schema_accepts_each_trust_snapshot(trust_id):
    _schema_validator("docs/contract/refund-handoff/0.1/contract.schema.json").validate(
        strict_loads(TRUST_BYTES[trust_id])
    )


@pytest.mark.parametrize(
    "item",
    [item for item in MANIFEST["vectors"] if item["expected"]["exit"] != 2],
    ids=lambda item: item["case"],
)
def test_contract_and_report_schemas_accept_each_classified_vector(item):
    bundle = strict_loads(_case(item["case"]))
    trust = strict_loads(TRUST_BYTES[item["trust_snapshot"]])
    _schema_validator("docs/contract/refund-handoff/0.1/contract.schema.json").validate(
        bundle
    )
    _schema_validator("docs/contract/refund-handoff/0.1/report.schema.json").validate(
        assess(bundle, trust)
    )


def test_run_provenance_schema_accepts_the_runner_shape():
    _schema_validator(
        "docs/contract/refund-handoff/0.1/run-provenance.schema.json"
    ).validate(strict_loads(_provenance_bytes()))


def test_unknown_reason_codes_fail_closed_in_code_and_schema():
    with pytest.raises(AssertionError, match="not registered"):
        reason_uri("unknown_reason_from_mutation")

    report = _report("04-changed-refund-tuple")
    claim = next(value for value in report["claims"].values() if value["reasons"])
    claim["reasons"][0] = (
        "https://probityai.github.io/agent-evidence-observer/contract/"
        "refund-handoff/0.1#reason-unknown_reason_from_mutation"
    )
    with pytest.raises(ValidationError):
        _schema_validator(
            "docs/contract/refund-handoff/0.1/report.schema.json"
        ).validate(report)


@pytest.mark.parametrize("item", MANIFEST["vectors"], ids=lambda item: item["case"])
def test_cli_preserves_each_vector_result(item, monkeypatch, capsys):
    path = VECTORS / item["file"]
    monkeypatch.setattr(
        "sys.argv",
        [
            "agent-evidence-read-refund-handoff",
            "--bundle",
            str(path),
            "--trust-snapshot",
            str(TRUST_ROOT / (item["trust_snapshot"] + ".json")),
        ],
    )
    assert main() == item["expected"]["exit"]
    captured = capsys.readouterr()
    if item["expected"]["exit"] == 2:
        assert captured.out == ""
        assert captured.err == (
            "Refund handoff bundle refused: " + item["expected"]["refusal"] + "\n"
        )
        assert (
            hashlib.sha256(captured.err.encode("ascii")).hexdigest()
            == item["expected"]["stderr_sha256"]
        )
        return
    report = strict_loads(captured.out.rstrip("\n").encode("ascii"))
    expected = item["expected"]
    assert report["overall"] == expected["overall"]
    assert report["claims"] == expected["claims"]
    assert (
        hashlib.sha256(captured.out.encode("ascii")).hexdigest()
        == expected["report_sha256"]
    )


def test_public_generator_reproduces_every_committed_byte(tmp_path):
    module = _load_script("refund_handoff_vectors", "generate_vectors.py")
    generated = tmp_path / "fixtures/vectors"
    module.generate(generated)
    for relative in ("vector-manifest.json",):
        assert (tmp_path / "fixtures" / relative).read_bytes() == (
            PROFILE / "fixtures" / relative
        ).read_bytes()
    assert {
        path.name: path.read_bytes()
        for path in (tmp_path / "fixtures/trust").glob("*.json")
    } == {path.name: path.read_bytes() for path in TRUST_ROOT.glob("*.json")}
    assert {path.name: path.read_bytes() for path in generated.glob("*.json")} == {
        path.name: path.read_bytes() for path in VECTORS.glob("*.json")
    }


def test_runner_rejects_manifest_path_traversal():
    runner = _load_script("refund_handoff_runner", "run_corpus.py")
    manifest = deepcopy(MANIFEST)
    manifest["vectors"][0]["file"] = "../outside.json"
    with pytest.raises(runner.VerificationError, match="does not match"):
        runner._check_manifest(manifest, TRUST_BYTES, CONTRACT_BYTES)


def test_runner_rejects_wrong_trust_snapshot_bytes():
    runner = _load_script("refund_handoff_runner_trust", "run_corpus.py")
    changed = dict(TRUST_BYTES)
    changed["baseline"] += b" "
    with pytest.raises(runner.VerificationError, match="trust snapshot digest"):
        runner._check_manifest(MANIFEST, changed, CONTRACT_BYTES)


def test_runner_bounds_each_child_output_stream():
    runner = _load_script("refund_handoff_runner_bound", "run_corpus.py")
    command = [
        sys.executable,
        "-c",
        "import sys; sys.stdout.write('x' * 1048577)",
    ]
    returncode, stdout, stderr, error = runner._run_bounded(command)
    assert returncode != 0
    assert len(stdout) > runner.MAX_STREAM_BYTES
    assert stderr == b""
    assert error == "verifier output exceeds the retained byte limit"


def test_runner_stops_a_descendant_after_its_parent_exits(tmp_path):
    runner = _load_script("refund_handoff_runner_escape", "run_corpus.py")
    marker = tmp_path / "retained-descendant"
    descendant = (
        "import pathlib,time;"
        "time.sleep(0.25);"
        f"pathlib.Path({str(marker)!r}).write_text('survived',encoding='ascii')"
    )
    parent = (
        "import subprocess,sys;"
        "subprocess.Popen([sys.executable,'-c',"
        + repr(descendant)
        + "],stdout=subprocess.DEVNULL,"
        "stderr=subprocess.DEVNULL)"
    )

    returncode, stdout, stderr, error = runner._run_bounded(
        [sys.executable, "-c", parent]
    )
    assert returncode == 0
    assert stdout == b""
    assert stderr == b""
    assert error is None
    time.sleep(0.75)
    assert not marker.exists()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux seccomp containment test")
def test_runner_denies_session_detach_before_child_execution(tmp_path):
    runner = _load_script("refund_handoff_runner_detach", "run_corpus.py")
    marker = tmp_path / "escaped-descendant"
    descendant = (
        "import pathlib,time;"
        "time.sleep(0.25);"
        f"pathlib.Path({str(marker)!r}).write_text('escaped',encoding='ascii')"
    )
    parent = (
        "import errno,subprocess,sys\n"
        "try:\n"
        " subprocess.Popen([sys.executable,'-c',"
        + repr(descendant)
        + "],start_new_session=True,stdout=subprocess.DEVNULL,"
        "stderr=subprocess.DEVNULL)\n"
        "except OSError as error:\n"
        " print(error.errno == errno.EPERM)\n"
    )
    returncode, stdout, stderr, error = runner._run_bounded(
        [sys.executable, "-c", parent]
    )
    assert (returncode, stdout, stderr, error) == (0, b"True\n", b"", None)
    time.sleep(0.75)
    assert not marker.exists()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process inspection test")
def test_runner_reports_process_group_inspection_failure(monkeypatch):
    runner = _load_script("refund_handoff_runner_inspection", "run_corpus.py")

    def unavailable(_group_id):
        raise runner.VerificationError("injected process inspection failure")

    monkeypatch.setattr(runner, "_linux_group_live_members", unavailable)
    returncode, _stdout, _stderr, error = runner._run_bounded(
        [sys.executable, "-c", "pass"]
    )
    assert returncode != 0
    assert error is not None
    assert "injected process inspection failure" in error


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object containment test")
def test_runner_windows_denies_breakaway(tmp_path):
    runner = _load_script("refund_handoff_runner_breakaway", "run_corpus.py")
    marker = tmp_path / "breakaway-descendant"
    descendant = (
        "import pathlib,time;"
        "time.sleep(0.25);"
        f"pathlib.Path({str(marker)!r}).write_text('escaped',encoding='ascii')"
    )
    parent = (
        "import subprocess,sys\n"
        "try:\n"
        " subprocess.Popen([sys.executable,'-c',"
        + repr(descendant)
        + "],creationflags=subprocess.CREATE_BREAKAWAY_FROM_JOB,"
        "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n"
        "except OSError:\n"
        " print('denied')\n"
    )
    returncode, stdout, stderr, error = runner._run_bounded(
        [sys.executable, "-c", parent]
    )
    assert (returncode, stdout, stderr, error) == (0, b"denied\n", b"", None)
    time.sleep(0.75)
    assert not marker.exists()


def test_runner_materializes_all_inputs_before_execution(tmp_path, monkeypatch):
    runner = _load_script("refund_handoff_runner_materialize", "run_corpus.py")
    source = tmp_path / "repo/interop" / PROFILE.name
    source.parent.mkdir(parents=True)
    shutil.copytree(PROFILE, source)
    shutil.copytree(
        ROOT / "docs/contract/refund-handoff",
        tmp_path / "repo/docs/contract/refund-handoff",
    )
    output = tmp_path / "results"
    provenance = tmp_path / "provenance.json"
    provenance.write_bytes(_provenance_bytes())
    calls = 0
    monkeypatch.setattr(runner, "__file__", str(source / "run_corpus.py"))
    _disable_runner_preflights(runner, monkeypatch)

    def run_after_source_replacement(command: list[str]):
        nonlocal calls
        calls += 1
        bundle_path = Path(command[command.index("--bundle") + 1])
        trust_path = Path(command[command.index("--trust-snapshot") + 1])
        assert output / "inputs" in bundle_path.parents
        assert trust_path.parent == output / "inputs/trust"
        if calls == 1:
            (source / "fixtures/trust/baseline.json").write_bytes(b"replaced")
            (source / "fixtures/vectors/01-observed-success.json").write_bytes(
                b"replaced"
            )
        return _in_process_cli(command)

    monkeypatch.setattr(runner, "_run_bounded", run_after_source_replacement)
    summary = runner.run(source, output, provenance)
    assert summary["status"] == "PASS"
    assert summary["vectors_run"] == len(MANIFEST["vectors"])
    assert calls == len(MANIFEST["vectors"])


def test_runner_retains_every_case_after_one_result_mismatch(tmp_path, monkeypatch):
    runner = _load_script("refund_handoff_runner_complete", "run_corpus.py")
    output = tmp_path / "results"
    provenance = tmp_path / "provenance.json"
    provenance.write_bytes(_provenance_bytes())
    calls = 0
    _disable_runner_preflights(runner, monkeypatch)

    def mismatch_first_case(command: list[str]):
        nonlocal calls
        calls += 1
        status, stdout, stderr, problem = _in_process_cli(command)
        if calls == 1:
            stdout += b" "
        return status, stdout, stderr, problem

    monkeypatch.setattr(runner, "_run_bounded", mismatch_first_case)
    with pytest.raises(
        runner.VerificationError,
        match="complete results are retained",
    ):
        runner.run(PROFILE, output, provenance)
    summary = strict_loads((output / "summary.json").read_bytes())
    assert summary["status"] == "FAIL"
    assert summary["vectors_run"] == len(MANIFEST["vectors"])
    assert summary["vectors_failed"] == 1
    assert summary["failed_cases"] == ["01-observed-success"]
    assert calls == len(MANIFEST["vectors"])
    assert summary["results"][-1]["case"] == MANIFEST["vectors"][-1]["case"]


def test_runner_rejects_stderr_on_a_classified_case():
    runner = _load_script("refund_handoff_runner_stderr", "run_corpus.py")
    item = MANIFEST["vectors"][0]
    stdout = canonical(_report(item["case"])) + b"\n"
    errors, _ = runner._case_errors(
        item["expected"]["exit"],
        stdout,
        b"unexpected diagnostic\n",
        None,
        item["expected"],
    )
    assert "classified report wrote stderr" in errors


def test_runner_retains_late_case_containment_failure(tmp_path, monkeypatch):
    runner = _load_script("refund_handoff_runner_late_failure", "run_corpus.py")
    output = tmp_path / "results"
    output.mkdir()
    item = MANIFEST["vectors"][0]

    def fail_containment(_command):
        raise runner.VerificationError("process group state vanished")

    monkeypatch.setattr(runner, "_run_bounded", fail_containment)
    result = runner._run_case(
        SimpleNamespace(vector_root=tmp_path, trust_root=tmp_path),
        output,
        tmp_path / "pycache",
        item,
    )
    prefix = output / item["case"]
    assert result["status"] == "FAIL"
    assert (prefix.with_suffix(".exit")).read_text(encoding="ascii") == "-1\n"
    assert (prefix.with_suffix(".runner-error")).read_text(encoding="ascii") == (
        "VerificationError: process group state vanished\n"
    )
    assert prefix.with_suffix(".stdout").read_bytes() == b""
    assert prefix.with_suffix(".stderr").read_bytes() == b""


def test_runner_keeps_partial_child_output_on_late_state_failure(monkeypatch):
    runner = _load_script("refund_handoff_runner_partial_failure", "run_corpus.py")

    def fail_after_output(*_args):
        time.sleep(0.15)
        raise runner.VerificationError("process state unreadable")

    monkeypatch.setattr(runner, "_wait_bounded", fail_after_output)
    status, stdout, stderr, problem = runner._run_bounded(
        [
            sys.executable,
            "-c",
            "import sys,time;sys.stdout.write('partial');sys.stdout.flush();time.sleep(1)",
        ]
    )
    assert status == -1
    assert stdout == b"partial"
    assert stderr == b""
    assert problem == "VerificationError: process state unreadable"


def test_runner_rejects_a_runtime_environment_mismatch(tmp_path, monkeypatch):
    runner = _load_script("refund_handoff_runner_environment", "run_corpus.py")
    actual = {
        "python": "3.12.4",
        "python_implementation": "CPython",
        "python_sha256": "1" * 64,
        "platform": "test-platform",
        "uv": "uv 0.12.23",
        "uv_sha256": "2" * 64,
    }
    monkeypatch.setattr(runner, "_runtime_environment", lambda _retained: actual)
    retained = tmp_path / "runtime"
    retained.mkdir()
    runner._check_runtime_environment(actual, retained)
    assert strict_loads((retained / "environment.json").read_bytes()) == actual

    expected = dict(actual)
    expected["uv_sha256"] = "3" * 64
    with pytest.raises(
        runner.VerificationError,
        match="runtime environment differs for uv_sha256",
    ):
        runner._check_runtime_environment(expected, tmp_path / "unused")


def test_runner_retains_failing_uv_version_measurement(tmp_path, monkeypatch):
    runner = _load_script("refund_handoff_runner_uv_failure", "run_corpus.py")
    python_path = Path(sys.executable)
    monkeypatch.setattr(
        runner,
        "_runtime_executable_paths",
        lambda: (python_path, python_path),
    )
    monkeypatch.setattr(
        runner,
        "_run_bounded",
        lambda _command: (17, b"partial version", b"failure bytes", "timeout"),
    )
    retained = tmp_path / "runtime"
    with pytest.raises(runner.VerificationError, match="uv version cannot be measured"):
        runner._runtime_environment(retained)
    assert (retained / "uv-version.exit").read_text(encoding="ascii") == "17\n"
    assert (retained / "uv-version.stdout").read_bytes() == b"partial version"
    assert (retained / "uv-version.stderr").read_bytes() == b"failure bytes"
    assert (retained / "uv-version.runner-error").read_text(encoding="ascii") == (
        "timeout\n"
    )


def test_runner_parses_non_ascii_linux_process_names(tmp_path, monkeypatch):
    runner = _load_script("refund_handoff_runner_proc_name", "run_corpus.py")
    monkeypatch.setattr(
        runner.os,
        "scandir",
        lambda _path: [SimpleNamespace(name="42", path="/proc/42")],
    )
    monkeypatch.setattr(
        Path,
        "read_bytes",
        lambda _self: b"42 (caf\xe9) S 1 77 0 0 0 0 0\n",
    )
    assert runner._linux_group_live_members(77) == [42]


def test_runner_retains_non_ascii_preflight_bytes_and_ascii_failure(tmp_path):
    runner = _load_script("refund_handoff_runner_custody", "run_corpus.py")
    provenance = tmp_path / "provenance.json"
    invalid_bytes = b'{"message":"caf\xc3\xa9"}'
    provenance.write_bytes(invalid_bytes)
    output = tmp_path / "results"
    with pytest.raises(runner.VerificationError, match="non-ASCII string"):
        runner.run(PROFILE, output, provenance)
    assert (output / "provenance.json").read_bytes() == invalid_bytes
    summary_bytes = (output / "summary.json").read_bytes()
    summary_bytes.decode("ascii")
    summary = strict_loads(summary_bytes)
    assert summary["stage"] == "preflight"
    assert summary["status"] == "FAIL"

    escaped = tmp_path / "escaped"
    escaped.mkdir()
    runner._write_failure_summary(
        escaped,
        stage="test",
        error=ValueError("caf\N{LATIN SMALL LETTER E WITH ACUTE}"),
    )
    escaped_summary = strict_loads((escaped / "summary.json").read_bytes())
    assert escaped_summary["error"] == r"ValueError: caf\xe9"


@pytest.mark.parametrize(
    "field",
    [
        "profile",
        "schema",
        "kind",
        "key_id",
        "handoff_id",
        "workflow_id",
        "issuer",
        "provider_id",
        "decision_scope",
        "decision_issuer",
        "decision_id",
        "approval_ref",
        "operation_id",
        "admission_ref",
        "decision_evidence_ref",
        "approval_evidence_ref",
        "tool",
        "arguments",
        "idempotency_key",
        "issued_at",
        "not_before",
        "expires_at",
    ],
)
def test_each_signed_handoff_field_mutation_refuses(field):
    bundle = strict_loads(_case("01-observed-success"))
    payload = bundle["handoffs"][0]["payload"]
    if field == "arguments":
        payload[field]["amount_minor"] += 1
    elif field in {
        "operation_id",
        "admission_ref",
        "decision_evidence_ref",
        "approval_evidence_ref",
        "idempotency_key",
    }:
        payload[field] = "0" * 64
    else:
        payload[field] += "-changed"
    with pytest.raises(VerificationError, match="signature"):
        assess(bundle, TRUST)


def test_response_loss_keeps_effect_and_completion_claims_separate():
    report = _report("10-response-lost-unresolved")
    assert report["claims"]["admission"]["state"] == "ESTABLISHED"
    assert report["claims"]["authenticated_handoff"]["state"] == "ESTABLISHED"
    assert report["claims"]["selected_effect_coverage"] == {
        "state": "ESTABLISHED",
        "reasons": [],
        "value": "present",
    }
    assert report["claims"]["completion"] == {
        "state": "NOT_ESTABLISHED",
        "reasons": [reason_uri("unresolved_completion")],
        "value": "unknown",
    }


def test_no_effect_is_an_established_business_outcome():
    report = _report("02-observed-no-effect")
    assert report["overall"] == "ESTABLISHED"
    assert report["claims"]["selected_effect_coverage"]["value"] == "absent"
    assert report["claims"]["completion"]["value"] == "no_effect"


def test_cutoff_excludes_future_conflict_from_every_claim():
    baseline = _report("01-observed-success")
    future = _report("34-future-conflict-does-not-retroact")
    assert future["claims"] == baseline["claims"]
    assert future["counts"]["excluded_after_cutoff"] == 1


def test_array_order_and_byte_duplicates_cannot_change_claims():
    baseline = _report("01-observed-success")
    assert _report("35-array-permutation")["claims"] == baseline["claims"]
    assert _report("36-byte-identical-event-duplicate")["claims"] == baseline["claims"]


def test_added_in_cutoff_contradiction_cannot_improve_any_claim():
    order = {"NOT_ESTABLISHED": 0, "CONTRADICTED": 0, "ESTABLISHED": 1}
    baseline = _report("01-observed-success")
    changed = _report("04-changed-refund-tuple")
    for name in baseline["claims"]:
        assert (
            order[changed["claims"][name]["state"]]
            <= order[baseline["claims"][name]["state"]]
        )


def test_report_keeps_exact_references_peer_scope_and_nonclaims():
    report = _report("01-observed-success")
    assert report["witness_scope"] == "PEER"
    assert set(report["references"]) == {
        "bundle_ref",
        "trust_snapshot_ref",
        "admission_checkpoint_ref",
        "handoff_checkpoint_ref",
        "admission_ref",
        "handoff_ref",
        "execution_manifest_ref",
        "provider_snapshot_ref",
        "effect_refs",
        "terminal_refs",
    }
    assert "remote exactly-once execution" in report["does_not_assert"]
    assert (
        "complete admission history or global decision single-consumption"
        in report["does_not_assert"]
    )
    assert (
        "execution-event coverage beyond the selected observer and manifest scope"
        in report["does_not_assert"]
    )
    assert (
        "independent operation, adoption, or commercial agreement"
        in report["does_not_assert"]
    )
    assert canonical(report) == canonical(deepcopy(report))


def test_operation_identity_survives_handoff_authority_rotation():
    baseline = strict_loads(_case("01-observed-success"))["target"]
    rotated = deepcopy(baseline)
    rotated["handoff_issuer"] = "fixture.rotated-handoff-authority"
    assert operation_id(rotated) == operation_id(baseline)


def test_trust_snapshot_rejects_one_key_under_two_roles():
    changed = deepcopy(TRUST)
    changed["keys"][1]["public_key"] = changed["keys"][0]["public_key"]
    cutoff = datetime(2026, 10, 12, 10, 8, tzinfo=UTC)
    with pytest.raises(VerificationError, match="repeats Ed25519 public-key bytes"):
        check_trust_snapshot(changed, cutoff)


def test_missing_records_remain_not_established():
    missing_outcome = _report("45-missing-attempt-outcome")
    assert missing_outcome["claims"]["completion"] == {
        "state": "NOT_ESTABLISHED",
        "reasons": [reason_uri("missing_attempt_outcome")],
        "value": "unknown",
    }
    missing_resolution = _report("46-reissue-without-resolution")
    assert missing_resolution["claims"]["approval_continuity"] == {
        "state": "NOT_ESTABLISHED",
        "reasons": [reason_uri("reissued_approval_lacks_resolution")],
    }


def test_terminal_outcome_rejects_later_unresolved_reconciliation():
    report = _report("47-reconciliation-after-success")
    assert report["claims"]["completion"]["state"] == "CONTRADICTED"
    assert report["claims"]["completion"]["reasons"] == [
        reason_uri("reconciliation_after_terminal_outcome")
    ]


def test_consumer_checkpoints_detect_separately_consistent_forks():
    assert _report("57-handoff-checkpoint-fork")["claims"]["authenticated_handoff"][
        "reasons"
    ] == [reason_uri("handoff_checkpoint_handoff_ref_mismatch")]
    admission_fork = _report("58-admission-checkpoint-fork")
    assert admission_fork["claims"]["admission"]["state"] == "CONTRADICTED"
    assert (
        reason_uri("admission_checkpoint_admission_ref_mismatch")
        in admission_fork["claims"]["admission"]["reasons"]
    )


def test_typed_evidence_references_prevent_cross_type_aliasing():
    assert (
        _selected_report("67-same-local-ref-different-evidence-types")["overall"]
        == "ESTABLISHED"
    )
    aliased = _selected_report("68-approval-ref-aliases-decision-input")
    assert aliased["claims"]["admission"]["state"] == "NOT_ESTABLISHED"
    assert (
        reason_uri("referenced_approval_evidence_missing")
        in aliased["claims"]["admission"]["reasons"]
    )


def test_input_evaluation_state_is_preserved_in_the_admission_claim():
    incomplete = _selected_report("73-incomplete-decision-evidence")
    assert incomplete["claims"]["admission"]["state"] == "NOT_ESTABLISHED"
    assert (
        reason_uri("verified_evidence_not_established")
        in incomplete["claims"]["admission"]["reasons"]
    )

    contradicted = _selected_report("74-contradicted-decision-evidence")
    assert contradicted["claims"]["admission"]["state"] == "CONTRADICTED"
    assert (
        reason_uri("verified_evidence_contradicted")
        in contradicted["claims"]["admission"]["reasons"]
    )


def test_post_cutoff_records_must_still_authenticate():
    item = next(
        item
        for item in MANIFEST["vectors"]
        if item["case"] == "75-unauthenticated-input-after-cutoff"
    )
    trust = strict_loads(TRUST_BYTES[item["trust_snapshot"]])
    with pytest.raises(
        VerificationError,
        match="signature does not verify under the pinned key",
    ):
        assess(strict_loads(_case(item["case"])), trust)


def test_independent_observer_and_recovery_boundaries_are_enforced():
    effect = _selected_report("69-same-principal-without-manifest")
    assert effect["claims"]["selected_effect_coverage"] == {
        "state": "CONTRADICTED",
        "reasons": [reason_uri("effect_observer_not_separate")],
        "value": "present",
    }
    recovery = _selected_report("70-recovery-observer-not-separate")
    assert recovery["claims"]["durable_admission"]["state"] == "CONTRADICTED"
    assert (
        reason_uri("recovery_observer_not_separate")
        in recovery["claims"]["durable_admission"]["reasons"]
    )
    timing = _selected_report("71-recovery-not-after-commit")
    assert timing["claims"]["durable_admission"]["state"] == "CONTRADICTED"
    assert (
        reason_uri("recovery_not_after_commit")
        in timing["claims"]["durable_admission"]["reasons"]
    )


@pytest.mark.parametrize(
    ("case", "completion_value"),
    [
        ("76-dispatch-at-handoff-signer-revocation", "effect_committed"),
        ("77-retry-at-handoff-signer-revocation", "no_effect"),
    ],
)
def test_handoff_signer_revocation_blocks_each_new_attempt(case, completion_value):
    report = _selected_report(case)
    assert report["overall"] == "CONTRADICTED"
    assert report["claims"]["completion"] == {
        "state": "CONTRADICTED",
        "reasons": [reason_uri("attempt_at_or_after_handoff_signer_revocation")],
        "value": completion_value,
    }
    for claim, result in report["claims"].items():
        if claim != "completion":
            assert result["state"] == "ESTABLISHED"
            assert result["reasons"] == []


def test_handoff_signer_revocation_does_not_block_later_reconciliation():
    report = _selected_report("78-reconciliation-after-handoff-signer-revocation")
    assert report["overall"] == "ESTABLISHED"
    assert all(result["state"] == "ESTABLISHED" for result in report["claims"].values())
    assert all(result["reasons"] == [] for result in report["claims"].values())
    assert report["claims"]["completion"]["value"] == "no_effect"


@pytest.mark.parametrize(
    ("case", "claim", "reason"),
    [
        (
            "79-mixed-execution-observer-under-one-manifest",
            "selected_log_consistency",
            "execution_event_observer_mismatch",
        ),
        (
            "80-effect-observer-differs-from-snapshot",
            "selected_effect_coverage",
            "effect_event_observer_mismatch",
        ),
    ],
)
def test_selected_observer_principal_must_sign_its_own_records(case, claim, reason):
    report = _selected_report(case)
    assert report["overall"] == "CONTRADICTED"
    assert report["claims"][claim]["state"] == "CONTRADICTED"
    assert reason_uri(reason) in report["claims"][claim]["reasons"]


def test_authentic_handoff_cannot_replace_a_missing_admission():
    report = _selected_report("72-missing-admission-with-authentic-handoff")
    assert report["overall"] == "NOT_ESTABLISHED"
    for claim in ("admission", "durable_admission", "authenticated_handoff"):
        assert report["claims"][claim]["state"] == "NOT_ESTABLISHED"
    assert (
        reason_uri("missing_admission_commit")
        in report["claims"]["admission"]["reasons"]
    )


def test_document_reader_refuses_oversize_and_symlink_inputs(tmp_path):
    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b"x" * (MAX_DOCUMENT_BYTES + 1))
    with pytest.raises(VerificationError, match="document byte limit"):
        read_document_bytes(oversized)
    target = tmp_path / "target.json"
    target.write_bytes(b"{}")
    link = tmp_path / "link.json"
    link.symlink_to(target)
    with pytest.raises(VerificationError, match="readable regular file"):
        read_document_bytes(link)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO files need os.mkfifo")
def test_document_readers_reject_a_fifo_without_blocking(tmp_path):
    runner = _load_script("refund_handoff_runner_fifo", "run_corpus.py")
    fifo = tmp_path / "input.json"
    os.mkfifo(fifo)

    for reader, error_type in (
        (read_document_bytes, VerificationError),
        (runner.read_document_bytes, runner.VerificationError),
    ):
        outcomes: queue.SimpleQueue[BaseException | bytes] = queue.SimpleQueue()
        worker = threading.Thread(
            target=_capture_reader_result,
            args=(reader, fifo, outcomes),
            daemon=True,
        )
        worker.start()
        worker.join(timeout=1)
        assert not worker.is_alive(), "FIFO input blocked the document reader"
        outcome = outcomes.get_nowait()
        assert isinstance(outcome, error_type)
        assert "regular file" in str(outcome)
