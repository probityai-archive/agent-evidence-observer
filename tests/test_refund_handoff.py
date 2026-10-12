"""Conformance, mutation, and monotonicity tests for refund-handoff/0.1."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import importlib.util
from pathlib import Path
import sys

import pytest

from probity_observer.crypto import VerificationError, canonical, strict_loads
from probity_observer.refund_handoff import assess, main

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "interop/refund-handoff-conformance-2026-10-12"
VECTORS = PROFILE / "fixtures/vectors"
TRUST_BYTES = (PROFILE / "fixtures/trust-snapshot.json").read_bytes()
TRUST = strict_loads(TRUST_BYTES)
MANIFEST = strict_loads((PROFILE / "fixtures/vector-manifest.json").read_bytes())


def _case(name: str) -> bytes:
    return (VECTORS / (name + ".json")).read_bytes()


def _report(name: str) -> dict:
    return assess(strict_loads(_case(name)), TRUST)


def _load_script(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, PROFILE / filename)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_manifest_selects_every_vector_byte_and_trust_snapshot():
    assert set(MANIFEST) == {
        "profile",
        "schema",
        "generator",
        "trust_snapshot_sha256",
        "vectors",
    }
    assert MANIFEST["trust_snapshot_sha256"] == hashlib.sha256(TRUST_BYTES).hexdigest()
    selected = {item["file"]: item["sha256"] for item in MANIFEST["vectors"]}
    actual = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in VECTORS.glob("*.json")
    }
    assert selected == actual


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
            str(PROFILE / "fixtures/trust-snapshot.json"),
        ],
    )
    assert main() == item["expected"]["exit"]
    captured = capsys.readouterr()
    if item["expected"]["exit"] == 2:
        assert captured.out == ""
        assert item["expected"]["refusal"] in captured.err
        return
    report = strict_loads(captured.out.rstrip("\n").encode("ascii"))
    expected = item["expected"]
    assert report["overall"] == expected["overall"]
    for field in ("effect_coverage", "completion"):
        if field in expected:
            assert report["claims"][field]["state"] == expected[field]
    if "completion_value" in expected:
        assert report["claims"]["completion"]["value"] == expected["completion_value"]
    if "excluded_after_cutoff" in expected:
        assert report["counts"]["excluded_after_cutoff"] == expected["excluded_after_cutoff"]
    if "unique_handoffs" in expected:
        assert report["counts"]["unique_handoffs"] == expected["unique_handoffs"]


def test_public_generator_reproduces_every_committed_byte(tmp_path):
    module = _load_script("refund_handoff_vectors", "generate_vectors.py")
    generated = tmp_path / "fixtures/vectors"
    module.generate(generated)
    for relative in ("trust-snapshot.json", "vector-manifest.json"):
        assert (tmp_path / "fixtures" / relative).read_bytes() == (
            PROFILE / "fixtures" / relative
        ).read_bytes()
    assert {path.name: path.read_bytes() for path in generated.glob("*.json")} == {
        path.name: path.read_bytes() for path in VECTORS.glob("*.json")
    }


def test_runner_rejects_manifest_path_traversal():
    runner = _load_script("refund_handoff_runner", "run_corpus.py")
    manifest = deepcopy(MANIFEST)
    manifest["vectors"][0]["file"] = "../outside.json"
    with pytest.raises(VerificationError, match="does not match"):
        runner._check_manifest(manifest, TRUST_BYTES)


def test_runner_rejects_wrong_trust_snapshot_bytes():
    runner = _load_script("refund_handoff_runner_trust", "run_corpus.py")
    with pytest.raises(VerificationError, match="trust snapshot digest"):
        runner._check_manifest(MANIFEST, TRUST_BYTES + b" ")


def test_runner_bounds_each_child_output_stream():
    runner = _load_script("refund_handoff_runner_bound", "run_corpus.py")
    command = [
        sys.executable,
        "-c",
        "import sys; sys.stdout.write('x' * 1048577)",
    ]
    with pytest.raises(VerificationError, match="byte limit"):
        runner._run_bounded(command)


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
    assert report["claims"]["effect_coverage"] == {
        "state": "ESTABLISHED",
        "reasons": [],
        "value": "present",
    }
    assert report["claims"]["completion"] == {
        "state": "NOT_ESTABLISHED",
        "reasons": ["unresolved_completion"],
        "value": "unknown",
    }


def test_no_effect_is_an_established_business_outcome():
    report = _report("02-observed-no-effect")
    assert report["overall"] == "ESTABLISHED"
    assert report["claims"]["effect_coverage"]["value"] == "absent"
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
        assert order[changed["claims"][name]["state"]] <= order[baseline["claims"][name]["state"]]


def test_report_keeps_exact_references_peer_scope_and_nonclaims():
    report = _report("01-observed-success")
    assert report["witness_scope"] == "PEER"
    assert set(report["references"]) == {
        "bundle_ref",
        "trust_snapshot_ref",
        "admission_ref",
        "handoff_ref",
        "execution_manifest_ref",
        "provider_snapshot_ref",
        "effect_refs",
        "terminal_refs",
    }
    assert "remote exactly-once execution" in report["does_not_assert"]
    assert "independent operation, adoption, or commercial agreement" in report["does_not_assert"]
    assert canonical(report) == canonical(deepcopy(report))
