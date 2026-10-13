"""Generate the deterministic hostile corpus for refund-handoff/0.1.

All Ed25519 seeds in this file are public test material.  They must never be
trusted outside this finite corpus.
"""

from __future__ import annotations

import hashlib
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from probity_observer.crypto import SigningKey, canonical, digest, strict_loads
from probity_observer.refund_handoff import (
    ADMISSION_DOMAIN,
    CONTRACT_ID,
    EVENT_DOMAIN,
    HANDOFF_DOMAIN,
    INPUT_DOMAIN,
    MANIFEST_DOMAIN,
    RECOVERY_DOMAIN,
    RESOLUTION_DOMAIN,
    SCHEMA,
    SNAPSHOT_DOMAIN,
    admission_state_root,
    assess,
    decision_binding_ref,
    idempotency_key,
    operation_id,
    provider_state_ref,
    verified_evidence_ref,
)

NAMESPACE = b"probity-public-refund-handoff-conformance-0.1:"
KEY_IDS = {
    "reader": "fixture.reader",
    "reader_alt": "fixture.reader-alt",
    "admission": "fixture.admission",
    "recovery": "fixture.recovery",
    "handoff": "fixture.handoff-retired",
    "handoff_active": "fixture.handoff-active",
    "execution": "fixture.execution",
    "execution_alt": "fixture.execution-alt",
    "effect": "fixture.effect",
    "effect_alt": "fixture.effect-alt",
    "revoked": "fixture.revoked-handoff",
    "unknown": "fixture.unknown-handoff",
}
ROLES = {
    "reader": "evidence-reader",
    "reader_alt": "evidence-reader",
    "admission": "admission-authority",
    "recovery": "recovery-observer",
    "handoff": "handoff-issuer",
    "handoff_active": "handoff-issuer",
    "execution": "execution-observer",
    "execution_alt": "execution-observer",
    "effect": "effect-observer",
    "effect_alt": "effect-observer",
    "revoked": "handoff-issuer",
}
PRINCIPALS = {
    "reader": "fixture.probity-reader",
    "reader_alt": "fixture.probity-reader-alt",
    "admission": "fixture.admission-authority",
    "recovery": "fixture.recovery-observer",
    "handoff": "fixture.handoff-authority",
    "handoff_active": "fixture.handoff-authority",
    "execution": "fixture.execution-observer",
    "execution_alt": "fixture.execution-observer-alt",
    "effect": "fixture.provider-observer",
    "effect_alt": "fixture.provider-observer-alt",
    "revoked": "fixture.revoked-handoff-authority",
}

WORKFLOW_ID = "fixture.refund-workflow-001"
DECISION_SCOPE = "fixture.pic-compatible.refund-pilot"
DECISION_ISSUER = "fixture.pic-compatible.authority-001"
PROVIDER_ID = "fixture.simulator-provider-001"
BASELINE_CUTOFF = "2026-10-12T10:08:00Z"
CONTRACT_ARTIFACTS = (
    "docs/contract/refund-handoff/0.1/contract.schema.json",
    "docs/contract/refund-handoff/0.1/reason-codes.json",
    "docs/contract/refund-handoff/0.1/reason-codes.schema.json",
    "docs/contract/refund-handoff/0.1/report.schema.json",
    "docs/contract/refund-handoff/0.1/run-provenance.schema.json",
)


def key(name: str) -> SigningKey:
    seed = hashlib.sha256(NAMESPACE + name.encode("ascii")).digest()
    return SigningKey(Ed25519PrivateKey.from_private_bytes(seed))


KEYS = {name: key(name) for name in KEY_IDS}


def envelope(payload: dict[str, Any], signer: str, domain: str) -> dict[str, Any]:
    signed = deepcopy(payload)
    signed["key_id"] = KEY_IDS[signer]
    return {
        "algorithm": "Ed25519",
        "key_id": KEY_IDS[signer],
        "payload": signed,
        "signature": KEYS[signer].sign(domain, signed),
    }


def trust_snapshot() -> dict[str, Any]:
    keys = []
    for name in (
        "reader",
        "reader_alt",
        "admission",
        "recovery",
        "handoff",
        "handoff_active",
        "execution",
        "execution_alt",
        "effect",
        "effect_alt",
        "revoked",
    ):
        revoked = name in {"handoff", "revoked"}
        revoked_at = (
            "2026-10-12T10:02:30Z"
            if name == "handoff"
            else "2026-10-01T00:00:00Z"
            if name == "revoked"
            else None
        )
        keys.append(
            {
                "key_id": KEY_IDS[name],
                "principal_id": PRINCIPALS[name],
                "role": ROLES[name],
                "public_key": KEYS[name].public_hex,
                "status": "revoked" if revoked else "active",
                "not_before": "2026-01-01T00:00:00Z",
                "not_after": "2027-01-01T00:00:00Z",
                "revoked_at": revoked_at,
                "scope": {
                    "workflow_ids": [WORKFLOW_ID],
                    "provider_ids": [PROVIDER_ID],
                    "decision_scopes": [DECISION_SCOPE],
                },
            }
        )
    baseline = build()
    admission = baseline["admission"]["payload"]
    handoff = baseline["handoffs"][0]["payload"]
    return {
        "profile": CONTRACT_ID,
        "schema": SCHEMA,
        "snapshot_id": "probity-public-conformance-2026-10-12",
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2027-01-01T00:00:00Z",
        "admission_checkpoint": {
            "authority_id": admission["authority_id"],
            "workflow_id": admission["workflow_id"],
            "decision_scope": admission["decision_scope"],
            "decision_issuer": admission["decision_issuer"],
            "decision_id": admission["decision_id"],
            "operation_id": admission["operation_id"],
            "admission_ref": digest(ADMISSION_DOMAIN, admission),
            "state_root": admission["state_root"],
            "observed_at": BASELINE_CUTOFF,
        },
        "handoff_checkpoint": {
            "issuer": handoff["issuer"],
            "workflow_id": handoff["workflow_id"],
            "decision_scope": handoff["decision_scope"],
            "decision_issuer": handoff["decision_issuer"],
            "decision_id": handoff["decision_id"],
            "handoff_id": handoff["handoff_id"],
            "operation_id": handoff["operation_id"],
            "handoff_ref": digest(HANDOFF_DOMAIN, handoff),
            "observed_at": BASELINE_CUTOFF,
        },
        "keys": keys,
    }


def conformance_trust_snapshots() -> dict[str, dict[str, Any]]:
    """Return every finite consumer trust input selected by the corpus."""
    baseline = trust_snapshot()
    admission_before_record = deepcopy(baseline)
    admission_before_record["snapshot_id"] = (
        "probity-public-conformance-admission-before-record"
    )
    admission_before_record["admission_checkpoint"]["observed_at"] = (
        "2026-10-12T10:00:59Z"
    )
    handoff_before_record = deepcopy(baseline)
    handoff_before_record["snapshot_id"] = (
        "probity-public-conformance-handoff-before-record"
    )
    handoff_before_record["handoff_checkpoint"]["observed_at"] = "2026-10-12T10:01:59Z"
    admission_stale = deepcopy(baseline)
    admission_stale["snapshot_id"] = "probity-public-conformance-admission-stale"
    admission_stale["admission_checkpoint"]["observed_at"] = "2026-10-12T10:07:00Z"
    handoff_stale = deepcopy(baseline)
    handoff_stale["snapshot_id"] = "probity-public-conformance-handoff-stale"
    handoff_stale["handoff_checkpoint"]["observed_at"] = "2026-10-12T10:07:00Z"
    cutoff_1014 = deepcopy(baseline)
    cutoff_1014["snapshot_id"] = "probity-public-conformance-cutoff-1014"
    cutoff_1014["admission_checkpoint"]["observed_at"] = "2026-10-12T10:14:00Z"
    cutoff_1014["handoff_checkpoint"]["observed_at"] = "2026-10-12T10:14:00Z"
    same_observer_principal = deepcopy(baseline)
    same_observer_principal["snapshot_id"] = (
        "probity-public-conformance-same-observer-principal"
    )
    for item in same_observer_principal["keys"]:
        if item["role"] == "effect-observer":
            item["principal_id"] = PRINCIPALS["execution"]
    recovery_admission_same_principal = deepcopy(baseline)
    recovery_admission_same_principal["snapshot_id"] = (
        "probity-public-conformance-recovery-admission-same-principal"
    )
    for item in recovery_admission_same_principal["keys"]:
        if item["role"] == "recovery-observer":
            item["principal_id"] = PRINCIPALS["admission"]
    same_local_bundle = build()
    same_local_bundle["inputs"][1]["payload"]["evidence_ref"] = same_local_bundle[
        "inputs"
    ][0]["payload"]["evidence_ref"]
    same_local_bundle["inputs"][1] = envelope(
        same_local_bundle["inputs"][1]["payload"], "reader", INPUT_DOMAIN
    )
    _refresh_input_bindings(same_local_bundle)
    same_local_snapshot = _snapshot_for_bundle(
        baseline,
        same_local_bundle,
        "probity-public-conformance-same-local-ref",
    )
    alias_bundle = build()
    alias_bundle["admission"]["payload"]["approval_evidence_ref"] = alias_bundle[
        "admission"
    ]["payload"]["decision_evidence_ref"]
    _resign_admission_dependents(alias_bundle)
    alias_snapshot = _snapshot_for_bundle(
        baseline,
        alias_bundle,
        "probity-public-conformance-typed-ref-alias",
    )
    incomplete_bundle = _with_decision_evaluation("NOT_ESTABLISHED")
    incomplete_snapshot = _snapshot_for_bundle(
        baseline,
        incomplete_bundle,
        "probity-public-conformance-incomplete-decision-evidence",
    )
    contradicted_bundle = _with_decision_evaluation("CONTRADICTED")
    contradicted_snapshot = _snapshot_for_bundle(
        baseline,
        contradicted_bundle,
        "probity-public-conformance-contradicted-decision-evidence",
    )
    retired_handoff_bundle = _use_retired_handoff(build())
    retired_handoff_snapshot = _snapshot_for_bundle(
        baseline,
        retired_handoff_bundle,
        "probity-public-conformance-retired-handoff",
    )
    return {
        "admission-before-record": admission_before_record,
        "admission-stale": admission_stale,
        "baseline": baseline,
        "contradicted-decision-evidence": contradicted_snapshot,
        "cutoff-1014": cutoff_1014,
        "effect-execution-same-principal": same_observer_principal,
        "handoff-before-record": handoff_before_record,
        "handoff-stale": handoff_stale,
        "incomplete-decision-evidence": incomplete_snapshot,
        "recovery-admission-same-principal": recovery_admission_same_principal,
        "retired-handoff": retired_handoff_snapshot,
        "same-local-ref": same_local_snapshot,
        "typed-ref-alias": alias_snapshot,
    }


def _snapshot_for_bundle(
    baseline: dict[str, Any],
    bundle: dict[str, Any],
    snapshot_id: str,
) -> dict[str, Any]:
    snapshot = deepcopy(baseline)
    snapshot["snapshot_id"] = snapshot_id
    admission = bundle["admission"]["payload"]
    snapshot["admission_checkpoint"].update(
        {
            "admission_ref": digest(ADMISSION_DOMAIN, admission),
            "state_root": admission["state_root"],
        }
    )
    handoff = bundle["handoffs"][0]["payload"]
    snapshot["handoff_checkpoint"]["handoff_ref"] = digest(HANDOFF_DOMAIN, handoff)
    return snapshot


def target() -> dict[str, Any]:
    return {
        "workflow_id": WORKFLOW_ID,
        "decision_scope": DECISION_SCOPE,
        "decision_issuer": DECISION_ISSUER,
        "decision_id": "decision-001",
        "admission_authority_id": PRINCIPALS["admission"],
        "handoff_issuer": PRINCIPALS["handoff"],
        "provider_id": PROVIDER_ID,
        "tool": "refund",
        "arguments": {
            "payment_id": "pay-A",
            "amount_minor": 4000,
            "currency": "EUR",
        },
    }


def verified_input(
    role: str,
    *,
    approval_ref: str = "approval-001",
    verified_at: str | None = None,
    arguments: dict[str, Any] | None = None,
    suffix: str = "001",
) -> dict[str, Any]:
    selected = target()
    when = verified_at or (
        "2026-10-12T10:00:00Z"
        if role == "decision_evidence"
        else "2026-10-12T10:00:30Z"
    )
    source = "PIC" if role == "decision_evidence" else "APS"
    payload = {
        "profile": CONTRACT_ID,
        "schema": SCHEMA,
        "kind": "verified_evidence",
        "key_id": KEY_IDS["reader"],
        "input_id": f"{source.lower()}-input-{suffix}",
        "evidence_role": role,
        "compatibility_profile": (
            "fixture.pic-compatible/refund-decision/0.1"
            if role == "decision_evidence"
            else "fixture.aps-compatible/approval-receipt/0.1"
        ),
        "evidence_ref": digest(
            "probity-public-source-fixture-v0.1",
            {"source": source, "case": "refund-" + suffix},
        ),
        "decision_scope": selected["decision_scope"],
        "decision_issuer": selected["decision_issuer"],
        "decision_id": selected["decision_id"],
        "approval_ref": approval_ref,
        "tool": "refund",
        "arguments": deepcopy(arguments or selected["arguments"]),
        "evaluation": "ESTABLISHED",
        "reader_id": PRINCIPALS["reader"],
        "verified_at": when,
    }
    return envelope(payload, "reader", INPUT_DOMAIN)


def _event_common(
    kind: str, event_id: str, attempt_id: str, occurred_at: str
) -> dict[str, Any]:
    selected = target()
    operation = operation_id(selected)
    return {
        "profile": CONTRACT_ID,
        "schema": SCHEMA,
        "kind": kind,
        "key_id": KEY_IDS["execution"],
        "event_id": event_id,
        "sequence": 0,
        "previous_event_ref": None,
        "workflow_id": selected["workflow_id"],
        "decision_scope": selected["decision_scope"],
        "handoff_issuer": selected["handoff_issuer"],
        "provider_id": selected["provider_id"],
        "operation_id": operation,
        "idempotency_key": idempotency_key(operation, selected["provider_id"]),
        "attempt_id": attempt_id,
        "observer_id": PRINCIPALS["execution"],
        "occurred_at": occurred_at,
    }


def _link_and_sign_events(
    bundle: dict[str, Any],
    *,
    observer_overrides: dict[str, str] | None = None,
    signer_overrides: dict[str, str] | None = None,
) -> None:
    """Rebuild the chain and all valid typed references by attempt identity."""
    payloads = [deepcopy(item["payload"]) for item in bundle["events"]]
    previous: str | None = None
    rebuilt: list[dict[str, Any]] = []
    attempt_refs: dict[str, str] = {}
    effect_refs: dict[str, str] = {}
    outcome_refs: dict[str, str] = {}
    reconciliation_refs: dict[str, str] = {}
    for sequence, payload in enumerate(payloads, start=1):
        payload["sequence"] = sequence
        payload["previous_event_ref"] = previous
        attempt_id = payload["attempt_id"]
        if payload["kind"] == "attempt":
            if payload["predecessor_attempt_ref"] is not None:
                prior_attempt_ids = list(attempt_refs)
                payload["predecessor_attempt_ref"] = attempt_refs[prior_attempt_ids[-1]]
        else:
            payload["attempt_ref"] = attempt_refs[attempt_id]
        if payload["kind"] == "outcome" and payload["effect_ref"] is not None:
            payload["effect_ref"] = effect_refs[attempt_id]
        if payload["kind"] == "reconciliation":
            payload["initial_outcome_ref"] = outcome_refs[attempt_id]
            payload["previous_reconciliation_ref"] = reconciliation_refs.get(attempt_id)
            if payload["effect_ref"] is not None:
                payload["effect_ref"] = effect_refs[attempt_id]
        default_signer = "effect" if payload["kind"] == "effect" else "execution"
        signer = (signer_overrides or {}).get(payload["kind"], default_signer)
        payload["key_id"] = KEY_IDS[signer]
        payload["observer_id"] = (observer_overrides or {}).get(
            payload["kind"], PRINCIPALS[signer]
        )
        signed = envelope(payload, signer, EVENT_DOMAIN)
        new_ref = digest(EVENT_DOMAIN, signed["payload"])
        if payload["kind"] == "attempt":
            attempt_refs[attempt_id] = new_ref
        elif payload["kind"] == "effect":
            effect_refs[attempt_id] = new_ref
        elif payload["kind"] == "outcome":
            outcome_refs[attempt_id] = new_ref
        else:
            reconciliation_refs[attempt_id] = new_ref
        previous = new_ref
        rebuilt.append(signed)
    bundle["events"] = rebuilt
    _refresh_manifest(bundle)
    _refresh_snapshot(bundle)


def _refresh_manifest(bundle: dict[str, Any]) -> None:
    if bundle["execution_manifest"] is None:
        return
    payload = deepcopy(bundle["execution_manifest"]["payload"])
    payload["event_count"] = len(bundle["events"])
    payload["head_event_ref"] = digest(EVENT_DOMAIN, bundle["events"][-1]["payload"])
    payload["cutoff"] = bundle["cutoff"]
    payload["issued_at"] = bundle["cutoff"]
    bundle["execution_manifest"] = envelope(payload, "execution", MANIFEST_DOMAIN)


def _refresh_snapshot(bundle: dict[str, Any]) -> None:
    if bundle["provider_snapshot"] is None:
        return
    payload = deepcopy(bundle["provider_snapshot"]["payload"])
    effect_ids = sorted(
        {
            item["payload"]["effect_id"]
            for item in bundle["events"]
            if item["payload"]["kind"] == "effect"
            and item["payload"]["occurred_at"] <= bundle["cutoff"]
        }
    )
    payload["effect_ids"] = effect_ids
    payload["effect_count"] = len(effect_ids)
    payload["observed_at"] = bundle["cutoff"]
    payload["state_ref"] = provider_state_ref(payload)
    bundle["provider_snapshot"] = envelope(payload, "effect", SNAPSHOT_DOMAIN)


def build(
    *,
    include_approval: bool = True,
    include_recovery: bool = True,
    include_effect: bool = True,
    outcome_state: str = "observed_success",
    response_received: bool = True,
    reconciliations: list[str] | None = None,
    attempt_at: str = "2026-10-12T10:03:00Z",
    effect_at: str = "2026-10-12T10:04:00Z",
    outcome_at: str = "2026-10-12T10:05:00Z",
    cutoff: str = BASELINE_CUTOFF,
) -> dict[str, Any]:
    selected = target()
    operation = operation_id(selected)
    idem = idempotency_key(operation, selected["provider_id"])
    decision = verified_input("decision_evidence")
    approval = verified_input("approval_evidence")
    inputs = [decision] + ([approval] if include_approval else [])
    decision_ref = verified_evidence_ref(decision["payload"])
    approval_ref = verified_evidence_ref(approval["payload"])
    admission = {
        "profile": CONTRACT_ID,
        "schema": SCHEMA,
        "kind": "admission_commit",
        "key_id": KEY_IDS["admission"],
        "admission_id": "admission-001",
        "workflow_id": selected["workflow_id"],
        "authority_id": selected["admission_authority_id"],
        "handoff_issuer": selected["handoff_issuer"],
        "provider_id": selected["provider_id"],
        "decision_scope": selected["decision_scope"],
        "decision_issuer": selected["decision_issuer"],
        "decision_id": selected["decision_id"],
        "approval_ref": "approval-001",
        "decision_evidence_ref": decision_ref,
        "approval_evidence_ref": approval_ref,
        "operation_id": operation,
        "decision_binding_ref": "0" * 64,
        "tool": selected["tool"],
        "arguments": deepcopy(selected["arguments"]),
        "state": "committed",
        "commit_sequence": 1,
        "previous_commit_ref": None,
        "state_root": "0" * 64,
        "committed_at": "2026-10-12T10:01:00Z",
    }
    admission["decision_binding_ref"] = decision_binding_ref(
        selected,
        admission["approval_ref"],
        decision_ref,
        approval_ref,
        operation,
    )
    admission["state_root"] = admission_state_root(admission)
    admission_envelope = envelope(admission, "admission", ADMISSION_DOMAIN)
    admission_ref = digest(ADMISSION_DOMAIN, admission_envelope["payload"])
    recovery = {
        "profile": CONTRACT_ID,
        "schema": SCHEMA,
        "kind": "admission_recovery",
        "key_id": KEY_IDS["recovery"],
        "recovery_id": "recovery-001",
        "recovery_observer_id": PRINCIPALS["recovery"],
        "workflow_id": selected["workflow_id"],
        "provider_id": selected["provider_id"],
        "decision_scope": selected["decision_scope"],
        "instance_id": "recovery-instance-002",
        "restart_id": "restart-001",
        "admission_ref": admission_ref,
        "operation_id": operation,
        "state_root": admission["state_root"],
        "state": "recovered_committed",
        "recovered_at": "2026-10-12T10:01:30Z",
    }
    handoff = {
        "profile": CONTRACT_ID,
        "schema": SCHEMA,
        "kind": "refund_handoff",
        "key_id": KEY_IDS["handoff_active"],
        "handoff_id": "handoff-001",
        "workflow_id": selected["workflow_id"],
        "issuer": selected["handoff_issuer"],
        "provider_id": selected["provider_id"],
        "decision_scope": selected["decision_scope"],
        "decision_issuer": selected["decision_issuer"],
        "decision_id": selected["decision_id"],
        "approval_ref": "approval-001",
        "operation_id": operation,
        "admission_ref": admission_ref,
        "decision_evidence_ref": decision_ref,
        "approval_evidence_ref": approval_ref,
        "tool": "refund",
        "arguments": deepcopy(selected["arguments"]),
        "idempotency_key": idem,
        "issued_at": "2026-10-12T10:02:00Z",
        "not_before": "2026-10-12T10:02:00Z",
        "expires_at": "2026-10-12T10:10:00Z",
    }
    handoff_envelope = envelope(handoff, "handoff_active", HANDOFF_DOMAIN)
    handoff_ref = digest(HANDOFF_DOMAIN, handoff_envelope["payload"])
    attempt = _event_common("attempt", "event-attempt-001", "attempt-001", attempt_at)
    attempt.update(
        {
            "handoff_ref": handoff_ref,
            "disposition": "initial",
            "predecessor_attempt_ref": None,
            "state": "dispatch_pending",
        }
    )
    attempt["sequence"] = 1
    attempt_envelope = envelope(attempt, "execution", EVENT_DOMAIN)
    attempt_ref = digest(EVENT_DOMAIN, attempt_envelope["payload"])
    events = [attempt_envelope]
    effect_ref: str | None = None
    if include_effect:
        effect = _event_common("effect", "event-effect-001", "attempt-001", effect_at)
        effect.update(
            {
                "sequence": 2,
                "previous_event_ref": attempt_ref,
                "attempt_ref": attempt_ref,
                "effect_id": "effect-001",
                "effect_type": "refund_committed",
                "arguments": deepcopy(selected["arguments"]),
                "observer_id": PRINCIPALS["effect"],
                "key_id": KEY_IDS["effect"],
            }
        )
        effect_envelope = envelope(effect, "effect", EVENT_DOMAIN)
        effect_ref = digest(EVENT_DOMAIN, effect_envelope["payload"])
        events.append(effect_envelope)
    outcome = _event_common("outcome", "event-outcome-001", "attempt-001", outcome_at)
    outcome.update(
        {
            "sequence": len(events) + 1,
            "previous_event_ref": digest(EVENT_DOMAIN, events[-1]["payload"]),
            "attempt_ref": attempt_ref,
            "state": outcome_state,
            "effect_ref": effect_ref if outcome_state != "observed_failure" else None,
            "response_received": response_received,
        }
    )
    outcome_envelope = envelope(outcome, "execution", EVENT_DOMAIN)
    events.append(outcome_envelope)
    initial_outcome_ref = digest(EVENT_DOMAIN, outcome_envelope["payload"])
    previous_reconciliation_ref: str | None = None
    for index, result in enumerate(reconciliations or [], start=1):
        record = _event_common(
            "reconciliation",
            f"event-reconciliation-{index:03d}",
            "attempt-001",
            f"2026-10-12T10:05:{index * 10:02d}Z",
        )
        record.update(
            {
                "sequence": len(events) + 1,
                "previous_event_ref": digest(EVENT_DOMAIN, events[-1]["payload"]),
                "attempt_ref": attempt_ref,
                "initial_outcome_ref": initial_outcome_ref,
                "previous_reconciliation_ref": previous_reconciliation_ref,
                "outcome": result,
                "effect_ref": effect_ref if result == "effect_confirmed" else None,
            }
        )
        signed = envelope(record, "execution", EVENT_DOMAIN)
        events.append(signed)
        previous_reconciliation_ref = digest(EVENT_DOMAIN, signed["payload"])
    manifest = {
        "profile": CONTRACT_ID,
        "schema": SCHEMA,
        "kind": "execution_manifest",
        "key_id": KEY_IDS["execution"],
        "manifest_id": "manifest-001",
        "workflow_id": selected["workflow_id"],
        "decision_scope": selected["decision_scope"],
        "handoff_issuer": selected["handoff_issuer"],
        "provider_id": selected["provider_id"],
        "operation_id": operation,
        "idempotency_key": idem,
        "event_count": len(events),
        "head_event_ref": digest(EVENT_DOMAIN, events[-1]["payload"]),
        "cutoff": cutoff,
        "observer_id": PRINCIPALS["execution"],
        "issued_at": cutoff,
    }
    effect_ids = ["effect-001"] if include_effect else []
    snapshot = {
        "profile": CONTRACT_ID,
        "schema": SCHEMA,
        "kind": "provider_snapshot",
        "key_id": KEY_IDS["effect"],
        "snapshot_id": "provider-snapshot-001",
        "workflow_id": selected["workflow_id"],
        "decision_scope": selected["decision_scope"],
        "handoff_issuer": selected["handoff_issuer"],
        "provider_id": selected["provider_id"],
        "operation_id": operation,
        "idempotency_key": idem,
        "query_scope": "refund_effects_by_idempotency_key",
        "effect_count": len(effect_ids),
        "effect_ids": effect_ids,
        "state_ref": "0" * 64,
        "observed_at": cutoff,
        "observer_id": PRINCIPALS["effect"],
    }
    snapshot["state_ref"] = provider_state_ref(snapshot)
    return {
        "profile": CONTRACT_ID,
        "schema": SCHEMA,
        "cutoff": cutoff,
        "target": selected,
        "inputs": inputs,
        "admission": admission_envelope,
        "recovery": envelope(recovery, "recovery", RECOVERY_DOMAIN)
        if include_recovery
        else None,
        "approval_resolutions": [],
        "handoffs": [handoff_envelope],
        "events": events,
        "execution_manifest": envelope(manifest, "execution", MANIFEST_DOMAIN),
        "provider_snapshot": envelope(snapshot, "effect", SNAPSHOT_DOMAIN),
    }


def _resign(bundle: dict[str, Any], member: str, signer: str, domain: str) -> None:
    bundle[member] = envelope(bundle[member]["payload"], signer, domain)


def _resign_event(
    bundle: dict[str, Any], index: int, signer: str | None = None
) -> None:
    payload = bundle["events"][index]["payload"]
    selected = signer or ("effect" if payload["kind"] == "effect" else "execution")
    bundle["events"][index] = envelope(payload, selected, EVENT_DOMAIN)


def _refresh_handoff_binding(bundle: dict[str, Any]) -> None:
    """Point every attempt at the current handoff and rebuild event references."""
    handoff_ref = digest(HANDOFF_DOMAIN, bundle["handoffs"][0]["payload"])
    for item in bundle["events"]:
        if item["payload"]["kind"] == "attempt":
            item["payload"]["handoff_ref"] = handoff_ref
    _link_and_sign_events(bundle)


def _use_retired_handoff(bundle: dict[str, Any]) -> dict[str, Any]:
    """Sign the selected handoff with the key revoked at 10:02:30Z."""
    payload = bundle["handoffs"][0]["payload"]
    bundle["handoffs"][0] = envelope(payload, "handoff", HANDOFF_DOMAIN)
    _refresh_handoff_binding(bundle)
    return bundle


def _append_no_effect_retry(
    bundle: dict[str, Any],
    *,
    attempt_at: str,
    outcome_at: str,
    outcome_state: str,
    response_received: bool,
) -> tuple[str, str]:
    """Append a predecessor-linked retry and its no-effect outcome."""
    first_attempt = next(
        item for item in bundle["events"] if item["payload"]["kind"] == "attempt"
    )
    first_attempt_ref = digest(EVENT_DOMAIN, first_attempt["payload"])
    second_attempt = _event_common(
        "attempt", "event-attempt-002", "attempt-002", attempt_at
    )
    second_attempt.update(
        {
            "sequence": len(bundle["events"]) + 1,
            "previous_event_ref": digest(EVENT_DOMAIN, bundle["events"][-1]["payload"]),
            "handoff_ref": digest(HANDOFF_DOMAIN, bundle["handoffs"][0]["payload"]),
            "disposition": "recovery",
            "predecessor_attempt_ref": first_attempt_ref,
            "state": "dispatch_pending",
        }
    )
    second_attempt_envelope = envelope(second_attempt, "execution", EVENT_DOMAIN)
    second_attempt_ref = digest(EVENT_DOMAIN, second_attempt_envelope["payload"])
    second_outcome = _event_common(
        "outcome", "event-outcome-002", "attempt-002", outcome_at
    )
    second_outcome.update(
        {
            "sequence": len(bundle["events"]) + 2,
            "previous_event_ref": second_attempt_ref,
            "attempt_ref": second_attempt_ref,
            "state": outcome_state,
            "effect_ref": None,
            "response_received": response_received,
        }
    )
    bundle["events"].extend(
        [
            second_attempt_envelope,
            envelope(second_outcome, "execution", EVENT_DOMAIN),
        ]
    )
    _link_and_sign_events(bundle)
    rebuilt_attempts = [
        item for item in bundle["events"] if item["payload"]["kind"] == "attempt"
    ]
    if len(rebuilt_attempts) != 2:
        raise AssertionError("no-effect retry helper requires exactly two attempts")
    return (
        digest(EVENT_DOMAIN, rebuilt_attempts[0]["payload"]),
        digest(EVENT_DOMAIN, rebuilt_attempts[1]["payload"]),
    )


def _resign_admission_dependents(bundle: dict[str, Any]) -> None:
    """Rebuild every signed reference downstream of the current input refs."""
    admission = bundle["admission"]["payload"]
    admission["decision_binding_ref"] = decision_binding_ref(
        bundle["target"],
        admission["approval_ref"],
        admission["decision_evidence_ref"],
        admission["approval_evidence_ref"],
        admission["operation_id"],
    )
    admission["state_root"] = admission_state_root(admission)
    bundle["admission"] = envelope(admission, "admission", ADMISSION_DOMAIN)
    admission_ref = digest(ADMISSION_DOMAIN, admission)
    if bundle["recovery"] is not None:
        bundle["recovery"]["payload"]["admission_ref"] = admission_ref
        bundle["recovery"]["payload"]["state_root"] = admission["state_root"]
        _resign(bundle, "recovery", "recovery", RECOVERY_DOMAIN)
    handoff = bundle["handoffs"][0]["payload"]
    handoff["admission_ref"] = admission_ref
    handoff["decision_evidence_ref"] = admission["decision_evidence_ref"]
    handoff["approval_evidence_ref"] = admission["approval_evidence_ref"]
    bundle["handoffs"][0] = envelope(handoff, "handoff_active", HANDOFF_DOMAIN)
    _refresh_handoff_binding(bundle)


def _refresh_input_bindings(bundle: dict[str, Any]) -> None:
    admission = bundle["admission"]["payload"]
    decision = next(
        item["payload"]
        for item in bundle["inputs"]
        if item["payload"]["evidence_role"] == "decision_evidence"
    )
    approval = next(
        item["payload"]
        for item in bundle["inputs"]
        if item["payload"]["evidence_role"] == "approval_evidence"
        and item["payload"]["approval_ref"] == admission["approval_ref"]
    )
    admission["decision_evidence_ref"] = verified_evidence_ref(decision)
    admission["approval_evidence_ref"] = verified_evidence_ref(approval)
    _resign_admission_dependents(bundle)


def _with_decision_evaluation(value: str) -> dict[str, Any]:
    bundle = build()
    index, decision = next(
        (index, item)
        for index, item in enumerate(bundle["inputs"])
        if item["payload"]["evidence_role"] == "decision_evidence"
    )
    decision["payload"]["evaluation"] = value
    bundle["inputs"][index] = envelope(decision["payload"], "reader", INPUT_DOMAIN)
    _refresh_input_bindings(bundle)
    return bundle


def _add_reissue(bundle: dict[str, Any]) -> None:
    reissue = verified_input(
        "approval_evidence",
        approval_ref="approval-002",
        verified_at="2026-10-12T10:02:10Z",
        suffix="002",
    )
    bundle["inputs"].append(reissue)
    admission_ref = digest(ADMISSION_DOMAIN, bundle["admission"]["payload"])
    operation = bundle["admission"]["payload"]["operation_id"]
    resolution = {
        "profile": CONTRACT_ID,
        "schema": SCHEMA,
        "kind": "approval_resolution",
        "key_id": KEY_IDS["admission"],
        "resolution_id": "resolution-001",
        "authority_id": PRINCIPALS["admission"],
        "workflow_id": bundle["target"]["workflow_id"],
        "provider_id": bundle["target"]["provider_id"],
        "decision_scope": bundle["target"]["decision_scope"],
        "decision_issuer": bundle["target"]["decision_issuer"],
        "decision_id": bundle["target"]["decision_id"],
        "original_approval_ref": "approval-001",
        "reissued_approval_ref": "approval-002",
        "original_admission_ref": admission_ref,
        "operation_id": operation,
        "tool": "refund",
        "arguments": deepcopy(bundle["target"]["arguments"]),
        "disposition": "resolved_existing",
        "resolved_at": "2026-10-12T10:02:20Z",
    }
    bundle["approval_resolutions"].append(
        envelope(resolution, "admission", RESOLUTION_DOMAIN)
    )


def vectors() -> dict[str, tuple[bytes, dict[str, Any], str]]:
    cases: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {}

    def add(name: str, bundle: dict[str, Any], **expected: Any) -> None:
        cases[name] = (bundle, expected)

    add("01-observed-success", build(), exit=0, overall="ESTABLISHED")
    add(
        "02-observed-no-effect",
        build(include_effect=False, outcome_state="observed_failure"),
        exit=0,
        overall="ESTABLISHED",
        completion="ESTABLISHED",
        completion_value="no_effect",
    )
    add(
        "03-missing-recovery",
        build(include_recovery=False),
        exit=3,
        overall="NOT_ESTABLISHED",
    )

    changed_tuple = build()
    changed_tuple["handoffs"][0]["payload"]["arguments"]["amount_minor"] = 4001
    changed_tuple["handoffs"][0] = envelope(
        changed_tuple["handoffs"][0]["payload"], "handoff_active", HANDOFF_DOMAIN
    )
    _refresh_handoff_binding(changed_tuple)
    add("04-changed-refund-tuple", changed_tuple, exit=3, overall="CONTRADICTED")

    changed_operation = build()
    changed_operation["handoffs"][0]["payload"]["operation_id"] = "0" * 64
    changed_operation["handoffs"][0] = envelope(
        changed_operation["handoffs"][0]["payload"],
        "handoff_active",
        HANDOFF_DOMAIN,
    )
    add("05-changed-operation-id", changed_operation, exit=3, overall="CONTRADICTED")

    allowed_reissue = build()
    _add_reissue(allowed_reissue)
    add("06-reissue-resolves-existing", allowed_reissue, exit=0, overall="ESTABLISHED")

    replacement_reissue = deepcopy(allowed_reissue)
    admission = replacement_reissue["admission"]["payload"]
    admission["approval_ref"] = "approval-002"
    admission["approval_evidence_ref"] = verified_evidence_ref(
        replacement_reissue["inputs"][-1]["payload"]
    )
    admission["decision_binding_ref"] = decision_binding_ref(
        replacement_reissue["target"],
        admission["approval_ref"],
        admission["decision_evidence_ref"],
        admission["approval_evidence_ref"],
        admission["operation_id"],
    )
    admission["state_root"] = admission_state_root(admission)
    replacement_reissue["admission"] = envelope(
        admission, "admission", ADMISSION_DOMAIN
    )
    add(
        "07-reissue-replaces-original",
        replacement_reissue,
        exit=3,
        overall="CONTRADICTED",
    )

    duplicate = build()
    duplicate["handoffs"].append(deepcopy(duplicate["handoffs"][0]))
    add(
        "08-identical-handoff-replay",
        duplicate,
        exit=0,
        overall="ESTABLISHED",
        unique_handoffs=1,
    )

    changed_replay = build()
    changed = deepcopy(changed_replay["handoffs"][0]["payload"])
    changed["expires_at"] = "2026-10-12T10:09:00Z"
    changed_replay["handoffs"].append(
        envelope(changed, "handoff_active", HANDOFF_DOMAIN)
    )
    add("09-changed-handoff-replay", changed_replay, exit=3, overall="CONTRADICTED")

    add(
        "10-response-lost-unresolved",
        build(outcome_state="unresolved", response_received=False),
        exit=3,
        overall="NOT_ESTABLISHED",
        selected_effect_coverage="ESTABLISHED",
        completion="NOT_ESTABLISHED",
    )
    add(
        "11-response-lost-reconciled",
        build(
            outcome_state="unresolved",
            response_received=False,
            reconciliations=["effect_confirmed"],
        ),
        exit=0,
        overall="ESTABLISHED",
    )
    add(
        "12-repeated-reconciliation",
        build(
            outcome_state="unresolved",
            response_received=False,
            reconciliations=["still_unresolved", "effect_confirmed"],
        ),
        exit=0,
        overall="ESTABLISHED",
    )
    add(
        "13-expired-before-dispatch",
        build(
            attempt_at="2026-10-12T10:11:00Z",
            effect_at="2026-10-12T10:12:00Z",
            outcome_at="2026-10-12T10:13:00Z",
            cutoff="2026-10-12T10:14:00Z",
        ),
        exit=3,
        overall="CONTRADICTED",
        trust_snapshot="cutoff-1014",
    )
    add(
        "14-missing-approval-evidence",
        build(include_approval=False),
        exit=3,
        overall="NOT_ESTABLISHED",
    )

    future_reconciliation = build(
        outcome_state="unresolved",
        response_received=False,
        reconciliations=["effect_confirmed"],
    )
    future_reconciliation["events"][-1]["payload"]["occurred_at"] = (
        "2026-10-12T10:09:00Z"
    )
    _resign_event(future_reconciliation, -1)
    manifest = future_reconciliation["execution_manifest"]["payload"]
    manifest["event_count"] = 3
    manifest["head_event_ref"] = digest(
        EVENT_DOMAIN, future_reconciliation["events"][-2]["payload"]
    )
    future_reconciliation["execution_manifest"] = envelope(
        manifest, "execution", MANIFEST_DOMAIN
    )
    add(
        "15-reconciliation-after-cutoff",
        future_reconciliation,
        exit=3,
        overall="NOT_ESTABLISHED",
        excluded_after_cutoff=1,
    )

    bad_signature = build()
    signature = bad_signature["handoffs"][0]["signature"]
    bad_signature["handoffs"][0]["signature"] = (
        "B" if signature[0] == "A" else "A"
    ) + signature[1:]
    add("16-bad-handoff-signature", bad_signature, exit=2, refusal="signature")

    unknown = build()
    unknown["handoffs"][0] = envelope(
        unknown["handoffs"][0]["payload"], "unknown", HANDOFF_DOMAIN
    )
    add("17-unknown-handoff-issuer", unknown, exit=2, refusal="trust snapshot")

    revoked = build()
    revoked_payload = deepcopy(revoked["handoffs"][0]["payload"])
    revoked_payload["issuer"] = PRINCIPALS["revoked"]
    revoked["handoffs"][0] = envelope(revoked_payload, "revoked", HANDOFF_DOMAIN)
    add("18-revoked-handoff-issuer", revoked, exit=2, refusal="revoked")

    extra = build()
    extra_payload = deepcopy(extra["handoffs"][0]["payload"])
    extra_payload["unregistered_hint"] = "must-refuse"
    extra["handoffs"][0] = envelope(extra_payload, "handoff_active", HANDOFF_DOMAIN)
    add("19-unknown-signed-member", extra, exit=2, refusal="closed profile")

    wrong_role = build()
    wrong_role["handoffs"][0] = envelope(
        wrong_role["handoffs"][0]["payload"], "admission", HANDOFF_DOMAIN
    )
    add("20-wrong-signer-role", wrong_role, exit=2, refusal="role")

    late_input = build()
    late_input["inputs"][0]["payload"]["verified_at"] = "2026-10-12T10:09:00Z"
    late_input["inputs"][0] = envelope(
        late_input["inputs"][0]["payload"], "reader", INPUT_DOMAIN
    )
    add(
        "21-input-after-cutoff",
        late_input,
        exit=3,
        overall="NOT_ESTABLISHED",
        excluded_after_cutoff=1,
    )

    early_effect = build()
    early_effect["events"][1]["payload"]["occurred_at"] = "2026-10-12T10:02:30Z"
    _link_and_sign_events(early_effect)
    add("22-effect-precedes-attempt", early_effect, exit=3, overall="CONTRADICTED")

    unknown_attempt = build()
    unknown_outcome = deepcopy(unknown_attempt["events"][2]["payload"])
    unknown_outcome.update(
        {
            "event_id": "event-outcome-unknown",
            "sequence": 4,
            "previous_event_ref": digest(
                EVENT_DOMAIN, unknown_attempt["events"][-1]["payload"]
            ),
            "attempt_id": "attempt-999",
            "attempt_ref": "f" * 64,
            "effect_ref": None,
            "state": "unresolved",
            "response_received": False,
            "occurred_at": "2026-10-12T10:05:30Z",
        }
    )
    unknown_attempt["events"].append(
        envelope(unknown_outcome, "execution", EVENT_DOMAIN)
    )
    _refresh_manifest(unknown_attempt)
    add(
        "23-success-references-unknown-attempt",
        unknown_attempt,
        exit=3,
        overall="CONTRADICTED",
    )

    regressed = build()
    later = deepcopy(regressed["events"][2]["payload"])
    later.update(
        {
            "event_id": "event-outcome-002",
            "sequence": 4,
            "previous_event_ref": digest(
                EVENT_DOMAIN, regressed["events"][-1]["payload"]
            ),
            "state": "unresolved",
            "effect_ref": None,
            "response_received": False,
            "occurred_at": "2026-10-12T10:05:30Z",
        }
    )
    regressed["events"].append(envelope(later, "execution", EVENT_DOMAIN))
    _refresh_manifest(regressed)
    add("24-success-followed-by-unresolved", regressed, exit=3, overall="CONTRADICTED")

    dispatch_early = build(attempt_at="2026-10-12T10:01:50Z")
    add("25-dispatch-before-issuance", dispatch_early, exit=3, overall="CONTRADICTED")

    later_unresolved = build(include_effect=False, outcome_state="observed_failure")
    first_attempt_ref, second_attempt_ref = _append_no_effect_retry(
        later_unresolved,
        attempt_at="2026-10-12T10:06:00Z",
        outcome_at="2026-10-12T10:06:30Z",
        outcome_state="unresolved",
        response_received=False,
    )
    add(
        "26-later-attempt-unresolved",
        later_unresolved,
        exit=3,
        overall="NOT_ESTABLISHED",
    )

    cross_attempt = deepcopy(later_unresolved)
    effect = _event_common(
        "effect", "event-effect-002", "attempt-002", "2026-10-12T10:06:15Z"
    )
    effect.update(
        {
            "sequence": 4,
            "previous_event_ref": second_attempt_ref,
            "attempt_ref": first_attempt_ref,
            "effect_id": "effect-002",
            "effect_type": "refund_committed",
            "arguments": deepcopy(cross_attempt["target"]["arguments"]),
            "observer_id": PRINCIPALS["effect"],
            "key_id": KEY_IDS["effect"],
        }
    )
    cross_attempt["events"].insert(3, envelope(effect, "effect", EVENT_DOMAIN))
    _link_and_sign_events(cross_attempt)
    # Restore the intentional reference to attempt A after the chain rebuild.
    cross_attempt["events"][3]["payload"]["attempt_ref"] = digest(
        EVENT_DOMAIN, cross_attempt["events"][0]["payload"]
    )
    _resign_event(cross_attempt, 3, "effect")
    cross_attempt["events"][4]["payload"]["previous_event_ref"] = digest(
        EVENT_DOMAIN, cross_attempt["events"][3]["payload"]
    )
    _resign_event(cross_attempt, 4, "execution")
    _refresh_manifest(cross_attempt)
    add(
        "27-cross-attempt-effect-reference",
        cross_attempt,
        exit=3,
        overall="CONTRADICTED",
    )

    rebound = deepcopy(later_unresolved)
    first_effect = _event_common(
        "effect", "event-effect-rebound-001", "attempt-001", "2026-10-12T10:03:30Z"
    )
    first_effect.update(
        {
            "attempt_ref": "0" * 64,
            "effect_id": "effect-rebound",
            "effect_type": "refund_committed",
            "arguments": deepcopy(rebound["target"]["arguments"]),
        }
    )
    second_effect = _event_common(
        "effect", "event-effect-rebound-002", "attempt-002", "2026-10-12T10:06:15Z"
    )
    second_effect.update(
        {
            "attempt_ref": "0" * 64,
            "effect_id": "effect-rebound",
            "effect_type": "refund_committed",
            "arguments": deepcopy(rebound["target"]["arguments"]),
        }
    )
    rebound["events"].insert(1, envelope(first_effect, "effect", EVENT_DOMAIN))
    rebound["events"].insert(-1, envelope(second_effect, "effect", EVENT_DOMAIN))
    _link_and_sign_events(rebound)
    add("28-effect-id-rebound", rebound, exit=3, overall="CONTRADICTED")

    broken_chain = build()
    broken_chain["events"][1]["payload"]["previous_event_ref"] = "a" * 64
    _resign_event(broken_chain, 1, "effect")
    changed_effect_ref = digest(EVENT_DOMAIN, broken_chain["events"][1]["payload"])
    broken_chain["events"][2]["payload"]["previous_event_ref"] = changed_effect_ref
    broken_chain["events"][2]["payload"]["effect_ref"] = changed_effect_ref
    _resign_event(broken_chain, 2, "execution")
    _refresh_manifest(broken_chain)
    add("29-broken-event-chain", broken_chain, exit=3, overall="CONTRADICTED")

    omitted = build()
    omitted["execution_manifest"]["payload"]["event_count"] = 2
    _resign(omitted, "execution_manifest", "execution", MANIFEST_DOMAIN)
    add("30-manifest-omits-event", omitted, exit=3, overall="CONTRADICTED")

    snapshot_count = build()
    snapshot_count["provider_snapshot"]["payload"]["effect_count"] = 2
    _resign(snapshot_count, "provider_snapshot", "effect", SNAPSHOT_DOMAIN)
    add(
        "31-provider-snapshot-count-mismatch",
        snapshot_count,
        exit=3,
        overall="CONTRADICTED",
    )

    bad_idem = build()
    bad_idem["handoffs"][0]["payload"]["idempotency_key"] = "b" * 64
    bad_idem["handoffs"][0] = envelope(
        bad_idem["handoffs"][0]["payload"], "handoff_active", HANDOFF_DOMAIN
    )
    _refresh_handoff_binding(bad_idem)
    add("32-idempotency-key-mismatch", bad_idem, exit=3, overall="CONTRADICTED")

    late_recovery = build()
    late_recovery["recovery"]["payload"]["recovered_at"] = "2026-10-12T10:02:30Z"
    _resign(late_recovery, "recovery", "recovery", RECOVERY_DOMAIN)
    add("33-recovery-after-handoff", late_recovery, exit=3, overall="CONTRADICTED")

    future_conflict = build()
    future_conflict["inputs"].append(
        verified_input(
            "decision_evidence",
            verified_at="2026-10-12T10:09:00Z",
            arguments={"payment_id": "pay-A", "amount_minor": 4001, "currency": "EUR"},
            suffix="future",
        )
    )
    add(
        "34-future-conflict-does-not-retroact",
        future_conflict,
        exit=0,
        overall="ESTABLISHED",
        excluded_after_cutoff=1,
    )

    permuted = build()
    permuted["inputs"].reverse()
    permuted["events"].reverse()
    add("35-array-permutation", permuted, exit=0, overall="ESTABLISHED")

    duplicate_event = build()
    duplicate_event["events"].append(deepcopy(duplicate_event["events"][1]))
    add(
        "36-byte-identical-event-duplicate",
        duplicate_event,
        exit=0,
        overall="ESTABLISHED",
    )

    failure_with_effect = build()
    failure_outcome = failure_with_effect["events"][2]["payload"]
    failure_outcome["state"] = "observed_failure"
    failure_outcome["effect_ref"] = None
    failure_outcome["response_received"] = True
    _resign_event(failure_with_effect, 2)
    _refresh_manifest(failure_with_effect)
    add(
        "38-observed-failure-with-effect",
        failure_with_effect,
        exit=3,
        overall="CONTRADICTED",
    )

    absent_with_effect = build(
        outcome_state="unresolved",
        response_received=False,
        reconciliations=["effect_absent"],
    )
    add(
        "39-effect-absent-with-effect",
        absent_with_effect,
        exit=3,
        overall="CONTRADICTED",
    )

    reused_event_id = build()
    reused_event_id["events"][1]["payload"]["event_id"] = "event-attempt-001"
    _resign_event(reused_event_id, 1, "effect")
    new_effect_ref = digest(EVENT_DOMAIN, reused_event_id["events"][1]["payload"])
    reused_event_id["events"][2]["payload"]["previous_event_ref"] = new_effect_ref
    reused_event_id["events"][2]["payload"]["effect_ref"] = new_effect_ref
    _resign_event(reused_event_id, 2)
    _refresh_manifest(reused_event_id)
    add("40-event-id-reuse", reused_event_id, exit=3, overall="CONTRADICTED")

    early_resolution = build()
    _add_reissue(early_resolution)
    early_resolution["approval_resolutions"][0]["payload"]["resolved_at"] = (
        "2026-10-12T10:02:00Z"
    )
    early_resolution["approval_resolutions"][0] = envelope(
        early_resolution["approval_resolutions"][0]["payload"],
        "admission",
        RESOLUTION_DOMAIN,
    )
    add(
        "41-resolution-precedes-reissue",
        early_resolution,
        exit=3,
        overall="CONTRADICTED",
    )

    conflicting_decision = build()
    conflicting_decision["inputs"].append(
        verified_input(
            "decision_evidence",
            approval_ref="approval-002",
            verified_at="2026-10-12T10:00:10Z",
            suffix="conflict",
        )
    )
    add(
        "42-conflicting-decision-evidence",
        conflicting_decision,
        exit=3,
        overall="CONTRADICTED",
    )

    excessive_lifetime = build()
    excessive_lifetime["handoffs"][0]["payload"]["expires_at"] = "2026-10-12T10:20:00Z"
    excessive_lifetime["handoffs"][0] = envelope(
        excessive_lifetime["handoffs"][0]["payload"],
        "handoff_active",
        HANDOFF_DOMAIN,
    )
    add(
        "43-excessive-handoff-lifetime",
        excessive_lifetime,
        exit=2,
        refusal="maximum lifetime",
    )

    terminal_regression = build(
        outcome_state="unresolved",
        response_received=False,
        reconciliations=["effect_confirmed", "still_unresolved"],
    )
    add(
        "44-terminal-reconciliation-regresses",
        terminal_regression,
        exit=3,
        overall="CONTRADICTED",
    )

    missing_outcome = build()
    missing_outcome["events"] = missing_outcome["events"][:-1]
    _link_and_sign_events(missing_outcome)
    add(
        "45-missing-attempt-outcome", missing_outcome, exit=3, overall="NOT_ESTABLISHED"
    )

    unresolved_reissue = build()
    unresolved_reissue["inputs"].append(
        verified_input(
            "approval_evidence",
            approval_ref="approval-002",
            verified_at="2026-10-12T10:02:10Z",
            suffix="unresolved",
        )
    )
    add(
        "46-reissue-without-resolution",
        unresolved_reissue,
        exit=3,
        overall="NOT_ESTABLISHED",
    )

    terminal_reconciliation = build()
    attempt_ref = digest(EVENT_DOMAIN, terminal_reconciliation["events"][0]["payload"])
    outcome_ref = digest(EVENT_DOMAIN, terminal_reconciliation["events"][2]["payload"])
    reconciliation = _event_common(
        "reconciliation",
        "event-reconciliation-after-success",
        "attempt-001",
        "2026-10-12T10:05:10Z",
    )
    reconciliation.update(
        {
            "sequence": 4,
            "previous_event_ref": outcome_ref,
            "attempt_ref": attempt_ref,
            "initial_outcome_ref": outcome_ref,
            "previous_reconciliation_ref": None,
            "outcome": "still_unresolved",
            "effect_ref": None,
        }
    )
    terminal_reconciliation["events"].append(
        envelope(reconciliation, "execution", EVENT_DOMAIN)
    )
    _refresh_manifest(terminal_reconciliation)
    add(
        "47-reconciliation-after-success",
        terminal_reconciliation,
        exit=3,
        overall="CONTRADICTED",
    )

    success_without_response = build()
    success_without_response["events"][2]["payload"]["response_received"] = False
    _resign_event(success_without_response, 2)
    _refresh_manifest(success_without_response)
    add(
        "48-success-without-response",
        success_without_response,
        exit=3,
        overall="CONTRADICTED",
    )

    failure_without_response = build(
        include_effect=False,
        outcome_state="observed_failure",
        response_received=False,
    )
    add(
        "49-failure-without-response",
        failure_without_response,
        exit=3,
        overall="CONTRADICTED",
    )

    unresolved_with_response = build(
        outcome_state="unresolved",
        response_received=True,
    )
    add(
        "50-unresolved-with-response",
        unresolved_with_response,
        exit=3,
        overall="CONTRADICTED",
    )

    outside_scope = build()
    outside_scope["inputs"][0]["payload"]["decision_scope"] = "fixture.outside-scope"
    outside_scope["inputs"][0] = envelope(
        outside_scope["inputs"][0]["payload"], "reader", INPUT_DOMAIN
    )
    add(
        "51-key-scope-crossing",
        outside_scope,
        exit=2,
        refusal="outside its decision_scopes scope",
    )

    mismatched_key_id = build()
    mismatched_payload = deepcopy(mismatched_key_id["inputs"][0]["payload"])
    mismatched_payload["key_id"] = KEY_IDS["reader_alt"]
    mismatched_key_id["inputs"][0] = {
        "algorithm": "Ed25519",
        "key_id": KEY_IDS["reader"],
        "payload": mismatched_payload,
        "signature": KEYS["reader"].sign(INPUT_DOMAIN, mismatched_payload),
    }
    add(
        "52-envelope-payload-key-id-mismatch",
        mismatched_key_id,
        exit=2,
        refusal="signed key_id differs",
    )

    bad_algorithm = build()
    bad_algorithm["handoffs"][0]["algorithm"] = "Ed448"
    add(
        "53-unsupported-signature-algorithm", bad_algorithm, exit=2, refusal="algorithm"
    )

    domain_substitution = build()
    handoff_payload = domain_substitution["handoffs"][0]["payload"]
    domain_substitution["handoffs"][0]["signature"] = KEYS["handoff_active"].sign(
        ADMISSION_DOMAIN, handoff_payload
    )
    add(
        "54-signature-domain-substitution",
        domain_substitution,
        exit=2,
        refusal="signature",
    )

    before_validity = build()
    before_validity["inputs"][0]["payload"]["verified_at"] = "2025-12-31T23:59:59Z"
    before_validity["inputs"][0] = envelope(
        before_validity["inputs"][0]["payload"], "reader", INPUT_DOMAIN
    )
    add(
        "55-record-before-key-validity",
        before_validity,
        exit=2,
        refusal="validity interval",
    )

    at_revocation = build()
    at_revocation["handoffs"][0]["payload"].update(
        {
            "issued_at": "2026-10-12T10:02:30Z",
            "not_before": "2026-10-12T10:02:30Z",
            "expires_at": "2026-10-12T10:09:00Z",
        }
    )
    at_revocation["handoffs"][0] = envelope(
        at_revocation["handoffs"][0]["payload"], "handoff", HANDOFF_DOMAIN
    )
    add(
        "56-record-at-key-revocation",
        at_revocation,
        exit=2,
        refusal="revoked at record time",
    )

    handoff_fork = build()
    handoff_fork["handoffs"][0]["payload"]["expires_at"] = "2026-10-12T10:09:00Z"
    handoff_fork["handoffs"][0] = envelope(
        handoff_fork["handoffs"][0]["payload"], "handoff_active", HANDOFF_DOMAIN
    )
    _refresh_handoff_binding(handoff_fork)
    add("57-handoff-checkpoint-fork", handoff_fork, exit=3, overall="CONTRADICTED")

    admission_fork = build()
    changed_admission = admission_fork["admission"]["payload"]
    changed_admission["admission_id"] = "admission-fork"
    changed_admission["state_root"] = admission_state_root(changed_admission)
    admission_fork["admission"] = envelope(
        changed_admission, "admission", ADMISSION_DOMAIN
    )
    changed_admission_ref = digest(ADMISSION_DOMAIN, changed_admission)
    admission_fork["recovery"]["payload"]["admission_ref"] = changed_admission_ref
    admission_fork["recovery"]["payload"]["state_root"] = changed_admission[
        "state_root"
    ]
    _resign(admission_fork, "recovery", "recovery", RECOVERY_DOMAIN)
    admission_fork["handoffs"][0]["payload"]["admission_ref"] = changed_admission_ref
    admission_fork["handoffs"][0] = envelope(
        admission_fork["handoffs"][0]["payload"],
        "handoff_active",
        HANDOFF_DOMAIN,
    )
    _refresh_handoff_binding(admission_fork)
    add("58-admission-checkpoint-fork", admission_fork, exit=3, overall="CONTRADICTED")

    result = {
        name: (canonical(value), expected) for name, (value, expected) in cases.items()
    }
    baseline = canonical(build()).decode("ascii")
    duplicate_json = baseline.replace(
        '"profile":',
        '"profile":"duplicate-must-refuse","profile":',
        1,
    ).encode("ascii")
    result["37-duplicate-json-member"] = (
        duplicate_json,
        {"exit": 2, "refusal": "duplicate JSON member"},
    )
    result["59-noncanonical-json"] = (
        baseline.replace('"schema":', '"schema": ', 1).encode("ascii"),
        {"exit": 2, "refusal": "not canonical"},
    )
    result["60-float-input"] = (
        baseline.replace('"amount_minor":4000', '"amount_minor":4000.0', 1).encode(
            "ascii"
        ),
        {"exit": 2, "refusal": "outside the prototype JSON profile"},
    )
    result["61-unsafe-integer"] = (
        baseline.replace(
            '"amount_minor":4000', '"amount_minor":9007199254740992', 1
        ).encode("ascii"),
        {"exit": 2, "refusal": "safe JSON range"},
    )
    result["62-non-ascii-input"] = (
        baseline.replace("pay-A", "pay-é", 1).encode("utf-8"),
        {"exit": 2, "refusal": "non-ASCII string"},
    )
    result["63-admission-checkpoint-before-record"] = (
        canonical(build()),
        {
            "exit": 2,
            "refusal": "admission checkpoint is not observed at the report cutoff",
            "trust_snapshot": "admission-before-record",
        },
    )
    result["64-handoff-checkpoint-before-record"] = (
        canonical(build()),
        {
            "exit": 2,
            "refusal": "handoff checkpoint is not observed at the report cutoff",
            "trust_snapshot": "handoff-before-record",
        },
    )
    result["65-admission-checkpoint-stale"] = (
        canonical(build()),
        {
            "exit": 2,
            "refusal": "admission checkpoint is not observed at the report cutoff",
            "trust_snapshot": "admission-stale",
        },
    )
    result["66-handoff-checkpoint-stale"] = (
        canonical(build()),
        {
            "exit": 2,
            "refusal": "handoff checkpoint is not observed at the report cutoff",
            "trust_snapshot": "handoff-stale",
        },
    )
    same_local_ref = build()
    same_local_ref["inputs"][1]["payload"]["evidence_ref"] = same_local_ref["inputs"][
        0
    ]["payload"]["evidence_ref"]
    same_local_ref["inputs"][1] = envelope(
        same_local_ref["inputs"][1]["payload"], "reader", INPUT_DOMAIN
    )
    _refresh_input_bindings(same_local_ref)
    result["67-same-local-ref-different-evidence-types"] = (
        canonical(same_local_ref),
        {"exit": 0, "overall": "ESTABLISHED", "trust_snapshot": "same-local-ref"},
    )
    typed_ref_alias = build()
    typed_ref_alias["admission"]["payload"]["approval_evidence_ref"] = typed_ref_alias[
        "admission"
    ]["payload"]["decision_evidence_ref"]
    _resign_admission_dependents(typed_ref_alias)
    result["68-approval-ref-aliases-decision-input"] = (
        canonical(typed_ref_alias),
        {
            "exit": 3,
            "overall": "NOT_ESTABLISHED",
            "trust_snapshot": "typed-ref-alias",
        },
    )
    missing_manifest_same_observer = build()
    missing_manifest_same_observer["execution_manifest"] = None
    for item in missing_manifest_same_observer["events"]:
        if item["payload"]["kind"] == "effect":
            item["payload"]["observer_id"] = PRINCIPALS["execution"]
    _link_and_sign_events(
        missing_manifest_same_observer,
        observer_overrides={"effect": PRINCIPALS["execution"]},
    )
    missing_manifest_same_observer["provider_snapshot"]["payload"]["observer_id"] = (
        PRINCIPALS["execution"]
    )
    _resign(
        missing_manifest_same_observer,
        "provider_snapshot",
        "effect",
        SNAPSHOT_DOMAIN,
    )
    result["69-same-principal-without-manifest"] = (
        canonical(missing_manifest_same_observer),
        {
            "exit": 3,
            "overall": "CONTRADICTED",
            "trust_snapshot": "effect-execution-same-principal",
        },
    )
    recovery_same_principal = build()
    recovery_same_principal["recovery"]["payload"]["recovery_observer_id"] = PRINCIPALS[
        "admission"
    ]
    _resign(
        recovery_same_principal,
        "recovery",
        "recovery",
        RECOVERY_DOMAIN,
    )
    result["70-recovery-observer-not-separate"] = (
        canonical(recovery_same_principal),
        {
            "exit": 3,
            "overall": "CONTRADICTED",
            "trust_snapshot": "recovery-admission-same-principal",
        },
    )
    recovery_at_commit = build()
    recovery_at_commit["recovery"]["payload"]["recovered_at"] = recovery_at_commit[
        "admission"
    ]["payload"]["committed_at"]
    _resign(recovery_at_commit, "recovery", "recovery", RECOVERY_DOMAIN)
    result["71-recovery-not-after-commit"] = (
        canonical(recovery_at_commit),
        {"exit": 3, "overall": "CONTRADICTED"},
    )
    missing_admission = build()
    missing_admission["admission"] = None
    result["72-missing-admission-with-authentic-handoff"] = (
        canonical(missing_admission),
        {"exit": 3, "overall": "NOT_ESTABLISHED"},
    )
    result["73-incomplete-decision-evidence"] = (
        canonical(_with_decision_evaluation("NOT_ESTABLISHED")),
        {
            "exit": 3,
            "overall": "NOT_ESTABLISHED",
            "trust_snapshot": "incomplete-decision-evidence",
        },
    )
    result["74-contradicted-decision-evidence"] = (
        canonical(_with_decision_evaluation("CONTRADICTED")),
        {
            "exit": 3,
            "overall": "CONTRADICTED",
            "trust_snapshot": "contradicted-decision-evidence",
        },
    )
    unauthenticated_future = build()
    future_input = verified_input(
        "decision_evidence",
        verified_at="2026-10-12T10:09:00Z",
        suffix="future-unauthenticated",
    )
    future_input["signature"] = "A" + future_input["signature"][1:]
    unauthenticated_future["inputs"].append(future_input)
    result["75-unauthenticated-input-after-cutoff"] = (
        canonical(unauthenticated_future),
        {
            "exit": 2,
            "refusal": "signature does not verify under the pinned key",
        },
    )
    dispatch_at_revocation = _use_retired_handoff(
        build(attempt_at="2026-10-12T10:02:30Z")
    )
    result["76-dispatch-at-handoff-signer-revocation"] = (
        canonical(dispatch_at_revocation),
        {
            "exit": 3,
            "overall": "CONTRADICTED",
            "trust_snapshot": "retired-handoff",
        },
    )
    retry_at_revocation = build(
        include_effect=False,
        outcome_state="observed_failure",
        attempt_at="2026-10-12T10:02:10Z",
        outcome_at="2026-10-12T10:02:20Z",
    )
    _append_no_effect_retry(
        retry_at_revocation,
        attempt_at="2026-10-12T10:02:30Z",
        outcome_at="2026-10-12T10:02:40Z",
        outcome_state="observed_failure",
        response_received=True,
    )
    _use_retired_handoff(retry_at_revocation)
    result["77-retry-at-handoff-signer-revocation"] = (
        canonical(retry_at_revocation),
        {
            "exit": 3,
            "overall": "CONTRADICTED",
            "trust_snapshot": "retired-handoff",
        },
    )
    reconciliation_after_revocation = _use_retired_handoff(
        build(
            include_effect=False,
            outcome_state="unresolved",
            response_received=False,
            reconciliations=["effect_absent"],
            attempt_at="2026-10-12T10:02:10Z",
            outcome_at="2026-10-12T10:02:20Z",
        )
    )
    result["78-reconciliation-after-handoff-signer-revocation"] = (
        canonical(reconciliation_after_revocation),
        {
            "exit": 0,
            "overall": "ESTABLISHED",
            "trust_snapshot": "retired-handoff",
        },
    )
    mixed_execution_observer = build()
    _link_and_sign_events(
        mixed_execution_observer,
        signer_overrides={"outcome": "execution_alt"},
    )
    result["79-mixed-execution-observer-under-one-manifest"] = (
        canonical(mixed_execution_observer),
        {"exit": 3, "overall": "CONTRADICTED"},
    )
    mismatched_effect_observer = build()
    _link_and_sign_events(
        mismatched_effect_observer,
        signer_overrides={"effect": "effect_alt"},
    )
    result["80-effect-observer-differs-from-snapshot"] = (
        canonical(mismatched_effect_observer),
        {"exit": 3, "overall": "CONTRADICTED"},
    )
    trust_inputs = conformance_trust_snapshots()
    normalized = {}
    for name, (raw, hint) in sorted(result.items()):
        selected_trust = hint.pop("trust_snapshot", "baseline")
        try:
            report = assess(strict_loads(raw), trust_inputs[selected_trust])
        except Exception as error:
            if hint["exit"] != 2 or hint["refusal"] not in str(error):
                raise AssertionError(
                    name + " produced an unexpected refusal"
                ) from error
            stderr = ("Refund handoff bundle refused: " + str(error) + "\n").encode(
                "ascii"
            )
            expected = {
                "exit": 2,
                "refusal": str(error),
                "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
            }
        else:
            exit_code = 0 if report["overall"] == "ESTABLISHED" else 3
            if hint["exit"] != exit_code or hint["overall"] != report["overall"]:
                raise AssertionError(name + " produced an unexpected classification")
            stdout = canonical(report) + b"\n"
            expected = {
                "exit": exit_code,
                "overall": report["overall"],
                "claims": report["claims"],
                "report_sha256": hashlib.sha256(stdout).hexdigest(),
            }
        normalized[name] = (raw, expected, selected_trust)
    return normalized


def generate(output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    selected = vectors()
    manifest = []
    for name, (raw, expected, trust_id) in sorted(selected.items()):
        filename = name + ".json"
        (output / filename).write_bytes(raw)
        manifest.append(
            {
                "case": name,
                "file": filename,
                "sha256": hashlib.sha256(raw).hexdigest(),
                "trust_snapshot": trust_id,
                "expected": expected,
            }
        )
    trust_root = output.parent / "trust"
    trust_root.mkdir(parents=True, exist_ok=True)
    trust_manifest = []
    for trust_id, value in sorted(conformance_trust_snapshots().items()):
        raw = canonical(value)
        relative = "trust/" + trust_id + ".json"
        (output.parent / relative).write_bytes(raw)
        trust_manifest.append(
            {
                "id": trust_id,
                "file": relative,
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
        )
    root = Path(__file__).resolve().parents[2]
    contract_manifest = []
    for relative in CONTRACT_ARTIFACTS:
        raw = (root / relative).read_bytes()
        contract_manifest.append(
            {"file": relative, "sha256": hashlib.sha256(raw).hexdigest()}
        )
    (output.parent / "vector-manifest.json").write_bytes(
        canonical(
            {
                "profile": CONTRACT_ID,
                "schema": SCHEMA,
                "generator": "generate_vectors.py",
                "contract_artifacts": contract_manifest,
                "trust_snapshots": trust_manifest,
                "vectors": manifest,
            }
        )
    )


if __name__ == "__main__":
    target_path = (
        Path(sys.argv[1])
        if len(sys.argv) == 2
        else Path(__file__).resolve().parent / "fixtures/vectors"
    )
    generate(target_path)
