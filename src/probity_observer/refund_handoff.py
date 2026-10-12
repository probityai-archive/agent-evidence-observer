"""Verify a bounded refund admission-to-effect evidence chain offline.

The verifier owns the report semantics and hostile conformance surface.  Input
products are replaceable producers of the generic decision_evidence and
approval_evidence roles.  A report never upgrades this PEER vantage into proof
of merchant authority, independent custody, or remote exactly-once execution.
"""

from __future__ import annotations

import argparse
from collections import defaultdict
from collections.abc import Sequence
from copy import deepcopy
from datetime import datetime, timezone
import re
import sys
from pathlib import Path
from typing import Any

from .crypto import VerificationError, canonical, digest, strict_loads, verify_signature


CONTRACT_ID = (
    "https://probityai.github.io/agent-evidence-observer/"
    "contract/refund-handoff/0.1"
)
SCHEMA = "refund-handoff/0.1"

INPUT_DOMAIN = "probity-refund-handoff-input-v0.1"
ADMISSION_DOMAIN = "probity-refund-handoff-admission-v0.1"
RECOVERY_DOMAIN = "probity-refund-handoff-recovery-v0.1"
RESOLUTION_DOMAIN = "probity-refund-handoff-approval-resolution-v0.1"
HANDOFF_DOMAIN = "probity-refund-handoff-v0.1"
EVENT_DOMAIN = "probity-refund-handoff-event-v0.1"
MANIFEST_DOMAIN = "probity-refund-handoff-execution-manifest-v0.1"
SNAPSHOT_DOMAIN = "probity-refund-handoff-provider-snapshot-v0.1"
BUNDLE_DOMAIN = "probity-refund-handoff-bundle-v0.1"
OPERATION_DOMAIN = "probity-refund-operation-v0.1"
IDEMPOTENCY_DOMAIN = "probity-refund-idempotency-v0.1"
DECISION_BINDING_DOMAIN = "probity-refund-decision-binding-v0.1"
ADMISSION_STATE_DOMAIN = "probity-refund-admission-state-v0.1"
PROVIDER_STATE_DOMAIN = "probity-refund-provider-state-v0.1"
TRUST_SNAPSHOT_DOMAIN = "probity-refund-trust-snapshot-v0.1"

MAX_HANDOFF_TTL_SECONDS = 600
HEX_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
STAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")

ENVELOPE_FIELDS = {"algorithm", "key_id", "payload", "signature"}
TARGET_FIELDS = {
    "workflow_id",
    "decision_scope",
    "decision_issuer",
    "decision_id",
    "admission_authority_id",
    "handoff_issuer",
    "provider_id",
    "tool",
    "arguments",
}
INPUT_FIELDS = {
    "profile",
    "schema",
    "kind",
    "key_id",
    "input_id",
    "evidence_role",
    "producer_profile",
    "evidence_ref",
    "decision_scope",
    "decision_issuer",
    "decision_id",
    "approval_ref",
    "tool",
    "arguments",
    "evaluation",
    "reader_id",
    "verified_at",
}
ADMISSION_FIELDS = {
    "profile",
    "schema",
    "kind",
    "key_id",
    "admission_id",
    "workflow_id",
    "authority_id",
    "handoff_issuer",
    "provider_id",
    "decision_scope",
    "decision_issuer",
    "decision_id",
    "approval_ref",
    "decision_evidence_ref",
    "approval_evidence_ref",
    "operation_id",
    "decision_binding_ref",
    "tool",
    "arguments",
    "state",
    "commit_sequence",
    "previous_commit_ref",
    "state_root",
    "committed_at",
}
RECOVERY_FIELDS = {
    "profile",
    "schema",
    "kind",
    "key_id",
    "recovery_id",
    "recovery_observer_id",
    "instance_id",
    "restart_id",
    "admission_ref",
    "operation_id",
    "state_root",
    "state",
    "recovered_at",
}
RESOLUTION_FIELDS = {
    "profile",
    "schema",
    "kind",
    "key_id",
    "resolution_id",
    "authority_id",
    "decision_scope",
    "decision_issuer",
    "decision_id",
    "original_approval_ref",
    "reissued_approval_ref",
    "original_admission_ref",
    "operation_id",
    "tool",
    "arguments",
    "disposition",
    "resolved_at",
}
HANDOFF_FIELDS = {
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
}
EVENT_COMMON_FIELDS = {
    "profile",
    "schema",
    "kind",
    "key_id",
    "event_id",
    "sequence",
    "previous_event_ref",
    "workflow_id",
    "issuer",
    "provider_id",
    "operation_id",
    "idempotency_key",
    "attempt_id",
    "observer_id",
    "occurred_at",
}
EVENT_FIELDS = {
    "attempt": EVENT_COMMON_FIELDS
    | {"handoff_ref", "disposition", "predecessor_attempt_ref", "state"},
    "effect": EVENT_COMMON_FIELDS
    | {"attempt_ref", "effect_id", "effect_type", "arguments"},
    "outcome": EVENT_COMMON_FIELDS
    | {"attempt_ref", "state", "effect_ref", "response_received"},
    "reconciliation": EVENT_COMMON_FIELDS
    | {
        "attempt_ref",
        "initial_outcome_ref",
        "previous_reconciliation_ref",
        "outcome",
        "effect_ref",
    },
}
MANIFEST_FIELDS = {
    "profile",
    "schema",
    "kind",
    "key_id",
    "manifest_id",
    "workflow_id",
    "issuer",
    "provider_id",
    "operation_id",
    "idempotency_key",
    "event_count",
    "head_event_ref",
    "cutoff",
    "observer_id",
    "issued_at",
}
SNAPSHOT_FIELDS = {
    "profile",
    "schema",
    "kind",
    "key_id",
    "snapshot_id",
    "provider_id",
    "operation_id",
    "idempotency_key",
    "query_scope",
    "effect_count",
    "effect_ids",
    "state_ref",
    "observed_at",
    "observer_id",
}


def _object(value: Any, fields: set[str], reason: str) -> dict[str, Any]:
    """Return an exact closed object or refuse the profile."""
    if not isinstance(value, dict) or set(value) != fields:
        raise VerificationError(reason + " has fields outside the closed profile")
    return value


def _identifier(value: Any, reason: str) -> str:
    if not isinstance(value, str) or not value or not value.isascii():
        raise VerificationError(reason + " is not a nonempty ASCII identifier")
    return value


def _sha256(value: Any, reason: str) -> str:
    if not isinstance(value, str) or HEX_DIGEST.fullmatch(value) is None:
        raise VerificationError(reason + " is not a lowercase SHA-256 digest")
    return value


def _stamp(value: Any, reason: str) -> datetime:
    if not isinstance(value, str) or STAMP.fullmatch(value) is None:
        raise VerificationError(reason + " is not a UTC second timestamp")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise VerificationError(reason + " is not a valid timestamp") from exc


def _refund(value: Any, reason: str = "refund arguments") -> dict[str, Any]:
    result = _object(
        value,
        {"payment_id", "amount_minor", "currency"},
        reason,
    )
    _identifier(result["payment_id"], reason + " payment_id")
    amount = result["amount_minor"]
    if type(amount) is not int or amount <= 0:
        raise VerificationError(reason + " amount_minor is not a positive integer")
    currency = result["currency"]
    if (
        not isinstance(currency, str)
        or len(currency) != 3
        or not currency.isascii()
        or not currency.isupper()
        or not currency.isalpha()
    ):
        raise VerificationError(reason + " currency is not an uppercase ISO-style code")
    return result


def _profile(payload: dict[str, Any], kind: str) -> None:
    if payload["profile"] != CONTRACT_ID or payload["schema"] != SCHEMA:
        raise VerificationError(kind + " selects a different contract profile")
    if payload["kind"] != kind:
        raise VerificationError(kind + " has a different signed kind")


def load_document(path: Path) -> Any:
    """Read one regular, canonical JSON file without following a symlink."""
    if path.is_symlink() or not path.is_file():
        raise VerificationError("input is not a regular file: " + path.name)
    return strict_loads(path.read_bytes())


def check_trust_snapshot(snapshot: Any, cutoff: datetime) -> dict[str, dict[str, Any]]:
    """Check the consumer-selected key set and return it by key identifier."""
    root = _object(
        snapshot,
        {"profile", "schema", "snapshot_id", "valid_from", "valid_until", "keys"},
        "trust snapshot",
    )
    if root["profile"] != CONTRACT_ID or root["schema"] != SCHEMA:
        raise VerificationError("trust snapshot selects a different profile")
    _identifier(root["snapshot_id"], "trust snapshot id")
    valid_from = _stamp(root["valid_from"], "trust snapshot valid_from")
    valid_until = _stamp(root["valid_until"], "trust snapshot valid_until")
    if not valid_from <= cutoff <= valid_until:
        raise VerificationError("cutoff is outside the trust snapshot interval")
    if not isinstance(root["keys"], list) or not root["keys"]:
        raise VerificationError("trust snapshot has no keys")
    result: dict[str, dict[str, Any]] = {}
    key_fields = {
        "key_id",
        "principal_id",
        "role",
        "public_key",
        "status",
        "not_before",
        "not_after",
        "revoked_at",
    }
    for candidate in root["keys"]:
        item = _object(candidate, key_fields, "trust key")
        key_id = _identifier(item["key_id"], "trust key id")
        _identifier(item["principal_id"], "trust principal id")
        if item["role"] not in {
            "evidence-reader",
            "admission-authority",
            "recovery-observer",
            "handoff-issuer",
            "execution-observer",
            "effect-observer",
        }:
            raise VerificationError("trust key has an unknown role")
        public = item["public_key"]
        if not isinstance(public, str) or re.fullmatch(r"[0-9a-f]{64}", public) is None:
            raise VerificationError("trust key has an invalid Ed25519 public key")
        if item["status"] not in {"active", "revoked"}:
            raise VerificationError("trust key has an unknown status")
        before = _stamp(item["not_before"], "trust key not_before")
        after = _stamp(item["not_after"], "trust key not_after")
        if before >= after:
            raise VerificationError("trust key has an empty validity interval")
        if item["revoked_at"] is not None:
            _stamp(item["revoked_at"], "trust key revoked_at")
        if item["status"] == "revoked" and item["revoked_at"] is None:
            raise VerificationError("revoked trust key lacks revoked_at")
        if item["status"] == "active" and item["revoked_at"] is not None:
            raise VerificationError("active trust key carries revoked_at")
        if key_id in result:
            raise VerificationError("trust snapshot repeats a key id")
        result[key_id] = deepcopy(item)
    return result


def _signed(
    envelope: Any,
    *,
    fields: set[str],
    kind: str,
    domain: str,
    role: str,
    time_field: str,
    trust: dict[str, dict[str, Any]],
) -> tuple[dict[str, Any], datetime, dict[str, Any]]:
    """Verify one closed signed record and its signer role and time interval."""
    outer = _object(envelope, ENVELOPE_FIELDS, kind + " envelope")
    if outer["algorithm"] != "Ed25519":
        raise VerificationError(kind + " uses an unsupported signature algorithm")
    payload = _object(outer["payload"], fields, kind)
    key_id = _identifier(outer["key_id"], kind + " envelope key_id")
    if key_id not in trust:
        raise VerificationError(kind + " signer is absent from the trust snapshot")
    key = trust[key_id]
    if key["role"] != role:
        raise VerificationError(kind + " signer has the wrong trust role")
    if key["status"] != "active":
        raise VerificationError(kind + " signer is revoked")
    signature = outer["signature"]
    if not isinstance(signature, str):
        raise VerificationError(kind + " signature is not text")
    verify_signature(key["public_key"], domain, payload, signature)
    _profile(payload, kind)
    if payload["key_id"] != key_id:
        raise VerificationError(kind + " signed key_id differs from its envelope")
    instant = _stamp(payload[time_field], kind + " " + time_field)
    if not (
        _stamp(key["not_before"], "trust key not_before")
        <= instant
        <= _stamp(key["not_after"], "trust key not_after")
    ):
        raise VerificationError(kind + " is outside its signer's validity interval")
    return payload, instant, key


def _basic_record(payload: dict[str, Any], principal: str, actor_field: str) -> None:
    _identifier(payload[actor_field], payload["kind"] + " " + actor_field)
    if payload[actor_field] != principal:
        raise VerificationError(payload["kind"] + " principal differs from its trust key")


def _input(
    envelope: Any, trust: dict[str, dict[str, Any]]
) -> tuple[dict[str, Any], datetime]:
    payload, instant, key = _signed(
        envelope,
        fields=INPUT_FIELDS,
        kind="verified_evidence",
        domain=INPUT_DOMAIN,
        role="evidence-reader",
        time_field="verified_at",
        trust=trust,
    )
    for field in (
        "input_id",
        "producer_profile",
        "evidence_ref",
        "decision_scope",
        "decision_issuer",
        "decision_id",
        "approval_ref",
    ):
        _identifier(payload[field], "verified evidence " + field)
    if payload["evidence_role"] not in {"decision_evidence", "approval_evidence"}:
        raise VerificationError("verified evidence has an unknown semantic role")
    if payload["evaluation"] not in {
        "ESTABLISHED",
        "CONTRADICTED",
        "NOT_ESTABLISHED",
    }:
        raise VerificationError("verified evidence has an unknown evaluation")
    if payload["tool"] != "refund":
        raise VerificationError("verified evidence has an unsupported tool")
    _refund(payload["arguments"], "verified evidence arguments")
    _basic_record(payload, key["principal_id"], "reader_id")
    return payload, instant


def _admission(
    envelope: Any, trust: dict[str, dict[str, Any]]
) -> tuple[dict[str, Any], datetime]:
    payload, instant, key = _signed(
        envelope,
        fields=ADMISSION_FIELDS,
        kind="admission_commit",
        domain=ADMISSION_DOMAIN,
        role="admission-authority",
        time_field="committed_at",
        trust=trust,
    )
    for field in (
        "admission_id",
        "workflow_id",
        "authority_id",
        "handoff_issuer",
        "provider_id",
        "decision_scope",
        "decision_issuer",
        "decision_id",
        "approval_ref",
    ):
        _identifier(payload[field], "admission " + field)
    for field in (
        "decision_evidence_ref",
        "approval_evidence_ref",
        "operation_id",
        "decision_binding_ref",
        "state_root",
    ):
        _sha256(payload[field], "admission " + field)
    if payload["previous_commit_ref"] is not None:
        _sha256(payload["previous_commit_ref"], "admission previous_commit_ref")
    if type(payload["commit_sequence"]) is not int or payload["commit_sequence"] < 1:
        raise VerificationError("admission commit_sequence is not positive")
    if payload["commit_sequence"] == 1 and payload["previous_commit_ref"] is not None:
        raise VerificationError("first admission commit has a predecessor")
    if payload["commit_sequence"] > 1 and payload["previous_commit_ref"] is None:
        raise VerificationError("later admission commit lacks a predecessor")
    if payload["state"] != "committed" or payload["tool"] != "refund":
        raise VerificationError("admission has an unsupported state or tool")
    _refund(payload["arguments"], "admission arguments")
    _basic_record(payload, key["principal_id"], "authority_id")
    return payload, instant


def _recovery(
    envelope: Any, trust: dict[str, dict[str, Any]]
) -> tuple[dict[str, Any], datetime]:
    payload, instant, key = _signed(
        envelope,
        fields=RECOVERY_FIELDS,
        kind="admission_recovery",
        domain=RECOVERY_DOMAIN,
        role="recovery-observer",
        time_field="recovered_at",
        trust=trust,
    )
    for field in (
        "recovery_id",
        "recovery_observer_id",
        "instance_id",
        "restart_id",
    ):
        _identifier(payload[field], "recovery " + field)
    for field in ("admission_ref", "operation_id", "state_root"):
        _sha256(payload[field], "recovery " + field)
    if payload["state"] != "recovered_committed":
        raise VerificationError("recovery has an unsupported state")
    if payload["instance_id"] == payload["restart_id"]:
        raise VerificationError("recovery instance and restart identifiers are equal")
    _basic_record(payload, key["principal_id"], "recovery_observer_id")
    return payload, instant


def _resolution(
    envelope: Any, trust: dict[str, dict[str, Any]]
) -> tuple[dict[str, Any], datetime]:
    payload, instant, key = _signed(
        envelope,
        fields=RESOLUTION_FIELDS,
        kind="approval_resolution",
        domain=RESOLUTION_DOMAIN,
        role="admission-authority",
        time_field="resolved_at",
        trust=trust,
    )
    for field in (
        "resolution_id",
        "authority_id",
        "decision_scope",
        "decision_issuer",
        "decision_id",
        "original_approval_ref",
        "reissued_approval_ref",
    ):
        _identifier(payload[field], "approval resolution " + field)
    for field in ("original_admission_ref", "operation_id"):
        _sha256(payload[field], "approval resolution " + field)
    if payload["disposition"] != "resolved_existing" or payload["tool"] != "refund":
        raise VerificationError("approval resolution has an unsupported disposition or tool")
    _refund(payload["arguments"], "approval resolution arguments")
    _basic_record(payload, key["principal_id"], "authority_id")
    return payload, instant


def _handoff(
    envelope: Any, trust: dict[str, dict[str, Any]]
) -> tuple[dict[str, Any], datetime, dict[str, Any]]:
    payload, instant, key = _signed(
        envelope,
        fields=HANDOFF_FIELDS,
        kind="refund_handoff",
        domain=HANDOFF_DOMAIN,
        role="handoff-issuer",
        time_field="issued_at",
        trust=trust,
    )
    for field in (
        "handoff_id",
        "workflow_id",
        "issuer",
        "provider_id",
        "decision_scope",
        "decision_issuer",
        "decision_id",
        "approval_ref",
    ):
        _identifier(payload[field], "handoff " + field)
    for field in (
        "operation_id",
        "admission_ref",
        "decision_evidence_ref",
        "approval_evidence_ref",
        "idempotency_key",
    ):
        _sha256(payload[field], "handoff " + field)
    if payload["tool"] != "refund":
        raise VerificationError("handoff has an unsupported tool")
    _refund(payload["arguments"], "handoff arguments")
    _basic_record(payload, key["principal_id"], "issuer")
    not_before = _stamp(payload["not_before"], "handoff not_before")
    expires = _stamp(payload["expires_at"], "handoff expires_at")
    if instant > not_before or not_before >= expires:
        raise VerificationError("handoff has an invalid issue or validity order")
    if (expires - instant).total_seconds() > MAX_HANDOFF_TTL_SECONDS:
        raise VerificationError("handoff exceeds the maximum lifetime")
    if expires > _stamp(key["not_after"], "handoff signer not_after"):
        raise VerificationError("handoff outlives its signer's validity")
    return payload, instant, key


def _event(
    envelope: Any, trust: dict[str, dict[str, Any]]
) -> tuple[dict[str, Any], datetime]:
    outer = _object(envelope, ENVELOPE_FIELDS, "event envelope")
    if not isinstance(outer["payload"], dict):
        raise VerificationError("event payload is not an object")
    kind = outer["payload"].get("kind")
    if kind not in EVENT_FIELDS:
        raise VerificationError("event has an unknown signed kind")
    role = "effect-observer" if kind == "effect" else "execution-observer"
    payload, instant, key = _signed(
        envelope,
        fields=EVENT_FIELDS[kind],
        kind=kind,
        domain=EVENT_DOMAIN,
        role=role,
        time_field="occurred_at",
        trust=trust,
    )
    for field in (
        "event_id",
        "workflow_id",
        "issuer",
        "provider_id",
        "attempt_id",
        "observer_id",
    ):
        _identifier(payload[field], kind + " " + field)
    for field in ("operation_id", "idempotency_key"):
        _sha256(payload[field], kind + " " + field)
    if type(payload["sequence"]) is not int or payload["sequence"] < 1:
        raise VerificationError(kind + " sequence is not positive")
    if payload["previous_event_ref"] is not None:
        _sha256(payload["previous_event_ref"], kind + " previous_event_ref")
    _basic_record(payload, key["principal_id"], "observer_id")
    if kind == "attempt":
        _sha256(payload["handoff_ref"], "attempt handoff_ref")
        if payload["predecessor_attempt_ref"] is not None:
            _sha256(
                payload["predecessor_attempt_ref"],
                "attempt predecessor_attempt_ref",
            )
        if payload["disposition"] not in {
            "initial",
            "recovery",
            "duplicate_delivery",
        }:
            raise VerificationError("attempt has an unknown disposition")
        if payload["state"] != "dispatch_pending":
            raise VerificationError("attempt has an unsupported state")
    elif kind == "effect":
        _sha256(payload["attempt_ref"], "effect attempt_ref")
        _identifier(payload["effect_id"], "effect id")
        if payload["effect_type"] != "refund_committed":
            raise VerificationError("effect has an unsupported type")
        _refund(payload["arguments"], "effect arguments")
    elif kind == "outcome":
        _sha256(payload["attempt_ref"], "outcome attempt_ref")
        if payload["state"] not in {
            "observed_success",
            "observed_failure",
            "unresolved",
        }:
            raise VerificationError("outcome has an unknown state")
        if payload["effect_ref"] is not None:
            _sha256(payload["effect_ref"], "outcome effect_ref")
        if type(payload["response_received"]) is not bool:
            raise VerificationError("outcome response_received is not Boolean")
    else:
        for field in ("attempt_ref", "initial_outcome_ref"):
            _sha256(payload[field], "reconciliation " + field)
        if payload["previous_reconciliation_ref"] is not None:
            _sha256(
                payload["previous_reconciliation_ref"],
                "reconciliation previous_reconciliation_ref",
            )
        if payload["outcome"] not in {
            "still_unresolved",
            "effect_confirmed",
            "effect_absent",
        }:
            raise VerificationError("reconciliation has an unknown outcome")
        if payload["effect_ref"] is not None:
            _sha256(payload["effect_ref"], "reconciliation effect_ref")
    return payload, instant


def _manifest(
    envelope: Any, trust: dict[str, dict[str, Any]]
) -> tuple[dict[str, Any], datetime]:
    payload, instant, key = _signed(
        envelope,
        fields=MANIFEST_FIELDS,
        kind="execution_manifest",
        domain=MANIFEST_DOMAIN,
        role="execution-observer",
        time_field="issued_at",
        trust=trust,
    )
    for field in (
        "manifest_id",
        "workflow_id",
        "issuer",
        "provider_id",
        "observer_id",
    ):
        _identifier(payload[field], "execution manifest " + field)
    for field in ("operation_id", "idempotency_key", "head_event_ref"):
        _sha256(payload[field], "execution manifest " + field)
    if type(payload["event_count"]) is not int or payload["event_count"] < 1:
        raise VerificationError("execution manifest event_count is not positive")
    _stamp(payload["cutoff"], "execution manifest cutoff")
    _basic_record(payload, key["principal_id"], "observer_id")
    return payload, instant


def _snapshot(
    envelope: Any, trust: dict[str, dict[str, Any]]
) -> tuple[dict[str, Any], datetime]:
    payload, instant, key = _signed(
        envelope,
        fields=SNAPSHOT_FIELDS,
        kind="provider_snapshot",
        domain=SNAPSHOT_DOMAIN,
        role="effect-observer",
        time_field="observed_at",
        trust=trust,
    )
    for field in ("snapshot_id", "provider_id", "query_scope", "observer_id"):
        _identifier(payload[field], "provider snapshot " + field)
    for field in ("operation_id", "idempotency_key", "state_ref"):
        _sha256(payload[field], "provider snapshot " + field)
    if type(payload["effect_count"]) is not int or payload["effect_count"] < 0:
        raise VerificationError("provider snapshot effect_count is negative")
    if not isinstance(payload["effect_ids"], list):
        raise VerificationError("provider snapshot effect_ids is not a list")
    for effect_id in payload["effect_ids"]:
        _identifier(effect_id, "provider snapshot effect id")
    if payload["effect_ids"] != sorted(set(payload["effect_ids"])):
        raise VerificationError("provider snapshot effect_ids is not a sorted set")
    if payload["query_scope"] != "refund_effects_by_idempotency_key":
        raise VerificationError("provider snapshot has an unsupported query scope")
    _basic_record(payload, key["principal_id"], "observer_id")
    return payload, instant


def operation_id(target: dict[str, Any]) -> str:
    """Derive the stable operation id without an approval revision identifier."""
    return digest(
        OPERATION_DOMAIN,
        {
            "profile": CONTRACT_ID,
            "schema": SCHEMA,
            "workflow_id": target["workflow_id"],
            "admission_authority_id": target["admission_authority_id"],
            "decision_scope": target["decision_scope"],
            "decision_issuer": target["decision_issuer"],
            "decision_id": target["decision_id"],
            "handoff_issuer": target["handoff_issuer"],
            "provider_id": target["provider_id"],
            "tool": target["tool"],
            "arguments": target["arguments"],
        },
    )


def idempotency_key(operation: str, provider_id: str) -> str:
    """Derive the full provider idempotency key without truncation."""
    return digest(
        IDEMPOTENCY_DOMAIN,
        {"operation_id": operation, "provider_id": provider_id},
    )


def decision_binding_ref(
    target: dict[str, Any],
    approval_ref: str,
    decision_evidence_ref: str,
    approval_evidence_ref: str,
    operation: str,
) -> str:
    """Bind one decision identity to one operation and its original evidence."""
    return digest(
        DECISION_BINDING_DOMAIN,
        {
            "decision_scope": target["decision_scope"],
            "decision_issuer": target["decision_issuer"],
            "decision_id": target["decision_id"],
            "approval_ref": approval_ref,
            "decision_evidence_ref": decision_evidence_ref,
            "approval_evidence_ref": approval_evidence_ref,
            "operation_id": operation,
            "tool": target["tool"],
            "arguments": target["arguments"],
        },
    )


def admission_state_root(admission: dict[str, Any]) -> str:
    """Recompute the signed decision and operation indexes in one commit."""
    return digest(
        ADMISSION_STATE_DOMAIN,
        {
            "commit_sequence": admission["commit_sequence"],
            "previous_commit_ref": admission["previous_commit_ref"],
            "decision_index": [
                {
                    "decision_scope": admission["decision_scope"],
                    "decision_issuer": admission["decision_issuer"],
                    "decision_id": admission["decision_id"],
                    "operation_id": admission["operation_id"],
                    "decision_binding_ref": admission["decision_binding_ref"],
                }
            ],
            "operation_index": [
                {
                    "operation_id": admission["operation_id"],
                    "admission_id": admission["admission_id"],
                    "decision_binding_ref": admission["decision_binding_ref"],
                }
            ],
        },
    )


def provider_state_ref(snapshot: dict[str, Any]) -> str:
    """Recompute the provider query result selected by the signed snapshot."""
    return digest(
        PROVIDER_STATE_DOMAIN,
        {
            "provider_id": snapshot["provider_id"],
            "operation_id": snapshot["operation_id"],
            "idempotency_key": snapshot["idempotency_key"],
            "query_scope": snapshot["query_scope"],
            "effect_ids": snapshot["effect_ids"],
        },
    )


def _claim(contradictions: list[str], missing: list[str], **extra: Any) -> dict[str, Any]:
    if contradictions:
        result: dict[str, Any] = {
            "state": "CONTRADICTED",
            "reasons": sorted(set(contradictions)),
        }
    elif missing:
        result = {
            "state": "NOT_ESTABLISHED",
            "reasons": sorted(set(missing)),
        }
    else:
        result = {"state": "ESTABLISHED", "reasons": []}
    result.update(extra)
    return result


def _deduplicate(records: list[dict[str, Any]], domain: str) -> list[dict[str, Any]]:
    by_ref = {digest(domain, record): record for record in records}
    return [by_ref[key] for key in sorted(by_ref)]


def _same_target(record: dict[str, Any], target: dict[str, Any]) -> bool:
    fields = ("workflow_id", "provider_id")
    return all(record[field] == target[field] for field in fields)


def _add_if(condition: bool, bucket: list[str], reason: str) -> None:
    if condition:
        bucket.append(reason)


def assess(bundle: Any, trust_snapshot: Any) -> dict[str, Any]:
    """Check one finite bundle and return a deterministic bounded report."""
    root = _object(
        bundle,
        {
            "profile",
            "schema",
            "cutoff",
            "target",
            "inputs",
            "admission",
            "recovery",
            "approval_resolutions",
            "handoffs",
            "events",
            "execution_manifest",
            "provider_snapshot",
        },
        "refund handoff bundle",
    )
    if root["profile"] != CONTRACT_ID or root["schema"] != SCHEMA:
        raise VerificationError("bundle selects a different contract profile")
    cutoff = _stamp(root["cutoff"], "bundle cutoff")
    target = _object(root["target"], TARGET_FIELDS, "bundle target")
    for field in TARGET_FIELDS - {"arguments"}:
        _identifier(target[field], "bundle target " + field)
    if target["tool"] != "refund":
        raise VerificationError("bundle target has an unsupported tool")
    _refund(target["arguments"], "bundle target arguments")
    trust = check_trust_snapshot(trust_snapshot, cutoff)
    for field in ("inputs", "approval_resolutions", "handoffs", "events"):
        if not isinstance(root[field], list):
            raise VerificationError("bundle " + field + " is not a list")

    parsed_inputs = [_input(value, trust) for value in root["inputs"]]
    parsed_resolutions = [
        _resolution(value, trust) for value in root["approval_resolutions"]
    ]
    parsed_handoffs = [_handoff(value, trust)[:2] for value in root["handoffs"]]
    parsed_events = [_event(value, trust) for value in root["events"]]
    parsed_admission = None if root["admission"] is None else _admission(root["admission"], trust)
    parsed_recovery = None if root["recovery"] is None else _recovery(root["recovery"], trust)
    parsed_manifest = (
        None
        if root["execution_manifest"] is None
        else _manifest(root["execution_manifest"], trust)
    )
    parsed_snapshot = (
        None
        if root["provider_snapshot"] is None
        else _snapshot(root["provider_snapshot"], trust)
    )

    excluded: defaultdict[str, int] = defaultdict(int)

    def before_cutoff(
        records: list[tuple[dict[str, Any], datetime]], label: str
    ) -> list[dict[str, Any]]:
        selected = []
        for payload, instant in records:
            if instant <= cutoff:
                selected.append(payload)
            else:
                excluded[label] += 1
        return selected

    inputs = _deduplicate(before_cutoff(parsed_inputs, "verified_evidence"), INPUT_DOMAIN)
    resolutions = _deduplicate(
        before_cutoff(parsed_resolutions, "approval_resolution"), RESOLUTION_DOMAIN
    )
    handoffs = _deduplicate(
        before_cutoff(parsed_handoffs, "refund_handoff"), HANDOFF_DOMAIN
    )
    events = _deduplicate(before_cutoff(parsed_events, "event"), EVENT_DOMAIN)

    def current(
        value: tuple[dict[str, Any], datetime] | None, label: str
    ) -> dict[str, Any] | None:
        if value is None:
            return None
        if value[1] > cutoff:
            excluded[label] += 1
            return None
        return value[0]

    admission = current(parsed_admission, "admission_commit")
    recovery = current(parsed_recovery, "admission_recovery")
    manifest = current(parsed_manifest, "execution_manifest")
    snapshot = current(parsed_snapshot, "provider_snapshot")

    operation = operation_id(target)
    idem = idempotency_key(operation, target["provider_id"])
    issue: dict[str, dict[str, list[str]]] = {
        name: {"contradictions": [], "missing": []}
        for name in (
            "admission",
            "durable_admission",
            "approval_continuity",
            "authenticated_handoff",
            "record_completeness",
            "effect_coverage",
            "completion",
        )
    }

    def contradiction(claim: str, reason: str) -> None:
        issue[claim]["contradictions"].append(reason)

    def missing(claim: str, reason: str) -> None:
        issue[claim]["missing"].append(reason)

    target_decision = (
        target["decision_scope"],
        target["decision_issuer"],
        target["decision_id"],
    )
    decision_inputs = [
        item
        for item in inputs
        if item["evidence_role"] == "decision_evidence"
        and (
            item["decision_scope"],
            item["decision_issuer"],
            item["decision_id"],
        )
        == target_decision
    ]
    approval_inputs = [
        item
        for item in inputs
        if item["evidence_role"] == "approval_evidence"
        and (
            item["decision_scope"],
            item["decision_issuer"],
            item["decision_id"],
        )
        == target_decision
    ]
    for item in decision_inputs + approval_inputs:
        if item["tool"] != target["tool"] or item["arguments"] != target["arguments"]:
            contradiction("admission", "verified_evidence_target_mismatch")
        if item["evaluation"] != "ESTABLISHED":
            contradiction("admission", "verified_evidence_not_established")
    if not decision_inputs:
        missing("admission", "missing_decision_evidence")
    decision_variants = {
        (
            item["approval_ref"],
            item["tool"],
            canonical(item["arguments"]),
            item["evaluation"],
        )
        for item in decision_inputs
    }
    if len(decision_variants) > 1:
        contradiction("admission", "conflicting_decision_evidence")
    if not approval_inputs:
        missing("admission", "missing_approval_evidence")

    admission_ref: str | None = None
    if admission is None:
        missing("admission", "missing_admission_commit")
        missing("durable_admission", "missing_admission_commit")
        missing("approval_continuity", "missing_admission_commit")
        missing("authenticated_handoff", "missing_admission_commit")
    else:
        admission_ref = digest(ADMISSION_DOMAIN, admission)
        expected_binding = decision_binding_ref(
            target,
            admission["approval_ref"],
            admission["decision_evidence_ref"],
            admission["approval_evidence_ref"],
            operation,
        )
        admission_pairs = {
            "workflow_id": target["workflow_id"],
            "authority_id": target["admission_authority_id"],
            "handoff_issuer": target["handoff_issuer"],
            "provider_id": target["provider_id"],
            "decision_scope": target["decision_scope"],
            "decision_issuer": target["decision_issuer"],
            "decision_id": target["decision_id"],
            "operation_id": operation,
            "tool": target["tool"],
            "arguments": target["arguments"],
            "decision_binding_ref": expected_binding,
        }
        for field, expected in admission_pairs.items():
            if admission[field] != expected:
                contradiction("admission", "admission_" + field + "_mismatch")
        if admission["state_root"] != admission_state_root(admission):
            contradiction("admission", "admission_state_root_mismatch")
        decision_matches = [
            item
            for item in decision_inputs
            if item["evidence_ref"] == admission["decision_evidence_ref"]
        ]
        approval_matches = [
            item
            for item in approval_inputs
            if item["evidence_ref"] == admission["approval_evidence_ref"]
        ]
        if not decision_matches:
            missing("admission", "referenced_decision_evidence_missing")
        elif len(decision_matches) > 1:
            contradiction("admission", "decision_evidence_ref_not_unique")
        if not approval_matches:
            missing("admission", "referenced_approval_evidence_missing")
        elif len(approval_matches) > 1:
            contradiction("admission", "approval_evidence_ref_not_unique")
        for item in decision_matches + approval_matches:
            if item["approval_ref"] != admission["approval_ref"]:
                contradiction("admission", "original_approval_ref_mismatch")
            if _stamp(item["verified_at"], "verified evidence time") > _stamp(
                admission["committed_at"], "admission time"
            ):
                contradiction("admission", "evidence_verified_after_admission")

    if recovery is None:
        missing("durable_admission", "missing_post_restart_recovery")
    elif admission is None or admission_ref is None:
        missing("durable_admission", "missing_admission_for_recovery")
    else:
        for field, expected in {
            "admission_ref": admission_ref,
            "operation_id": operation,
            "state_root": admission["state_root"],
        }.items():
            if recovery[field] != expected:
                contradiction("durable_admission", "recovery_" + field + "_mismatch")
        non_recovery_principals = {
            key["principal_id"]
            for key in trust.values()
            if key["role"] != "recovery-observer"
        }
        if recovery["recovery_observer_id"] in non_recovery_principals:
            contradiction("durable_admission", "recovery_observer_not_separate")
        if _stamp(recovery["recovered_at"], "recovery time") <= _stamp(
            admission["committed_at"], "admission time"
        ):
            contradiction("durable_admission", "recovery_not_after_commit")

    original_approval = admission["approval_ref"] if admission is not None else None
    reissues = [
        item
        for item in approval_inputs
        if original_approval is not None and item["approval_ref"] != original_approval
    ]
    resolutions_by_reissue: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
    for resolution in resolutions:
        resolutions_by_reissue[resolution["reissued_approval_ref"]].append(resolution)
        if admission is None or admission_ref is None:
            missing("approval_continuity", "resolution_without_admission")
            continue
        expected = {
            "authority_id": target["admission_authority_id"],
            "decision_scope": target["decision_scope"],
            "decision_issuer": target["decision_issuer"],
            "decision_id": target["decision_id"],
            "original_approval_ref": original_approval,
            "original_admission_ref": admission_ref,
            "operation_id": operation,
            "tool": target["tool"],
            "arguments": target["arguments"],
        }
        for field, value in expected.items():
            if resolution[field] != value:
                contradiction("approval_continuity", "resolution_" + field + "_mismatch")
        if _stamp(resolution["resolved_at"], "resolution time") <= _stamp(
            admission["committed_at"], "admission time"
        ):
            contradiction("approval_continuity", "resolution_not_after_admission")
    for reissue in reissues:
        matches = resolutions_by_reissue[reissue["approval_ref"]]
        if len(matches) != 1:
            contradiction("approval_continuity", "reissued_approval_not_resolved_once")
        elif _stamp(matches[0]["resolved_at"], "resolution time") < _stamp(
            reissue["verified_at"], "reissue verification time"
        ):
            contradiction("approval_continuity", "resolution_precedes_reissued_evidence")
    resolved_refs = {item["approval_ref"] for item in reissues}
    for reissued_ref in resolutions_by_reissue:
        if reissued_ref not in resolved_refs:
            contradiction("approval_continuity", "resolution_lacks_reissued_evidence")

    target_handoffs = [
        handoff
        for handoff in handoffs
        if handoff["workflow_id"] == target["workflow_id"]
        and handoff["decision_scope"] == target["decision_scope"]
        and handoff["decision_issuer"] == target["decision_issuer"]
        and handoff["decision_id"] == target["decision_id"]
        and handoff["provider_id"] == target["provider_id"]
    ]
    primary: dict[str, Any] | None = None
    if not target_handoffs:
        missing("authenticated_handoff", "missing_target_handoff")
    else:
        exact = [
            item
            for item in target_handoffs
            if item["operation_id"] == operation
            and admission_ref is not None
            and item["admission_ref"] == admission_ref
        ]
        if len(exact) != 1:
            contradiction("authenticated_handoff", "target_handoff_not_unique")
        if exact:
            primary = exact[0]
        if len(target_handoffs) != len(exact):
            contradiction("authenticated_handoff", "conflicting_target_handoff")
    handoff_ref: str | None = None
    if primary is not None and admission is not None:
        handoff_ref = digest(HANDOFF_DOMAIN, primary)
        expected = {
            "workflow_id": target["workflow_id"],
            "issuer": target["handoff_issuer"],
            "provider_id": target["provider_id"],
            "decision_scope": target["decision_scope"],
            "decision_issuer": target["decision_issuer"],
            "decision_id": target["decision_id"],
            "approval_ref": admission["approval_ref"],
            "operation_id": operation,
            "admission_ref": admission_ref,
            "decision_evidence_ref": admission["decision_evidence_ref"],
            "approval_evidence_ref": admission["approval_evidence_ref"],
            "tool": target["tool"],
            "arguments": target["arguments"],
            "idempotency_key": idem,
        }
        for field, value in expected.items():
            if primary[field] != value:
                contradiction("authenticated_handoff", "handoff_" + field + "_mismatch")
        if recovery is None:
            missing("authenticated_handoff", "handoff_lacks_recovery_evidence")
        elif _stamp(primary["issued_at"], "handoff issued_at") <= _stamp(
            recovery["recovered_at"], "recovery time"
        ):
            contradiction("authenticated_handoff", "handoff_not_after_recovery")
    for resolution in resolutions:
        if any(
            _stamp(item["issued_at"], "handoff issued_at")
            > _stamp(resolution["resolved_at"], "resolution time")
            for item in target_handoffs
        ):
            contradiction("approval_continuity", "fresh_handoff_after_reissue_resolution")

    sorted_events = sorted(events, key=lambda item: (item["sequence"], digest(EVENT_DOMAIN, item)))
    event_refs = {digest(EVENT_DOMAIN, item): item for item in sorted_events}
    if len(event_refs) != len(sorted_events):
        raise AssertionError("deduplicated event references are not unique")
    event_ids: dict[str, str] = {}
    previous_ref: str | None = None
    previous_time: datetime | None = None
    for position, event in enumerate(sorted_events, start=1):
        if event["sequence"] != position or event["previous_event_ref"] != previous_ref:
            contradiction("record_completeness", "execution_event_chain_break")
        occurred = _stamp(event["occurred_at"], "event occurred_at")
        if previous_time is not None and occurred < previous_time:
            contradiction("record_completeness", "execution_event_time_regression")
        event_ref = digest(EVENT_DOMAIN, event)
        prior_event_ref = event_ids.get(event["event_id"])
        if prior_event_ref is not None and prior_event_ref != event_ref:
            contradiction("record_completeness", "execution_event_id_reused")
        event_ids[event["event_id"]] = event_ref
        previous_ref = event_ref
        previous_time = occurred
        if not _same_target(event, target):
            contradiction("record_completeness", "execution_event_target_mismatch")
        if (
            event["issuer"] != target["handoff_issuer"]
            or event["operation_id"] != operation
            or event["idempotency_key"] != idem
        ):
            contradiction("record_completeness", "execution_event_binding_mismatch")
    if not sorted_events:
        missing("record_completeness", "missing_execution_events")
    if manifest is None:
        missing("record_completeness", "missing_execution_manifest")
    else:
        expected = {
            "workflow_id": target["workflow_id"],
            "issuer": target["handoff_issuer"],
            "provider_id": target["provider_id"],
            "operation_id": operation,
            "idempotency_key": idem,
            "event_count": len(sorted_events),
            "head_event_ref": previous_ref,
            "cutoff": root["cutoff"],
        }
        for field, value in expected.items():
            if manifest[field] != value:
                contradiction("record_completeness", "manifest_" + field + "_mismatch")
        if _stamp(manifest["issued_at"], "manifest issued_at") != cutoff:
            contradiction("record_completeness", "manifest_not_at_cutoff")

    attempts = [item for item in sorted_events if item["kind"] == "attempt"]
    effects = [item for item in sorted_events if item["kind"] == "effect"]
    outcomes = [item for item in sorted_events if item["kind"] == "outcome"]
    reconciliations = [
        item for item in sorted_events if item["kind"] == "reconciliation"
    ]
    attempt_by_ref = {digest(EVENT_DOMAIN, item): item for item in attempts}
    effects_by_ref = {digest(EVENT_DOMAIN, item): item for item in effects}

    effect_value = "unknown"
    if snapshot is None:
        missing("effect_coverage", "missing_provider_snapshot")
    else:
        expected = {
            "provider_id": target["provider_id"],
            "operation_id": operation,
            "idempotency_key": idem,
        }
        for field, value in expected.items():
            if snapshot[field] != value:
                contradiction("effect_coverage", "provider_snapshot_" + field + "_mismatch")
        if _stamp(snapshot["observed_at"], "snapshot observed_at") != cutoff:
            contradiction("effect_coverage", "provider_snapshot_not_at_cutoff")
        supplied_effect_ids = sorted({item["effect_id"] for item in effects})
        if snapshot["effect_count"] != len(snapshot["effect_ids"]):
            contradiction("effect_coverage", "provider_snapshot_count_mismatch")
        if snapshot["effect_ids"] != supplied_effect_ids:
            contradiction("effect_coverage", "provider_snapshot_effect_set_mismatch")
        if snapshot["state_ref"] != provider_state_ref(snapshot):
            contradiction("effect_coverage", "provider_snapshot_state_ref_mismatch")
        effect_value = "present" if snapshot["effect_count"] else "absent"

    completion_value = "unknown"
    if not attempts:
        missing("completion", "missing_dispatch_attempt")
    if primary is None or handoff_ref is None:
        missing("completion", "missing_authenticated_handoff")
    terminal: dict[str, tuple[str, datetime]] = {}
    terminal_refs: list[str] = []
    previous_attempt_ref: str | None = None
    previous_terminal: tuple[str, datetime] | None = None
    seen_effect_ids: dict[str, str] = {}
    for index, attempt in enumerate(attempts):
        attempt_ref = digest(EVENT_DOMAIN, attempt)
        occurred = _stamp(attempt["occurred_at"], "attempt time")
        if handoff_ref is not None and attempt["handoff_ref"] != handoff_ref:
            contradiction("completion", "attempt_handoff_ref_mismatch")
        if primary is not None:
            dispatch_floor = max(
                _stamp(primary["issued_at"], "handoff issued_at"),
                _stamp(primary["not_before"], "handoff not_before"),
            )
            if occurred < dispatch_floor:
                contradiction("completion", "attempt_before_handoff_validity")
            if occurred >= _stamp(primary["expires_at"], "handoff expires_at"):
                contradiction("completion", "attempt_at_or_after_handoff_expiry")
        if recovery is not None and occurred <= _stamp(
            recovery["recovered_at"], "recovery time"
        ):
            contradiction("completion", "attempt_not_after_recovery")
        if index == 0:
            if attempt["disposition"] != "initial" or attempt["predecessor_attempt_ref"] is not None:
                contradiction("completion", "first_attempt_not_initial")
        else:
            if attempt["disposition"] not in {"recovery", "duplicate_delivery"}:
                contradiction("completion", "later_attempt_has_invalid_disposition")
            if attempt["predecessor_attempt_ref"] != previous_attempt_ref:
                contradiction("completion", "later_attempt_predecessor_mismatch")
            if previous_terminal is None:
                contradiction("completion", "later_attempt_follows_unresolved_attempt")
            elif previous_terminal[0] != "absent":
                contradiction("completion", "later_attempt_follows_effect_or_success")
            elif occurred <= previous_terminal[1]:
                contradiction("completion", "later_attempt_precedes_prior_terminal")

        matching_effects = [
            item
            for item in effects
            if item["attempt_id"] == attempt["attempt_id"]
            or item["attempt_ref"] == attempt_ref
        ]
        for effect in matching_effects:
            effect_ref = digest(EVENT_DOMAIN, effect)
            if (
                effect["attempt_id"] != attempt["attempt_id"]
                or effect["attempt_ref"] != attempt_ref
            ):
                contradiction("completion", "effect_crosses_attempt_binding")
            if effect["arguments"] != target["arguments"]:
                contradiction("completion", "effect_refund_tuple_mismatch")
            if _stamp(effect["occurred_at"], "effect time") < occurred:
                contradiction("completion", "effect_precedes_attempt")
            prior = seen_effect_ids.get(effect["effect_id"])
            if prior is not None and prior != attempt_ref:
                contradiction("completion", "effect_id_rebound_to_another_attempt")
            seen_effect_ids[effect["effect_id"]] = attempt_ref
            if effect_ref not in effects_by_ref:
                raise AssertionError("effect reference map is incomplete")

        matching_outcomes = [
            item
            for item in outcomes
            if item["attempt_id"] == attempt["attempt_id"]
            or item["attempt_ref"] == attempt_ref
        ]
        exact_outcomes = [
            item
            for item in matching_outcomes
            if item["attempt_id"] == attempt["attempt_id"]
            and item["attempt_ref"] == attempt_ref
        ]
        if len(exact_outcomes) != 1 or len(matching_outcomes) != len(exact_outcomes):
            contradiction("completion", "attempt_outcome_not_exactly_one")
            previous_attempt_ref = attempt_ref
            previous_terminal = None
            continue
        outcome = exact_outcomes[0]
        outcome_ref = digest(EVENT_DOMAIN, outcome)
        if _stamp(outcome["occurred_at"], "outcome time") < occurred:
            contradiction("completion", "outcome_precedes_attempt")
        state = outcome["state"]
        current_terminal: tuple[str, datetime] | None = None
        if state == "observed_success":
            effect = effects_by_ref.get(outcome["effect_ref"])
            if (
                effect is None
                or effect["attempt_id"] != attempt["attempt_id"]
                or effect["attempt_ref"] != attempt_ref
            ):
                contradiction("completion", "success_effect_ref_not_same_attempt")
            elif _stamp(outcome["occurred_at"], "outcome time") < _stamp(
                effect["occurred_at"], "effect time"
            ):
                contradiction("completion", "success_precedes_effect")
            if outcome["response_received"] is not True:
                contradiction("completion", "success_without_response")
            current_terminal = ("present", _stamp(outcome["occurred_at"], "outcome time"))
            terminal_refs.append(outcome_ref)
        elif state == "observed_failure":
            if outcome["effect_ref"] is not None or outcome["response_received"] is not True:
                contradiction("completion", "observed_failure_has_effect_or_no_response")
            if matching_effects:
                contradiction("completion", "observed_failure_conflicts_with_effect")
            current_terminal = ("absent", _stamp(outcome["occurred_at"], "outcome time"))
            terminal_refs.append(outcome_ref)
        else:
            if outcome["response_received"] is not False:
                contradiction("completion", "unresolved_outcome_has_response")
            if outcome["effect_ref"] is not None:
                unresolved_effect = effects_by_ref.get(outcome["effect_ref"])
                if (
                    unresolved_effect is None
                    or unresolved_effect["attempt_id"] != attempt["attempt_id"]
                    or unresolved_effect["attempt_ref"] != attempt_ref
                ):
                    contradiction("completion", "unresolved_effect_ref_not_same_attempt")
                elif _stamp(outcome["occurred_at"], "outcome time") < _stamp(
                    unresolved_effect["occurred_at"], "effect time"
                ):
                    contradiction("completion", "unresolved_outcome_precedes_effect")
            chain = sorted(
                [
                    item
                    for item in reconciliations
                    if item["attempt_id"] == attempt["attempt_id"]
                    or item["attempt_ref"] == attempt_ref
                ],
                key=lambda item: item["sequence"],
            )
            previous_reconciliation_ref: str | None = None
            reached_terminal = False
            for reconciliation in chain:
                reconciliation_ref = digest(EVENT_DOMAIN, reconciliation)
                if (
                    reconciliation["attempt_id"] != attempt["attempt_id"]
                    or reconciliation["attempt_ref"] != attempt_ref
                    or reconciliation["initial_outcome_ref"] != outcome_ref
                ):
                    contradiction("completion", "reconciliation_crosses_attempt_binding")
                if reconciliation["previous_reconciliation_ref"] != previous_reconciliation_ref:
                    contradiction("completion", "reconciliation_predecessor_mismatch")
                if _stamp(reconciliation["occurred_at"], "reconciliation time") < _stamp(
                    outcome["occurred_at"], "outcome time"
                ):
                    contradiction("completion", "reconciliation_precedes_outcome")
                resolution = reconciliation["outcome"]
                if reached_terminal:
                    contradiction("completion", "reconciliation_after_terminal")
                if resolution == "still_unresolved":
                    if reconciliation["effect_ref"] is not None:
                        contradiction("completion", "unresolved_reconciliation_has_effect")
                elif resolution == "effect_confirmed":
                    effect = effects_by_ref.get(reconciliation["effect_ref"])
                    if (
                        effect is None
                        or effect["attempt_id"] != attempt["attempt_id"]
                        or effect["attempt_ref"] != attempt_ref
                    ):
                        contradiction("completion", "reconciliation_effect_not_same_attempt")
                    elif _stamp(
                        reconciliation["occurred_at"], "reconciliation time"
                    ) < _stamp(effect["occurred_at"], "effect time"):
                        contradiction("completion", "reconciliation_precedes_effect")
                    current_terminal = (
                        "present",
                        _stamp(reconciliation["occurred_at"], "reconciliation time"),
                    )
                    terminal_refs.append(reconciliation_ref)
                    reached_terminal = True
                else:
                    if reconciliation["effect_ref"] is not None:
                        contradiction("completion", "effect_absent_reconciliation_has_effect")
                    if matching_effects:
                        contradiction("completion", "effect_absent_conflicts_with_effect")
                    current_terminal = (
                        "absent",
                        _stamp(reconciliation["occurred_at"], "reconciliation time"),
                    )
                    terminal_refs.append(reconciliation_ref)
                    reached_terminal = True
                previous_reconciliation_ref = reconciliation_ref
        if current_terminal is None:
            missing("completion", "unresolved_completion")
        else:
            terminal[attempt_ref] = current_terminal
        previous_attempt_ref = attempt_ref
        previous_terminal = current_terminal

    known_attempt_ids = {item["attempt_id"] for item in attempts}
    known_attempt_refs = set(attempt_by_ref)
    for event in effects + outcomes + reconciliations:
        if event["attempt_id"] not in known_attempt_ids or event["attempt_ref"] not in known_attempt_refs:
            contradiction("completion", "event_references_unknown_attempt")
    if len(effects) > 1:
        contradiction("completion", "multiple_refund_effects")
    if snapshot is not None and snapshot["effect_count"] == 0 and effects:
        contradiction("completion", "terminal_effect_conflicts_with_provider_snapshot")
    if snapshot is not None and snapshot["effect_count"] > 0 and not effects:
        contradiction("completion", "provider_effect_lacks_typed_event")
    if attempts and len(terminal) == len(attempts):
        completion_value = "effect_committed" if effects else "no_effect"

    for resolution in resolutions:
        resolution_time = _stamp(resolution["resolved_at"], "resolution time")
        terminal_before = any(value[1] <= resolution_time for value in terminal.values())
        if terminal_before and any(
            _stamp(item["occurred_at"], "attempt time") > resolution_time
            for item in attempts
        ):
            contradiction("approval_continuity", "terminal_operation_reopened_after_reissue")

    claims = {
        name: _claim(
            value["contradictions"],
            value["missing"],
            **(
                {"value": effect_value}
                if name == "effect_coverage"
                else {"value": completion_value}
                if name == "completion"
                else {}
            ),
        )
        for name, value in issue.items()
    }
    states = {value["state"] for value in claims.values()}
    overall = (
        "CONTRADICTED"
        if "CONTRADICTED" in states
        else "ESTABLISHED"
        if states == {"ESTABLISHED"}
        else "NOT_ESTABLISHED"
    )
    references = {
        "bundle_ref": digest(BUNDLE_DOMAIN, root),
        "trust_snapshot_ref": digest(TRUST_SNAPSHOT_DOMAIN, trust_snapshot),
        "admission_ref": admission_ref,
        "handoff_ref": handoff_ref,
        "execution_manifest_ref": (
            None if manifest is None else digest(MANIFEST_DOMAIN, manifest)
        ),
        "provider_snapshot_ref": (
            None if snapshot is None else digest(SNAPSHOT_DOMAIN, snapshot)
        ),
        "effect_refs": sorted(effects_by_ref),
        "terminal_refs": sorted(terminal_refs),
    }
    return {
        "profile": CONTRACT_ID,
        "schema": SCHEMA,
        "cutoff": root["cutoff"],
        "target": deepcopy(target),
        "target_operation_id": operation,
        "overall": overall,
        "claims": claims,
        "counts": {
            "inputs": len(inputs),
            "handoffs": len(handoffs),
            "unique_handoffs": len(target_handoffs),
            "events": len(sorted_events),
            "attempts": len(attempts),
            "effects": len(effects),
            "excluded_after_cutoff": sum(excluded.values()),
            "excluded_by_kind": dict(sorted(excluded.items())),
        },
        "references": references,
        "witness_scope": "PEER",
        "does_not_assert": [
            "merchant authority or delegated business authority",
            "production deployment or host adoption",
            "independent durability or non-operator custody",
            "provider coverage beyond the selected observer and query scope",
            "remote exactly-once execution",
            "independent operation, adoption, or commercial agreement",
        ],
    }


def main(argv: Sequence[str] | None = None) -> int:
    """Run the offline verifier with consumer-selected bundle and trust files."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--trust-snapshot", required=True, type=Path)
    arguments = parser.parse_args(argv)
    try:
        report = assess(
            load_document(arguments.bundle),
            load_document(arguments.trust_snapshot),
        )
    except (VerificationError, OSError, KeyError, TypeError, ValueError) as error:
        print("Refund handoff bundle refused: " + str(error), file=sys.stderr)
        return 2
    sys.stdout.buffer.write(canonical(report) + b"\n")
    return 0 if report["overall"] == "ESTABLISHED" else 3


if __name__ == "__main__":
    raise SystemExit(main())
