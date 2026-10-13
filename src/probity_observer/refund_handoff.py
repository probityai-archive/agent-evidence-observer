"""Verify a bounded refund admission-to-effect evidence chain offline.

The verifier owns the report semantics and hostile conformance surface.  Input
products are replaceable producers of the generic decision_evidence and
approval_evidence roles.  A report never upgrades this PEER vantage into proof
of merchant authority, independent custody, or remote exactly-once execution.
"""

from __future__ import annotations

import argparse
import os
import re
import stat
import sys
from collections import defaultdict
from collections.abc import Callable, Sequence
from copy import deepcopy
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .crypto import VerificationError, canonical, digest, strict_loads, verify_signature
from .refund_handoff_reasons import lookup_reason_contract

CONTRACT_ID = (
    "https://probityai.github.io/agent-evidence-observer/contract/refund-handoff/0.1"
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
ADMISSION_CHECKPOINT_DOMAIN = "probity-refund-admission-checkpoint-v0.1"
HANDOFF_CHECKPOINT_DOMAIN = "probity-refund-handoff-checkpoint-v0.1"

MAX_HANDOFF_TTL_SECONDS = 600
MAX_DOCUMENT_BYTES = 1_048_576
MAX_BUNDLE_RECORDS = 512
MAX_TRUST_KEYS = 128
MAX_IDENTIFIER_BYTES = 512
HEX_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
STAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
REASON_CODE = re.compile(r"[a-z][a-z0-9_]*\Z")
REASON_URI_PREFIX = CONTRACT_ID + "#reason-"

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
    "compatibility_profile",
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
    "workflow_id",
    "provider_id",
    "decision_scope",
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
    "workflow_id",
    "provider_id",
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
    "decision_scope",
    "handoff_issuer",
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
    "decision_scope",
    "handoff_issuer",
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
    "workflow_id",
    "decision_scope",
    "handoff_issuer",
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

CLAIM_NAMES = (
    "admission",
    "durable_admission",
    "approval_continuity",
    "authenticated_handoff",
    "selected_log_consistency",
    "selected_effect_coverage",
    "completion",
)


@dataclass(frozen=True)
class _PreparedEvidence:
    root: dict[str, Any]
    target: dict[str, Any]
    cutoff: datetime
    trust: dict[str, dict[str, Any]]
    checkpoints: dict[str, Any]
    inputs: list[dict[str, Any]]
    resolutions: list[dict[str, Any]]
    handoffs: list[dict[str, Any]]
    events: list[dict[str, Any]]
    admission: dict[str, Any] | None
    recovery: dict[str, Any] | None
    manifest: dict[str, Any] | None
    snapshot: dict[str, Any] | None
    operation: str
    idempotency_key: str
    excluded: dict[str, int]


@dataclass
class _IssueBook:
    values: dict[str, dict[str, list[str]]] = dataclass_field(
        default_factory=lambda: {
            name: {"contradictions": [], "missing": []} for name in CLAIM_NAMES
        }
    )

    def contradict(self, claim: str, reason: str) -> None:
        self._check_contract(claim, reason, "CONTRADICTED")
        self.values[claim]["contradictions"].append(reason)

    def miss(self, claim: str, reason: str) -> None:
        self._check_contract(claim, reason, "NOT_ESTABLISHED")
        self.values[claim]["missing"].append(reason)

    @staticmethod
    def _check_contract(claim: str, reason: str, state: str) -> None:
        try:
            claims, expected_state = lookup_reason_contract(reason)
        except ValueError as error:
            raise AssertionError("unregistered report reason: " + reason) from error
        if claim not in claims or state != expected_state:
            raise AssertionError(
                "report reason contract mismatch: " + claim + "/" + reason
            )

    def claims(self, effect_value: str, completion_value: str) -> dict[str, Any]:
        return {
            name: _claim(
                value["contradictions"],
                value["missing"],
                **(
                    {"value": effect_value}
                    if name == "selected_effect_coverage"
                    else {"value": completion_value}
                    if name == "completion"
                    else {}
                ),
            )
            for name, value in self.values.items()
        }


@dataclass(frozen=True)
class _AdmissionEvidence:
    decision_inputs: list[dict[str, Any]]
    approval_inputs: list[dict[str, Any]]
    admission_ref: str | None


@dataclass(frozen=True)
class _HandoffEvidence:
    target_handoffs: list[dict[str, Any]]
    primary: dict[str, Any] | None
    handoff_ref: str | None


@dataclass(frozen=True)
class _EventEvidence:
    sorted_events: list[dict[str, Any]]
    attempts: list[dict[str, Any]]
    effects: list[dict[str, Any]]
    outcomes: list[dict[str, Any]]
    reconciliations: list[dict[str, Any]]
    effects_by_ref: dict[str, dict[str, Any]]


@dataclass(frozen=True)
class _CompletionEvidence:
    value: str
    terminal: dict[str, tuple[str, datetime]]
    terminal_refs: list[str]


@dataclass
class _CompletionState:
    terminal: dict[str, tuple[str, datetime]] = dataclass_field(default_factory=dict)
    terminal_refs: list[str] = dataclass_field(default_factory=list)
    previous_attempt_ref: str | None = None
    previous_terminal: tuple[str, datetime] | None = None
    seen_effect_ids: dict[str, str] = dataclass_field(default_factory=dict)


@dataclass
class _ReconciliationState:
    previous_ref: str | None = None
    terminal: tuple[str, datetime] | None = None
    terminal_refs: list[str] = dataclass_field(default_factory=list)
    reached_terminal: bool = False


def _object(value: Any, fields: set[str], reason: str) -> dict[str, Any]:
    """Return an exact closed object or refuse the profile."""
    if not isinstance(value, dict) or set(value) != fields:
        raise VerificationError(reason + " has fields outside the closed profile")
    return value


def _identifier(value: Any, reason: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or not value.isascii()
        or len(value.encode("ascii")) > MAX_IDENTIFIER_BYTES
    ):
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
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
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


def reason_uri(code: str) -> str:
    """Return the stable contract URI for one closed report reason code."""
    if REASON_CODE.fullmatch(code) is None:
        raise AssertionError("internal reason code is not stable snake case")
    try:
        lookup_reason_contract(code)
    except ValueError as error:
        raise AssertionError("internal reason code is not registered") from error
    return REASON_URI_PREFIX + code


def _regular_document_stat(path: Path) -> os.stat_result:
    try:
        before = os.lstat(path)
    except OSError as error:
        raise VerificationError(
            "input is not a readable regular file: " + path.name
        ) from error
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    file_attributes = getattr(before, "st_file_attributes", 0)
    if (
        stat.S_ISLNK(before.st_mode)
        or file_attributes & reparse_flag
        or not stat.S_ISREG(before.st_mode)
    ):
        raise VerificationError("input is not a readable regular file: " + path.name)
    return before


def _open_document(path: Path) -> tuple[int, int]:
    before = _regular_document_stat(path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise VerificationError(
            "input is not a readable regular file: " + path.name
        ) from error
    try:
        metadata = os.fstat(descriptor)
        if not os.path.samestat(before, metadata):
            raise VerificationError("input changed while opening: " + path.name)
        if not stat.S_ISREG(metadata.st_mode):
            raise VerificationError(
                "input is not a readable regular file: " + path.name
            )
        if metadata.st_size > MAX_DOCUMENT_BYTES:
            raise VerificationError(
                "input exceeds the document byte limit: " + path.name
            )
    except Exception:
        os.close(descriptor)
        raise
    return descriptor, metadata.st_size


def read_document_bytes(path: Path) -> bytes:
    """Read one bounded regular file through one no-follow file descriptor."""
    descriptor, size = _open_document(path)
    try:
        chunks: list[bytes] = []
        remaining = size
        while remaining:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                raise VerificationError("input changed while reading: " + path.name)
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if os.read(descriptor, 1):
            raise VerificationError("input changed while reading: " + path.name)
    finally:
        os.close(descriptor)
    return raw


def load_document(path: Path) -> Any:
    """Parse one bounded canonical JSON document from one file snapshot."""
    return strict_loads(read_document_bytes(path))


def _check_checkpoint(
    value: Any,
    *,
    kind: str,
    fields: set[str],
    identifier_fields: tuple[str, ...],
    digest_fields: tuple[str, ...],
    cutoff: datetime,
) -> dict[str, Any]:
    checkpoint = _object(value, fields | {"observed_at"}, kind + " checkpoint")
    for name in identifier_fields:
        _identifier(checkpoint[name], kind + " checkpoint " + name)
    for name in digest_fields:
        _sha256(checkpoint[name], kind + " checkpoint " + name)
    if _stamp(checkpoint["observed_at"], kind + " checkpoint observed_at") != cutoff:
        raise VerificationError(
            kind + " checkpoint is not observed at the report cutoff"
        )
    return checkpoint


def _check_trust_scope(value: Any) -> None:
    scope = _object(
        value,
        {"workflow_ids", "provider_ids", "decision_scopes"},
        "trust key scope",
    )
    for name in ("workflow_ids", "provider_ids", "decision_scopes"):
        values = scope[name]
        if not isinstance(values, list) or not values:
            raise VerificationError("trust key scope has an empty dimension")
        for item in values:
            _identifier(item, "trust key scope value")
        if values != sorted(set(values)):
            raise VerificationError("trust key scope is not a sorted set")


def _check_trust_key_interval(item: dict[str, Any]) -> None:
    if item["status"] not in {"active", "revoked"}:
        raise VerificationError("trust key has an unknown status")
    before = _stamp(item["not_before"], "trust key not_before")
    after = _stamp(item["not_after"], "trust key not_after")
    if before >= after:
        raise VerificationError("trust key has an empty validity interval")
    revoked_at = (
        None
        if item["revoked_at"] is None
        else _stamp(item["revoked_at"], "trust key revoked_at")
    )
    if item["status"] == "revoked" and revoked_at is None:
        raise VerificationError("revoked trust key lacks revoked_at")
    if item["status"] == "active" and revoked_at is not None:
        raise VerificationError("active trust key carries revoked_at")
    if revoked_at is not None and not before <= revoked_at <= after:
        raise VerificationError("trust key revocation is outside its validity interval")


def _check_trust_key(candidate: Any) -> tuple[str, str, dict[str, Any]]:
    item = _object(
        candidate,
        {
            "key_id",
            "principal_id",
            "role",
            "public_key",
            "status",
            "not_before",
            "not_after",
            "revoked_at",
            "scope",
        },
        "trust key",
    )
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
    public_key = item["public_key"]
    if (
        not isinstance(public_key, str)
        or re.fullmatch(r"[0-9a-f]{64}", public_key) is None
    ):
        raise VerificationError("trust key has an invalid Ed25519 public key")
    _check_trust_scope(item["scope"])
    _check_trust_key_interval(item)
    return key_id, public_key, item


def check_trust_snapshot(
    snapshot: Any, cutoff: datetime
) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    """Check consumer-selected keys, scopes, and the selected admission pin."""
    root = _object(
        snapshot,
        {
            "profile",
            "schema",
            "snapshot_id",
            "valid_from",
            "valid_until",
            "admission_checkpoint",
            "handoff_checkpoint",
            "keys",
        },
        "trust snapshot",
    )
    if root["profile"] != CONTRACT_ID or root["schema"] != SCHEMA:
        raise VerificationError("trust snapshot selects a different profile")
    _identifier(root["snapshot_id"], "trust snapshot id")
    valid_from = _stamp(root["valid_from"], "trust snapshot valid_from")
    valid_until = _stamp(root["valid_until"], "trust snapshot valid_until")
    if not valid_from <= cutoff <= valid_until:
        raise VerificationError("cutoff is outside the trust snapshot interval")
    if (
        not isinstance(root["keys"], list)
        or not root["keys"]
        or len(root["keys"]) > MAX_TRUST_KEYS
    ):
        raise VerificationError("trust snapshot has no keys")
    admission_checkpoint = _check_checkpoint(
        root["admission_checkpoint"],
        kind="admission",
        fields={
            "authority_id",
            "workflow_id",
            "decision_scope",
            "decision_issuer",
            "decision_id",
            "operation_id",
            "admission_ref",
            "state_root",
        },
        identifier_fields=(
            "authority_id",
            "workflow_id",
            "decision_scope",
            "decision_issuer",
            "decision_id",
        ),
        digest_fields=("operation_id", "admission_ref", "state_root"),
        cutoff=cutoff,
    )
    handoff_checkpoint = _check_checkpoint(
        root["handoff_checkpoint"],
        kind="handoff",
        fields={
            "issuer",
            "workflow_id",
            "decision_scope",
            "decision_issuer",
            "decision_id",
            "handoff_id",
            "operation_id",
            "handoff_ref",
        },
        identifier_fields=(
            "issuer",
            "workflow_id",
            "decision_scope",
            "decision_issuer",
            "decision_id",
            "handoff_id",
        ),
        digest_fields=("operation_id", "handoff_ref"),
        cutoff=cutoff,
    )

    result: dict[str, dict[str, Any]] = {}
    public_keys: set[str] = set()
    for candidate in root["keys"]:
        key_id, public_key, item = _check_trust_key(candidate)
        if public_key in public_keys:
            raise VerificationError("trust snapshot repeats Ed25519 public-key bytes")
        public_keys.add(public_key)
        if key_id in result:
            raise VerificationError("trust snapshot repeats a key id")
        result[key_id] = deepcopy(item)
    return result, {
        "admission": deepcopy(admission_checkpoint),
        "handoff": deepcopy(handoff_checkpoint),
    }


def _key_scope(
    key: dict[str, Any],
    *,
    workflow_id: str | None = None,
    provider_id: str | None = None,
    decision_scope: str | None = None,
) -> None:
    """Refuse a valid signature used outside its consumer-selected scope."""
    checks = {
        "workflow_ids": workflow_id,
        "provider_ids": provider_id,
        "decision_scopes": decision_scope,
    }
    for field, value in checks.items():
        if value is not None and value not in key["scope"][field]:
            raise VerificationError("signer key is outside its " + field + " scope")


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
    if key["status"] == "revoked" and instant >= _stamp(
        key["revoked_at"], "trust key revoked_at"
    ):
        raise VerificationError(kind + " signer was revoked at record time")
    return payload, instant, key


def _basic_record(payload: dict[str, Any], principal: str, actor_field: str) -> None:
    _identifier(payload[actor_field], payload["kind"] + " " + actor_field)
    if payload[actor_field] != principal:
        raise VerificationError(
            payload["kind"] + " principal differs from its trust key"
        )


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
        "compatibility_profile",
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
    _key_scope(key, decision_scope=payload["decision_scope"])
    return payload, instant


def _check_admission_sequence(payload: dict[str, Any]) -> None:
    if payload["previous_commit_ref"] is not None:
        _sha256(payload["previous_commit_ref"], "admission previous_commit_ref")
    sequence = payload["commit_sequence"]
    if type(sequence) is not int or sequence < 1:
        raise VerificationError("admission commit_sequence is not positive")
    if sequence == 1 and payload["previous_commit_ref"] is not None:
        raise VerificationError("first admission commit has a predecessor")
    if sequence > 1 and payload["previous_commit_ref"] is None:
        raise VerificationError("later admission commit lacks a predecessor")


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
    _check_admission_sequence(payload)
    if payload["state"] != "committed" or payload["tool"] != "refund":
        raise VerificationError("admission has an unsupported state or tool")
    _refund(payload["arguments"], "admission arguments")
    _basic_record(payload, key["principal_id"], "authority_id")
    _key_scope(
        key,
        workflow_id=payload["workflow_id"],
        provider_id=payload["provider_id"],
        decision_scope=payload["decision_scope"],
    )
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
        "workflow_id",
        "provider_id",
        "decision_scope",
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
    _key_scope(
        key,
        workflow_id=payload["workflow_id"],
        provider_id=payload["provider_id"],
        decision_scope=payload["decision_scope"],
    )
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
        "workflow_id",
        "provider_id",
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
        raise VerificationError(
            "approval resolution has an unsupported disposition or tool"
        )
    _refund(payload["arguments"], "approval resolution arguments")
    _basic_record(payload, key["principal_id"], "authority_id")
    _key_scope(
        key,
        workflow_id=payload["workflow_id"],
        provider_id=payload["provider_id"],
        decision_scope=payload["decision_scope"],
    )
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
    _key_scope(
        key,
        workflow_id=payload["workflow_id"],
        provider_id=payload["provider_id"],
        decision_scope=payload["decision_scope"],
    )
    not_before = _stamp(payload["not_before"], "handoff not_before")
    expires = _stamp(payload["expires_at"], "handoff expires_at")
    if instant > not_before or not_before >= expires:
        raise VerificationError("handoff has an invalid issue or validity order")
    if (expires - instant).total_seconds() > MAX_HANDOFF_TTL_SECONDS:
        raise VerificationError("handoff exceeds the maximum lifetime")
    if expires > _stamp(key["not_after"], "handoff signer not_after"):
        raise VerificationError("handoff outlives its signer's validity")
    return payload, instant, key


def _check_attempt_event(payload: dict[str, Any]) -> None:
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


def _check_effect_event(payload: dict[str, Any]) -> None:
    _sha256(payload["attempt_ref"], "effect attempt_ref")
    _identifier(payload["effect_id"], "effect id")
    if payload["effect_type"] != "refund_committed":
        raise VerificationError("effect has an unsupported type")
    _refund(payload["arguments"], "effect arguments")


def _check_outcome_event(payload: dict[str, Any]) -> None:
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


def _check_reconciliation_event(payload: dict[str, Any]) -> None:
    for name in ("attempt_ref", "initial_outcome_ref"):
        _sha256(payload[name], "reconciliation " + name)
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


EVENT_CHECKS = {
    "attempt": _check_attempt_event,
    "effect": _check_effect_event,
    "outcome": _check_outcome_event,
    "reconciliation": _check_reconciliation_event,
}


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
        "decision_scope",
        "handoff_issuer",
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
    _key_scope(
        key,
        workflow_id=payload["workflow_id"],
        provider_id=payload["provider_id"],
        decision_scope=payload["decision_scope"],
    )
    EVENT_CHECKS[kind](payload)
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
        "decision_scope",
        "handoff_issuer",
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
    _key_scope(
        key,
        workflow_id=payload["workflow_id"],
        provider_id=payload["provider_id"],
        decision_scope=payload["decision_scope"],
    )
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
    for field in (
        "snapshot_id",
        "workflow_id",
        "decision_scope",
        "handoff_issuer",
        "provider_id",
        "query_scope",
        "observer_id",
    ):
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
    _key_scope(
        key,
        workflow_id=payload["workflow_id"],
        provider_id=payload["provider_id"],
        decision_scope=payload["decision_scope"],
    )
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


def verified_evidence_ref(payload: dict[str, Any]) -> str:
    """Reference one exact typed reader output, not its untyped source-local id."""
    return digest(INPUT_DOMAIN, payload)


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


def _claim(
    contradictions: list[str], missing: list[str], **extra: Any
) -> dict[str, Any]:
    if contradictions:
        result: dict[str, Any] = {
            "state": "CONTRADICTED",
            "reasons": [reason_uri(code) for code in sorted(set(contradictions))],
        }
    elif missing:
        result = {
            "state": "NOT_ESTABLISHED",
            "reasons": [reason_uri(code) for code in sorted(set(missing))],
        }
    else:
        result = {"state": "ESTABLISHED", "reasons": []}
    result.update(extra)
    return result


def _deduplicate(records: list[dict[str, Any]], domain: str) -> list[dict[str, Any]]:
    by_ref = {digest(domain, record): record for record in records}
    return [by_ref[key] for key in sorted(by_ref)]


def _before_cutoff(
    records: list[tuple[dict[str, Any], datetime]],
    cutoff: datetime,
    label: str,
    excluded: defaultdict[str, int],
) -> list[dict[str, Any]]:
    selected = []
    for payload, instant in records:
        if instant <= cutoff:
            selected.append(payload)
        else:
            excluded[label] += 1
    return selected


def _current_at_cutoff(
    value: tuple[dict[str, Any], datetime] | None,
    cutoff: datetime,
    label: str,
    excluded: defaultdict[str, int],
) -> dict[str, Any] | None:
    if value is None:
        return None
    if value[1] > cutoff:
        excluded[label] += 1
        return None
    return value[0]


def _bounded_list(root: dict[str, Any], name: str) -> list[Any]:
    value = root[name]
    if not isinstance(value, list) or len(value) > MAX_BUNDLE_RECORDS:
        raise VerificationError("bundle " + name + " is not a list")
    return value


def _optional_record(
    value: Any,
    parser: Callable[
        [Any, dict[str, dict[str, Any]]],
        tuple[dict[str, Any], datetime],
    ],
    trust: dict[str, dict[str, Any]],
) -> tuple[dict[str, Any], datetime] | None:
    return None if value is None else parser(value, trust)


def _prepare_evidence(bundle: Any, trust_snapshot: Any) -> _PreparedEvidence:
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
    for name in TARGET_FIELDS - {"arguments"}:
        _identifier(target[name], "bundle target " + name)
    if target["tool"] != "refund":
        raise VerificationError("bundle target has an unsupported tool")
    _refund(target["arguments"], "bundle target arguments")
    trust, checkpoints = check_trust_snapshot(trust_snapshot, cutoff)
    input_records = _bounded_list(root, "inputs")
    resolution_records = _bounded_list(root, "approval_resolutions")
    handoff_records = _bounded_list(root, "handoffs")
    event_records = _bounded_list(root, "events")
    parsed_inputs = [_input(value, trust) for value in input_records]
    parsed_resolutions = [_resolution(value, trust) for value in resolution_records]
    parsed_handoffs = [_handoff(value, trust)[:2] for value in handoff_records]
    parsed_events = [_event(value, trust) for value in event_records]
    parsed_admission = _optional_record(root["admission"], _admission, trust)
    parsed_recovery = _optional_record(root["recovery"], _recovery, trust)
    parsed_manifest = _optional_record(root["execution_manifest"], _manifest, trust)
    parsed_snapshot = _optional_record(root["provider_snapshot"], _snapshot, trust)

    excluded: defaultdict[str, int] = defaultdict(int)
    inputs = _deduplicate(
        _before_cutoff(parsed_inputs, cutoff, "verified_evidence", excluded),
        INPUT_DOMAIN,
    )
    resolutions = _deduplicate(
        _before_cutoff(parsed_resolutions, cutoff, "approval_resolution", excluded),
        RESOLUTION_DOMAIN,
    )
    handoffs = _deduplicate(
        _before_cutoff(parsed_handoffs, cutoff, "refund_handoff", excluded),
        HANDOFF_DOMAIN,
    )
    events = _deduplicate(
        _before_cutoff(parsed_events, cutoff, "event", excluded),
        EVENT_DOMAIN,
    )
    operation = operation_id(target)
    return _PreparedEvidence(
        root=root,
        target=target,
        cutoff=cutoff,
        trust=trust,
        checkpoints=checkpoints,
        inputs=inputs,
        resolutions=resolutions,
        handoffs=handoffs,
        events=events,
        admission=_current_at_cutoff(
            parsed_admission, cutoff, "admission_commit", excluded
        ),
        recovery=_current_at_cutoff(
            parsed_recovery, cutoff, "admission_recovery", excluded
        ),
        manifest=_current_at_cutoff(
            parsed_manifest, cutoff, "execution_manifest", excluded
        ),
        snapshot=_current_at_cutoff(
            parsed_snapshot, cutoff, "provider_snapshot", excluded
        ),
        operation=operation,
        idempotency_key=idempotency_key(operation, target["provider_id"]),
        excluded=dict(excluded),
    )


def _target_inputs(
    inputs: list[dict[str, Any]],
    target: dict[str, Any],
    role: str,
) -> list[dict[str, Any]]:
    target_decision = (
        target["decision_scope"],
        target["decision_issuer"],
        target["decision_id"],
    )
    return [
        item
        for item in inputs
        if item["evidence_role"] == role
        and (
            item["decision_scope"],
            item["decision_issuer"],
            item["decision_id"],
        )
        == target_decision
    ]


def _contradict_mismatches(
    actual: dict[str, Any],
    expected: dict[str, Any],
    issues: _IssueBook,
    claim: str,
    prefix: str,
) -> None:
    for name, expected_value in expected.items():
        if actual[name] != expected_value:
            issues.contradict(claim, prefix + name + "_mismatch")


def _check_verified_inputs(
    prepared: _PreparedEvidence,
    issues: _IssueBook,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    decision_inputs = _target_inputs(
        prepared.inputs, prepared.target, "decision_evidence"
    )
    approval_inputs = _target_inputs(
        prepared.inputs, prepared.target, "approval_evidence"
    )
    for item in decision_inputs + approval_inputs:
        if item["arguments"] != prepared.target["arguments"]:
            issues.contradict("admission", "verified_evidence_arguments_mismatch")
        if item["evaluation"] == "CONTRADICTED":
            issues.contradict("admission", "verified_evidence_contradicted")
        elif item["evaluation"] == "NOT_ESTABLISHED":
            issues.miss("admission", "verified_evidence_not_established")
    if not decision_inputs:
        issues.miss("admission", "missing_decision_evidence")
    variants = {
        (
            item["approval_ref"],
            item["tool"],
            canonical(item["arguments"]),
            item["evaluation"],
        )
        for item in decision_inputs
    }
    if len(variants) > 1:
        issues.contradict("admission", "conflicting_decision_evidence")
    if not approval_inputs:
        issues.miss("admission", "missing_approval_evidence")
    return decision_inputs, approval_inputs


def _check_admission_record(
    prepared: _PreparedEvidence,
    issues: _IssueBook,
    decision_inputs: list[dict[str, Any]],
    approval_inputs: list[dict[str, Any]],
) -> str | None:
    admission = prepared.admission
    if admission is None:
        for claim in (
            "admission",
            "durable_admission",
            "approval_continuity",
            "authenticated_handoff",
        ):
            issues.miss(claim, "missing_admission_commit")
        return None

    admission_ref = digest(ADMISSION_DOMAIN, admission)
    target = prepared.target
    expected_binding = decision_binding_ref(
        target,
        admission["approval_ref"],
        admission["decision_evidence_ref"],
        admission["approval_evidence_ref"],
        prepared.operation,
    )
    expected_admission = {
        "workflow_id": target["workflow_id"],
        "authority_id": target["admission_authority_id"],
        "handoff_issuer": target["handoff_issuer"],
        "provider_id": target["provider_id"],
        "decision_scope": target["decision_scope"],
        "decision_issuer": target["decision_issuer"],
        "decision_id": target["decision_id"],
        "operation_id": prepared.operation,
        "arguments": target["arguments"],
        "decision_binding_ref": expected_binding,
    }
    _contradict_mismatches(
        admission,
        expected_admission,
        issues,
        "admission",
        "admission_",
    )
    if admission["state_root"] != admission_state_root(admission):
        issues.contradict("admission", "admission_state_root_mismatch")

    checkpoint = prepared.checkpoints["admission"]
    expected_checkpoint = {
        "authority_id": admission["authority_id"],
        "workflow_id": admission["workflow_id"],
        "decision_scope": admission["decision_scope"],
        "decision_issuer": admission["decision_issuer"],
        "decision_id": admission["decision_id"],
        "operation_id": admission["operation_id"],
        "admission_ref": admission_ref,
        "state_root": admission["state_root"],
    }
    _contradict_mismatches(
        checkpoint,
        expected_checkpoint,
        issues,
        "admission",
        "admission_checkpoint_",
    )

    decision_matches = [
        item
        for item in decision_inputs
        if verified_evidence_ref(item) == admission["decision_evidence_ref"]
    ]
    approval_matches = [
        item
        for item in approval_inputs
        if verified_evidence_ref(item) == admission["approval_evidence_ref"]
    ]
    _check_referenced_inputs(
        admission,
        decision_matches,
        approval_matches,
        issues,
    )
    return admission_ref


def _check_referenced_inputs(
    admission: dict[str, Any],
    decision_matches: list[dict[str, Any]],
    approval_matches: list[dict[str, Any]],
    issues: _IssueBook,
) -> None:
    if not decision_matches:
        issues.miss("admission", "referenced_decision_evidence_missing")
    if not approval_matches:
        issues.miss("admission", "referenced_approval_evidence_missing")
    for item in decision_matches + approval_matches:
        if item["approval_ref"] != admission["approval_ref"]:
            issues.contradict("admission", "original_approval_ref_mismatch")
        if _stamp(item["verified_at"], "verified evidence time") > _stamp(
            admission["committed_at"], "admission time"
        ):
            issues.contradict("admission", "evidence_verified_after_admission")


def _check_admission_evidence(
    prepared: _PreparedEvidence,
    issues: _IssueBook,
) -> _AdmissionEvidence:
    decision_inputs, approval_inputs = _check_verified_inputs(prepared, issues)
    admission_ref = _check_admission_record(
        prepared,
        issues,
        decision_inputs,
        approval_inputs,
    )
    return _AdmissionEvidence(decision_inputs, approval_inputs, admission_ref)


def _check_recovery_evidence(
    prepared: _PreparedEvidence,
    issues: _IssueBook,
    admission_ref: str | None,
) -> None:
    recovery = prepared.recovery
    admission = prepared.admission
    if recovery is None:
        issues.miss("durable_admission", "missing_post_restart_recovery")
        return
    if admission is None or admission_ref is None:
        return
    expected_recovery = {
        "workflow_id": prepared.target["workflow_id"],
        "provider_id": prepared.target["provider_id"],
        "decision_scope": prepared.target["decision_scope"],
        "admission_ref": admission_ref,
        "operation_id": prepared.operation,
        "state_root": admission["state_root"],
    }
    for name, expected in expected_recovery.items():
        if recovery[name] != expected:
            issues.contradict("durable_admission", "recovery_" + name + "_mismatch")
    non_recovery_principals = {
        admission["authority_id"],
        *(item["reader_id"] for item in prepared.inputs),
        *(item["authority_id"] for item in prepared.resolutions),
        *(item["issuer"] for item in prepared.handoffs),
        *(item["observer_id"] for item in prepared.events),
    }
    if prepared.manifest is not None:
        non_recovery_principals.add(prepared.manifest["observer_id"])
    if prepared.snapshot is not None:
        non_recovery_principals.add(prepared.snapshot["observer_id"])
    if recovery["recovery_observer_id"] in non_recovery_principals:
        issues.contradict("durable_admission", "recovery_observer_not_separate")
    if _stamp(recovery["recovered_at"], "recovery time") <= _stamp(
        admission["committed_at"], "admission time"
    ):
        issues.contradict("durable_admission", "recovery_not_after_commit")


def _check_resolution_record(
    prepared: _PreparedEvidence,
    issues: _IssueBook,
    resolution: dict[str, Any],
    admission_ref: str,
) -> None:
    admission = prepared.admission
    if admission is None:
        raise AssertionError("resolution check lacks the selected admission")
    expected_resolution = {
        "authority_id": prepared.target["admission_authority_id"],
        "workflow_id": prepared.target["workflow_id"],
        "provider_id": prepared.target["provider_id"],
        "decision_scope": prepared.target["decision_scope"],
        "decision_issuer": prepared.target["decision_issuer"],
        "decision_id": prepared.target["decision_id"],
        "original_approval_ref": admission["approval_ref"],
        "original_admission_ref": admission_ref,
        "operation_id": prepared.operation,
        "arguments": prepared.target["arguments"],
    }
    for name, expected in expected_resolution.items():
        if resolution[name] != expected:
            issues.contradict("approval_continuity", "resolution_" + name + "_mismatch")
    if _stamp(resolution["resolved_at"], "resolution time") <= _stamp(
        admission["committed_at"], "admission time"
    ):
        issues.contradict("approval_continuity", "resolution_not_after_admission")


def _check_reissue_resolution(
    issues: _IssueBook,
    reissue: dict[str, Any],
    matches: list[dict[str, Any]],
) -> None:
    if not matches:
        issues.miss("approval_continuity", "reissued_approval_lacks_resolution")
    elif len(matches) > 1:
        issues.contradict("approval_continuity", "reissued_approval_not_resolved_once")
    elif _stamp(matches[0]["resolved_at"], "resolution time") < _stamp(
        reissue["verified_at"], "reissue verification time"
    ):
        issues.contradict(
            "approval_continuity", "resolution_precedes_reissued_evidence"
        )


def _index_approval_resolutions(
    prepared: _PreparedEvidence,
    issues: _IssueBook,
    admission_ref: str | None,
) -> defaultdict[str, list[dict[str, Any]]]:
    admission = prepared.admission
    by_reissue: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
    for resolution in prepared.resolutions:
        by_reissue[resolution["reissued_approval_ref"]].append(resolution)
        if admission is None or admission_ref is None:
            continue
        _check_resolution_record(prepared, issues, resolution, admission_ref)
    return by_reissue


def _check_unmatched_resolutions(
    issues: _IssueBook,
    by_reissue: defaultdict[str, list[dict[str, Any]]],
    reissues: list[dict[str, Any]],
) -> None:
    resolved_refs = {item["approval_ref"] for item in reissues}
    for reissued_ref in by_reissue:
        if reissued_ref not in resolved_refs:
            issues.contradict(
                "approval_continuity", "resolution_lacks_reissued_evidence"
            )


def _check_approval_resolutions(
    prepared: _PreparedEvidence,
    issues: _IssueBook,
    approval_inputs: list[dict[str, Any]],
    admission_ref: str | None,
) -> None:
    original_approval = (
        None if prepared.admission is None else prepared.admission["approval_ref"]
    )
    reissues = [
        item
        for item in approval_inputs
        if original_approval is not None and item["approval_ref"] != original_approval
    ]
    by_reissue = _index_approval_resolutions(prepared, issues, admission_ref)

    for reissue in reissues:
        _check_reissue_resolution(
            issues,
            reissue,
            by_reissue[reissue["approval_ref"]],
        )
    _check_unmatched_resolutions(issues, by_reissue, reissues)


def _matches_target_handoff(handoff: dict[str, Any], target: dict[str, Any]) -> bool:
    fields = (
        "workflow_id",
        "decision_scope",
        "decision_issuer",
        "decision_id",
        "provider_id",
    )
    return all(handoff[name] == target[name] for name in fields)


def _matches_exact_handoff(
    handoff: dict[str, Any], operation: str, admission_ref: str | None
) -> bool:
    return (
        admission_ref is not None
        and handoff["operation_id"] == operation
        and handoff["admission_ref"] == admission_ref
    )


def _target_handoffs(prepared: _PreparedEvidence) -> list[dict[str, Any]]:
    return [
        handoff
        for handoff in prepared.handoffs
        if _matches_target_handoff(handoff, prepared.target)
    ]


def _exact_handoffs(
    handoffs: list[dict[str, Any]],
    operation: str,
    admission_ref: str | None,
) -> list[dict[str, Any]]:
    return [
        item
        for item in handoffs
        if _matches_exact_handoff(item, operation, admission_ref)
    ]


def _checkpoint_handoffs(
    exact: list[dict[str, Any]], checkpoint_ref: str
) -> list[dict[str, Any]]:
    return [item for item in exact if digest(HANDOFF_DOMAIN, item) == checkpoint_ref]


def _select_primary_handoff(
    prepared: _PreparedEvidence,
    issues: _IssueBook,
    admission_ref: str | None,
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    target_handoffs = _target_handoffs(prepared)
    if not target_handoffs:
        issues.miss("authenticated_handoff", "missing_target_handoff")
        return target_handoffs, None
    if admission_ref is None:
        return target_handoffs, None
    exact = _exact_handoffs(target_handoffs, prepared.operation, admission_ref)
    if len(exact) != 1:
        issues.contradict("authenticated_handoff", "target_handoff_not_unique")
    checkpoint_matches = _checkpoint_handoffs(
        exact,
        prepared.checkpoints["handoff"]["handoff_ref"],
    )
    primary = checkpoint_matches[0] if len(checkpoint_matches) == 1 else None
    if primary is None and exact:
        primary = exact[0]
    if len(target_handoffs) != len(exact):
        issues.contradict("authenticated_handoff", "conflicting_target_handoff")
    return target_handoffs, primary


def _check_primary_handoff(
    prepared: _PreparedEvidence,
    issues: _IssueBook,
    primary: dict[str, Any] | None,
) -> str | None:
    admission = prepared.admission
    if primary is None or admission is None:
        return None
    target = prepared.target
    handoff_ref = digest(HANDOFF_DOMAIN, primary)
    expected_handoff = {
        "issuer": target["handoff_issuer"],
        "approval_ref": admission["approval_ref"],
        "decision_evidence_ref": admission["decision_evidence_ref"],
        "approval_evidence_ref": admission["approval_evidence_ref"],
        "arguments": target["arguments"],
        "idempotency_key": prepared.idempotency_key,
    }
    for name, expected in expected_handoff.items():
        if primary[name] != expected:
            issues.contradict("authenticated_handoff", "handoff_" + name + "_mismatch")

    checkpoint = prepared.checkpoints["handoff"]
    expected_checkpoint = {
        "issuer": primary["issuer"],
        "workflow_id": primary["workflow_id"],
        "decision_scope": primary["decision_scope"],
        "decision_issuer": primary["decision_issuer"],
        "decision_id": primary["decision_id"],
        "handoff_id": primary["handoff_id"],
        "operation_id": primary["operation_id"],
        "handoff_ref": handoff_ref,
    }
    for name, expected in expected_checkpoint.items():
        if checkpoint[name] != expected:
            issues.contradict(
                "authenticated_handoff",
                "handoff_checkpoint_" + name + "_mismatch",
            )
    if prepared.recovery is None:
        issues.miss("authenticated_handoff", "handoff_lacks_recovery_evidence")
    elif _stamp(primary["issued_at"], "handoff issued_at") <= _stamp(
        prepared.recovery["recovered_at"], "recovery time"
    ):
        issues.contradict("authenticated_handoff", "handoff_not_after_recovery")
    return handoff_ref


def _check_fresh_handoff_after_resolution(
    resolutions: list[dict[str, Any]],
    target_handoffs: list[dict[str, Any]],
    issues: _IssueBook,
) -> None:
    for resolution in resolutions:
        if any(
            _stamp(item["issued_at"], "handoff issued_at")
            > _stamp(resolution["resolved_at"], "resolution time")
            for item in target_handoffs
        ):
            issues.contradict(
                "approval_continuity", "fresh_handoff_after_reissue_resolution"
            )


def _check_handoff_evidence(
    prepared: _PreparedEvidence,
    issues: _IssueBook,
    admission_ref: str | None,
) -> _HandoffEvidence:
    target_handoffs, primary = _select_primary_handoff(
        prepared,
        issues,
        admission_ref,
    )
    handoff_ref = _check_primary_handoff(
        prepared,
        issues,
        primary,
    )
    _check_fresh_handoff_after_resolution(
        prepared.resolutions,
        target_handoffs,
        issues,
    )
    return _HandoffEvidence(target_handoffs, primary, handoff_ref)


def _check_event_link(
    event: dict[str, Any],
    position: int,
    previous_ref: str | None,
    previous_time: datetime | None,
    issues: _IssueBook,
) -> datetime:
    if event["sequence"] != position or event["previous_event_ref"] != previous_ref:
        issues.contradict("selected_log_consistency", "execution_event_chain_break")
    occurred = _stamp(event["occurred_at"], "event occurred_at")
    if previous_time is not None and occurred < previous_time:
        issues.contradict("selected_log_consistency", "execution_event_time_regression")
    return occurred


def _check_event_identity(
    event: dict[str, Any],
    event_ref: str,
    event_ids: dict[str, str],
    issues: _IssueBook,
) -> None:
    prior_ref = event_ids.get(event["event_id"])
    if prior_ref is not None and prior_ref != event_ref:
        issues.contradict("selected_log_consistency", "execution_event_id_reused")
    event_ids[event["event_id"]] = event_ref


def _check_event_binding(
    prepared: _PreparedEvidence,
    event: dict[str, Any],
    issues: _IssueBook,
) -> None:
    expected = {
        "workflow_id": prepared.target["workflow_id"],
        "provider_id": prepared.target["provider_id"],
        "decision_scope": prepared.target["decision_scope"],
        "handoff_issuer": prepared.target["handoff_issuer"],
        "operation_id": prepared.operation,
        "idempotency_key": prepared.idempotency_key,
    }
    _contradict_mismatches(
        event,
        expected,
        issues,
        "selected_log_consistency",
        "execution_event_",
    )


def _check_event_chain(
    prepared: _PreparedEvidence,
    issues: _IssueBook,
) -> tuple[list[dict[str, Any]], str | None]:
    events = sorted(
        prepared.events,
        key=lambda item: (item["sequence"], digest(EVENT_DOMAIN, item)),
    )
    event_refs = {digest(EVENT_DOMAIN, item): item for item in events}
    if len(event_refs) != len(events):
        raise AssertionError("deduplicated event references are not unique")
    event_ids: dict[str, str] = {}
    previous_ref: str | None = None
    previous_time: datetime | None = None
    for position, event in enumerate(events, start=1):
        occurred = _check_event_link(
            event,
            position,
            previous_ref,
            previous_time,
            issues,
        )
        event_ref = digest(EVENT_DOMAIN, event)
        _check_event_identity(event, event_ref, event_ids, issues)
        _check_event_binding(prepared, event, issues)
        previous_ref = event_ref
        previous_time = occurred
    if not events:
        issues.miss("selected_log_consistency", "missing_execution_events")
    return events, previous_ref


def _check_execution_manifest(
    prepared: _PreparedEvidence,
    issues: _IssueBook,
    event_count: int,
    head_event_ref: str | None,
) -> None:
    manifest = prepared.manifest
    if manifest is None:
        issues.miss("selected_log_consistency", "missing_execution_manifest")
        return
    expected_manifest = {
        "workflow_id": prepared.target["workflow_id"],
        "decision_scope": prepared.target["decision_scope"],
        "handoff_issuer": prepared.target["handoff_issuer"],
        "provider_id": prepared.target["provider_id"],
        "operation_id": prepared.operation,
        "idempotency_key": prepared.idempotency_key,
        "event_count": event_count,
        "head_event_ref": head_event_ref,
        "cutoff": prepared.root["cutoff"],
    }
    for name, expected in expected_manifest.items():
        if manifest[name] != expected:
            issues.contradict(
                "selected_log_consistency", "manifest_" + name + "_mismatch"
            )
    if any(
        event["observer_id"] != manifest["observer_id"]
        for event in prepared.events
        if event["kind"] != "effect"
    ):
        issues.contradict(
            "selected_log_consistency", "execution_event_observer_mismatch"
        )
    if _stamp(manifest["issued_at"], "manifest issued_at") != prepared.cutoff:
        issues.contradict("selected_log_consistency", "manifest_not_at_cutoff")


def _check_execution_evidence(
    prepared: _PreparedEvidence,
    issues: _IssueBook,
) -> _EventEvidence:
    events, head_event_ref = _check_event_chain(prepared, issues)
    _check_execution_manifest(
        prepared,
        issues,
        len(events),
        head_event_ref,
    )
    attempts = [item for item in events if item["kind"] == "attempt"]
    effects = [item for item in events if item["kind"] == "effect"]
    outcomes = [item for item in events if item["kind"] == "outcome"]
    reconciliations = [item for item in events if item["kind"] == "reconciliation"]
    return _EventEvidence(
        sorted_events=events,
        attempts=attempts,
        effects=effects,
        outcomes=outcomes,
        reconciliations=reconciliations,
        effects_by_ref={digest(EVENT_DOMAIN, item): item for item in effects},
    )


def _check_effect_snapshot(
    prepared: _PreparedEvidence,
    execution: _EventEvidence,
    issues: _IssueBook,
) -> str:
    snapshot = prepared.snapshot
    if snapshot is None:
        issues.miss("selected_effect_coverage", "missing_provider_snapshot")
        return "unknown"
    expected_snapshot = {
        "workflow_id": prepared.target["workflow_id"],
        "decision_scope": prepared.target["decision_scope"],
        "handoff_issuer": prepared.target["handoff_issuer"],
        "provider_id": prepared.target["provider_id"],
        "operation_id": prepared.operation,
        "idempotency_key": prepared.idempotency_key,
    }
    _contradict_mismatches(
        snapshot,
        expected_snapshot,
        issues,
        "selected_effect_coverage",
        "provider_snapshot_",
    )
    if _stamp(snapshot["observed_at"], "snapshot observed_at") != prepared.cutoff:
        issues.contradict("selected_effect_coverage", "provider_snapshot_not_at_cutoff")
    supplied_effect_ids = sorted({item["effect_id"] for item in execution.effects})
    if snapshot["effect_count"] != len(snapshot["effect_ids"]):
        issues.contradict(
            "selected_effect_coverage", "provider_snapshot_count_mismatch"
        )
    if snapshot["effect_ids"] != supplied_effect_ids:
        issues.contradict(
            "selected_effect_coverage", "provider_snapshot_effect_set_mismatch"
        )
    if snapshot["state_ref"] != provider_state_ref(snapshot):
        issues.contradict(
            "selected_effect_coverage", "provider_snapshot_state_ref_mismatch"
        )
    if any(
        event["observer_id"] != snapshot["observer_id"]
        for event in execution.effects
    ):
        issues.contradict(
            "selected_effect_coverage", "effect_event_observer_mismatch"
        )
    execution_observers = {
        item["observer_id"]
        for item in execution.sorted_events
        if item["kind"] != "effect"
    }
    if prepared.manifest is not None:
        execution_observers.add(prepared.manifest["observer_id"])
    if snapshot["observer_id"] in execution_observers:
        issues.contradict("selected_effect_coverage", "effect_observer_not_separate")
    return "present" if snapshot["effect_count"] else "absent"


def _related_to_attempt(
    records: list[dict[str, Any]],
    attempt: dict[str, Any],
    attempt_ref: str,
) -> list[dict[str, Any]]:
    return [
        item
        for item in records
        if item["attempt_id"] == attempt["attempt_id"]
        or item["attempt_ref"] == attempt_ref
    ]


def _check_dispatch_window(
    prepared: _PreparedEvidence,
    handoff: _HandoffEvidence,
    issues: _IssueBook,
    attempt: dict[str, Any],
    occurred: datetime,
) -> None:
    if (
        handoff.handoff_ref is not None
        and attempt["handoff_ref"] != handoff.handoff_ref
    ):
        issues.contradict("completion", "attempt_handoff_ref_mismatch")
    if handoff.primary is not None:
        dispatch_floor = max(
            _stamp(handoff.primary["issued_at"], "handoff issued_at"),
            _stamp(handoff.primary["not_before"], "handoff not_before"),
        )
        if occurred < dispatch_floor:
            issues.contradict("completion", "attempt_before_handoff_validity")
        if occurred >= _stamp(handoff.primary["expires_at"], "handoff expires_at"):
            issues.contradict("completion", "attempt_at_or_after_handoff_expiry")
        signer = prepared.trust[handoff.primary["key_id"]]
        if signer["status"] == "revoked" and occurred >= _stamp(
            signer["revoked_at"], "handoff key revoked_at"
        ):
            issues.contradict(
                "completion", "attempt_at_or_after_handoff_signer_revocation"
            )
    if prepared.recovery is not None and occurred <= _stamp(
        prepared.recovery["recovered_at"], "recovery time"
    ):
        issues.contradict("completion", "attempt_not_after_recovery")


def _check_attempt_predecessor(
    issues: _IssueBook,
    state: _CompletionState,
    attempt: dict[str, Any],
    index: int,
    occurred: datetime,
) -> None:
    if index == 0:
        if (
            attempt["disposition"] != "initial"
            or attempt["predecessor_attempt_ref"] is not None
        ):
            issues.contradict("completion", "first_attempt_not_initial")
        return
    if attempt["disposition"] not in {"recovery", "duplicate_delivery"}:
        issues.contradict("completion", "later_attempt_has_invalid_disposition")
    if attempt["predecessor_attempt_ref"] != state.previous_attempt_ref:
        issues.contradict("completion", "later_attempt_predecessor_mismatch")
    if state.previous_terminal is None:
        issues.contradict("completion", "later_attempt_follows_unresolved_attempt")
    elif state.previous_terminal[0] != "absent":
        issues.contradict("completion", "later_attempt_follows_effect_or_success")
    elif occurred <= state.previous_terminal[1]:
        issues.contradict("completion", "later_attempt_precedes_prior_terminal")


def _check_attempt_dispatch(
    prepared: _PreparedEvidence,
    handoff: _HandoffEvidence,
    issues: _IssueBook,
    state: _CompletionState,
    attempt: dict[str, Any],
    index: int,
) -> tuple[str, datetime]:
    attempt_ref = digest(EVENT_DOMAIN, attempt)
    occurred = _stamp(attempt["occurred_at"], "attempt time")
    _check_dispatch_window(prepared, handoff, issues, attempt, occurred)
    _check_attempt_predecessor(issues, state, attempt, index, occurred)
    return attempt_ref, occurred


def _check_attempt_effects(
    prepared: _PreparedEvidence,
    execution: _EventEvidence,
    issues: _IssueBook,
    state: _CompletionState,
    attempt: dict[str, Any],
    attempt_ref: str,
    attempt_time: datetime,
) -> list[dict[str, Any]]:
    matching = _related_to_attempt(execution.effects, attempt, attempt_ref)
    for effect in matching:
        effect_ref = digest(EVENT_DOMAIN, effect)
        if (
            effect["attempt_id"] != attempt["attempt_id"]
            or effect["attempt_ref"] != attempt_ref
        ):
            issues.contradict("completion", "effect_crosses_attempt_binding")
        if effect["arguments"] != prepared.target["arguments"]:
            issues.contradict("completion", "effect_refund_tuple_mismatch")
        if _stamp(effect["occurred_at"], "effect time") < attempt_time:
            issues.contradict("completion", "effect_precedes_attempt")
        prior_attempt = state.seen_effect_ids.get(effect["effect_id"])
        if prior_attempt is not None and prior_attempt != attempt_ref:
            issues.contradict("completion", "effect_id_rebound_to_another_attempt")
        state.seen_effect_ids[effect["effect_id"]] = attempt_ref
        if effect_ref not in execution.effects_by_ref:
            raise AssertionError("effect reference map is incomplete")
    return matching


def _select_attempt_outcome(
    execution: _EventEvidence,
    issues: _IssueBook,
    attempt: dict[str, Any],
    attempt_ref: str,
) -> dict[str, Any] | None:
    matching = _related_to_attempt(execution.outcomes, attempt, attempt_ref)
    exact = [
        item
        for item in matching
        if item["attempt_id"] == attempt["attempt_id"]
        and item["attempt_ref"] == attempt_ref
    ]
    if not exact:
        if matching:
            issues.contradict("completion", "outcome_crosses_attempt_binding")
        else:
            issues.miss("completion", "missing_attempt_outcome")
        return None
    if len(exact) > 1 or len(matching) != len(exact):
        issues.contradict("completion", "attempt_outcome_not_exactly_one")
        return None
    return exact[0]


def _reject_reconciliation_after_terminal(
    reconciliations: list[dict[str, Any]],
    issues: _IssueBook,
    attempt: dict[str, Any],
    attempt_ref: str,
    outcome_ref: str,
) -> None:
    if reconciliations:
        issues.contradict("completion", "reconciliation_after_terminal_outcome")
    for reconciliation in reconciliations:
        if (
            reconciliation["attempt_id"] != attempt["attempt_id"]
            or reconciliation["attempt_ref"] != attempt_ref
            or reconciliation["initial_outcome_ref"] != outcome_ref
        ):
            issues.contradict("completion", "reconciliation_crosses_attempt_binding")


def _terminal_success(
    execution: _EventEvidence,
    issues: _IssueBook,
    attempt: dict[str, Any],
    attempt_ref: str,
    outcome: dict[str, Any],
    outcome_ref: str,
    reconciliations: list[dict[str, Any]],
) -> tuple[str, datetime]:
    _reject_reconciliation_after_terminal(
        reconciliations,
        issues,
        attempt,
        attempt_ref,
        outcome_ref,
    )
    effect = execution.effects_by_ref.get(outcome["effect_ref"])
    if (
        effect is None
        or effect["attempt_id"] != attempt["attempt_id"]
        or effect["attempt_ref"] != attempt_ref
    ):
        issues.contradict("completion", "success_effect_ref_not_same_attempt")
    elif _stamp(outcome["occurred_at"], "outcome time") < _stamp(
        effect["occurred_at"], "effect time"
    ):
        issues.contradict("completion", "success_precedes_effect")
    if outcome["response_received"] is not True:
        issues.contradict("completion", "success_without_response")
    return "present", _stamp(outcome["occurred_at"], "outcome time")


def _terminal_failure(
    issues: _IssueBook,
    attempt: dict[str, Any],
    attempt_ref: str,
    outcome: dict[str, Any],
    outcome_ref: str,
    reconciliations: list[dict[str, Any]],
    matching_effects: list[dict[str, Any]],
) -> tuple[str, datetime]:
    _reject_reconciliation_after_terminal(
        reconciliations,
        issues,
        attempt,
        attempt_ref,
        outcome_ref,
    )
    if outcome["effect_ref"] is not None:
        issues.contradict("completion", "observed_failure_has_effect_ref")
    if outcome["response_received"] is not True:
        issues.contradict("completion", "observed_failure_without_response")
    if matching_effects:
        issues.contradict("completion", "observed_failure_conflicts_with_effect")
    return "absent", _stamp(outcome["occurred_at"], "outcome time")


def _check_unresolved_effect_reference(
    execution: _EventEvidence,
    issues: _IssueBook,
    attempt: dict[str, Any],
    attempt_ref: str,
    outcome: dict[str, Any],
) -> None:
    if outcome["effect_ref"] is None:
        return
    effect = execution.effects_by_ref.get(outcome["effect_ref"])
    if (
        effect is None
        or effect["attempt_id"] != attempt["attempt_id"]
        or effect["attempt_ref"] != attempt_ref
    ):
        issues.contradict("completion", "unresolved_effect_ref_not_same_attempt")
    elif _stamp(outcome["occurred_at"], "outcome time") < _stamp(
        effect["occurred_at"], "effect time"
    ):
        issues.contradict("completion", "unresolved_outcome_precedes_effect")


def _check_reconciliation_link(
    issues: _IssueBook,
    state: _ReconciliationState,
    attempt: dict[str, Any],
    attempt_ref: str,
    outcome: dict[str, Any],
    reconciliation: dict[str, Any],
    reconciliation_ref: str,
) -> None:
    if (
        reconciliation["attempt_id"] != attempt["attempt_id"]
        or reconciliation["attempt_ref"] != attempt_ref
        or reconciliation["initial_outcome_ref"] != digest(EVENT_DOMAIN, outcome)
    ):
        issues.contradict("completion", "reconciliation_crosses_attempt_binding")
    if reconciliation["previous_reconciliation_ref"] != state.previous_ref:
        issues.contradict("completion", "reconciliation_predecessor_mismatch")
    if _stamp(reconciliation["occurred_at"], "reconciliation time") < _stamp(
        outcome["occurred_at"], "outcome time"
    ):
        issues.contradict("completion", "reconciliation_precedes_outcome")
    if state.reached_terminal:
        issues.contradict("completion", "reconciliation_after_terminal")
    state.previous_ref = reconciliation_ref


def _confirm_reconciled_effect(
    execution: _EventEvidence,
    issues: _IssueBook,
    state: _ReconciliationState,
    attempt: dict[str, Any],
    attempt_ref: str,
    reconciliation: dict[str, Any],
    reconciliation_ref: str,
) -> None:
    effect = execution.effects_by_ref.get(reconciliation["effect_ref"])
    if (
        effect is None
        or effect["attempt_id"] != attempt["attempt_id"]
        or effect["attempt_ref"] != attempt_ref
    ):
        issues.contradict("completion", "reconciliation_effect_not_same_attempt")
    elif _stamp(reconciliation["occurred_at"], "reconciliation time") < _stamp(
        effect["occurred_at"], "effect time"
    ):
        issues.contradict("completion", "reconciliation_precedes_effect")
    state.terminal = (
        "present",
        _stamp(reconciliation["occurred_at"], "reconciliation time"),
    )
    state.terminal_refs.append(reconciliation_ref)
    state.reached_terminal = True


def _confirm_reconciled_absence(
    issues: _IssueBook,
    state: _ReconciliationState,
    matching_effects: list[dict[str, Any]],
    reconciliation: dict[str, Any],
    reconciliation_ref: str,
) -> None:
    if reconciliation["effect_ref"] is not None:
        issues.contradict("completion", "effect_absent_reconciliation_has_effect")
    if matching_effects:
        issues.contradict("completion", "effect_absent_conflicts_with_effect")
    state.terminal = (
        "absent",
        _stamp(reconciliation["occurred_at"], "reconciliation time"),
    )
    state.terminal_refs.append(reconciliation_ref)
    state.reached_terminal = True


def _apply_reconciliation(
    execution: _EventEvidence,
    issues: _IssueBook,
    state: _ReconciliationState,
    attempt: dict[str, Any],
    attempt_ref: str,
    matching_effects: list[dict[str, Any]],
    reconciliation: dict[str, Any],
    reconciliation_ref: str,
) -> None:
    resolution = reconciliation["outcome"]
    if resolution == "still_unresolved":
        if reconciliation["effect_ref"] is not None:
            issues.contradict("completion", "unresolved_reconciliation_has_effect")
    elif resolution == "effect_confirmed":
        _confirm_reconciled_effect(
            execution,
            issues,
            state,
            attempt,
            attempt_ref,
            reconciliation,
            reconciliation_ref,
        )
    else:
        _confirm_reconciled_absence(
            issues,
            state,
            matching_effects,
            reconciliation,
            reconciliation_ref,
        )


def _terminal_from_reconciliation(
    execution: _EventEvidence,
    issues: _IssueBook,
    attempt: dict[str, Any],
    attempt_ref: str,
    outcome: dict[str, Any],
    matching_effects: list[dict[str, Any]],
    reconciliations: list[dict[str, Any]],
) -> tuple[tuple[str, datetime] | None, list[str]]:
    state = _ReconciliationState()
    for reconciliation in sorted(reconciliations, key=lambda item: item["sequence"]):
        reconciliation_ref = digest(EVENT_DOMAIN, reconciliation)
        _check_reconciliation_link(
            issues,
            state,
            attempt,
            attempt_ref,
            outcome,
            reconciliation,
            reconciliation_ref,
        )
        _apply_reconciliation(
            execution,
            issues,
            state,
            attempt,
            attempt_ref,
            matching_effects,
            reconciliation,
            reconciliation_ref,
        )
    return state.terminal, state.terminal_refs


def _terminal_from_outcome(
    execution: _EventEvidence,
    issues: _IssueBook,
    attempt: dict[str, Any],
    attempt_ref: str,
    attempt_time: datetime,
    outcome: dict[str, Any],
    matching_effects: list[dict[str, Any]],
) -> tuple[tuple[str, datetime] | None, list[str]]:
    outcome_ref = digest(EVENT_DOMAIN, outcome)
    reconciliations = _related_to_attempt(
        execution.reconciliations,
        attempt,
        attempt_ref,
    )
    if _stamp(outcome["occurred_at"], "outcome time") < attempt_time:
        issues.contradict("completion", "outcome_precedes_attempt")
    if outcome["state"] == "observed_success":
        terminal = _terminal_success(
            execution,
            issues,
            attempt,
            attempt_ref,
            outcome,
            outcome_ref,
            reconciliations,
        )
        return terminal, [outcome_ref]
    if outcome["state"] == "observed_failure":
        terminal = _terminal_failure(
            issues,
            attempt,
            attempt_ref,
            outcome,
            outcome_ref,
            reconciliations,
            matching_effects,
        )
        return terminal, [outcome_ref]
    if outcome["response_received"] is not False:
        issues.contradict("completion", "unresolved_outcome_has_response")
    _check_unresolved_effect_reference(
        execution,
        issues,
        attempt,
        attempt_ref,
        outcome,
    )
    return _terminal_from_reconciliation(
        execution,
        issues,
        attempt,
        attempt_ref,
        outcome,
        matching_effects,
        reconciliations,
    )


def _check_unknown_attempt_references(
    execution: _EventEvidence,
    issues: _IssueBook,
) -> None:
    attempt_by_ref = {digest(EVENT_DOMAIN, item): item for item in execution.attempts}
    known_attempt_ids = {item["attempt_id"] for item in execution.attempts}
    for event in execution.effects + execution.outcomes + execution.reconciliations:
        if (
            event["attempt_id"] not in known_attempt_ids
            or event["attempt_ref"] not in attempt_by_ref
        ):
            issues.contradict("completion", "event_references_unknown_attempt")


def _check_snapshot_completion_consistency(
    prepared: _PreparedEvidence,
    execution: _EventEvidence,
    issues: _IssueBook,
) -> None:
    if prepared.snapshot is None:
        return
    if prepared.snapshot["effect_count"] == 0 and execution.effects:
        issues.contradict(
            "completion", "terminal_effect_conflicts_with_provider_snapshot"
        )
    if prepared.snapshot["effect_count"] > 0 and not execution.effects:
        issues.contradict("completion", "provider_effect_lacks_typed_event")


def _check_completion_consistency(
    prepared: _PreparedEvidence,
    execution: _EventEvidence,
    issues: _IssueBook,
    state: _CompletionState,
) -> str:
    _check_unknown_attempt_references(execution, issues)
    if len(execution.effects) > 1:
        issues.contradict("completion", "multiple_refund_effects")
    _check_snapshot_completion_consistency(prepared, execution, issues)
    if execution.attempts and len(state.terminal) == len(execution.attempts):
        return "effect_committed" if execution.effects else "no_effect"
    return "unknown"


def _check_reopened_operation(
    prepared: _PreparedEvidence,
    execution: _EventEvidence,
    issues: _IssueBook,
    terminal: dict[str, tuple[str, datetime]],
) -> None:
    for resolution in prepared.resolutions:
        resolution_time = _stamp(resolution["resolved_at"], "resolution time")
        terminal_before = any(
            value[1] <= resolution_time for value in terminal.values()
        )
        if terminal_before and any(
            _stamp(item["occurred_at"], "attempt time") > resolution_time
            for item in execution.attempts
        ):
            issues.contradict(
                "approval_continuity", "terminal_operation_reopened_after_reissue"
            )


def _check_completion(
    prepared: _PreparedEvidence,
    execution: _EventEvidence,
    handoff: _HandoffEvidence,
    issues: _IssueBook,
) -> _CompletionEvidence:
    if not execution.attempts:
        issues.miss("completion", "missing_dispatch_attempt")
    if handoff.primary is None or handoff.handoff_ref is None:
        issues.miss("completion", "missing_authenticated_handoff")
    state = _CompletionState()
    for index, attempt in enumerate(execution.attempts):
        attempt_ref, attempt_time = _check_attempt_dispatch(
            prepared,
            handoff,
            issues,
            state,
            attempt,
            index,
        )
        matching_effects = _check_attempt_effects(
            prepared,
            execution,
            issues,
            state,
            attempt,
            attempt_ref,
            attempt_time,
        )
        outcome = _select_attempt_outcome(
            execution,
            issues,
            attempt,
            attempt_ref,
        )
        if outcome is None:
            state.previous_attempt_ref = attempt_ref
            state.previous_terminal = None
            continue
        terminal, terminal_refs = _terminal_from_outcome(
            execution,
            issues,
            attempt,
            attempt_ref,
            attempt_time,
            outcome,
            matching_effects,
        )
        state.terminal_refs.extend(terminal_refs)
        if terminal is None:
            issues.miss("completion", "unresolved_completion")
        else:
            state.terminal[attempt_ref] = terminal
        state.previous_attempt_ref = attempt_ref
        state.previous_terminal = terminal
    value = _check_completion_consistency(prepared, execution, issues, state)
    _check_reopened_operation(prepared, execution, issues, state.terminal)
    return _CompletionEvidence(value, state.terminal, state.terminal_refs)


def assess(bundle: Any, trust_snapshot: Any) -> dict[str, Any]:
    """Check one finite bundle and return a deterministic bounded report."""
    prepared = _prepare_evidence(bundle, trust_snapshot)
    root = prepared.root
    target = prepared.target
    checkpoints = prepared.checkpoints
    inputs = prepared.inputs
    handoffs = prepared.handoffs
    manifest = prepared.manifest
    snapshot = prepared.snapshot
    operation = prepared.operation
    excluded = prepared.excluded
    issues = _IssueBook()

    admission_evidence = _check_admission_evidence(prepared, issues)
    approval_inputs = admission_evidence.approval_inputs
    admission_ref = admission_evidence.admission_ref

    _check_recovery_evidence(prepared, issues, admission_ref)

    _check_approval_resolutions(
        prepared,
        issues,
        approval_inputs,
        admission_ref,
    )

    handoff_evidence = _check_handoff_evidence(prepared, issues, admission_ref)
    target_handoffs = handoff_evidence.target_handoffs
    handoff_ref = handoff_evidence.handoff_ref

    execution = _check_execution_evidence(prepared, issues)
    sorted_events = execution.sorted_events
    attempts = execution.attempts
    effects = execution.effects
    effects_by_ref = execution.effects_by_ref
    effect_value = _check_effect_snapshot(prepared, execution, issues)

    completion = _check_completion(prepared, execution, handoff_evidence, issues)
    completion_value = completion.value
    terminal_refs = completion.terminal_refs

    claims = issues.claims(effect_value, completion_value)
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
        "admission_checkpoint_ref": digest(
            ADMISSION_CHECKPOINT_DOMAIN, checkpoints["admission"]
        ),
        "handoff_checkpoint_ref": digest(
            HANDOFF_CHECKPOINT_DOMAIN, checkpoints["handoff"]
        ),
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
            "complete admission history or global decision single-consumption",
            "handoff history beyond the selected consumer checkpoint",
            "execution-event coverage beyond the selected observer and manifest scope",
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
    except (
        VerificationError,
        OSError,
        KeyError,
        TypeError,
        ValueError,
        RecursionError,
    ) as error:
        refusal = ("Refund handoff bundle refused: " + str(error) + "\n").encode(
            "utf-8", errors="backslashreplace"
        )
        sys.stderr.buffer.write(refusal)
        return 2
    sys.stdout.buffer.write(canonical(report) + b"\n")
    return 0 if report["overall"] == "ESTABLISHED" else 3


if __name__ == "__main__":
    raise SystemExit(main())
