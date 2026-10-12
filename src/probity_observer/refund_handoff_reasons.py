"""Closed reason contracts for the refund handoff profile."""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Literal

type EvidenceState = Literal["CONTRADICTED", "NOT_ESTABLISHED"]
type ReasonContract = tuple[tuple[str, ...], EvidenceState]

_PROFILE = (
    "https://probityai.github.io/agent-evidence-observer/contract/refund-handoff/0.1"
)
_REGISTRY_SCHEMA_URI = _PROFILE + "/reason-codes.schema.json"
_REGISTRY_SCHEMA = "refund-handoff-reason-codes/0.1"
_REASON_NAMESPACE = _PROFILE + "#reason-"
_EXPECTED_REASON_COUNT = 155

_REASON_ROWS: tuple[tuple[str, tuple[str, ...], EvidenceState], ...] = (
    ("admission_arguments_mismatch", ("admission",), "CONTRADICTED"),
    ("admission_authority_id_mismatch", ("admission",), "CONTRADICTED"),
    (
        "admission_checkpoint_admission_ref_mismatch",
        ("admission",),
        "CONTRADICTED",
    ),
    (
        "admission_checkpoint_authority_id_mismatch",
        ("admission",),
        "CONTRADICTED",
    ),
    (
        "admission_checkpoint_decision_id_mismatch",
        ("admission",),
        "CONTRADICTED",
    ),
    (
        "admission_checkpoint_decision_issuer_mismatch",
        ("admission",),
        "CONTRADICTED",
    ),
    (
        "admission_checkpoint_decision_scope_mismatch",
        ("admission",),
        "CONTRADICTED",
    ),
    (
        "admission_checkpoint_operation_id_mismatch",
        ("admission",),
        "CONTRADICTED",
    ),
    (
        "admission_checkpoint_state_root_mismatch",
        ("admission",),
        "CONTRADICTED",
    ),
    (
        "admission_checkpoint_workflow_id_mismatch",
        ("admission",),
        "CONTRADICTED",
    ),
    (
        "admission_decision_binding_ref_mismatch",
        ("admission",),
        "CONTRADICTED",
    ),
    ("admission_decision_id_mismatch", ("admission",), "CONTRADICTED"),
    ("admission_decision_issuer_mismatch", ("admission",), "CONTRADICTED"),
    ("admission_decision_scope_mismatch", ("admission",), "CONTRADICTED"),
    ("admission_handoff_issuer_mismatch", ("admission",), "CONTRADICTED"),
    ("admission_operation_id_mismatch", ("admission",), "CONTRADICTED"),
    ("admission_provider_id_mismatch", ("admission",), "CONTRADICTED"),
    ("admission_state_root_mismatch", ("admission",), "CONTRADICTED"),
    ("admission_workflow_id_mismatch", ("admission",), "CONTRADICTED"),
    ("conflicting_decision_evidence", ("admission",), "CONTRADICTED"),
    ("evidence_verified_after_admission", ("admission",), "CONTRADICTED"),
    (
        "missing_admission_commit",
        (
            "admission",
            "approval_continuity",
            "authenticated_handoff",
            "durable_admission",
        ),
        "NOT_ESTABLISHED",
    ),
    ("missing_approval_evidence", ("admission",), "NOT_ESTABLISHED"),
    ("missing_decision_evidence", ("admission",), "NOT_ESTABLISHED"),
    ("original_approval_ref_mismatch", ("admission",), "CONTRADICTED"),
    ("referenced_approval_evidence_missing", ("admission",), "NOT_ESTABLISHED"),
    ("referenced_decision_evidence_missing", ("admission",), "NOT_ESTABLISHED"),
    ("verified_evidence_arguments_mismatch", ("admission",), "CONTRADICTED"),
    ("verified_evidence_contradicted", ("admission",), "CONTRADICTED"),
    ("verified_evidence_not_established", ("admission",), "NOT_ESTABLISHED"),
    (
        "missing_post_restart_recovery",
        ("durable_admission",),
        "NOT_ESTABLISHED",
    ),
    (
        "recovery_admission_ref_mismatch",
        ("durable_admission",),
        "CONTRADICTED",
    ),
    (
        "recovery_decision_scope_mismatch",
        ("durable_admission",),
        "CONTRADICTED",
    ),
    ("recovery_not_after_commit", ("durable_admission",), "CONTRADICTED"),
    (
        "recovery_observer_not_separate",
        ("durable_admission",),
        "CONTRADICTED",
    ),
    (
        "recovery_operation_id_mismatch",
        ("durable_admission",),
        "CONTRADICTED",
    ),
    (
        "recovery_provider_id_mismatch",
        ("durable_admission",),
        "CONTRADICTED",
    ),
    (
        "recovery_state_root_mismatch",
        ("durable_admission",),
        "CONTRADICTED",
    ),
    (
        "recovery_workflow_id_mismatch",
        ("durable_admission",),
        "CONTRADICTED",
    ),
    (
        "fresh_handoff_after_reissue_resolution",
        ("approval_continuity",),
        "CONTRADICTED",
    ),
    (
        "reissued_approval_lacks_resolution",
        ("approval_continuity",),
        "NOT_ESTABLISHED",
    ),
    (
        "reissued_approval_not_resolved_once",
        ("approval_continuity",),
        "CONTRADICTED",
    ),
    (
        "resolution_arguments_mismatch",
        ("approval_continuity",),
        "CONTRADICTED",
    ),
    (
        "resolution_authority_id_mismatch",
        ("approval_continuity",),
        "CONTRADICTED",
    ),
    (
        "resolution_decision_id_mismatch",
        ("approval_continuity",),
        "CONTRADICTED",
    ),
    (
        "resolution_decision_issuer_mismatch",
        ("approval_continuity",),
        "CONTRADICTED",
    ),
    (
        "resolution_decision_scope_mismatch",
        ("approval_continuity",),
        "CONTRADICTED",
    ),
    (
        "resolution_lacks_reissued_evidence",
        ("approval_continuity",),
        "CONTRADICTED",
    ),
    (
        "resolution_not_after_admission",
        ("approval_continuity",),
        "CONTRADICTED",
    ),
    (
        "resolution_operation_id_mismatch",
        ("approval_continuity",),
        "CONTRADICTED",
    ),
    (
        "resolution_original_admission_ref_mismatch",
        ("approval_continuity",),
        "CONTRADICTED",
    ),
    (
        "resolution_original_approval_ref_mismatch",
        ("approval_continuity",),
        "CONTRADICTED",
    ),
    (
        "resolution_precedes_reissued_evidence",
        ("approval_continuity",),
        "CONTRADICTED",
    ),
    (
        "resolution_provider_id_mismatch",
        ("approval_continuity",),
        "CONTRADICTED",
    ),
    (
        "resolution_workflow_id_mismatch",
        ("approval_continuity",),
        "CONTRADICTED",
    ),
    (
        "terminal_operation_reopened_after_reissue",
        ("approval_continuity",),
        "CONTRADICTED",
    ),
    (
        "conflicting_target_handoff",
        ("authenticated_handoff",),
        "CONTRADICTED",
    ),
    (
        "handoff_approval_evidence_ref_mismatch",
        ("authenticated_handoff",),
        "CONTRADICTED",
    ),
    (
        "handoff_approval_ref_mismatch",
        ("authenticated_handoff",),
        "CONTRADICTED",
    ),
    (
        "handoff_arguments_mismatch",
        ("authenticated_handoff",),
        "CONTRADICTED",
    ),
    (
        "handoff_checkpoint_decision_id_mismatch",
        ("authenticated_handoff",),
        "CONTRADICTED",
    ),
    (
        "handoff_checkpoint_decision_issuer_mismatch",
        ("authenticated_handoff",),
        "CONTRADICTED",
    ),
    (
        "handoff_checkpoint_decision_scope_mismatch",
        ("authenticated_handoff",),
        "CONTRADICTED",
    ),
    (
        "handoff_checkpoint_handoff_id_mismatch",
        ("authenticated_handoff",),
        "CONTRADICTED",
    ),
    (
        "handoff_checkpoint_handoff_ref_mismatch",
        ("authenticated_handoff",),
        "CONTRADICTED",
    ),
    (
        "handoff_checkpoint_issuer_mismatch",
        ("authenticated_handoff",),
        "CONTRADICTED",
    ),
    (
        "handoff_checkpoint_operation_id_mismatch",
        ("authenticated_handoff",),
        "CONTRADICTED",
    ),
    (
        "handoff_checkpoint_workflow_id_mismatch",
        ("authenticated_handoff",),
        "CONTRADICTED",
    ),
    (
        "handoff_decision_evidence_ref_mismatch",
        ("authenticated_handoff",),
        "CONTRADICTED",
    ),
    (
        "handoff_idempotency_key_mismatch",
        ("authenticated_handoff",),
        "CONTRADICTED",
    ),
    (
        "handoff_issuer_mismatch",
        ("authenticated_handoff",),
        "CONTRADICTED",
    ),
    (
        "handoff_lacks_recovery_evidence",
        ("authenticated_handoff",),
        "NOT_ESTABLISHED",
    ),
    (
        "handoff_not_after_recovery",
        ("authenticated_handoff",),
        "CONTRADICTED",
    ),
    (
        "missing_target_handoff",
        ("authenticated_handoff",),
        "NOT_ESTABLISHED",
    ),
    (
        "target_handoff_not_unique",
        ("authenticated_handoff",),
        "CONTRADICTED",
    ),
    (
        "execution_event_chain_break",
        ("selected_log_consistency",),
        "CONTRADICTED",
    ),
    (
        "execution_event_decision_scope_mismatch",
        ("selected_log_consistency",),
        "CONTRADICTED",
    ),
    (
        "execution_event_handoff_issuer_mismatch",
        ("selected_log_consistency",),
        "CONTRADICTED",
    ),
    (
        "execution_event_id_reused",
        ("selected_log_consistency",),
        "CONTRADICTED",
    ),
    (
        "execution_event_idempotency_key_mismatch",
        ("selected_log_consistency",),
        "CONTRADICTED",
    ),
    (
        "execution_event_operation_id_mismatch",
        ("selected_log_consistency",),
        "CONTRADICTED",
    ),
    (
        "execution_event_observer_mismatch",
        ("selected_log_consistency",),
        "CONTRADICTED",
    ),
    (
        "execution_event_provider_id_mismatch",
        ("selected_log_consistency",),
        "CONTRADICTED",
    ),
    (
        "execution_event_time_regression",
        ("selected_log_consistency",),
        "CONTRADICTED",
    ),
    (
        "execution_event_workflow_id_mismatch",
        ("selected_log_consistency",),
        "CONTRADICTED",
    ),
    (
        "manifest_cutoff_mismatch",
        ("selected_log_consistency",),
        "CONTRADICTED",
    ),
    (
        "manifest_decision_scope_mismatch",
        ("selected_log_consistency",),
        "CONTRADICTED",
    ),
    (
        "manifest_event_count_mismatch",
        ("selected_log_consistency",),
        "CONTRADICTED",
    ),
    (
        "manifest_handoff_issuer_mismatch",
        ("selected_log_consistency",),
        "CONTRADICTED",
    ),
    (
        "manifest_head_event_ref_mismatch",
        ("selected_log_consistency",),
        "CONTRADICTED",
    ),
    (
        "manifest_idempotency_key_mismatch",
        ("selected_log_consistency",),
        "CONTRADICTED",
    ),
    (
        "manifest_not_at_cutoff",
        ("selected_log_consistency",),
        "CONTRADICTED",
    ),
    (
        "manifest_operation_id_mismatch",
        ("selected_log_consistency",),
        "CONTRADICTED",
    ),
    (
        "manifest_provider_id_mismatch",
        ("selected_log_consistency",),
        "CONTRADICTED",
    ),
    (
        "manifest_workflow_id_mismatch",
        ("selected_log_consistency",),
        "CONTRADICTED",
    ),
    (
        "missing_execution_events",
        ("selected_log_consistency",),
        "NOT_ESTABLISHED",
    ),
    (
        "missing_execution_manifest",
        ("selected_log_consistency",),
        "NOT_ESTABLISHED",
    ),
    (
        "effect_event_observer_mismatch",
        ("selected_effect_coverage",),
        "CONTRADICTED",
    ),
    (
        "effect_observer_not_separate",
        ("selected_effect_coverage",),
        "CONTRADICTED",
    ),
    (
        "missing_provider_snapshot",
        ("selected_effect_coverage",),
        "NOT_ESTABLISHED",
    ),
    (
        "provider_snapshot_count_mismatch",
        ("selected_effect_coverage",),
        "CONTRADICTED",
    ),
    (
        "provider_snapshot_decision_scope_mismatch",
        ("selected_effect_coverage",),
        "CONTRADICTED",
    ),
    (
        "provider_snapshot_effect_set_mismatch",
        ("selected_effect_coverage",),
        "CONTRADICTED",
    ),
    (
        "provider_snapshot_handoff_issuer_mismatch",
        ("selected_effect_coverage",),
        "CONTRADICTED",
    ),
    (
        "provider_snapshot_idempotency_key_mismatch",
        ("selected_effect_coverage",),
        "CONTRADICTED",
    ),
    (
        "provider_snapshot_not_at_cutoff",
        ("selected_effect_coverage",),
        "CONTRADICTED",
    ),
    (
        "provider_snapshot_operation_id_mismatch",
        ("selected_effect_coverage",),
        "CONTRADICTED",
    ),
    (
        "provider_snapshot_provider_id_mismatch",
        ("selected_effect_coverage",),
        "CONTRADICTED",
    ),
    (
        "provider_snapshot_state_ref_mismatch",
        ("selected_effect_coverage",),
        "CONTRADICTED",
    ),
    (
        "provider_snapshot_workflow_id_mismatch",
        ("selected_effect_coverage",),
        "CONTRADICTED",
    ),
    ("attempt_at_or_after_handoff_expiry", ("completion",), "CONTRADICTED"),
    (
        "attempt_at_or_after_handoff_signer_revocation",
        ("completion",),
        "CONTRADICTED",
    ),
    ("attempt_before_handoff_validity", ("completion",), "CONTRADICTED"),
    ("attempt_handoff_ref_mismatch", ("completion",), "CONTRADICTED"),
    ("attempt_not_after_recovery", ("completion",), "CONTRADICTED"),
    ("attempt_outcome_not_exactly_one", ("completion",), "CONTRADICTED"),
    ("effect_absent_conflicts_with_effect", ("completion",), "CONTRADICTED"),
    (
        "effect_absent_reconciliation_has_effect",
        ("completion",),
        "CONTRADICTED",
    ),
    ("effect_crosses_attempt_binding", ("completion",), "CONTRADICTED"),
    (
        "effect_id_rebound_to_another_attempt",
        ("completion",),
        "CONTRADICTED",
    ),
    ("effect_precedes_attempt", ("completion",), "CONTRADICTED"),
    ("effect_refund_tuple_mismatch", ("completion",), "CONTRADICTED"),
    ("event_references_unknown_attempt", ("completion",), "CONTRADICTED"),
    ("first_attempt_not_initial", ("completion",), "CONTRADICTED"),
    (
        "later_attempt_follows_effect_or_success",
        ("completion",),
        "CONTRADICTED",
    ),
    (
        "later_attempt_follows_unresolved_attempt",
        ("completion",),
        "CONTRADICTED",
    ),
    (
        "later_attempt_has_invalid_disposition",
        ("completion",),
        "CONTRADICTED",
    ),
    (
        "later_attempt_precedes_prior_terminal",
        ("completion",),
        "CONTRADICTED",
    ),
    (
        "later_attempt_predecessor_mismatch",
        ("completion",),
        "CONTRADICTED",
    ),
    ("missing_attempt_outcome", ("completion",), "NOT_ESTABLISHED"),
    ("missing_authenticated_handoff", ("completion",), "NOT_ESTABLISHED"),
    ("missing_dispatch_attempt", ("completion",), "NOT_ESTABLISHED"),
    ("multiple_refund_effects", ("completion",), "CONTRADICTED"),
    (
        "observed_failure_conflicts_with_effect",
        ("completion",),
        "CONTRADICTED",
    ),
    ("observed_failure_has_effect_ref", ("completion",), "CONTRADICTED"),
    ("observed_failure_without_response", ("completion",), "CONTRADICTED"),
    ("outcome_crosses_attempt_binding", ("completion",), "CONTRADICTED"),
    ("outcome_precedes_attempt", ("completion",), "CONTRADICTED"),
    ("provider_effect_lacks_typed_event", ("completion",), "CONTRADICTED"),
    ("reconciliation_after_terminal", ("completion",), "CONTRADICTED"),
    (
        "reconciliation_after_terminal_outcome",
        ("completion",),
        "CONTRADICTED",
    ),
    (
        "reconciliation_crosses_attempt_binding",
        ("completion",),
        "CONTRADICTED",
    ),
    (
        "reconciliation_effect_not_same_attempt",
        ("completion",),
        "CONTRADICTED",
    ),
    ("reconciliation_precedes_effect", ("completion",), "CONTRADICTED"),
    ("reconciliation_precedes_outcome", ("completion",), "CONTRADICTED"),
    (
        "reconciliation_predecessor_mismatch",
        ("completion",),
        "CONTRADICTED",
    ),
    ("success_effect_ref_not_same_attempt", ("completion",), "CONTRADICTED"),
    ("success_precedes_effect", ("completion",), "CONTRADICTED"),
    ("success_without_response", ("completion",), "CONTRADICTED"),
    (
        "terminal_effect_conflicts_with_provider_snapshot",
        ("completion",),
        "CONTRADICTED",
    ),
    ("unresolved_completion", ("completion",), "NOT_ESTABLISHED"),
    (
        "unresolved_effect_ref_not_same_attempt",
        ("completion",),
        "CONTRADICTED",
    ),
    ("unresolved_outcome_has_response", ("completion",), "CONTRADICTED"),
    (
        "unresolved_outcome_precedes_effect",
        ("completion",),
        "CONTRADICTED",
    ),
    (
        "unresolved_reconciliation_has_effect",
        ("completion",),
        "CONTRADICTED",
    ),
)


REASON_CONTRACTS: Mapping[str, ReasonContract] = MappingProxyType(
    {code: (claims, state) for code, claims, state in _REASON_ROWS}
)

if len(REASON_CONTRACTS) != len(_REASON_ROWS):
    raise RuntimeError("refund handoff reason registry contains a duplicate code")
if len(REASON_CONTRACTS) != _EXPECTED_REASON_COUNT:
    raise RuntimeError("refund handoff reason registry must contain exactly 155 codes")


def lookup_reason_contract(code: str) -> ReasonContract:
    """Return the claims and default state for one closed reason code."""
    if not isinstance(code, str):
        raise TypeError("reason code must be a string")
    try:
        return REASON_CONTRACTS[code]
    except KeyError:
        raise ValueError("unknown refund handoff reason code: " + code) from None


def build_reason_registry() -> dict[str, object]:
    """Build a fresh JSON document for the closed reason-code registry."""
    reasons = [
        {
            "uri": _REASON_NAMESPACE + code,
            "code": code,
            "claims": list(claims),
            "default_evidence_state": state,
        }
        for code, (claims, state) in REASON_CONTRACTS.items()
    ]
    return {
        "$schema": _REGISTRY_SCHEMA_URI,
        "profile": _PROFILE,
        "schema": _REGISTRY_SCHEMA,
        "namespace": _REASON_NAMESPACE,
        "reasons": reasons,
    }


__all__ = [
    "REASON_CONTRACTS",
    "ReasonContract",
    "build_reason_registry",
    "lookup_reason_contract",
]
