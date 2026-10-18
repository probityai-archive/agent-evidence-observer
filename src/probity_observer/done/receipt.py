"""The done verdict and the done receipt, from the records of one run.

The run directory holds the records under fixed names. Each record arrives as a DSSE
envelope and is opened under a pinned key before anything reads it (:func:`open_run`). The
three checks then run in ``probity-verify`` on the pinned bytes (:func:`checks`):
``protected_paths/v1``, ``acceptance_observed/v1`` and ``tool_claim_match/v1``, the last with
the contract pinned so a claimed acceptance command is judged by its sealed run writes. The
done verdict is probity-verify's own combination of the three (:func:`verdict`):

1. The first ``contradicted`` check, in that order, gives ``contradicted`` with its reason.
2. Three ``supported`` checks give ``supported`` (``done_checks_supported``).
3. Otherwise ``not_established`` with the first such check's reason.

Grader-path mutations, coverage gaps the agent caused, held-out failures, replays that called
nothing, unexercised patch hunks and a missing held-out split are decided inside those
checks, from the observation and the grade, so the receipt's verdict is exactly the one
probity-verify's ``done_receipt/v1`` derives again from the same records.

The receipt is the ``probity-done-receipt/v1`` predicate, signed by the harness key and
naming its verifier (``verifier.id``); its in-toto Statement is written unsigned (see
:mod:`.formats`).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from probity_verify.adapters.done_receipt import combine
from probity_verify.core import adjudicate

from .formats import RECEIPT_PREDICATE, VERIFIER_ID, DoneError, encode, open_record, sha256, sign_record, statement

RECEIPT_SCHEMA = "probity-done-receipt/v1"
ROLES = {"contract": "probity-done-contract/v1", "tree": "probity-tree/v2",
         "observation": "probity-observation/v3", "capability": "probity-capabilities/v1",
         "grade": "probity-acceptance-grade/v1", "claims": "probity-tool-claims/v1"}
CHECKS = (
    ("protected_paths/v1", "protected-paths", ("contract", "capability", "observation", "tree")),
    ("acceptance_observed/v1", "acceptance", ("contract", "tree", "grade")),
    ("tool_claim_match/v1", "tool-claims", ("claims", "capability", "observation", "contract")),
)
OBSERVED = {"tree", "observation", "grade"}
SOURCES = "sources"


@dataclass(frozen=True)
class Pins:
    """The consumer's pins: which key signs which record, and who produced it."""

    harness_key: str
    host_key: str
    grader_key: str
    observed_party: str = "agent"
    observer_producer: str = "host-observer"
    allow_no_heldout: bool = False
    grader_producer: str = "harness-verifier"
    scopes: dict[str, str] = field(default_factory=lambda: {"tree": "PEER", "observation": "PEER",
                                                            "grade": "PEER"})

    def key(self, role: str) -> str:
        if role in ("contract", "claims"):
            return self.harness_key
        if role == "grade":
            return self.grader_key
        return self.host_key


def open_run(run: Path, pins: Pins) -> dict[str, bytes]:
    """Verify every record envelope under its pinned key; return the payload bytes by role.

    ``<role>.dsse.json`` must open to exactly the bytes of ``<role>.json``.
    """
    opened = {}
    for role, schema in ROLES.items():
        envelope = (run / f"{role}.dsse.json").read_bytes()
        payload = open_record(envelope, pins.key(role), schema)
        if payload != (run / f"{role}.json").read_bytes():
            raise DoneError(f"{role}.json is not the payload its envelope signs")
        opened[role] = payload
    return opened


def write_sources(run: Path, sources: dict[str, bytes]) -> None:
    """Keep the grader's protected sources as ``sources/<sha256>`` in the run directory."""
    if not sources:
        return
    (run / SOURCES).mkdir(exist_ok=True)
    for digest, data in sources.items():
        if sha256(data) != digest:
            raise DoneError("a protected source does not match its digest")
        (run / SOURCES / digest).write_bytes(data)


def _source_artifacts(run: Path) -> dict[str, dict[str, Any]]:
    """``source:<sha256>`` case artifacts, each bound by its own digest."""
    folder = run / SOURCES
    if not folder.is_dir():
        return {}
    found = {}
    for path in sorted(folder.iterdir()):
        data = path.read_bytes()
        if sha256(data) == path.name:
            found[f"source:{path.name}"] = {"path": f"{SOURCES}/{path.name}",
                                             "sha256": path.name, "length": len(data)}
    return found


def _artifact(name: str, data: bytes) -> dict[str, Any]:
    return {"path": name, "sha256": sha256(data), "length": len(data)}


def _case(claim_id: str, roles: tuple[str, ...], records: dict[str, bytes],
          extra: dict[str, dict[str, Any]] | None = None) -> dict[str, Any]:
    """The case: its id is the records' ``claim_id``, which every adapter checks."""
    artifacts = {role: _artifact(f"{role}.json", records[role]) for role in roles}
    artifacts.update(extra or {})
    return {"schema_version": "probity-case/v1", "case_id": claim_id, "artifacts": artifacts}


def _witnesses(roles: tuple[str, ...], records: dict[str, bytes], pins: Pins) -> dict[str, Any]:
    witnesses = {}
    for role in roles:
        pin: dict[str, Any] = {"artifact": role, "sha256": sha256(records[role]),
                               "authority": f"signed by {pins.key(role)}"}
        if role in OBSERVED:
            producer = pins.grader_producer if role == "grade" else pins.observer_producer
            pin.update(producer=producer, vantage="independent",
                       witness_scope=pins.scopes.get(role, "PEER"))
        witnesses[role] = pin
    return witnesses


def _policy(claim_type: str, claim_id: str, roles: tuple[str, ...], records: dict[str, bytes],
            pins: Pins) -> dict[str, Any]:
    observation = json.loads(records["observation"])
    assessment: dict[str, Any] = {"claim_type": claim_type, "observed_party": pins.observed_party,
                                  "invocation_id": observation["invocation_id"]}
    assessment.update({f"{role}_witness": role for role in roles})
    if claim_type != "acceptance_observed/v1":
        assessment["scope"] = observation["scope"]
    elif pins.allow_no_heldout:
        assessment["allow_no_heldout"] = True
    return {"schema_version": "probity-policy/v1", "witnesses": _witnesses(roles, records, pins),
            "assessments": {claim_id: assessment}}


def checks(run: Path, records: dict[str, bytes], pins: Pins,
           require_witness_scope: str = "PEER") -> list[dict[str, Any]]:
    """Run the three probity-verify checks on the signed record bytes; write their cases."""
    out = run / "verify"
    out.mkdir(exist_ok=True)
    found = []
    claim_id = json.loads(records["observation"])["claim_id"]
    sources = _source_artifacts(run)
    for claim_type, check_name, roles in CHECKS:
        case = _case(claim_id, roles, records,
                     sources if claim_type == "protected_paths/v1" else None)
        policy = _policy(claim_type, claim_id, roles, records, pins)
        (out / f"{check_name}.case.json").write_bytes(encode(case))
        (out / f"{check_name}.policy.json").write_bytes(encode(policy))
        result = adjudicate(case, policy, run, require_witness_scope=require_witness_scope)
        (out / f"{check_name}.decision.json").write_bytes(encode(result))
        entry = {"claim_type": claim_type, "decision": result["decision"],
                 "reason": result["reason"],
                 "vantage": result.get("vantage", "unestablished")}
        if result["decision"] != "not_established":
            entry["witness_scope"] = result.get("witness_scope", "PEER")
        else:
            entry["vantage"] = "unestablished"
        found.append(entry)
    return found


def verdict(found: list[dict[str, Any]]) -> dict[str, Any]:
    """probity-verify's combination of the three checks, with its vantage."""
    derived = combine(found)
    if derived["decision"] == "not_established":
        return {"decision": "not_established", "reason": derived["reason"],
                "vantage": "unestablished"}
    return {"decision": derived["decision"], "reason": derived["reason"],
            "vantage": "independent", "witness_scope": derived.get("witness_scope", "PEER")}


def done_receipt_case(run: Path, records: dict[str, bytes], statement_bytes: bytes, pins: Pins,
                      verifier_ids: list[str] | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    """The case and policy for probity-verify's ``done_receipt/v1`` over one attempt."""
    observation = json.loads(records["observation"])
    claim_id = observation["claim_id"]
    roles = tuple(ROLES)
    every = {**records, "receipt": statement_bytes}
    case = _case(claim_id, roles, records, {"receipt": _artifact("done-receipt.statement.json",
                                                                 statement_bytes),
                                            **_source_artifacts(run)})
    assessment: dict[str, Any] = {"claim_type": "done_receipt/v1",
                                  "observed_party": pins.observed_party,
                                  "invocation_id": observation["invocation_id"],
                                  "scope": observation["scope"], "receipt_witness": "receipt"}
    assessment.update({f"{role}_witness": role for role in roles})
    if pins.allow_no_heldout:
        assessment["allow_no_heldout"] = True
    if verifier_ids is not None:
        assessment["verifier_ids"] = list(verifier_ids)
    witnesses = _witnesses(roles, records, pins)
    witnesses["receipt"] = {"artifact": "receipt", "sha256": sha256(every["receipt"]),
                            "authority": f"signed by {pins.harness_key}"}
    return case, {"schema_version": "probity-policy/v1", "witnesses": witnesses,
                  "assessments": {claim_id: assessment}}


def _optional(run: Path, name: str) -> tuple[bytes | None, dict[str, Any] | None]:
    path = run / name
    if not path.is_file():
        return None, None
    data = path.read_bytes()
    return data, json.loads(data)


def assemble(run: Path, pins: Pins, require_witness_scope: str = "PEER") -> dict[str, Any]:
    """Open the records, run the checks and derive the verdict: the unsigned predicate.

    The caller adds the optional members (``policy``, ``stop_decision``,
    ``verifier_isolation``) and signs it with :func:`sign_receipt`.
    """
    records = open_run(run, pins)
    found = checks(run, records, pins, require_witness_scope)
    launch_bytes, _ = _optional(run, "launch.json")
    launch_receipt_bytes, _ = _optional(run, "receipt.json")
    observation = json.loads(records["observation"])
    digests = {role: {"sha256": sha256(data)} for role, data in records.items()}
    if launch_bytes is not None and launch_receipt_bytes is not None:
        digests["launch"] = {"sha256": sha256(launch_bytes)}
        digests["launch_receipt"] = {"sha256": sha256(launch_receipt_bytes)}
    return {
        "schema_version": RECEIPT_SCHEMA, "verifier": {"id": VERIFIER_ID},
        "claim_id": observation["claim_id"],
        "invocation_id": observation["invocation_id"], "records": digests, "checks": found,
        "verdict": verdict(found),
        "external_effects": observation.get("external_mutations", []),
    }


@dataclass(frozen=True)
class Receipt:
    predicate: dict[str, Any]
    data: bytes
    envelope: bytes


def sign_receipt(run: Path, predicate: dict[str, Any], key) -> Receipt:
    """Sign the receipt and write it with its unsigned in-toto Statement."""
    tree = json.loads((run / "tree.json").read_bytes())
    data, envelope = sign_record(predicate, key)
    (run / "done-receipt.json").write_bytes(data)
    (run / "done-receipt.dsse.json").write_bytes(envelope)
    (run / "done-receipt.statement.json").write_bytes(encode(statement(
        RECEIPT_PREDICATE, "workspace-tree", tree["tree_sha256"], predicate)))
    return Receipt(predicate, data, envelope)


def write_record(run: Path, role: str, record: dict[str, Any], key) -> bytes:
    """Write ``<role>.json`` and ``<role>.dsse.json`` for one record; return its bytes."""
    data, envelope = sign_record(record, key)
    (run / f"{role}.json").write_bytes(data)
    (run / f"{role}.dsse.json").write_bytes(envelope)
    return data


def sign_observer_records(run: Path, host_key) -> None:
    """Re-encode the launcher's observation, capability and tree records and sign them."""
    for role in ("observation", "capability", "tree"):
        write_record(run, role, json.loads((run / f"{role}.json").read_bytes()), host_key)


def verifier_id(predicate: dict[str, Any]) -> str:
    """The receipt's required ``verifier.id``: an absolute https URI naming the verifier that
    signed it. A receipt without one is refused."""
    verifier = predicate.get("verifier")
    found = verifier.get("id") if isinstance(verifier, dict) else None
    if not isinstance(found, str) or not found.startswith("https://") or len(found) <= 8:
        raise DoneError("the receipt carries no verifier.id (a required https URI)")
    return found


def decision_line(found: dict[str, Any]) -> str:
    """``Decision: <decision> / <reason> (vantage: ..., witness_scope: ...)``."""
    parts = [f"vantage: {found['vantage']}"]
    if "witness_scope" in found:
        parts.append(f"witness_scope: {found['witness_scope']}")
    return f"Decision: {found['decision']} / {found['reason']} ({', '.join(parts)})"
