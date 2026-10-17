"""Offline verification of a witnessed record, and the witness scope it earns.

``witnessScope`` (``witness_scope`` in probity-verify's records) is a claim
about who operates the keys, so it is decided here from consumer pins and never
read from the record. A record reaches ``EXTERNAL`` only when all of these hold:

1. the envelope carries valid signatures from two distinct pinned keys, the
   host's and the witness's (2-of-2; one signature is refused, not downgraded);
2. the witness's checkpoint verifies under the pinned witness key;
3. the record's leaf, recomputed from the verified statement, is included in
   that checkpoint;
4. when the consumer retains an earlier checkpoint of the same log, the new
   one is proven consistent with it (otherwise :class:`EquivocationError`);
5. the consumer's pins name different operators for the two keys.

If 1 to 4 hold and the pins name one operator, the scope is ``PEER``: the
co-signature is real but nobody outside the host's operator stands behind it.
The operator names are the consumer's own statement, made outside the bundle;
this module cannot check them, and nothing a producer writes can set them.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from jcs_admit import dsse

from .checkpoint import (
    RECORD_FORMAT,
    Checkpoint,
    WitnessError,
    check_key,
    check_name,
    canonical,
    check_pair,
    leaf_record,
    read_checkpoint,
    verifier,
)
from .proofs import ProofError, leaf_hash, parse_inclusion, verify_inclusion

PEER = "PEER"
EXTERNAL = "EXTERNAL"


@dataclass(frozen=True)
class KeyPin:
    """A public key the consumer trusts, and the operator the consumer says holds it."""

    public_key: str
    operator: str

    def __post_init__(self) -> None:
        check_key(self.public_key, "pinned key")
        if not isinstance(self.operator, str) or not self.operator.strip():
            raise WitnessError("a key pin needs a non-empty operator name")


@dataclass(frozen=True)
class WitnessVerdict:
    """A verified witnessed record."""

    payload_type: str
    payload: bytes
    claim_id: str
    index: int
    checkpoint: Checkpoint
    witness_scope: str

    def as_packet(self) -> dict[str, str]:
        """The scope under the observer packet's field name."""
        return {"witnessScope": self.witness_scope}

    def as_verify_record(self) -> dict[str, str]:
        """The scope under probity-verify's record field name."""
        return {"witness_scope": self.witness_scope}


@dataclass(frozen=True)
class CheckedRecord:
    """A bundle whose signatures, checkpoint and inclusion proof verified."""

    payload_type: str
    payload: bytes
    claim_id: str
    index: int
    checkpoint: Checkpoint


def check_witnessed_record(bundle: Any, host_key: str, witness_key: str) -> CheckedRecord:
    """Check a ``probity-witnessed-record/v1`` bundle's signatures and inclusion.

    This is steps 1 to 3 of the module rules; it says nothing about operators.

    Raises:
        WitnessError: A field, signature, checkpoint or inclusion check fails.
            One valid signature out of two is refused.
    """
    if not isinstance(bundle, dict) or set(bundle) != {
        "format", "origin", "claimId", "producerKey", "envelope", "checkpoint", "inclusion",
    }:
        raise WitnessError("witnessed record has invalid fields")
    if bundle["format"] != RECORD_FORMAT:
        raise WitnessError("witnessed record has an unsupported format")
    if host_key == witness_key:
        raise WitnessError("the host and witness pins name one key")
    if bundle["producerKey"] != host_key:
        raise WitnessError("witnessed record names a different producer key")
    origin = check_name(bundle["origin"], "record origin")
    claim_id = check_name(bundle["claimId"], "record claim id")
    if not isinstance(bundle["envelope"], str) or not isinstance(bundle["checkpoint"], str):
        raise WitnessError("witnessed record envelopes must be JSON text")
    try:
        verified = dsse.verify_threshold(
            bundle["envelope"].encode("utf-8"),
            [verifier(host_key), verifier(witness_key)],
            2,
        )
    except dsse.DsseError as exc:
        raise WitnessError(f"record is not signed by both the host and the witness: {exc.variant}") from exc
    checkpoint = read_checkpoint(bundle["checkpoint"].encode("utf-8"), witness_key, origin)
    leaf = leaf_hash(canonical(leaf_record(claim_id, host_key, verified.payload_type, verified.payload)))
    try:
        proof_origin, index, size, proof_leaf, path = parse_inclusion(bundle["inclusion"])
        if (proof_origin, size, proof_leaf) != (origin, checkpoint.size, leaf):
            raise ProofError("inclusion proof is for a different leaf or checkpoint")
        verify_inclusion(leaf, index, size, path, checkpoint.root_hash)
    except ProofError as exc:
        raise WitnessError(f"record is not included in the witness checkpoint: {exc}") from exc
    return CheckedRecord(verified.payload_type, verified.payload, claim_id, index, checkpoint)


def verify_witnessed_record(
    bundle: Any,
    host: KeyPin,
    witness: KeyPin,
    retained: bytes | None = None,
    consistency: dict[str, Any] | None = None,
) -> WitnessVerdict:
    """Verify a ``probity-witnessed-record/v1`` bundle under consumer pins.

    Args:
        bundle: The bundle the witness returned for the record.
        host: Pin for the producer key that signed the statement.
        witness: Pin for the witness key.
        retained: A checkpoint envelope of the same log that the consumer
            already holds, if any.
        consistency: The witness's consistency proof between ``retained``
            and the bundle's checkpoint; required when their sizes differ.

    Raises:
        WitnessError: Any check fails, including a single signature.
        EquivocationError: The retained and new checkpoints cannot both hold.
    """
    checked = check_witnessed_record(bundle, host.public_key, witness.public_key)
    if retained is not None:
        earlier = read_checkpoint(retained, witness.public_key, checked.checkpoint.origin)
        check_pair(earlier, checked.checkpoint, consistency)
    scope = EXTERNAL if host.operator != witness.operator else PEER
    return WitnessVerdict(
        checked.payload_type, checked.payload, checked.claim_id, checked.index, checked.checkpoint, scope
    )
