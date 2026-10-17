"""Signed checkpoints, log leaves and equivocation evidence for the witness.

A checkpoint is a DSSE envelope whose payload is the RFC 8785 bytes of::

    {"format": "probity-witness-checkpoint/v1", "origin": <log name>,
     "rootHash": <hex>, "size": <leaf count>, "witnessKey": <hex>}

with payload type ``application/vnd.probity.witness-checkpoint.v1+json``. It
carries no clock: one log has one checkpoint per size, so a second, different
checkpoint for the same origin and size is a fork that the two signatures
prove on their own.

A leaf is the RFC 8785 bytes of::

    {"claimId": <id>, "format": "probity-witness-leaf/v1",
     "paeSha256": <hex>, "payloadType": <type>, "producerKey": <hex>}

``paeSha256`` is the SHA-256 of the DSSE pre-authentication encoding, which the
producer's and the witness's signatures both cover. The leaf therefore binds
the signed statement, not one particular set of signature entries.

Keys are 32-byte Ed25519 public keys written as lowercase hexadecimal, and the
same text is each key's DSSE ``keyid``. A consumer pins every key it trusts;
nothing in a record selects its own key.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from probityai import dsse, jcs

from .proofs import ProofError, decode_hash, parse_consistency, verify_consistency

CHECKPOINT_FORMAT = "probity-witness-checkpoint/v1"
CHECKPOINT_TYPE = "application/vnd.probity.witness-checkpoint.v1+json"
LEAF_FORMAT = "probity-witness-leaf/v1"
EQUIVOCATION_FORMAT = "probity-witness-equivocation/v1"
RECORD_FORMAT = "probity-witnessed-record/v1"
PUBLIC_KEY = re.compile(r"[0-9a-f]{64}\Z")
NAME = re.compile(r"[A-Za-z0-9._:/@+-]{1,256}\Z")


class WitnessError(ValueError):
    """A witness record is malformed or does not verify under the pinned keys."""


class EquivocationError(WitnessError):
    """Two checkpoints signed by one witness key cannot both describe one log.

    ``evidence`` is a ``probity-witness-equivocation/v1`` record that a third
    party can check with :func:`verify_equivocation`.
    """

    def __init__(self, message: str, evidence: dict[str, Any]) -> None:
        super().__init__(message)
        self.evidence = evidence


def canonical(value: Any) -> bytes:
    """Return the RFC 8785 bytes of a JSON value through ``probityai.jcs``."""
    return jcs.admit(json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8"))


def parse_canonical(data: bytes, label: str) -> Any:
    """Parse JSON bytes that must already be in RFC 8785 form."""
    try:
        if jcs.admit(data) != data:
            raise WitnessError(f"{label} is not RFC 8785 canonical")
    except jcs.JcsError as exc:
        raise WitnessError(f"{label} is not admissible JSON: {exc.variant}") from exc
    return json.loads(data)


def check_key(value: Any, label: str) -> str:
    """Require one lowercase-hex Ed25519 public key."""
    if not isinstance(value, str) or PUBLIC_KEY.fullmatch(value) is None:
        raise WitnessError(f"{label} is not a lowercase hex Ed25519 public key")
    return value


def check_name(value: Any, label: str) -> str:
    """Require a bounded ASCII identifier (an origin or a claim id)."""
    if not isinstance(value, str) or NAME.fullmatch(value) is None:
        raise WitnessError(f"{label} is not a bounded ASCII identifier")
    return value


def verifier(public_key: str) -> dsse.Ed25519Verifier:
    """Build a DSSE verifier whose ``keyid`` is the public key's hex text."""
    return dsse.Ed25519Verifier(bytes.fromhex(check_key(public_key, "public key")), key_id=public_key)


def signer(seed: bytes) -> dsse.Ed25519Signer:
    """Build a DSSE signer from a 32-byte seed, with the public key as ``keyid``."""
    probe = dsse.Ed25519Signer(seed)
    return dsse.Ed25519Signer(seed, key_id=probe.public_key.hex())


@dataclass(frozen=True)
class Checkpoint:
    """A verified checkpoint: the payload fields and the envelope that signed them."""

    origin: str
    size: int
    root_hash: bytes
    witness_key: str
    envelope: bytes

    def payload(self) -> dict[str, Any]:
        """Return the signed payload fields."""
        return checkpoint_payload(self.origin, self.size, self.root_hash, self.witness_key)


def checkpoint_payload(origin: str, size: int, root_hash: bytes, witness_key: str) -> dict[str, Any]:
    """Build the checkpoint payload object."""
    return {
        "format": CHECKPOINT_FORMAT,
        "origin": origin,
        "size": size,
        "rootHash": root_hash.hex(),
        "witnessKey": witness_key,
    }


def sign_checkpoint(witness: dsse.Ed25519Signer, origin: str, size: int, root_hash: bytes) -> bytes:
    """Sign a checkpoint and return its DSSE envelope bytes."""
    payload = canonical(checkpoint_payload(origin, size, root_hash, witness.public_key.hex()))
    return dsse.sign(CHECKPOINT_TYPE, payload, witness)


def read_checkpoint(envelope: bytes, witness_key: str, origin: str | None = None) -> Checkpoint:
    """Verify a checkpoint envelope under a pinned witness key.

    Raises
    ------
    WitnessError
        If the signature, payload type, payload bytes, fields, witness key or
        (when given) origin differ.
    """
    try:
        verified = dsse.verify(envelope, verifier(witness_key))
    except dsse.DsseError as exc:
        raise WitnessError(f"checkpoint does not verify under the pinned witness key: {exc.variant}") from exc
    if verified.payload_type != CHECKPOINT_TYPE:
        raise WitnessError("checkpoint has an unsupported payload type")
    body = parse_canonical(verified.payload, "checkpoint payload")
    if not isinstance(body, dict) or set(body) != {"format", "origin", "size", "rootHash", "witnessKey"}:
        raise WitnessError("checkpoint has invalid fields")
    if body["format"] != CHECKPOINT_FORMAT:
        raise WitnessError("checkpoint has an unsupported format")
    if body["witnessKey"] != witness_key:
        raise WitnessError("checkpoint names a different witness key")
    if origin is not None and body["origin"] != origin:
        raise WitnessError("checkpoint is for a different log origin")
    size = body["size"]
    if type(size) is not int or size < 0:
        raise WitnessError("checkpoint size is not a non-negative integer")
    try:
        root_hash = decode_hash(body["rootHash"], "checkpoint root hash")
    except ProofError as exc:
        raise WitnessError(str(exc)) from exc
    return Checkpoint(check_name(body["origin"], "checkpoint origin"), size, root_hash, witness_key, envelope)


def leaf_record(claim_id: str, producer_key: str, payload_type: str, payload: bytes) -> dict[str, Any]:
    """Build the log leaf for one producer-signed statement."""
    return {
        "format": LEAF_FORMAT,
        "claimId": check_name(claim_id, "claim id"),
        "producerKey": check_key(producer_key, "producer key"),
        "payloadType": payload_type,
        "paeSha256": hashlib.sha256(dsse.pae(payload_type, payload)).hexdigest(),
    }


def check_leaf(value: Any) -> dict[str, Any]:
    """Validate a leaf object read from a log or a bundle."""
    if not isinstance(value, dict) or set(value) != {"format", "claimId", "producerKey", "payloadType", "paeSha256"}:
        raise WitnessError("log leaf has invalid fields")
    if value["format"] != LEAF_FORMAT or not isinstance(value["payloadType"], str) or not value["payloadType"]:
        raise WitnessError("log leaf has an unsupported format")
    check_name(value["claimId"], "leaf claim id")
    check_key(value["producerKey"], "leaf producer key")
    try:
        decode_hash(value["paeSha256"], "leaf PAE digest")
    except ProofError as exc:
        raise WitnessError(str(exc)) from exc
    return value


def cosign(envelope: bytes, witness: dsse.Ed25519Signer) -> bytes:
    """Add the witness's signature over the same PAE to a producer's envelope.

    The caller must have verified the producer's signature first. The returned
    envelope keeps every existing signature entry and appends one.
    """
    document = json.loads(envelope)
    body = base64.b64decode(document["payload"], validate=True)
    own = json.loads(dsse.sign(document["payloadType"], body, witness))["signatures"]
    document["signatures"] = [*document["signatures"], *own]
    return json.dumps(document, separators=(",", ":")).encode("ascii")


def _evidence(kind: str, first: Checkpoint, second: Checkpoint, proof: dict[str, Any] | None) -> dict[str, Any]:
    return {
        "format": EQUIVOCATION_FORMAT,
        "kind": kind,
        "origin": first.origin,
        "witnessKey": first.witness_key,
        "checkpoints": [first.envelope.decode("ascii"), second.envelope.decode("ascii")],
        "consistency": proof,
    }


def check_pair(first: Checkpoint, second: Checkpoint, proof: dict[str, Any] | None = None) -> None:
    """Refuse two checkpoints of one log that cannot both be true.

    Same size and a different root is a fork that the two signatures prove.
    For different sizes the caller supplies the witness's consistency proof
    between them; a proof that does not verify (or a missing one) is reported
    as ``unproven-consistency``, which the witness can answer only by
    producing a valid proof.

    Raises
    ------
    EquivocationError
        With a ``probity-witness-equivocation/v1`` evidence record.
    WitnessError
        If the checkpoints are for different logs or witness keys.
    """
    if (first.origin, first.witness_key) != (second.origin, second.witness_key):
        raise WitnessError("checkpoints are for different logs or witness keys")
    low, high = (first, second) if first.size <= second.size else (second, first)
    if low.size == high.size:
        if low.root_hash != high.root_hash:
            raise EquivocationError("witness signed two roots for one size", _evidence("fork", low, high, None))
        return
    try:
        if proof is None:
            raise ProofError("no consistency proof was supplied")
        origin, size_a, size_b, path = parse_consistency(proof)
        if (origin, size_a, size_b) != (low.origin, low.size, high.size):
            raise ProofError("consistency proof is for different checkpoints")
        verify_consistency(low.size, high.size, low.root_hash, high.root_hash, path)
    except ProofError as exc:
        raise EquivocationError(
            f"witness checkpoints are not proven consistent: {exc}",
            _evidence("unproven-consistency", low, high, proof),
        ) from exc


def verify_equivocation(evidence: Any, witness_key: str) -> str:
    """Check a ``fork`` equivocation record with nothing but the pinned witness key.

    Returns the origin whose witness forked. Only the ``fork`` kind proves
    itself: an ``unproven-consistency`` record shows that the witness did not
    supply a valid proof, which a reader confirms by asking the witness for one.

    Raises
    ------
    WitnessError
        If the record does not prove a fork under ``witness_key``.
    """
    if not isinstance(evidence, dict) or set(evidence) != {
        "format", "kind", "origin", "witnessKey", "checkpoints", "consistency",
    }:
        raise WitnessError("equivocation record has invalid fields")
    if evidence["format"] != EQUIVOCATION_FORMAT or evidence["kind"] != "fork":
        raise WitnessError("equivocation record does not claim a fork")
    pair = evidence["checkpoints"]
    if not isinstance(pair, list) or len(pair) != 2 or not all(isinstance(item, str) for item in pair):
        raise WitnessError("equivocation record needs two checkpoint envelopes")
    first, second = (read_checkpoint(item.encode("ascii"), witness_key, evidence["origin"]) for item in pair)
    if first.size != second.size or first.root_hash == second.root_hash:
        raise WitnessError("equivocation record does not hold two roots for one size")
    return first.origin
