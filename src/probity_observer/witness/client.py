"""Client protocol for a witness: submit, retain the latest checkpoint, catch forks.

The client pins the witness key and origin, and keeps the newest checkpoint it
has verified in a state file. Every checkpoint it receives afterwards, from the
witness or from anyone else (``audit``), must be proven consistent with the
retained one through the witness's own consistency proof. A failure raises
:class:`EquivocationError` and writes its evidence record beside the state
file, so the evidence survives the process.

An unreachable or refusing witness raises :class:`WitnessUnavailable`. That is
inconclusive: it is never reported as an equivocation or as a clean result.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from probityai import dsse

from .checkpoint import (
    Checkpoint,
    EquivocationError,
    WitnessError,
    canonical,
    check_key,
    check_name,
    check_pair,
    read_checkpoint,
)
from .scope import CheckedRecord, check_witnessed_record

STATE_FORMAT = "probity-witness-client-state/v1"


class WitnessUnavailable(WitnessError):
    """The witness did not answer, or refused the request; nothing was decided."""

    def __init__(self, message: str, status: int | None = None, body: Any = None) -> None:
        super().__init__(message)
        self.status = status
        self.body = body


def _write_atomic(path: Path, data: bytes) -> None:
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        os.write(descriptor, data)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)


class WitnessClient:
    """Talk to one witness, pinned by URL, origin and public key."""

    def __init__(self, url: str, witness_key: str, origin: str, state: Path, timeout: float = 10.0) -> None:
        self.url = url.rstrip("/")
        self.witness_key = check_key(witness_key, "witness key")
        self.origin = check_name(origin, "origin")
        self.state = state
        self.timeout = timeout

    def _request(self, path: str, body: dict[str, Any] | None = None, **query: int) -> Any:
        target = f"{self.url}{path}"
        if query:
            target += "?" + urllib.parse.urlencode(query)
        data = None if body is None else json.dumps(body).encode("utf-8")
        request = urllib.request.Request(target, data=data, method="GET" if body is None else "POST")
        if data is not None:
            request.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:  # noqa: S310 - pinned witness URL
                return json.loads(response.read())
        except urllib.error.HTTPError as exc:
            try:
                detail = json.loads(exc.read())
            except ValueError:
                detail = None
            raise WitnessUnavailable(f"witness refused {path} with HTTP {exc.code}", exc.code, detail) from exc
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise WitnessUnavailable(f"witness did not answer {path}: {exc}") from exc

    def retained(self) -> Checkpoint | None:
        """Return the retained checkpoint, verified again, or ``None`` if there is none yet."""
        if not self.state.exists():
            return None
        state = json.loads(self.state.read_bytes())
        if not isinstance(state, dict) or set(state) != {"format", "origin", "witnessKey", "checkpoint"}:
            raise WitnessError("client state has invalid fields")
        if (state["format"], state["origin"], state["witnessKey"]) != (STATE_FORMAT, self.origin, self.witness_key):
            raise WitnessError("client state is for a different witness")
        return read_checkpoint(state["checkpoint"].encode("ascii"), self.witness_key, self.origin)

    def _retain(self, checkpoint: Checkpoint) -> None:
        state = {
            "format": STATE_FORMAT,
            "origin": self.origin,
            "witnessKey": self.witness_key,
            "checkpoint": checkpoint.envelope.decode("ascii"),
        }
        _write_atomic(self.state, canonical(state))

    def _record(self, error: EquivocationError) -> Path:
        data = canonical(error.evidence)
        path = self.state.with_name(f"equivocation-{hashlib.sha256(data).hexdigest()[:16]}.json")
        _write_atomic(path, data)
        return path

    def consistency(self, first: int, second: int) -> dict[str, Any]:
        """Fetch the witness's consistency proof between two sizes."""
        return self._request("/v1/proof/consistency", first=first, second=second)

    def advance(self, checkpoint: Checkpoint) -> Checkpoint:
        """Check a newly received checkpoint against the retained one and keep the newer.

        Raises:
            EquivocationError: The two cannot both be checkpoints of one log.
                The evidence record is written beside the state file first.
        """
        earlier = self.retained()
        if earlier is not None:
            low, high = (earlier, checkpoint) if earlier.size <= checkpoint.size else (checkpoint, earlier)
            proof = None
            if low.size != high.size:
                try:
                    proof = self.consistency(low.size, high.size)
                except WitnessUnavailable as missing:
                    # The witness signed both sizes, so "not found" for either is its
                    # own refusal to prove them consistent. Anything else decides nothing.
                    if missing.status != 404:
                        raise
            try:
                check_pair(low, high, proof)
            except EquivocationError as error:
                self._record(error)
                raise
            if checkpoint.size <= earlier.size:
                return earlier
        self._retain(checkpoint)
        return checkpoint

    def latest(self) -> Checkpoint:
        """Fetch, verify and retain the witness's latest checkpoint."""
        reply = self._request("/v1/checkpoint")
        if not isinstance(reply, dict) or not isinstance(reply.get("checkpoint"), str):
            raise WitnessError("witness checkpoint reply has invalid fields")
        return self.advance(read_checkpoint(reply["checkpoint"].encode("ascii"), self.witness_key, self.origin))

    def audit(self, envelope: bytes) -> Checkpoint:
        """Check a checkpoint received from someone else (gossip) against this client's view."""
        return self.advance(read_checkpoint(envelope, self.witness_key, self.origin))

    def submit(self, envelope: bytes, claim_id: str, producer_key: str) -> tuple[dict[str, Any], CheckedRecord]:
        """Submit a producer-signed envelope and verify the witnessed record that comes back.

        The bundle must co-sign exactly the submitted statement, include it in
        the returned checkpoint, and that checkpoint must be consistent with
        the retained one.
        """
        submitted = dsse.verify(envelope, dsse.Ed25519Verifier(bytes.fromhex(check_key(producer_key, "producer key"))))
        bundle = self._request(
            "/v1/add", {"envelope": envelope.decode("utf-8"), "claimId": claim_id, "producerKey": producer_key}
        )
        checked = check_witnessed_record(bundle, producer_key, self.witness_key)
        if (checked.payload_type, checked.payload, checked.claim_id) != (
            submitted.payload_type, submitted.payload, claim_id,
        ):
            raise WitnessError("witness co-signed a different statement than the one submitted")
        if checked.checkpoint.origin != self.origin:
            raise WitnessError("witness answered for a different origin")
        self.advance(checked.checkpoint)
        return bundle, checked
