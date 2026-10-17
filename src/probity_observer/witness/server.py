"""A single-operator witness: Ed25519 key, file-backed append-only log, HTTP API.

The operator runs one :class:`WitnessLog` per directory. A registered producer
submits a DSSE envelope it signed together with a claim id. The witness checks
the producer's signature, appends one leaf to its Merkle log, signs a new
checkpoint, adds its own signature to the envelope, and returns the
``probity-witnessed-record/v1`` bundle: the co-signed envelope, the checkpoint
and the inclusion proof. Anyone can then ask the witness for consistency
proofs between its checkpoints and for the raw entries.

The directory holds::

    witness.json       origin, witness public key and registered producer keys
    witness.seed       the 32-byte Ed25519 seed as hex, mode 0600
    entries.jsonl      one RFC 8785 line per leaf, with the producer's envelope
    checkpoints.jsonl  one signed checkpoint per size, starting at size 0
    witness.lock       held for as long as a process has the log open

On open, every entry and every checkpoint is re-verified and every checkpoint
root is recomputed from the entries, so an edited, deleted or reordered entry
stops the witness from serving rather than being signed over. A log with one
entry beyond its last checkpoint (a stop between the two appends) gets the
missing checkpoint signed; nothing else is repaired.

What this does not establish: who operates the host, that the clock is honest
(checkpoints carry none), or that the operator publishes the same checkpoint to
everyone. Consumers detect a fork by comparing checkpoints with each other and
with :func:`probity_observer.witness.checkpoint.check_pair`.
"""

from __future__ import annotations

import base64
import fcntl
import json
import logging
import os
import secrets
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from jcs_admit import dsse

from . import proofs
from .checkpoint import (
    RECORD_FORMAT,
    WitnessError,
    canonical,
    check_key,
    check_leaf,
    check_name,
    cosign,
    leaf_record,
    read_checkpoint,
    sign_checkpoint,
    signer,
    verifier,
)

CONFIG_FORMAT = "probity-witness-config/v1"
MAX_BODY = 1 << 20
MAX_ENTRIES_PAGE = 1000
LOGGER = logging.getLogger(__name__)


class TamperedLogError(WitnessError):
    """The log on disk disagrees with itself or with the checkpoints signed over it."""


class ProducerRefused(WitnessError):
    """The submitting producer key is not registered, or its signature fails."""


class ProducerEquivocation(WitnessError):
    """A producer submitted a second, different statement under one claim id."""

    def __init__(self, message: str, index: int) -> None:
        super().__init__(message)
        self.index = index


class RootAccumulator:
    """Running Merkle root over appended leaf hashes (perfect-subtree stack)."""

    def __init__(self) -> None:
        self._stack: list[tuple[int, bytes]] = []

    def append(self, leaf: bytes) -> None:
        """Add one leaf hash and merge equal-height subtrees."""
        height, node = 0, leaf
        while self._stack and self._stack[-1][0] == height:
            _, left = self._stack.pop()
            node = proofs.node_hash(left, node)
            height += 1
        self._stack.append((height, node))

    def root(self) -> bytes:
        """Return the root of every leaf appended so far."""
        if not self._stack:
            return proofs.EMPTY_ROOT
        node = self._stack[-1][1]
        for _, left in reversed(self._stack[:-1]):
            node = proofs.node_hash(left, node)
        return node


def _append_line(path: Path, line: bytes) -> None:
    """Append one line durably: write, fsync the file, fsync its directory."""
    created = not path.exists()
    descriptor = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.write(descriptor, line + b"\n")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    if created:
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)


def _lines(path: Path) -> list[bytes]:
    raw = path.read_bytes() if path.exists() else b""
    if raw and not raw.endswith(b"\n"):
        raise TamperedLogError(f"{path.name} ends with an incomplete line")
    return raw.splitlines()


def init_witness(directory: Path, origin: str, producers: list[str], seed: bytes | None = None) -> str:
    """Create a witness directory with a fresh key and a signed size-0 checkpoint.

    Returns the witness public key as hex. Refuses a directory that already
    holds a witness.
    """
    check_name(origin, "origin")
    for key in producers:
        check_key(key, "producer key")
    directory.mkdir(parents=True, exist_ok=True)
    if (directory / "witness.json").exists() or (directory / "witness.seed").exists():
        raise WitnessError("directory already holds a witness")
    seed = secrets.token_bytes(32) if seed is None else seed
    if len(seed) != 32:
        raise WitnessError("a witness seed is 32 bytes")
    key = signer(seed)
    public = key.public_key.hex()
    descriptor = os.open(directory / "witness.seed", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, seed.hex().encode("ascii") + b"\n")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    config = {"format": CONFIG_FORMAT, "origin": origin, "witnessKey": public, "producers": sorted(set(producers))}
    _append_line(directory / "witness.json", canonical(config))
    _append_line(directory / "checkpoints.jsonl", sign_checkpoint(key, origin, 0, proofs.EMPTY_ROOT))
    return public


@dataclass(frozen=True)
class _Entry:
    leaf: dict[str, Any]
    leaf_hash: bytes
    envelope: bytes


class WitnessLog:
    """The witness's append-only log, opened for exclusive use by one process."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self._lock = threading.Lock()
        self._lock_file = open(directory / "witness.lock", "a+b")  # noqa: SIM115 - held for the log's lifetime
        try:
            fcntl.flock(self._lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            self._lock_file.close()
            raise WitnessError("another process has this witness log open") from exc
        try:
            self._load()
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        """Release the directory lock."""
        self._lock_file.close()

    def __enter__(self) -> "WitnessLog":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    @property
    def public_key(self) -> str:
        """The witness public key as hex."""
        return self._public

    @property
    def size(self) -> int:
        """The number of leaves in the log."""
        return len(self._entries)

    def _load(self) -> None:
        lines = _lines(self.directory / "witness.json")
        if len(lines) != 1:
            raise TamperedLogError("witness.json must hold one line")
        config = json.loads(lines[0])
        if not isinstance(config, dict) or set(config) != {"format", "origin", "witnessKey", "producers"}:
            raise TamperedLogError("witness.json has invalid fields")
        if config["format"] != CONFIG_FORMAT or not isinstance(config["producers"], list):
            raise TamperedLogError("witness.json has an unsupported format")
        self.origin = check_name(config["origin"], "origin")
        self.producers = frozenset(check_key(key, "producer key") for key in config["producers"])
        seed = bytes.fromhex((self.directory / "witness.seed").read_text().strip())
        self._signer = signer(seed)
        self._public = self._signer.public_key.hex()
        if self._public != config["witnessKey"]:
            raise TamperedLogError("witness.seed does not match the configured witness key")
        self._entries: list[_Entry] = []
        self._claims: dict[tuple[str, str], int] = {}
        self._checkpoints: list[bytes] = []
        accumulator = RootAccumulator()
        roots = [accumulator.root()]
        for number, line in enumerate(_lines(self.directory / "entries.jsonl")):
            entry = self._read_entry(number, line)
            self._claims[(entry.leaf["producerKey"], entry.leaf["claimId"])] = number
            self._entries.append(entry)
            accumulator.append(entry.leaf_hash)
            roots.append(accumulator.root())
        signed = _lines(self.directory / "checkpoints.jsonl")
        if not len(roots) - 1 <= len(signed) <= len(roots):
            raise TamperedLogError("checkpoints do not match the number of entries")
        for size, envelope in enumerate(signed):
            checkpoint = read_checkpoint(envelope, self._public, self.origin)
            if checkpoint.size != size or checkpoint.root_hash != roots[size]:
                raise TamperedLogError(f"log entries no longer produce the checkpoint signed at size {size}")
            self._checkpoints.append(envelope)
        if len(signed) == len(roots) - 1:
            LOGGER.warning("signing the checkpoint missing after entry %d", len(self._entries) - 1)
            self._sign_next()

    def _read_entry(self, number: int, line: bytes) -> _Entry:
        try:
            entry = json.loads(line)
            if canonical(entry) != line:
                raise TamperedLogError(f"entry {number} is not RFC 8785 canonical")
            if not isinstance(entry, dict) or set(entry) != {"index", "leaf", "envelope"} or entry["index"] != number:
                raise TamperedLogError(f"entry {number} has invalid fields or index")
            leaf = check_leaf(entry["leaf"])
            envelope = base64.b64decode(entry["envelope"], validate=True)
            verified = dsse.verify(envelope, verifier(leaf["producerKey"]))
        except (ValueError, dsse.DsseError) as exc:
            raise TamperedLogError(f"entry {number} does not verify: {exc}") from exc
        if leaf_record(leaf["claimId"], leaf["producerKey"], verified.payload_type, verified.payload) != leaf:
            raise TamperedLogError(f"entry {number} leaf differs from its envelope")
        if (leaf["producerKey"], leaf["claimId"]) in self._claims:
            raise TamperedLogError(f"entry {number} repeats a claim id")
        return _Entry(leaf, proofs.leaf_hash(canonical(leaf)), envelope)

    def _leaves(self, size: int | None = None) -> list[bytes]:
        entries = self._entries if size is None else self._entries[:size]
        return [entry.leaf_hash for entry in entries]

    def _sign_next(self) -> None:
        size = len(self._entries)
        envelope = sign_checkpoint(self._signer, self.origin, size, proofs.root(self._leaves()))
        _append_line(self.directory / "checkpoints.jsonl", envelope)
        self._checkpoints.append(envelope)

    def checkpoint(self, size: int | None = None) -> bytes:
        """Return the signed checkpoint for ``size`` (default: the latest)."""
        with self._lock:
            if size is None:
                return self._checkpoints[-1]
            if not 0 <= size < len(self._checkpoints):
                raise IndexError("no checkpoint for that size")
            return self._checkpoints[size]

    def inclusion(self, index: int, size: int | None = None) -> dict[str, Any]:
        """Return an inclusion proof for leaf ``index`` in the tree of ``size`` leaves."""
        with self._lock:
            size = len(self._entries) if size is None else size
            if not 0 <= index < size <= len(self._entries):
                raise IndexError("index or size is outside the log")
            leaves = self._leaves(size)
            return proofs.inclusion_record(
                self.origin, index, size, leaves[index], proofs.inclusion_path(index, leaves)
            )

    def consistency(self, first: int, second: int) -> dict[str, Any]:
        """Return a consistency proof between the trees of ``first`` and ``second`` leaves."""
        with self._lock:
            if not 0 <= first <= second <= len(self._entries):
                raise IndexError("sizes are outside the log")
            return proofs.consistency_record(
                self.origin, first, second, proofs.consistency_path(first, self._leaves(second))
            )

    def entries(self, start: int, end: int) -> list[dict[str, Any]]:
        """Return raw entries ``start`` to ``end`` (exclusive), at most one page."""
        with self._lock:
            if not 0 <= start <= end <= len(self._entries) or end - start > MAX_ENTRIES_PAGE:
                raise IndexError("entry range is outside the log or too long")
            return [
                {"index": number, "leaf": entry.leaf, "envelope": base64.b64encode(entry.envelope).decode("ascii")}
                for number, entry in enumerate(self._entries[start:end], start)
            ]

    def add(self, envelope: bytes, claim_id: str, producer_key: str) -> dict[str, Any]:
        """Log one producer-signed statement and return its witnessed-record bundle.

        Raises
        ------
        ProducerRefused
            If the producer key is not registered or does not sign the envelope.
        ProducerEquivocation
            If the producer already logged a different statement under the claim id.
        """
        check_key(producer_key, "producer key")
        check_name(claim_id, "claim id")
        if producer_key not in self.producers:
            raise ProducerRefused("producer key is not registered with this witness")
        try:
            verified = dsse.verify(envelope, verifier(producer_key))
        except dsse.DsseError as exc:
            raise ProducerRefused(f"envelope does not verify under the producer key: {exc.variant}") from exc
        leaf = leaf_record(claim_id, producer_key, verified.payload_type, verified.payload)
        with self._lock:
            index = self._claims.get((producer_key, claim_id))
            if index is not None and self._entries[index].leaf != leaf:
                raise ProducerEquivocation("producer logged a different statement under this claim id", index)
            if index is None:
                index = len(self._entries)
                record = {"index": index, "leaf": leaf, "envelope": base64.b64encode(envelope).decode("ascii")}
                _append_line(self.directory / "entries.jsonl", canonical(record))
                self._entries.append(_Entry(leaf, proofs.leaf_hash(canonical(leaf)), envelope))
                self._claims[(producer_key, claim_id)] = index
                self._sign_next()
            size = len(self._entries)
            leaves = self._leaves()
            inclusion = proofs.inclusion_record(
                self.origin, index, size, leaves[index], proofs.inclusion_path(index, leaves)
            )
            checkpoint = self._checkpoints[-1]
        return {
            "format": RECORD_FORMAT,
            "origin": self.origin,
            "claimId": claim_id,
            "producerKey": producer_key,
            "envelope": cosign(envelope, self._signer).decode("ascii"),
            "checkpoint": checkpoint.decode("ascii"),
            "inclusion": inclusion,
        }


class _Handler(BaseHTTPRequestHandler):
    """JSON over HTTP for one :class:`WitnessLog`."""

    log: WitnessLog
    server_version = "probity-witness/1"

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - BaseHTTPRequestHandler signature
        LOGGER.info("%s %s", self.address_string(), format % args)

    def _send(self, status: int, value: Any) -> None:
        body = canonical(value)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _int(self, query: dict[str, list[str]], name: str) -> int:
        values = query.get(name, [])
        if len(values) != 1 or not values[0].isdigit():
            raise ValueError(f"query parameter {name} must be one non-negative integer")
        return int(values[0])

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler method name
        url = urlsplit(self.path)
        query = parse_qs(url.query, keep_blank_values=True)
        try:
            if url.path == "/v1/key":
                self._send(200, {"origin": self.log.origin, "witnessKey": self.log.public_key, "size": self.log.size})
            elif url.path == "/v1/checkpoint":
                size = self._int(query, "size") if "size" in query else None
                self._send(200, {"checkpoint": self.log.checkpoint(size).decode("ascii")})
            elif url.path == "/v1/proof/inclusion":
                size = self._int(query, "size") if "size" in query else None
                self._send(200, self.log.inclusion(self._int(query, "index"), size))
            elif url.path == "/v1/proof/consistency":
                self._send(200, self.log.consistency(self._int(query, "first"), self._int(query, "second")))
            elif url.path == "/v1/entries":
                self._send(200, {"entries": self.log.entries(self._int(query, "start"), self._int(query, "end"))})
            else:
                self._send(404, {"error": "unknown path"})
        except IndexError as exc:
            self._send(404, {"error": str(exc)})
        except ValueError as exc:
            self._send(400, {"error": str(exc)})

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler method name
        if urlsplit(self.path).path != "/v1/add":
            self._send(404, {"error": "unknown path"})
            return
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self._send(411, {"error": "Content-Length is required"})
            return
        if not 0 < length <= MAX_BODY:
            self._send(413, {"error": "request body is empty or too large"})
            return
        try:
            request = json.loads(self.rfile.read(length))
            if not isinstance(request, dict) or set(request) != {"envelope", "claimId", "producerKey"}:
                raise ValueError("request needs exactly envelope, claimId and producerKey")
            if not isinstance(request["envelope"], str):
                raise ValueError("envelope must be the envelope's JSON text")
            bundle = self.log.add(request["envelope"].encode("utf-8"), request["claimId"], request["producerKey"])
        except ProducerEquivocation as exc:
            self._send(409, {"error": str(exc), "index": exc.index})
        except ProducerRefused as exc:
            self._send(403, {"error": str(exc)})
        except ValueError as exc:
            self._send(400, {"error": str(exc)})
        else:
            self._send(200, bundle)


def make_server(log: WitnessLog, host: str, port: int) -> ThreadingHTTPServer:
    """Bind an HTTP server for ``log``; the caller runs ``serve_forever``."""
    handler = type("WitnessHandler", (_Handler,), {"log": log})
    return ThreadingHTTPServer((host, port), handler)

