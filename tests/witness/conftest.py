"""Shared keys and witness directories for the witness tests."""

from __future__ import annotations

from pathlib import Path

import pytest
from probityai import dsse

from probity_observer.witness.checkpoint import signer
from probity_observer.witness.server import WitnessLog, init_witness

HOST_SEED = bytes(range(32))
WITNESS_SEED = bytes(range(32, 64))
OTHER_SEED = bytes(range(64, 96))
PAYLOAD_TYPE = "application/vnd.in-toto+json"


@pytest.fixture
def host() -> dsse.Ed25519Signer:
    return signer(HOST_SEED)


@pytest.fixture
def other() -> dsse.Ed25519Signer:
    return signer(OTHER_SEED)


@pytest.fixture
def witness_key() -> str:
    return signer(WITNESS_SEED).public_key.hex()


def statement(host: dsse.Ed25519Signer, text: str) -> bytes:
    """A host-signed DSSE envelope over a small JSON payload."""
    return dsse.sign(PAYLOAD_TYPE, b'{"claim":"' + text.encode("ascii") + b'"}', host)


@pytest.fixture
def make_log(tmp_path: Path, host: dsse.Ed25519Signer):
    """Create a witness directory (same witness seed each time) and open it."""
    opened: list[WitnessLog] = []

    def make(name: str = "witness", origin: str = "example.org/witness") -> WitnessLog:
        directory = tmp_path / name
        init_witness(directory, origin, [host.public_key.hex()], seed=WITNESS_SEED)
        log = WitnessLog(directory)
        opened.append(log)
        return log

    yield make
    for log in opened:
        log.close()
