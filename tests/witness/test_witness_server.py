"""The file-backed witness log: appends, refusals, restart and tamper detection."""

from __future__ import annotations

import base64
import json
import os
import stat

import pytest
from conftest import WITNESS_SEED, statement
from probityai import dsse

from probity_observer.witness import proofs
from probity_observer.witness.checkpoint import (
    WitnessError,
    canonical,
    leaf_record,
    read_checkpoint,
    sign_checkpoint,
    signer,
)
from probity_observer.witness.server import (
    ProducerEquivocation,
    ProducerRefused,
    RootAccumulator,
    TamperedLogError,
    WitnessLog,
    init_witness,
)


def test_init_signs_an_empty_checkpoint_and_keeps_the_seed_private(make_log, witness_key):
    log = make_log()
    assert log.public_key == witness_key
    checkpoint = read_checkpoint(log.checkpoint(), witness_key, "example.org/witness")
    assert (checkpoint.size, checkpoint.root_hash) == (0, proofs.EMPTY_ROOT)
    assert stat.S_IMODE(os.stat(log.directory / "witness.seed").st_mode) == 0o600


def test_init_refuses_an_existing_witness(tmp_path, host):
    init_witness(tmp_path / "w", "o", [host.public_key.hex()], seed=WITNESS_SEED)
    with pytest.raises(WitnessError):
        init_witness(tmp_path / "w", "o", [host.public_key.hex()], seed=WITNESS_SEED)


def test_add_returns_a_bundle_whose_proof_matches_the_checkpoint(make_log, host, witness_key):
    log = make_log()
    bundles = [log.add(statement(host, f"c{n}"), f"claim-{n}", host.public_key.hex()) for n in range(5)]
    for number, bundle in enumerate(bundles):
        checkpoint = read_checkpoint(bundle["checkpoint"].encode(), witness_key)
        assert checkpoint.size == number + 1
        _, index, size, leaf, path = proofs.parse_inclusion(bundle["inclusion"])
        assert (index, size) == (number, number + 1)
        proofs.verify_inclusion(leaf, index, size, path, checkpoint.root_hash)
    assert log.size == 5


def test_resubmitting_the_same_statement_is_idempotent(make_log, host):
    log = make_log()
    envelope = statement(host, "same")
    first = log.add(envelope, "claim", host.public_key.hex())
    again = log.add(envelope, "claim", host.public_key.hex())
    assert log.size == 1
    assert again == first


def test_a_second_statement_under_one_claim_id_is_refused(make_log, host):
    log = make_log()
    log.add(statement(host, "first"), "claim", host.public_key.hex())
    with pytest.raises(ProducerEquivocation) as refused:
        log.add(statement(host, "second"), "claim", host.public_key.hex())
    assert refused.value.index == 0
    assert log.size == 1


def test_unregistered_and_forged_producers_are_refused(make_log, host, other):
    log = make_log()
    with pytest.raises(ProducerRefused):
        log.add(statement(other, "x"), "claim", other.public_key.hex())
    with pytest.raises(ProducerRefused):
        log.add(statement(other, "x"), "claim", host.public_key.hex())
    assert log.size == 0


def test_a_second_process_cannot_open_the_log(make_log):
    log = make_log()
    with pytest.raises(WitnessError):
        WitnessLog(log.directory)


def test_restart_reloads_the_same_log(make_log, host):
    log = make_log()
    for n in range(3):
        log.add(statement(host, f"c{n}"), f"claim-{n}", host.public_key.hex())
    latest = log.checkpoint()
    log.close()
    with WitnessLog(log.directory) as reopened:
        assert reopened.size == 3
        assert reopened.checkpoint() == latest
        assert reopened.checkpoint(1) == log._checkpoints[1]


def _filled(make_log, host, count=3):
    log = make_log()
    for n in range(count):
        log.add(statement(host, f"c{n}"), f"claim-{n}", host.public_key.hex())
    log.close()
    return log.directory


def _rewrite(path, change):
    lines = path.read_bytes().splitlines()
    path.write_bytes(b"".join(line + b"\n" for line in change(lines)))


def _edit_entry(number, edit):
    def change(lines):
        entry = json.loads(lines[number])
        edit(entry)
        lines[number] = json.dumps(entry, sort_keys=True, separators=(",", ":")).encode()
        return lines
    return change


TAMPERING = {
    "changed claim id": _edit_entry(1, lambda e: e["leaf"].update(claimId="claim-x")),
    "changed PAE digest": _edit_entry(1, lambda e: e["leaf"].update(paeSha256="0" * 64)),
    "envelope from another entry": None,
    "swapped entries": lambda lines: [lines[1], lines[0], *lines[2:]],
    "deleted entry": lambda lines: [lines[0], lines[2]],
    "deleted last two entries": lambda lines: lines[:1],
    "non-canonical entry": lambda lines: [lines[0].replace(b",", b", ", 1), *lines[1:]],
}


@pytest.mark.parametrize("name", sorted(TAMPERING))
def test_a_tampered_entry_stops_the_witness(make_log, host, name):
    directory = _filled(make_log, host)
    entries = directory / "entries.jsonl"
    if name == "envelope from another entry":
        def change(lines):
            a, b = json.loads(lines[0]), json.loads(lines[1])
            b["envelope"] = a["envelope"]
            lines[1] = json.dumps(b, sort_keys=True, separators=(",", ":")).encode()
            return lines
        _rewrite(entries, change)
    else:
        _rewrite(entries, TAMPERING[name])
    with pytest.raises(TamperedLogError):
        WitnessLog(directory)


def test_a_rewritten_history_with_rebuilt_entries_does_not_match_old_checkpoints(make_log, host):
    directory = _filled(make_log, host)
    entries = directory / "entries.jsonl"
    replacement = statement(host, "rewritten")
    def change(lines):
        entry = json.loads(lines[1])
        verified = dsse.verify(replacement, dsse.Ed25519Verifier(host.public_key))
        entry["leaf"] = leaf_record("claim-1", host.public_key.hex(), verified.payload_type, verified.payload)
        entry["envelope"] = base64.b64encode(replacement).decode()
        lines[1] = json.dumps(entry, sort_keys=True, separators=(",", ":")).encode()
        return lines
    _rewrite(entries, change)
    with pytest.raises(TamperedLogError, match="checkpoint signed at size 2"):
        WitnessLog(directory)


def test_a_partial_line_and_a_foreign_checkpoint_are_refused(make_log, host):
    directory = _filled(make_log, host)
    entries = directory / "entries.jsonl"
    entries.write_bytes(entries.read_bytes() + b'{"index":3')
    with pytest.raises(TamperedLogError, match="incomplete line"):
        WitnessLog(directory)
    _rewrite(entries, lambda lines: lines[:3])
    checkpoints = directory / "checkpoints.jsonl"
    _rewrite(checkpoints, lambda lines: [*lines[:-1], lines[1]])
    with pytest.raises(TamperedLogError):
        WitnessLog(directory)


def test_a_stop_between_the_two_appends_is_completed_on_open(make_log, host):
    directory = _filled(make_log, host)
    checkpoints = directory / "checkpoints.jsonl"
    _rewrite(checkpoints, lambda lines: lines[:-1])
    with WitnessLog(directory) as log:
        assert len(log._checkpoints) == 4
        assert read_checkpoint(log.checkpoint(), log.public_key).size == 3
    _rewrite(checkpoints, lambda lines: lines[:-2])
    with pytest.raises(TamperedLogError):
        WitnessLog(directory)


def test_a_seed_that_does_not_match_the_configured_key_is_refused(make_log, host):
    directory = _filled(make_log, host, count=1)
    (directory / "witness.seed").write_text(bytes(32).hex() + "\n")
    with pytest.raises(TamperedLogError):
        WitnessLog(directory)


def test_proof_ranges_and_entry_pages(make_log, host):
    log = make_log()
    for n in range(4):
        log.add(statement(host, f"c{n}"), f"claim-{n}", host.public_key.hex())
    assert len(log.entries(1, 3)) == 2
    for bad in ((3, 2), (0, 5)):
        with pytest.raises(IndexError):
            log.entries(*bad)
    with pytest.raises(IndexError):
        log.inclusion(4)
    with pytest.raises(IndexError):
        log.consistency(2, 5)
    with pytest.raises(IndexError):
        log.checkpoint(5)


def test_the_accumulator_matches_the_recursive_root():
    accumulator = RootAccumulator()
    tree = []
    for n in range(70):
        assert accumulator.root() == proofs.root(tree)
        leaf = proofs.leaf_hash(n.to_bytes(2, "big"))
        tree.append(leaf)
        accumulator.append(leaf)


def test_a_repeated_claim_id_is_refused_on_open_even_under_valid_checkpoints(make_log, host):
    """An operator who edits the files holds the seed; the log still refuses two statements for one claim."""
    log = make_log()
    log.add(statement(host, "first"), "claim", host.public_key.hex())
    log.close()
    directory = log.directory
    replacement = statement(host, "second")
    verified = dsse.verify(replacement, dsse.Ed25519Verifier(host.public_key))
    leaf = leaf_record("claim", host.public_key.hex(), verified.payload_type, verified.payload)
    entry = {"index": 1, "leaf": leaf, "envelope": base64.b64encode(replacement).decode()}
    entries = directory / "entries.jsonl"
    entries.write_bytes(entries.read_bytes() + canonical(entry) + b"\n")
    tree = [proofs.leaf_hash(canonical(json.loads(line)["leaf"])) for line in entries.read_bytes().splitlines()]
    witness = signer(WITNESS_SEED)
    checkpoints = directory / "checkpoints.jsonl"
    checkpoints.write_bytes(checkpoints.read_bytes() + sign_checkpoint(witness, "example.org/witness", 2, proofs.root(tree)) + b"\n")
    with pytest.raises(TamperedLogError, match="repeats a claim id"):
        WitnessLog(directory)
