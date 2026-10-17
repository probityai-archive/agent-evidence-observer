"""Offline verification: 2-of-2 signatures, inclusion, consistency, equivocation and scope."""

from __future__ import annotations

import base64
import json

import pytest
from conftest import WITNESS_SEED, statement
from probityai import dsse

from probity_observer.witness.checkpoint import (
    CHECKPOINT_TYPE,
    EquivocationError,
    WitnessError,
    check_pair,
    read_checkpoint,
    signer,
    verify_equivocation,
)
from probity_observer.witness.scope import EXTERNAL, PEER, KeyPin, verify_witnessed_record


def pins(host, witness_key, host_operator="lab-a", witness_operator="lab-b"):
    return KeyPin(host.public_key.hex(), host_operator), KeyPin(witness_key, witness_operator)


def _with_signatures(bundle, keep):
    envelope = json.loads(bundle["envelope"])
    envelope["signatures"] = keep(envelope["signatures"])
    return {**bundle, "envelope": json.dumps(envelope)}


def test_a_cosigned_record_from_another_operator_is_external(make_log, host, witness_key):
    log = make_log()
    bundle = log.add(statement(host, "done"), "run-1", host.public_key.hex())
    verdict = verify_witnessed_record(bundle, *pins(host, witness_key))
    assert verdict.witness_scope == EXTERNAL
    assert verdict.payload == b'{"claim":"done"}'
    assert verdict.as_packet() == {"witnessScope": "EXTERNAL"}
    assert verdict.as_verify_record() == {"witness_scope": "EXTERNAL"}


def test_one_operator_for_both_keys_is_peer(make_log, host, witness_key):
    log = make_log()
    bundle = log.add(statement(host, "done"), "run-1", host.public_key.hex())
    verdict = verify_witnessed_record(bundle, *pins(host, witness_key, "lab-a", "lab-a"))
    assert verdict.witness_scope == PEER


@pytest.mark.parametrize("keep", [
    lambda sigs: sigs[:1],
    lambda sigs: sigs[1:],
    lambda sigs: [sigs[0], sigs[0]],
    lambda sigs: [sigs[1], sigs[1]],
    lambda sigs: [sigs[0], {**sigs[1], "sig": sigs[0]["sig"]}],
], ids=["host only", "witness only", "host twice", "witness twice", "witness keyid on host sig"])
def test_threshold_refuses_one_of_two(make_log, host, witness_key, keep):
    log = make_log()
    bundle = log.add(statement(host, "done"), "run-1", host.public_key.hex())
    with pytest.raises(WitnessError, match="both the host and the witness"):
        verify_witnessed_record(_with_signatures(bundle, keep), *pins(host, witness_key))


def test_a_signature_from_an_unpinned_key_does_not_count(make_log, host, other, witness_key):
    log = make_log()
    bundle = log.add(statement(host, "done"), "run-1", host.public_key.hex())
    foreign = json.loads(dsse.sign("application/vnd.in-toto+json", b'{"claim":"done"}', other))["signatures"]
    forged = _with_signatures(bundle, lambda sigs: [sigs[0], *foreign])
    with pytest.raises(WitnessError):
        verify_witnessed_record(forged, *pins(host, witness_key))


def test_pins_must_name_two_keys(make_log, host, witness_key):
    log = make_log()
    bundle = log.add(statement(host, "done"), "run-1", host.public_key.hex())
    with pytest.raises(WitnessError, match="name one key"):
        verify_witnessed_record(bundle, KeyPin(witness_key, "a"), KeyPin(witness_key, "b"))
    with pytest.raises(WitnessError):
        KeyPin(witness_key, " ")


def test_bundle_fields_are_checked_against_the_signed_statement(make_log, host, witness_key):
    log = make_log()
    log.add(statement(host, "zero"), "run-0", host.public_key.hex())
    bundle = log.add(statement(host, "done"), "run-1", host.public_key.hex())
    other_bundle = log.add(statement(host, "two"), "run-2", host.public_key.hex())
    for change in (
        {"claimId": "run-9"},
        {"origin": "elsewhere"},
        {"inclusion": {**bundle["inclusion"], "index": 0}},
        {"inclusion": {**bundle["inclusion"], "leafHash": other_bundle["inclusion"]["leafHash"]}},
        {"inclusion": other_bundle["inclusion"]},
        {"checkpoint": other_bundle["checkpoint"]},
        {"envelope": other_bundle["envelope"]},
        {"format": "probity-witnessed-record/v0"},
    ):
        with pytest.raises(WitnessError):
            verify_witnessed_record({**bundle, **change}, *pins(host, witness_key))


def test_a_retained_checkpoint_needs_a_consistency_proof(make_log, host, witness_key):
    log = make_log()
    first = log.add(statement(host, "a"), "run-1", host.public_key.hex())
    for n in range(2, 7):
        later = log.add(statement(host, f"r{n}"), f"run-{n}", host.public_key.hex())
    retained = first["checkpoint"].encode()
    proof = log.consistency(1, 6)
    verdict = verify_witnessed_record(later, *pins(host, witness_key), retained=retained, consistency=proof)
    assert verdict.checkpoint.size == 6
    with pytest.raises(EquivocationError):
        verify_witnessed_record(later, *pins(host, witness_key), retained=retained)
    with pytest.raises(EquivocationError):
        verify_witnessed_record(later, *pins(host, witness_key), retained=retained, consistency=log.consistency(2, 6))
    for change in ({"first": 2}, {"origin": "example.org/other"}):
        with pytest.raises(EquivocationError, match="different checkpoints"):
            verify_witnessed_record(later, *pins(host, witness_key), retained=retained, consistency={**proof, **change})


def test_a_witness_that_forks_its_log_is_caught_by_anyone(make_log, host, witness_key):
    """The same witness key signs two histories: one shown to one consumer, one to another."""
    honest = make_log("honest")
    forked = make_log("forked")
    shown_a = honest.add(statement(host, "pass"), "run-1", host.public_key.hex())
    shown_b = forked.add(statement(host, "fail"), "run-1", host.public_key.hex())
    a = read_checkpoint(shown_a["checkpoint"].encode(), witness_key)
    b = read_checkpoint(shown_b["checkpoint"].encode(), witness_key)
    with pytest.raises(EquivocationError) as caught:
        check_pair(a, b)
    evidence = json.loads(json.dumps(caught.value.evidence))
    assert verify_equivocation(evidence, witness_key) == "example.org/witness"
    with pytest.raises(WitnessError):
        verify_equivocation(evidence, host.public_key.hex())
    with pytest.raises(WitnessError, match="two roots"):
        verify_equivocation({**evidence, "checkpoints": [evidence["checkpoints"][0]] * 2}, witness_key)

    forked.add(statement(host, "more"), "run-2", host.public_key.hex())
    grown = read_checkpoint(forked.checkpoint(), witness_key)
    with pytest.raises(EquivocationError) as diverged:
        check_pair(a, grown, forked.consistency(1, 2))
    assert diverged.value.evidence["kind"] == "unproven-consistency"
    with pytest.raises(WitnessError):
        verify_equivocation(diverged.value.evidence, witness_key)
    check_pair(b, grown, forked.consistency(1, 2))


def test_an_honest_pair_and_a_different_log_are_not_equivocation(make_log, host, witness_key):
    log = make_log()
    log.add(statement(host, "a"), "run-1", host.public_key.hex())
    one = read_checkpoint(log.checkpoint(), witness_key)
    check_pair(one, one)
    other_log = make_log("other", origin="example.org/other")
    other = read_checkpoint(other_log.checkpoint(), witness_key)
    with pytest.raises(WitnessError) as refused:
        check_pair(one, other)
    assert not isinstance(refused.value, EquivocationError)


def test_a_checkpoint_under_another_key_type_or_origin_is_refused(make_log, host, witness_key):
    log = make_log()
    with pytest.raises(WitnessError, match="different log origin"):
        read_checkpoint(log.checkpoint(), witness_key, "example.org/other")
    witness = signer(WITNESS_SEED)
    body = base64.b64decode(json.loads(log.checkpoint())["payload"])
    with pytest.raises(WitnessError, match="payload type"):
        read_checkpoint(dsse.sign("application/json", body, witness), witness_key)
    with pytest.raises(WitnessError):
        read_checkpoint(log.checkpoint(), host.public_key.hex())
    payload = base64.b64decode(json.loads(log.checkpoint())["payload"])
    for payload_type in ("application/json", CHECKPOINT_TYPE):
        with pytest.raises(WitnessError):
            read_checkpoint(dsse.sign(payload_type, payload, host), host.public_key.hex())
