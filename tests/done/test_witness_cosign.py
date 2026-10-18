"""An attempt's records co-signed by a separately keyed witness reach EXTERNAL scope."""

import json
import threading

import pytest

from probity_observer.done import cli, witnessing
from probity_observer.done.formats import public_key
from probity_observer.witness.checkpoint import canonical, signer
from probity_observer.witness.client import WitnessClient
from probity_observer.witness.server import WitnessLog, init_witness, make_server

from .test_cli import pubs, seeds, signed_run  # noqa: F401 (seeds is a fixture)

WITNESS_SEED = bytes(range(100, 132))
GATE_WITNESS_SEED = bytes(range(140, 172))
ORIGIN = "witness.example/done"


@pytest.fixture
def keys(harness, host, grader):
    return harness, host, grader


def serve(directory, seed, producers):
    init_witness(directory, ORIGIN, producers, seed=seed)
    log = WitnessLog(directory)
    server = make_server(log, "127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return log, server, f"http://127.0.0.1:{server.server_port}"


@pytest.fixture
def witness(tmp_path, keys):
    producers = [public_key(keys[1]), public_key(keys[2])]
    log, server, url = serve(tmp_path / "witness", WITNESS_SEED, producers)
    yield url, signer(WITNESS_SEED).public_key.hex()
    server.shutdown()
    server.server_close()
    log.close()


def cosign(run, keys, url, witness_key, state):
    client = WitnessClient(url, witness_key, ORIGIN, state)
    witnessing.submitter(client, public_key(keys[1]), public_key(keys[2]))(run)


def external(run, witness_key, *extra):
    return ["verify", "--run", str(run), *pubs(), "--require-witness-scope", "EXTERNAL",
            "--witness-key", witness_key, "--host-operator", "gate-box",
            "--grader-operator", "gate-box", "--witness-operator", "witness-box", *extra]


def test_a_cosigned_honest_receipt_verifies_as_external(tmp_path, keys, witness, capsys):
    url, witness_key = witness
    run = signed_run(tmp_path, keys)
    cosign(run, keys, url, witness_key, tmp_path / "state.json")
    for role in witnessing.ROLES:
        bundle = json.loads((run / f"{role}.witnessed.json").read_bytes())
        assert bundle["claimId"] == f"{tmp_path.name}/honest/{role}"
    assert cli.main(external(run, witness_key)) == 0
    assert capsys.readouterr().out.startswith(
        "Decision: supported / done_checks_supported (vantage: independent, witness_scope: EXTERNAL)")


def test_one_operator_for_both_keys_is_peer_and_does_not_meet_external(tmp_path, keys, witness, capsys):
    url, witness_key = witness
    run = signed_run(tmp_path, keys)
    cosign(run, keys, url, witness_key, tmp_path / "state.json")
    same = external(run, witness_key)
    same[same.index("--witness-operator") + 1] = "gate-box"
    assert cli.main(same) == 2
    assert "witness_scope_below_required" in capsys.readouterr().out


def test_a_receipt_with_no_witness_bundle_is_held_below_external(tmp_path, keys, witness, capsys):
    run = signed_run(tmp_path, keys)
    assert cli.main(external(run, witness[1])) == 2
    assert "witness_scope_below_required" in capsys.readouterr().out


def test_a_bundle_without_the_witness_signature_is_refused(tmp_path, keys, witness, capsys):
    url, witness_key = witness
    run = signed_run(tmp_path, keys)
    cosign(run, keys, url, witness_key, tmp_path / "state.json")
    path = run / "grade.witnessed.json"
    bundle = json.loads(path.read_bytes())
    envelope = json.loads(bundle["envelope"])
    envelope["signatures"] = [item for item in envelope["signatures"] if item["keyid"] != witness_key]
    assert len(envelope["signatures"]) == 1
    bundle["envelope"] = json.dumps(envelope)
    path.write_bytes(canonical(bundle))
    assert cli.main(external(run, witness_key)) == cli.REFUSED
    assert "not signed by both" in capsys.readouterr().err


def test_a_witness_the_gate_runs_itself_is_refused_under_the_pinned_witness_key(
        tmp_path, keys, witness, capsys):
    """The gate host holds every key but the witness's; a log it runs with its own key fails."""
    run = signed_run(tmp_path, keys)
    producers = [public_key(keys[1]), public_key(keys[2])]
    log, server, url = serve(tmp_path / "gate-witness", GATE_WITNESS_SEED, producers)
    try:
        cosign(run, keys, url, signer(GATE_WITNESS_SEED).public_key.hex(), tmp_path / "gate.json")
    finally:
        server.shutdown()
        server.server_close()
        log.close()
    assert cli.main(external(run, witness[1])) == cli.REFUSED
    assert "refused" in capsys.readouterr().err.lower()


def test_a_contradicted_verdict_stands_without_any_witness(tmp_path, keys, witness, capsys):
    """Only ``supported`` needs EXTERNAL; a PEER ``contradicted`` stands (ruling P-15 item 3)."""
    run = signed_run(tmp_path, keys, "planted")
    assert cli.main(external(run, witness[1])) == 1
    assert capsys.readouterr().out.startswith("Decision: contradicted")


def test_a_witness_that_does_not_answer_leaves_no_bundle_and_says_why(tmp_path, keys, capsys):
    run = signed_run(tmp_path, keys)
    cosign(run, keys, "http://127.0.0.1:9", signer(WITNESS_SEED).public_key.hex(),
           tmp_path / "state.json")
    assert not list(run.glob("*.witnessed.json"))
    assert (run / "witness-unavailable.txt").read_text().startswith("tree: witness did not answer")
    assert "witness did not answer" in capsys.readouterr().err


def test_run_refuses_a_witness_url_without_its_key_and_origin(tmp_path, seeds):
    argv = ["run", "--contract", str(tmp_path / "c"), "--out", str(tmp_path / "o"), "--image", "x",
            "--task-id", "t", "--harness-key", seeds["harness"], "--host-key", seeds["host"],
            "--grader-key", seeds["grader"], "--witness-url", "http://127.0.0.1:9", "--", "true"]
    assert cli.main(argv) == cli.REFUSED
