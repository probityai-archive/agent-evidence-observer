"""The client protocol over HTTP, a witness in a separate process, and the CLI."""

from __future__ import annotations

import json
import socket
import subprocess
import sys
import threading
from pathlib import Path

import pytest
from conftest import HOST_SEED, statement

from probity_observer.witness import cli
from probity_observer.witness.checkpoint import EquivocationError, WitnessError, read_checkpoint
from probity_observer.witness.client import WitnessClient, WitnessUnavailable
from probity_observer.witness.scope import EXTERNAL, KeyPin, verify_witnessed_record
from probity_observer.witness.server import make_server

ORIGIN = "example.org/witness"


@pytest.fixture
def serve():
    servers = []

    def start(log):
        server = make_server(log, "127.0.0.1", 0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        servers.append(server)
        return f"http://127.0.0.1:{server.server_port}"

    yield start
    for server in servers:
        server.shutdown()
        server.server_close()


def test_submit_verifies_and_retains_the_checkpoint(make_log, serve, host, witness_key, tmp_path):
    url = serve(make_log())
    client = WitnessClient(url, witness_key, ORIGIN, tmp_path / "state.json")
    assert client.retained() is None
    for n in range(4):
        bundle, checked = client.submit(statement(host, f"c{n}"), f"run-{n}", host.public_key.hex())
        assert checked.index == n
        assert client.retained().size == n + 1
    verdict = verify_witnessed_record(bundle, KeyPin(host.public_key.hex(), "lab-a"), KeyPin(witness_key, "lab-b"))
    assert verdict.witness_scope == EXTERNAL
    assert client.latest().size == 4


def test_http_refusals_map_to_statuses(make_log, serve, host, other, witness_key, tmp_path):
    url = serve(make_log())
    client = WitnessClient(url, witness_key, ORIGIN, tmp_path / "state.json")
    client.submit(statement(host, "first"), "run", host.public_key.hex())
    with pytest.raises(WitnessUnavailable) as conflict:
        client.submit(statement(host, "second"), "run", host.public_key.hex())
    assert (conflict.value.status, conflict.value.body["index"]) == (409, 0)
    with pytest.raises(WitnessUnavailable) as forbidden:
        client.submit(statement(other, "x"), "run-x", other.public_key.hex())
    assert forbidden.value.status == 403
    with pytest.raises(WitnessUnavailable) as missing:
        client.consistency(0, 9)
    assert missing.value.status == 404
    with pytest.raises(WitnessUnavailable) as malformed:
        client._request("/v1/proof/inclusion", index=-1)
    assert malformed.value.status == 400


def test_a_client_catches_a_witness_that_shows_it_a_fork(make_log, serve, host, witness_key, tmp_path):
    honest_url = serve(make_log("honest"))
    fork_url = serve(make_log("forked"))
    state = tmp_path / "state.json"
    WitnessClient(honest_url, witness_key, ORIGIN, state).submit(statement(host, "pass"), "run-1", host.public_key.hex())
    retained = WitnessClient(honest_url, witness_key, ORIGIN, state).retained()
    forked = WitnessClient(fork_url, witness_key, ORIGIN, state)
    with pytest.raises(EquivocationError):
        forked.submit(statement(host, "fail"), "run-1", host.public_key.hex())
    assert forked.retained() == retained
    evidence = list(tmp_path.glob("equivocation-*.json"))
    assert len(evidence) == 1
    assert json.loads(evidence[0].read_bytes())["kind"] == "fork"


def test_gossip_from_another_consumer_is_checked(make_log, serve, host, witness_key, tmp_path):
    honest = make_log("honest")
    forked = make_log("forked")
    url = serve(honest)
    client = WitnessClient(url, witness_key, ORIGIN, tmp_path / "state.json")
    for n in range(3):
        client.submit(statement(host, f"c{n}"), f"run-{n}", host.public_key.hex())
    honest.add(statement(host, "c3"), "run-3", host.public_key.hex())
    client.audit(honest.checkpoint())
    assert client.retained().size == 4
    client.audit(honest.checkpoint(2))
    assert client.retained().size == 4
    for n in range(5):
        forked.add(statement(host, f"f{n}"), f"run-{n}", host.public_key.hex())
    with pytest.raises(EquivocationError):
        client.audit(forked.checkpoint())


def test_an_unreachable_witness_is_inconclusive(witness_key, tmp_path):
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    client = WitnessClient(f"http://127.0.0.1:{port}", witness_key, ORIGIN, tmp_path / "state.json", timeout=2)
    with pytest.raises(WitnessUnavailable):
        client.latest()
    assert not (tmp_path / "state.json").exists()


def test_client_state_for_another_witness_is_refused(make_log, serve, host, other, witness_key, tmp_path):
    url = serve(make_log())
    state = tmp_path / "state.json"
    WitnessClient(url, witness_key, ORIGIN, state).latest()
    with pytest.raises(WitnessError):
        WitnessClient(url, other.public_key.hex(), ORIGIN, state).retained()
    with pytest.raises(WitnessError):
        WitnessClient(url, witness_key, "example.org/other", state).retained()


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "probity_observer.witness.cli", *args], capture_output=True, text=True, check=False
    )


def test_a_witness_in_its_own_process_reaches_external_scope_through_the_cli(tmp_path):
    host_seed = tmp_path / "host.seed"
    host_key = _run("keygen", str(host_seed)).stdout.strip()
    witness_seed = tmp_path / "witness.seed"
    offline_key = _run("keygen", str(witness_seed)).stdout.strip()
    witness_dir = tmp_path / "witness"
    witness_key = _run("init", str(witness_dir), "--origin", ORIGIN, "--producer", host_key,
                       "--seed", str(witness_seed)).stdout.strip()
    assert witness_key == offline_key
    assert _run("init", str(tmp_path / "again"), "--origin", ORIGIN, "--seed", str(host_seed)).returncode == 0
    short = tmp_path / "short.seed"
    short.write_text("00" * 16)
    assert _run("init", str(tmp_path / "short"), "--origin", ORIGIN, "--seed", str(short)).returncode == cli.REFUSED
    server = subprocess.Popen(
        [sys.executable, "-m", "probity_observer.witness.cli", "serve", str(witness_dir), "--port", "0"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
    )
    try:
        port = json.loads(server.stdout.readline())["port"]
        url = f"http://127.0.0.1:{port}"
        payload = tmp_path / "statement.json"
        payload.write_text('{"verdict":"supported"}')
        envelope = tmp_path / "envelope.json"
        signed = _run("sign", str(payload), "--seed", str(host_seed), "--payload-type", "application/vnd.in-toto+json")
        envelope.write_text(signed.stdout)
        state = ["--witness-key", witness_key, "--origin", ORIGIN, "--state", str(tmp_path / "state.json")]
        submitted = _run("submit", url, str(envelope), "--seed", str(host_seed), "--claim-id", "run-1", *state)
        assert submitted.returncode == 0, submitted.stderr
        bundle = tmp_path / "bundle.json"
        bundle.write_text(submitted.stdout)
        common = ["--host-key", host_key, "--witness-key", witness_key, "--host-operator", "lab-a"]
        external = _run("verify", str(bundle), *common, "--witness-operator", "lab-b")
        assert external.returncode == 0, external.stderr
        assert json.loads(external.stdout)["witnessScope"] == "EXTERNAL"
        peer = _run("verify", str(bundle), *common, "--witness-operator", "lab-a")
        assert json.loads(peer.stdout)["witnessScope"] == "PEER"
        one = json.loads(bundle.read_text())
        envelope_doc = json.loads(one["envelope"])
        envelope_doc["signatures"] = envelope_doc["signatures"][:1]
        one["envelope"] = json.dumps(envelope_doc)
        bundle.write_text(json.dumps(one))
        refused = _run("verify", str(bundle), *common, "--witness-operator", "lab-b")
        assert refused.returncode == cli.REFUSED and refused.stdout == ""
        audited = _run("audit", url, *state)
        assert audited.returncode == 0 and json.loads(audited.stdout)["size"] == 1
    finally:
        server.terminate()
        server.wait(timeout=10)
    unavailable = _run("audit", url, *state)
    assert unavailable.returncode == cli.UNAVAILABLE


def test_cli_reports_equivocation_with_exit_three(make_log, host, witness_key, tmp_path):
    honest = make_log("honest")
    forked = make_log("forked")
    honest.add(statement(host, "pass"), "run-1", host.public_key.hex())
    forked.add(statement(host, "fail"), "run-1", host.public_key.hex())
    a = read_checkpoint(honest.checkpoint(), witness_key)
    b = read_checkpoint(forked.checkpoint(), witness_key)
    from probity_observer.witness.checkpoint import check_pair

    with pytest.raises(EquivocationError) as caught:
        check_pair(a, b)
    evidence = tmp_path / "evidence.json"
    evidence.write_text(json.dumps(caught.value.evidence))
    assert cli.main(["check-equivocation", str(evidence), "--witness-key", witness_key]) == 0
    assert cli.main(["check-equivocation", str(evidence), "--witness-key", host.public_key.hex()]) == cli.REFUSED
    seed = tmp_path / "seed"
    seed.write_text(HOST_SEED.hex())
    url = "http://127.0.0.1:9"
    honest_state = tmp_path / "state.json"
    WitnessClient(url, witness_key, ORIGIN, honest_state)._retain(a)
    fork_file = tmp_path / "fork.json"
    fork_file.write_bytes(forked.checkpoint())
    code = cli.main(["audit", url, "--witness-key", witness_key, "--origin", ORIGIN,
                     "--state", str(honest_state), str(fork_file)])
    assert code == cli.EQUIVOCATION
    assert Path(next(tmp_path.glob("equivocation-*.json"))).exists()


def test_a_client_refuses_a_bundle_for_another_statement(make_log, host, witness_key, tmp_path, monkeypatch):
    elsewhere = make_log("elsewhere")
    substituted = elsewhere.add(statement(host, "substituted"), "run-1", host.public_key.hex())
    client = WitnessClient("http://127.0.0.1:9", witness_key, ORIGIN, tmp_path / "state.json")
    monkeypatch.setattr(client, "_request", lambda *args, **kwargs: substituted)
    with pytest.raises(WitnessError, match="different statement"):
        client.submit(statement(host, "submitted"), "run-1", host.public_key.hex())
    assert client.retained() is None
