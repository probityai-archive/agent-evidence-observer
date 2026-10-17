"""The launch receipt: what it binds, and that no member shadows another."""

import hashlib

from probity_observer import record_oe
from probity_observer.launch import launch_agent
from probity_observer.sensors import inotify, strace
from probity_observer.sensors.treedigest import Tree

T0 = 1_800_000_000.0


def receipt(tmp_path):
    (tmp_path / "transcript.txt").write_bytes(b"out\n")
    (tmp_path / "trace.txt").write_bytes(b"")
    found = strace.Effects(events=[strace.Event("exec", 10, T0, argv=["agent"], exit=0)],
                           root_pid=10, root_exited=True, last_time=T0)
    strace.assign_origins(found)
    tree = Tree(files={"a.txt": "0" * 64})
    context = record_oe.Context("claim-1", "call-1", "host-observer", "/workspace", T0, T0 + 2)
    built = record_oe.build(context, found, strace.Trace(), inotify.Report(), tree)
    spec = launch_agent.LaunchSpec(backend="docker", image="img", agent_argv=("agent",),
                                   workspace=tmp_path, claim_id="claim-1",
                                   invocation_id="call-1")
    written = launch_agent.write_records(built, tmp_path)
    return launch_agent.receipt_record(
        spec, built, written, run_dir=tmp_path, launch_sha256="1" * 64,
        start_sha256="2" * 64, tree=tree, exit_code=0, agent_exit=0, timed_out=False)


def test_receipt_tree_digest_is_the_tree_not_the_tree_record(tmp_path):
    record = receipt(tmp_path)
    tree_bytes = (tmp_path / "tree.json").read_bytes()
    assert record["tree_sha256"] == Tree(files={"a.txt": "0" * 64}).sha256
    assert record["tree_record_sha256"] == hashlib.sha256(tree_bytes).hexdigest()
    assert record["tree_sha256"] != record["tree_record_sha256"]


def test_receipt_pins_every_record_by_its_bytes(tmp_path):
    record = receipt(tmp_path)
    for role in ("observation", "capability", "tree"):
        data = (tmp_path / f"{role}.json").read_bytes()
        assert record[f"{role}_record_sha256"] == hashlib.sha256(data).hexdigest()
    assert "observation_sha256" not in record and "capability_sha256" not in record
    assert record["transcript_sha256"] == hashlib.sha256(b"out\n").hexdigest()
