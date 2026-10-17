"""The S1/S2 join and the done-receipt records built from the sensors."""

import json

from probity_observer import record_oe
from probity_observer.sensors import inotify, strace
from probity_observer.sensors.treedigest import Tree

WS = "/workspace"
T0 = 1_800_000_000.0


def event(kind, t, pid=10, **fields):
    return strace.Event(kind, pid, T0 + t, **fields)


def effects(*events, exited=True):
    found = strace.Effects(events=list(events), root_pid=10, root_exited=exited,
                           last_time=T0 + 5)
    strace.assign_origins(found)
    return found


def change(kind, path, t, scanned=False):
    return inotify.Change(T0 + t, kind, path, 0, scanned=scanned)


def built(found, report=None, trace=None, tree=None):
    context = record_oe.Context("claim-1", "call-1", "host-observer", WS, T0, T0 + 6)
    return record_oe.build(context, found, trace or strace.Trace(), report or inotify.Report(),
                           tree or Tree(files={"a.txt": "0" * 64}))


def test_direct_host_write_is_unattributed_and_opens_a_gap():
    found = effects(event("exec", 0.1, argv=["agent"], exit=0),
                    event("write", 1.0, path="/workspace/agent.txt"))
    report = inotify.Report(changes=[change("write", "agent.txt", 1.0),
                                     change("write", "host.txt", 2.5)])
    unmatched = record_oe.join(found, report, WS)
    assert [item.path for item in unmatched] == ["host.txt"]
    records = built(found, report)
    observation = records["observation"]
    assert observation["coverage"] == "incomplete"
    host = [item for item in observation["events"] if item.get("path") == "host.txt"]
    assert host and "origin" not in host[0] and host[0]["type"] == "write"
    assert records["sensors"]["join"]["unattributed"][0]["path"] == "host.txt"


def test_every_change_matched_gives_complete_coverage():
    found = effects(event("exec", 0.1, argv=["agent"], exit=0),
                    event("write", 1.0, path="/workspace/a.txt"),
                    event("rename", 1.5, path="/workspace/a.txt", target="/workspace/b.txt"))
    report = inotify.Report(changes=[change("write", "a.txt", 1.0),
                                     change("rename", "a.txt", 1.5),
                                     change("rename", "b.txt", 1.5)])
    assert record_oe.join(found, report, WS) == []
    assert built(found, report)["observation"]["coverage"] == "complete"


def test_scanned_entries_match_a_created_or_renamed_parent_only():
    found = effects(event("exec", 0.1, argv=["agent"], exit=0),
                    event("rename", 1.0, path="/workspace/tmp", target="/workspace/pkg"))
    report = inotify.Report(changes=[change("create", "pkg/mod.py", 1.1, scanned=True),
                                     change("create", "other/mod.py", 1.1, scanned=True),
                                     change("write", "pkg/live.py", 1.2)])
    assert [item.path for item in record_oe.join(found, report, WS)] == [
        "other/mod.py", "pkg/live.py"]


def test_inotify_loss_makes_coverage_unknown():
    found = effects(event("exec", 0.1, argv=["agent"], exit=0))
    assert built(found, inotify.Report(overflow=True))["observation"]["coverage"] == "unknown"


def test_lost_tracer_names_a_gap_to_the_end():
    found = effects(event("exec", 0.1, argv=["agent"]), exited=False)
    observation = built(found)["observation"]
    assert observation["coverage"] == "incomplete"
    assert observation["gaps"][-1]["end"] == observation["scope"]["end"]
    assert built(found)["sensors"]["s2_strace"]["tracer"] == "lost"


def test_escape_syscall_names_a_gap():
    found = effects(event("exec", 0.1, argv=["agent"], exit=0))
    found.escapes.append({"syscall": "io_uring_setup", "pid": 10, "time": T0 + 2})
    assert built(found)["observation"]["coverage"] == "incomplete"


def test_unparsed_trace_lines_name_a_gap():
    found = effects(event("exec", 0.1, argv=["agent"], exit=0))
    assert built(found, trace=strace.Trace(unparsed=["strace: oops"]))["observation"][
        "coverage"] == "incomplete"


def test_origins_survive_renumbering_when_host_events_are_inserted():
    found = effects(
        event("exec", 0.1, argv=["agent"], exit=0),
        event("exec", 1.0, pid=11, argv=["python3", "-m", "pytest"], exit=0),
        event("write", 2.0, pid=11, path="/workspace/tests/__pycache__/x.pyc"))
    found.parents[11] = 10
    strace.assign_origins(found)
    report = inotify.Report(changes=[change("write", "host.txt", 0.5),
                                     change("write", "tests/__pycache__/x.pyc", 2.0)])
    events = built(found, report)["observation"]["events"]
    by_type = {(item["type"], item.get("path")): item for item in events}
    run = next(item for item in events if item["type"] == "exec" and item["argv"][0] == "python3")
    assert by_type[("write", "tests/__pycache__/x.pyc")]["origin"] == run["id"]
    assert [item["step"] for item in events] == list(range(1, len(events) + 1))


def test_outside_effects_go_to_the_receipt_not_the_record():
    found = effects(event("exec", 0.1, argv=["agent"], exit=0),
                    event("write", 1.0, path="/tmp/.local/lib/python3.12/site-packages/x.pth"),
                    event("write", 1.1, path="/dev/null"),
                    event("connect", 1.2, address="{sa_family=AF_INET}"),
                    event("rename", 1.3, path="/tmp/stage", target="/workspace/in.txt"))
    records = built(found)
    paths = [item.get("path") for item in records["observation"]["events"]]
    assert "in.txt" in paths and not any(path and path.startswith("/") for path in paths)
    created = [item for item in records["observation"]["events"] if item.get("path") == "in.txt"]
    assert created[0]["type"] == "create"
    external = records["sensors"]["external_effects"]
    assert [item["type"] for item in external] == ["write", "connect", "rename"]
    assert external[0]["paths"] == ["/tmp/.local/lib/python3.12/site-packages/x.pth"]


def test_records_carry_the_verify_field_names():
    records = built(effects(event("exec", 0.1, argv=["agent"], exit=0)))
    for role in ("observation", "tree"):
        assert records[role]["witness_scope"] == "PEER"
        assert records[role]["vantage"] == "independent"
    assert "witnessScope" not in json.dumps(records["observation"])
    assert set(records["capability"]["visible_event_types"]) >= {
        "exec", "write", "create", "rename", "link", "unlink", "truncate", "chmod"}
