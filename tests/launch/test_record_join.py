"""The S1/S2 join and the done-receipt records built from the sensors."""

import json

import pytest

from probity_observer import record_oe
from probity_observer.sensors import inotify, strace
from probity_observer.sensors import treedigest
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


def built(found, report=None, trace=None, tree=None, timed_out=False, separated=True):
    context = record_oe.Context("claim-1", "call-1", "host-observer", WS, T0, T0 + 6,
                                timed_out=timed_out, tracer_uid_separated=separated)
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


def test_a_created_directory_does_not_cover_what_is_found_inside_it():
    found = effects(event("exec", 0.1, argv=["agent"], exit=0),
                    event("create", 1.0, path="/workspace/a"),
                    event("create", 1.0, path="/workspace/b"))
    report = inotify.Report(changes=[change("create", "a", 1.0),
                                     change("create", "a/b", 1.0, scanned=True)])
    assert [item.path for item in record_oe.join(found, report, WS)] == ["a/b"]


def test_unresolved_descriptor_names_a_gap():
    found = effects(event("exec", 0.1, argv=["agent"], exit=0))
    found.unresolved.append({"syscall": "mkdirat", "pid": 10, "time": T0 + 2})
    records = built(found)
    assert records["observation"]["coverage"] == "incomplete"
    assert records["sensors"]["s2_strace"]["unresolved"][0]["syscall"] == "mkdirat"


def test_a_failed_watch_makes_coverage_unknown():
    found = effects(event("exec", 0.1, argv=["agent"], exit=0))
    report = inotify.Report(watch_failures=[{"path": "a", "errno": "ENOSPC", "time": T0 + 1}])
    assert built(found, report)["observation"]["coverage"] == "unknown"


def causes(observation):
    return [(gap["start"][-9:-1], gap["end"][-9:-1], gap["gap_cause"])
            for gap in observation["gaps"]]


def test_an_overflow_during_an_agent_burst_is_the_agents_gap():
    found = effects(event("exec", 0.1, argv=["agent"], exit=0),
                    event("write", 2.5, path="/workspace/a.txt"))
    report = inotify.Report(changes=[change("write", "a.txt", 2.5)], overflow=True,
                            overflows=[{"from": T0 + 2, "to": T0 + 3.2}])
    observation = built(found, report)["observation"]
    assert observation["coverage"] == "incomplete"
    assert causes(observation) == [("08:00:02", "08:00:04", "agent")]


def test_an_overflow_with_no_agent_mutation_is_not_attributed():
    found = effects(event("exec", 0.1, argv=["agent"], exit=0))
    report = inotify.Report(overflow=True, overflows=[{"from": T0 + 2, "to": T0 + 3.2}])
    assert causes(built(found, report)["observation"]) == [("08:00:02", "08:00:04", "unknown")]


@pytest.mark.parametrize("timed_out,separated,cause", [
    (False, False, "agent"), (True, False, "host"), (False, True, "host"), (True, True, "host")])
def test_a_lost_tracer_is_attributed_from_the_launch_facts(timed_out, separated, cause):
    found = effects(event("exec", 0.1, argv=["agent"]), exited=False)
    observation = built(found, timed_out=timed_out, separated=separated)["observation"]
    assert observation["gaps"][-1]["gap_cause"] == cause


def test_a_signal_the_tracer_died_on_makes_the_lost_tracer_the_agents():
    found = effects(event("exec", 0.1, argv=["agent"]), exited=False)
    found.signals.append({"syscall": "kill", "pid": 10, "time": T0 + 1, "target": 29,
                          "signal": "SIGKILL", "status": "interrupted", "outside_tree": True})
    observation = built(found, separated=True)["observation"]
    assert observation["gaps"][-1]["gap_cause"] == "agent"


def test_gap_causes_for_escapes_unresolved_calls_and_host_changes():
    found = effects(event("exec", 0.1, argv=["agent"], exit=0))
    found.escapes.append({"syscall": "kill", "pid": 10, "time": T0 + 4, "target": 9})
    found.unresolved.append({"syscall": "mkdirat", "pid": 10, "time": T0 + 1})
    report = inotify.Report(changes=[change("write", "host.txt", 2.5)])
    assert causes(built(found, report)["observation"]) == [
        ("08:00:01", "08:00:02", "sensor"), ("08:00:02", "08:00:03", "unknown"),
        ("08:00:04", "08:00:07", "agent")]


def test_unparsed_lines_are_the_agents_where_it_shares_the_tracers_uid():
    found = effects(event("exec", 0.1, argv=["agent"], exit=0))
    trace = strace.Trace(unparsed=["forged"])
    assert built(found, trace=trace, separated=False)["observation"]["gaps"][0][
        "gap_cause"] == "agent"
    assert built(found, trace=trace, separated=True)["observation"]["gaps"][0][
        "gap_cause"] == "sensor"


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


def test_outside_mutations_are_observation_events_with_their_location():
    found = effects(event("exec", 0.1, argv=["agent"], exit=0),
                    event("exec", 0.5, pid=11, argv=["python3", "-m", "pytest"], exit=0),
                    event("write", 0.6, pid=11, path="/tmp/pytest-of-x/cache"),
                    event("write", 1.0, path="/tmp/.local/lib/python3.12/site-packages/x.pth"),
                    event("write", 1.05, path="/usr/lib/python3.12/sitecustomize.py"),
                    event("write", 1.1, path="/dev/null"),
                    event("connect", 1.2, address="{sa_family=AF_INET}"),
                    event("rename", 1.3, path="/tmp/stage", target="/workspace/in.txt"))
    found.parents[11] = 10
    strace.assign_origins(found)
    observation = built(found)["observation"]
    paths = [item.get("path") for item in observation["events"]]
    assert "in.txt" in paths and not any(path and path.startswith("/") for path in paths)
    created = [item for item in observation["events"] if item.get("path") == "in.txt"]
    assert created[0]["type"] == "create"
    [connect] = [item for item in observation["events"] if item["type"] == "connect"]
    assert connect["address"] == "{sa_family=AF_INET}"
    outside = observation["external_mutations"]
    assert [(item["type"], item["paths"], item["location"]) for item in outside] == [
        ("write", ["/tmp/pytest-of-x/cache"], "outside_workspace"),
        ("write", ["/tmp/.local/lib/python3.12/site-packages/x.pth"], "grader_path"),
        ("write", ["/usr/lib/python3.12/sitecustomize.py"], "grader_path"),
        ("rename", ["/tmp/stage"], "outside_workspace")]
    run = next(item for item in observation["events"] if item.get("argv", [""])[0] == "python3")
    assert outside[0]["origin"] == run["id"] and "origin" not in outside[1]
    steps = [item["step"] for item in observation["events"] + outside]
    assert len(set(steps)) == len(steps)
    by_step = sorted(observation["events"] + outside, key=lambda item: item["step"])
    assert [item["time"] for item in by_step] == sorted(item["time"] for item in by_step)
    assert "external_effects" not in built(found)["sensors"]


@pytest.mark.parametrize("path,location", [
    ("/usr/lib/python3/dist-packages/pkg/__init__.py", "grader_path"),
    ("/opt/verifier/run.py", "grader_path"),
    ("/logs/reward.json", "grader_path"),
    ("/logs/reward.txt", "grader_path"),
    ("/home/u/.local/lib/python3.12/site-packages/usercustomize.py", "grader_path"),
    ("/tmp/hooks/evil.pth", "grader_path"),
    ("/tmp/notes.txt", "outside_workspace"),
    ("/tmp/site-packages-notes.txt", "outside_workspace"),
])
def test_grader_path_rule(path, location):
    assert record_oe.location(path) == location


def test_records_carry_the_verify_field_names():
    records = built(effects(event("exec", 0.1, argv=["agent"], exit=0)))
    for role in ("observation", "tree"):
        assert records[role]["witness_scope"] == "PEER"
        assert records[role]["vantage"] == "independent"
    assert "witnessScope" not in json.dumps(records["observation"])
    assert set(records["capability"]["visible_event_types"]) >= {
        "exec", "write", "create", "rename", "link", "unlink", "truncate", "chmod"}


def test_a_link_from_inside_to_outside_is_recorded_on_the_inside_path():
    found = effects(event("exec", 0.1, argv=["agent"], exit=0),
                    event("link", 1.0, path="/workspace/tests/test_app.py", target="/tmp/alias"))
    report = inotify.Report(changes=[change("chmod", "tests/test_app.py", 1.0)])
    records = built(found, report)
    links = [item for item in records["observation"]["events"] if item["type"] == "link"]
    assert links == [{"id": "e2", "step": 2, "time": links[0]["time"], "type": "link",
                      "path": "tests/test_app.py"}]
    assert record_oe.join(found, report, WS) == []
    assert records["observation"]["coverage"] == "complete"


@pytest.mark.parametrize("kind", ["rename", "link"])
@pytest.mark.parametrize("inside", ["path", "target", "both"])
def test_every_mutation_touching_the_workspace_reaches_the_observation(kind, inside):
    paths = {"path": "/tmp/out-a", "target": "/tmp/out-b"}
    if inside in ("path", "both"):
        paths["path"] = "/workspace/in-a"
    if inside in ("target", "both"):
        paths["target"] = "/workspace/in-b"
    found = effects(event("exec", 0.1, argv=["agent"], exit=0), event(kind, 1.0, **paths))
    recorded = [item for item in built(found)["observation"]["events"] if item["type"] != "exec"]
    named = {item.get("path") for item in recorded} | {item.get("target") for item in recorded}
    expected = {strace.within(value, WS) for value in paths.values()} - {None}
    assert expected <= named


def test_join_credits_only_paths_that_reach_the_observation():
    found = effects(event("exec", 0.1, argv=["agent"], exit=0),
                    event("link", 1.0, path="/workspace/a.txt", target="/tmp/alias"),
                    event("rename", 1.1, path="/tmp/stage", target="/workspace/pkg"))
    credited = record_oe.credited_paths(found, WS)
    recorded = built(found)["observation"]["events"]
    named = {item.get("path") for item in recorded} | {item.get("target") for item in recorded}
    assert credited[0] <= named
    assert credited == ({"a.txt", "pkg"}, {"pkg"})


def test_tree_record_binds_links_special_files_and_modes():
    tree = Tree(files={"a.txt": "0" * 64, "run.sh": "1" * 64}, executable=["run.sh"],
                symlinks={"conftest.py": "/tmp/evil"}, special={"pipe": "fifo"})
    record = built(effects(event("exec", 0.1, argv=["agent"], exit=0)), tree=tree)["tree"]
    assert record["schema_version"] == "probity-tree/v2"
    assert set(record) == {"schema_version", "claim_id", "invocation_id", "producer",
                           "vantage", "witness_scope", "tree_sha256", "files", "executable",
                           "symlinks", "special"}
    assert record["tree_sha256"] == treedigest.record_digest(record)
    assert record["symlinks"] == {"conftest.py": "/tmp/evil"}
    without_link = dict(record, symlinks={})
    assert treedigest.record_digest(without_link) != record["tree_sha256"]


def test_exec_events_carry_the_executed_path_cwd_and_loader_environment():
    found = effects(event("exec", 0.1, argv=["pytest", "-q"], exe="/workspace/.bin/pytest",
                          cwd="/workspace", env={"PATH": "./.bin:/usr/bin"}, exit=0))
    observation = built(found)["observation"]
    assert observation["schema_version"] == "probity-observation/v3"
    assert observation["workspace_root"] == WS
    [run] = observation["events"]
    assert run["exe"] == "/workspace/.bin/pytest" and run["cwd"] == "/workspace"
    assert run["env"] == {"PATH": "./.bin:/usr/bin"} and run["argv"] == ["pytest", "-q"]
