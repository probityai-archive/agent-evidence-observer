"""S4 exec identity: hash the running executable chain, fail closed, and gate each exec."""

from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from probity_observer.launch import identity_gate
from probity_observer.sensors import binary_identity, strace
from probity_observer.sensors.binary_identity import IdentityError

SELF_SHA = hashlib.sha256(Path(os.path.realpath(sys.executable)).read_bytes()).hexdigest()
SOURCE = Path(binary_identity.__file__).read_text()


@pytest.fixture
def child():
    """A sleeping child of this test process, killed afterwards."""
    process = subprocess.Popen(["sleep", "30"])
    yield process
    process.kill()
    process.wait()


def sha_of(path: str) -> str:
    return hashlib.sha256(Path(os.path.realpath(path)).read_bytes()).hexdigest()


def test_resolve_hashes_the_process_and_its_ancestors_up_to_the_root(child) -> None:
    chain = binary_identity.resolve(child.pid, root=os.getpid())
    assert [item["pid"] for item in chain] == [child.pid, os.getpid()]
    assert chain[0]["path"] == os.path.realpath(shutil.which("sleep"))
    assert chain[0]["sha256"] == sha_of(chain[0]["path"])
    assert chain[1]["sha256"] == SELF_SHA
    assert binary_identity.resolve(os.getpid(), root=os.getpid()) == [
        {**binary_identity.link(os.getpid()), "pid": os.getpid()}]


def test_without_a_root_the_walk_stops_below_init(monkeypatch) -> None:
    parents = {30: 20, 20: 10, 10: 1}
    monkeypatch.setattr(binary_identity, "link", lambda pid, proc="/proc": {
        "pid": pid, "parent": parents.get(pid, 0), "path": f"/bin/{pid}", "sha256": "0" * 64})
    assert [item["pid"] for item in binary_identity.resolve(30)] == [30, 20, 10]
    assert [item["pid"] for item in binary_identity.resolve(30, root=1)] == [30, 20, 10, 1]
    assert [item["pid"] for item in binary_identity.resolve(30, root=20)] == [30, 20]


def test_a_gone_or_unreadable_process_fails_closed() -> None:
    gone = subprocess.Popen(["true"])
    gone.wait()
    with pytest.raises(IdentityError, match="open /proc"):
        binary_identity.resolve(gone.pid)
    assert binary_identity.state(gone.pid) is None


def test_a_change_during_hashing_is_refused(child, monkeypatch) -> None:
    real = binary_identity._snapshot
    calls = []

    def drifting(pid, proc, handle):
        snap = real(pid, proc, handle)
        calls.append(pid)
        return {**snap, "start": snap["start"] + len(calls)}

    monkeypatch.setattr(binary_identity, "_snapshot", drifting)
    with pytest.raises(IdentityError, match="changed while its executable identity"):
        binary_identity.link(child.pid)


def test_a_replaced_file_behind_the_open_link_is_refused(child, monkeypatch) -> None:
    real = binary_identity._snapshot

    def swapped(pid, proc, handle):
        return {**real(pid, proc, handle), "live": (0, 0, 0, 0, 0)}

    monkeypatch.setattr(binary_identity, "_snapshot", swapped)
    with pytest.raises(IdentityError, match="changed while its executable was opened"):
        binary_identity.link(child.pid)


def test_a_malformed_stat_and_deleted_executable_are_handled(tmp_path, monkeypatch) -> None:
    proc = tmp_path / "proc"
    (proc / "7").mkdir(parents=True)
    (proc / "7" / "stat").write_text("garbage")
    with pytest.raises(IdentityError, match="unexpected format"):
        binary_identity._stat_fields(7, str(proc))
    gone = tmp_path / "gone-binary"
    (proc / "7" / "exe").symlink_to(str(gone) + binary_identity.DELETED)
    assert binary_identity._exe_path(7, str(proc)) == str(gone)


def test_too_deep_an_ancestry_is_refused(monkeypatch) -> None:
    counter = iter(range(10_000, 20_000))
    monkeypatch.setattr(binary_identity, "link",
                        lambda pid, proc="/proc": {"pid": pid, "parent": next(counter),
                                                   "path": "/x", "sha256": "0" * 64})
    with pytest.raises(IdentityError, match="deeper than"):
        binary_identity.resolve(5)


def test_answer_waits_for_the_stop_resolves_and_continues(child) -> None:
    os.kill(child.pid, signal.SIGSTOP)
    assert binary_identity.wait_stopped(child.pid)
    answer = binary_identity.answer(child.pid, True, root=os.getpid())
    assert answer["status"] == "complete" and answer["chain"][-1]["pid"] == os.getpid()
    assert binary_identity.state(child.pid) not in ("t", "T")
    os.kill(child.pid, signal.SIGSTOP)
    binary_identity.wait_stopped(child.pid)
    assert binary_identity.answer(child.pid, False, root=os.getpid()) == {
        "pid": child.pid, "status": "not_executed"}
    assert binary_identity.state(child.pid) not in ("t", "T")


def test_a_process_that_never_stops_is_a_failed_answer(child) -> None:
    assert not binary_identity.wait_stopped(child.pid, limit=0.05)
    answer = binary_identity.answer(child.pid, True, root=os.getpid(), proc="/proc")
    assert answer["status"] == "failed"


def test_resolution_failure_is_reported_and_the_process_continued(child, monkeypatch) -> None:
    os.kill(child.pid, signal.SIGSTOP)
    binary_identity.wait_stopped(child.pid)

    def broken(pid, root=None, proc="/proc"):
        raise IdentityError("open /proc/x/exe: Permission denied")

    monkeypatch.setattr(binary_identity, "resolve", broken)
    assert binary_identity.answer(child.pid, True, root=1)["reason"].startswith("open")
    assert binary_identity.state(child.pid) not in ("t", "T")


def test_serve_answers_one_line_per_request(child) -> None:
    sink = io.StringIO()
    os.kill(child.pid, signal.SIGSTOP)
    assert binary_identity.serve(os.getpid(), io.StringIO(f"{child.pid} ok\nnonsense\n"),
                                 sink) == 0
    ready, first, second = [json.loads(line) for line in sink.getvalue().splitlines()]
    assert ready == binary_identity.READY
    assert first["status"] == "complete" and second["reason"] == "malformed request"


def test_the_module_source_runs_standalone_as_the_resolver(child) -> None:
    os.kill(child.pid, signal.SIGSTOP)
    done = subprocess.run([sys.executable, "-I", "-c", SOURCE, "serve", str(os.getpid())],
                          input=f"{child.pid} ok\n", capture_output=True, text=True, timeout=30)
    ready, answer = [json.loads(line) for line in done.stdout.splitlines()]
    assert ready == binary_identity.READY
    assert answer["status"] == "complete" and answer["chain"][-1]["sha256"] == SELF_SHA


@pytest.mark.parametrize("line,expected", [
    ('9     1.25 execve("\\x2f", [], 0x1 /* 7 vars */) = 0', (9, True)),
    ('9     1.25 execve("\\x2f", [], 0x1 /* 7 vars */) = -1 ENOENT (No such file)', (9, False)),
    ("12 1.5 <... execve resumed>) = 0", (12, True)),
    ('12 1.5 execveat(3, "", [], [], AT_EMPTY_PATH) = 0', (12, True)),
    ('12 1.5 execve("\\x2f", [], 0x1 <unfinished ...>', None),
    ('12 1.5 openat(AT_FDCWD, "\\x2f", O_RDONLY) = 3', None),
    ("+++ exited with 0 +++", None),
])
def test_exec_results_reads_completed_execs_from_the_trace(line, expected) -> None:
    assert identity_gate.exec_results(line) == expected


def test_assign_matches_answers_to_exec_events_by_pid_and_order() -> None:
    events = [strace.Event("exec", 5, 1.0), strace.Event("write", 5, 1.1, path="x"),
              strace.Event("exec", 6, 1.2), strace.Event("exec", 5, 1.3),
              strace.Event("exec", 7, 1.4)]
    chain = [{"pid": 5, "parent": 1, "path": "/bin/a", "sha256": "a" * 64}]
    results = [(5, False, {"status": "not_executed"}),
               (5, True, {"status": "complete", "chain": chain}),
               (6, True, {"status": "failed", "reason": "open /proc/6/exe: denied"}),
               (5, True, {"status": "complete", "chain": chain})]
    assert identity_gate.assign(events, results) == 2
    assert events[0].identity == {"status": "complete",
                                  "chain": [{"pid": 5, "path": "/bin/a", "sha256": "a" * 64}]}
    assert events[1].identity is None
    assert events[2].identity == {"status": "failed", "reason": "open /proc/6/exe: denied"}
    assert events[3].identity["status"] == "complete"
    assert events[4].identity == {"status": "failed", "reason": "exec not seen by the gate"}


def exec_line(pid: int, when: float, path: str = "/bin/sh", result: str = "0") -> str:
    hexed = "".join(f"\\x{byte:02x}" for byte in path.encode())
    return f'{pid} {when} execve("{hexed}", [], 0x1 /* 1 var */) = {result}\n'


def stop_lines(pid: int, when: float, code: str = "SI_KERNEL") -> str:
    return (f"{pid} {when} --- SIGSTOP {{si_signo=SIGSTOP, si_code={code}}} ---\n"
            f"{pid} {when} --- stopped by SIGSTOP ---\n")


def test_the_gate_serves_execs_it_reads_from_a_growing_trace(tmp_path, child) -> None:
    trace = tmp_path / "trace.txt"
    trace.write_bytes(b"")
    argv = [sys.executable, "-I", "-c", SOURCE, "serve", str(os.getpid())]
    gate = identity_gate.Gate(trace, argv)
    gate.start()
    os.kill(child.pid, signal.SIGSTOP)
    with open(trace, "a") as handle:
        handle.write(exec_line(4242, 1.0, sys.executable))
        handle.write(exec_line(child.pid, 1.1))
        handle.write(stop_lines(child.pid, 1.2, "SI_USER"))
        handle.write(stop_lines(child.pid, 1.2))
        handle.write(exec_line(999999, 1.3, result="-1 ENOENT (x)"))
        handle.write(stop_lines(999999, 1.4))
        handle.write(f"{child.pid} 1.5 openat(")
    deadline = time.monotonic() + 30
    while len(gate.answers) < 3 and time.monotonic() < deadline:
        time.sleep(0.05)
    gate.stop()
    start, served, failed = gate.results()
    assert start[2]["status"] == "complete" and start[2]["basis"] == "startup_file"
    assert start[2]["chain"][0]["sha256"] == SELF_SHA
    assert start[2]["chain"][1]["pid"] == os.getpid()
    assert served[2]["status"] == "complete" and served[2]["chain"][0]["pid"] == child.pid
    assert failed[:2] == (999999, False) and failed[2]["status"] == "failed"
    assert binary_identity.state(child.pid) not in ("t", "T")
    summary = gate.summary()
    assert summary["requests"] == 3 and summary["complete"] == 2 and summary["failed"] == 1
    assert identity_gate.identity_record(start[2])["basis"] == "startup_file"


def test_an_exec_whose_stop_never_shows_is_never_answered(tmp_path) -> None:
    gate = identity_gate.Gate(tmp_path / "t", ["true"])
    gate.feed(exec_line(5, 1.0))
    gate.feed(exec_line(6, 1.1))
    gate.feed(stop_lines(7, 1.2).splitlines()[0])
    gate.feed(stop_lines(7, 1.2).splitlines()[1])
    assert [kind for _, kind in gate.requests] == ["start"]
    event = strace.Event("exec", 6, 1.1)
    identity_gate.assign([event], gate.results())
    assert event.identity == {"status": "failed", "reason": "exec not seen by the gate"}


def test_startup_and_malformed_requests(tmp_path) -> None:
    sink = io.StringIO()
    missing = (tmp_path / "nope").as_posix().encode().hex()
    binary_identity.serve(os.getpid(), io.StringIO(f"5 start {missing}\n5 start zz\n"), sink)
    ready, first, second = [json.loads(line) for line in sink.getvalue().splitlines()]
    assert ready == binary_identity.READY
    assert first["status"] == second["status"] == "failed"
    assert "open" in first["reason"]


def test_a_resolver_that_never_starts_fails_every_exec(tmp_path, monkeypatch) -> None:
    """No wall-clock bound decides this: the resolver exits, so its one attempt ends there."""
    monkeypatch.setattr(identity_gate, "START_WAIT", 0.0)
    trace = tmp_path / "trace.txt"
    trace.write_text(exec_line(5, 1.0))
    gate = identity_gate.Gate(trace, [sys.executable, "-c", "import sys; sys.stderr.write('no such container\\n'); sys.exit(1)"])
    gate.start()
    gate.stop()
    [(pid, ok, answer)] = gate.results()
    assert (pid, ok, answer["status"]) == (5, True, "failed")
    assert answer["reason"] == "resolver gave no answer"
    assert "resolver did not start" in gate.errors and "no such container" in gate.errors


def test_a_live_resolver_that_never_announces_is_not_started(tmp_path, monkeypatch) -> None:
    """A process that stays alive without its ready line is not a started resolver."""
    monkeypatch.setattr(identity_gate, "START_WAIT", 0.0)
    monkeypatch.setattr(identity_gate, "ATTEMPT_WAIT", 0.3)
    trace = tmp_path / "trace.txt"
    trace.write_text(exec_line(5, 1.0))
    gate = identity_gate.Gate(trace, [sys.executable, "-c", "import time; time.sleep(60)"])
    gate.start()
    gate.stop()
    [(_, _, answer)] = gate.results()
    assert answer["reason"] == "resolver gave no answer"
    assert gate.errors == ["resolver ended without its ready line", "resolver did not start"]


def test_a_resolver_that_answers_before_announcing_is_not_started(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(identity_gate, "START_WAIT", 0.0)
    gate = identity_gate.Gate(tmp_path / "t", [sys.executable, "-c",
                                               "print('{\"status\": \"complete\"}')"])
    gate.start()
    gate.stop()
    assert "resolver wrote before its ready line" in gate.errors
    assert "resolver did not start" in gate.errors


def test_resolver_argv_runs_this_module_inside_the_container() -> None:
    argv = identity_gate.resolver_argv("docker", "probity-agent-x")
    assert argv[:8] == ["docker", "exec", "-i", "--user", "0:0", "--workdir", "/",
                        "probity-agent-x"]
    assert argv[8:11] == ["python3", "-I", "-c"] and argv[11] == SOURCE
    assert argv[12:] == ["serve", "1"]


def test_the_trace_parser_reads_announced_stops_as_neither_calls_nor_noise() -> None:
    text = exec_line(9, 1.0) + stop_lines(9, 1.1) + "9 1.2 +++ exited with 0 +++\n"
    trace = strace.parse(text)
    assert trace.stops == 2 and trace.unparsed == [] and len(trace.calls) == 1
