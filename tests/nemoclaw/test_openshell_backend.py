"""The OpenShell launch backend's parts that need neither docker nor OpenShell."""

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from probity_observer.launch import (
    backend_openshell,
    identity_gate,
    launch_agent,
    tracer_attach,
)
from probity_observer.openshell import pins
from probity_observer.openshell import policy as network_policy
from probity_observer.sensors import strace, treedigest

POLICY = b"""version: 1
filesystem_policy:
  include_workdir: true
  read_only: [/usr, /lib, /proc, /etc]
  read_write: [/sandbox, /tmp]
process:
  run_as_user: "1000"
  run_as_group: "1000"
network_policies: {}
"""


def identity():
    return backend_openshell.Identity("img", "sha256:abc", "strace -- version 6.13", "27", {
        "binaries": {"openshell": {"path": "/opt/openshell", "sha256": "0" * 64},
                     "openshell-gateway": {"path": "/opt/openshell-gateway", "sha256": "1" * 64}}})


def test_the_backend_is_registered_under_its_name() -> None:
    assert launch_agent.BACKENDS["openshell"] is backend_openshell
    assert backend_openshell.WORKSPACE == "/sandbox" and backend_openshell.STARTUP_EXEC is False


def test_the_agent_runs_under_the_policys_numeric_uid_only() -> None:
    assert backend_openshell.policy_uid(network_policy.load(POLICY)) == 1000
    for value in (b'"sandbox"', b'"0"', b"1000"):
        with pytest.raises(backend_openshell.BackendError, match="numeric non-root"):
            backend_openshell.policy_uid(network_policy.load(POLICY.replace(b'"1000"\n  run_as_group',
                                                                             value + b"\n  run_as_group")))


def test_the_gateway_config_pins_both_runtime_images(tmp_path) -> None:
    text = backend_openshell.gateway_config(tmp_path, 4242, "probity-x")
    assert 'bind_address = "127.0.0.1:4242"' in text and 'compute_driver = "docker"' in text
    assert f'supervisor_image = "{pins.SUPERVISOR_IMAGE}"' in text
    assert f'sandbox_runtime_image = "{pins.SANDBOX_RUNTIME_IMAGE}"' in text
    assert 'image_pull_policy = "never"' in text and 'gateway_id = "probity-x"' in text


def test_the_exec_and_tracer_argv_carry_the_marker_and_the_gated_flags(tmp_path) -> None:
    session = backend_openshell.Session(identity(), policy_path=tmp_path / "p.yaml", name="sbx")
    try:
        argv = session.exec_argv(["python3", "-c", "x"], {"B": "2", "A": "1"})
        at = argv.index("--")
        assert argv[at + 1:at + 3] == ["/bin/sh", "-c"] and argv[at + 3] == backend_openshell.WRAPPER
        assert argv[at + 4] == session.marker and argv[at + 5:] == ["python3", "-c", "x"]
        assert argv[argv.index("--env") + 1] == "A=1" and "--no-login-shell" in argv
        session.sandbox_container = "c0ffee"
        tracer = session.tracer_argv()
        assert tracer[tracer.index("--pid") + 1] == "container:c0ffee"
        assert tracer[tracer.index("--network") + 1] == "none"
        assert tracer[tracer.index("--cap-drop") + 1] == "ALL"
        assert [tracer[i + 1] for i, item in enumerate(tracer) if item == "--cap-add"] == \
            ["SYS_PTRACE", "KILL"]
        flags = tracer[tracer.index(session.marker) + 2:]
        assert flags == list(backend_openshell.tracer_flags())
        assert "signal=none" not in flags and "inject=execve,execveat:signal=SIGSTOP" in flags
        assert strace.TRACE_EXPRESSION in flags
        assert session.resolver_argv()[:8] == ["docker", "exec", "-i", "--user", "0:0", "--workdir",
                                               "/", session.tracer_name]
        assert len(session.name) <= backend_openshell.NAME_LENGTH
    finally:
        session.close()
    assert not session.state.exists()


def test_the_wrapper_runs_nothing_until_a_tracer_is_attached(tmp_path) -> None:
    """With no tracer the wrapper spins on builtins and never reaches the agent's argv."""
    flag = tmp_path / "ran"
    process = subprocess.Popen(["/bin/sh", "-c", backend_openshell.WRAPPER, "marker", "touch",
                                str(flag)])
    try:
        time.sleep(0.5)
        assert process.poll() is None and not flag.exists()
    finally:
        process.kill()
        process.wait()


def tree(files=None, executable=(), symlinks=None):
    return treedigest.Tree(files=dict(files or {}), executable=list(executable),
                           symlinks=dict(symlinks or {}))


def test_the_tree_diff_names_each_changed_path_once() -> None:
    before = tree({"a": "1", "b": "2", "c": "3"}, symlinks={"l": "a"})
    after = tree({"a": "1", "b": "9", "c": "3", "d": "4"}, executable=["c"], symlinks={"l": "b"})
    changes = backend_openshell.tree_changes(before, after, 7.0)
    assert [(item.kind, item.path) for item in changes] == [
        ("write", "b"), ("chmod", "c"), ("create", "d"), ("write", "l")]
    assert {item.time for item in changes} == {7.0}
    assert backend_openshell.tree_changes(after, before, 7.0)[0].path == "b"
    assert {item.kind for item in backend_openshell.tree_changes(before, tree(), 1.0)} == {"unlink"}


def test_the_tree_is_replaced_exactly(tmp_path) -> None:
    source, target = tmp_path / "s", tmp_path / "t"
    (source / "d").mkdir(parents=True)
    (source / "d" / "f").write_text("new")
    (target / "old").mkdir(parents=True)
    (target / "x").write_text("gone")
    os.symlink("x", target / "link")
    backend_openshell._replace_tree(source, target)
    assert sorted(item.name for item in target.iterdir()) == ["d"]
    assert (target / "d" / "f").read_text() == "new"


def fake_proc(root: Path, pid: int, argv: list[bytes], parent: int) -> None:
    (root / str(pid)).mkdir(parents=True)
    (root / str(pid) / "cmdline").write_bytes(b"\0".join(argv) + b"\0")
    (root / str(pid) / "stat").write_text(f"{pid} (x y) S {parent} 0 0\n")


def test_the_marker_finds_one_process_by_its_argv_zero(tmp_path) -> None:
    fake_proc(tmp_path, 1, [b"/supervisor"], 0)
    fake_proc(tmp_path, 7, [b"/bin/sh", b"-c", b"w", b"m-1", b"python3"], 1)
    fake_proc(tmp_path, 8, [b"sh", b"m-1", b"-c", b"m-1", b"x"], 1)
    fake_proc(tmp_path, 6, [b"/bin/sh", b"-c", b"m-1"], 1)
    fake_proc(tmp_path, 9, [b"python3"], 7)
    fake_proc(tmp_path, 10, [b"cat"], 9)
    (tmp_path / "self").mkdir()
    assert tracer_attach.find(b"m-1", 0.5, str(tmp_path)) == 7
    assert tracer_attach.find(b"m-2", 0.05, str(tmp_path)) is None
    assert sorted(tracer_attach.descendants(7, str(tmp_path))) == [7, 9, 10]
    fake_proc(tmp_path, 11, [b"/bin/sh", b"-c", b"w", b"m-1", b"again"], 1)
    assert tracer_attach.find(b"m-1", 0.5, str(tmp_path)) is None


def test_an_attached_gate_gates_the_first_exec_too(tmp_path) -> None:
    gate = identity_gate.Gate(tmp_path / "t", ["true"], startup_exec=False)
    hexed = "".join(f"\\x{byte:02x}" for byte in b"/bin/sh")
    gate.feed(f'5 1.0 execve("{hexed}", [], 0x1 /* 1 var */) = 0')
    gate.feed("5 1.1 --- SIGSTOP {si_signo=SIGSTOP, si_code=SI_KERNEL} ---")
    gate.feed("5 1.1 --- stopped by SIGSTOP ---")
    assert gate.requests == [(5, "ok")]


def test_the_tracer_side_reports_a_missing_marker() -> None:
    source = Path(tracer_attach.__file__).read_text()
    done = subprocess.run([sys.executable, "-I", "-c", source, "probity-no-such-marker", "0.1",
                           "-f"], capture_output=True, text=True, timeout=30, check=False)
    assert done.returncode == 2 and '"status": "not_found"' in done.stdout


def test_the_marker_and_the_tree_below_it_are_found_in_the_real_proc() -> None:
    marker = f"probity-test-{os.getpid()}"
    target = subprocess.Popen(["/bin/sh", "-c", "sleep 60 & wait", marker, "agent"])
    try:
        found = tracer_attach.find(marker.encode(), 5.0)
        assert found == target.pid
        tree_pids = tracer_attach.descendants(found)
        assert len(tree_pids) == 2
        for pid in tree_pids:
            os.kill(pid, signal.SIGKILL)
        target.wait(timeout=10)
    finally:
        if target.poll() is None:
            target.kill()
