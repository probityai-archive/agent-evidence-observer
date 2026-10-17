"""Container argv for each backend: what the launch digest binds."""

import hashlib

import pytest

from probity_observer.launch import backend_apptainer, backend_docker
from probity_observer.sensors import strace


def identity(module, image):
    return module.Identity(image, "sha256:" + "a" * 64, "strace -- version 6.13", "1")


def test_docker_runs_the_tracer_first_and_drops_the_agent_to_a_uid():
    argv = backend_docker.command(identity(backend_docker, "img"), name="n", workspace="/ws",
                                  agent_argv=["python3", "x.py"], env={"B": "2", "A": "1"},
                                  uid=1000, network=False)
    entry = argv.index("--entrypoint")
    assert argv[entry + 1:entry + 3] == ["strace", "sha256:" + "a" * 64]
    assert argv[argv.index("--network") + 1] == "none"
    assert "--cap-drop" in argv and argv[argv.index("--cap-drop") + 1] == "ALL"
    assert strace.TRACE_EXPRESSION in argv
    tail = argv[argv.index("--", entry) + 1:]
    assert tail == ["/bin/sh", "-c", backend_docker.WRAPPER, "1000", "python3", "x.py"]
    envs = [argv[i + 1] for i, item in enumerate(argv) if item == "--env"]
    assert envs == ["HOME=/tmp", "A=1", "B=2"]
    assert "/ws:/workspace" in argv


def test_docker_network_is_explicit():
    argv = backend_docker.command(identity(backend_docker, "img"), name="n", workspace="/ws",
                                  agent_argv=["a"], env={}, uid=1, network=True)
    assert argv[argv.index("--network") + 1] == "bridge"


def test_apptainer_contains_everything_and_binds_only_the_workspace():
    argv = backend_apptainer.command(identity(backend_apptainer, "/x/agent.sif"), name="n",
                                     workspace="/scratch/ws", agent_argv=["python3", "x.py"],
                                     env={}, uid=1000, network=False)
    assert argv[:3] == ["apptainer", "exec", "--containall"]
    assert argv.count("--bind") == 1 and "/scratch/ws:/workspace" in argv
    assert argv[argv.index("--network") + 1] == "none"
    image = argv.index("/x/agent.sif")
    assert argv[image + 1] == "strace" and strace.TRACE_EXPRESSION in argv
    assert argv[-3:] == ["agent", "python3", "x.py"]


def test_apptainer_with_network_has_no_network_flag():
    argv = backend_apptainer.command(identity(backend_apptainer, "/x/a.sif"), name="n",
                                     workspace="/ws", agent_argv=["a"], env={}, uid=1,
                                     network=True)
    assert "--network" not in argv


ROOT_MAPPED = "         0       6981          1\n"
SUBUID_MAPPED = "         0       1001          1\n         1     165536      65536\n"


def apptainer_identity(uid_map):
    return backend_apptainer.Identity("/x/a.sif", "sha256:" + "a" * 64,
                                      "strace -- version 6.13", "1", uid_map)


def test_a_root_mapped_namespace_does_not_separate_the_tracer():
    # Measured on a HiPerGator compute node (no /etc/subuid entry): apptainer
    # falls back to the fakeroot command in a namespace mapping uid 0 only, and
    # an agent "dropped" to 65534 by setpriv still killed its tracer.
    assert not apptainer_identity(ROOT_MAPPED).uid_separated
    assert not apptainer_identity("").uid_separated
    assert backend_apptainer.uid_separated(apptainer_identity(ROOT_MAPPED)) is False


def test_a_subuid_mapped_namespace_separates_the_tracer():
    assert apptainer_identity(SUBUID_MAPPED).uid_separated
    assert backend_apptainer.mapped(SUBUID_MAPPED, backend_apptainer.AGENT_UID)
    assert not backend_apptainer.mapped(SUBUID_MAPPED, 70000)
    assert not backend_apptainer.mapped(SUBUID_MAPPED, 65537)
    assert backend_apptainer.mapped(SUBUID_MAPPED, 65536)


def test_separated_apptainer_runs_under_fakeroot_and_drops_the_agent():
    argv = backend_apptainer.command(apptainer_identity(SUBUID_MAPPED), name="n",
                                     workspace="/ws", agent_argv=["python3", "x.py"], env={},
                                     uid=backend_apptainer.AGENT_UID, network=False)
    assert argv[:4] == ["apptainer", "exec", "--fakeroot", "--containall"]
    tail = argv[argv.index("--") + 1:]
    assert tail == ["/bin/sh", "-c", backend_apptainer.SEPARATED_WRAPPER, "65534",
                    "python3", "x.py"]


def test_unseparated_apptainer_keeps_one_uid():
    argv = backend_apptainer.command(apptainer_identity(ROOT_MAPPED), name="n", workspace="/ws",
                                     agent_argv=["a"], env={}, uid=1, network=False)
    assert "--fakeroot" not in argv and "setpriv" not in " ".join(argv)


def test_docker_always_separates():
    assert backend_docker.uid_separated(identity(backend_docker, "img")) is True


FAKE_APPTAINER = """#!/bin/sh
echo "$*" >> "$FAKE_LOG"
case "$*" in
  --version) echo "apptainer version 1.4.2" ;;
  *"strace -V"*) echo "strace -- version 6.13" ;;
  *"/proc/self/uid_map"*) [ -n "$FAKE_MAP_FAIL" ] && exit 1; printf "$FAKE_MAP" ;;
  *chown*) ;;
  *) exit 2 ;;
esac
"""


@pytest.fixture
def fake_apptainer(tmp_path, monkeypatch):
    tool = tmp_path / "apptainer"
    tool.write_text(FAKE_APPTAINER)
    tool.chmod(0o755)
    image = tmp_path / "agent.sif"
    image.write_bytes(b"sif")
    monkeypatch.setenv("FAKE_LOG", str(tmp_path / "calls.log"))
    monkeypatch.setenv("FAKE_MAP", SUBUID_MAPPED)
    monkeypatch.setenv("FAKE_MAP_FAIL", "")
    return tool, image, tmp_path / "calls.log"


def test_preflight_pins_the_image_and_measures_the_uid_map(fake_apptainer, monkeypatch):
    tool, image, _ = fake_apptainer
    found = backend_apptainer.preflight(str(image), apptainer=str(tool))
    assert found.image_id == "sha256:" + hashlib.sha256(b"sif").hexdigest()
    assert found.strace_version == "strace -- version 6.13" and found.uid_separated
    monkeypatch.setenv("FAKE_MAP", ROOT_MAPPED)
    assert not backend_apptainer.preflight(str(image), apptainer=str(tool)).uid_separated
    monkeypatch.setenv("FAKE_MAP_FAIL", "1")
    failed = backend_apptainer.preflight(str(image), apptainer=str(tool))
    assert failed.uid_map == "" and not failed.uid_separated


def test_preflight_refuses_a_missing_image_or_a_failing_runtime(fake_apptainer, tmp_path):
    tool, image, _ = fake_apptainer
    with pytest.raises(backend_apptainer.BackendError):
        backend_apptainer.preflight(str(tmp_path / "missing.sif"), apptainer=str(tool))
    with pytest.raises(backend_apptainer.BackendError):
        backend_apptainer.preflight(str(image), apptainer=str(tmp_path / "no-such-tool"))


def test_workspace_is_handed_over_and_back_only_when_separated(fake_apptainer, tmp_path):
    tool, image, log = fake_apptainer
    separated = apptainer_identity(SUBUID_MAPPED)
    backend_apptainer.prepare(separated, tmp_path, apptainer=str(tool))
    backend_apptainer.restore(separated, tmp_path, apptainer=str(tool))
    calls = log.read_text().splitlines()
    assert [call.split()[-3:] for call in calls] == [["-R", "65534:65534", "/workspace"],
                                                       ["-R", "0:0", "/workspace"]]
    assert all(call.startswith("exec --fakeroot --containall --bind") for call in calls)
    log.write_text("")
    unseparated = apptainer_identity(ROOT_MAPPED)
    backend_apptainer.prepare(unseparated, tmp_path, apptainer=str(tool))
    backend_apptainer.restore(unseparated, tmp_path, apptainer=str(tool))
    assert log.read_text() == ""
    assert backend_apptainer.agent_uid(separated, tmp_path, 1000) == 65534
    assert backend_apptainer.agent_uid(unseparated, tmp_path, 1000) == 1000


def test_default_workspace_root_reads_node_local_scratch(monkeypatch, tmp_path):
    monkeypatch.delenv("SLURM_TMPDIR", raising=False)
    monkeypatch.setenv("TMPDIR", str(tmp_path))
    assert backend_apptainer.default_workspace_root() == tmp_path
    monkeypatch.delenv("TMPDIR")
    with pytest.raises(backend_apptainer.BackendError):
        backend_apptainer.default_workspace_root()


def test_docker_has_nothing_to_hand_over(tmp_path):
    ident = identity(backend_docker, "img")
    assert backend_docker.agent_uid(ident, tmp_path, 1000) == 1000
    assert backend_docker.prepare(ident, tmp_path) is None
    assert backend_docker.restore(ident, tmp_path) is None


def test_malformed_uid_map_lines_map_nothing_and_kill_signals_the_process():
    assert not backend_apptainer.mapped("not a map\n0 1000\n", 0)

    class Process:
        killed = False

        def kill(self):
            self.killed = True

    process = Process()
    backend_apptainer.kill(process)
    assert process.killed
