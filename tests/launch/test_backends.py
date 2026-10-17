"""Container argv for each backend: what the launch digest binds."""

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
