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
