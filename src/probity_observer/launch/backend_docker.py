"""Docker backend: the workstation and CI route.

The container's first process is the tracer, running as root inside the
container with only ``CAP_SYS_PTRACE``, ``CAP_DAC_READ_SEARCH``, ``CAP_SETUID``
and ``CAP_SETGID``. The tracer needs ``CAP_DAC_READ_SEARCH`` to read
``/proc/<pid>/fd`` of the unprivileged agent and print each descriptor's path;
without it, paths relative to a directory descriptor cannot be placed. A
``/bin/sh`` wrapper merges the agent's stderr into its stdout and execs
``setpriv`` to drop to an unprivileged uid before the agent's own argv runs, so
the agent cannot signal the tracer, read its descriptors, or write into the
trace stream. The tracer writes to the container's stderr, which only the
launcher reads; the agent's output arrives on the container's stdout.

The image must provide ``strace`` (6.6 or later, for ``fchmodat2``),
``setpriv`` and ``/bin/sh``; :func:`preflight` checks all three and records the
tracer's version.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass

from ..sensors import strace

NAME = "docker"
WORKSPACE = "/workspace"
CAPABILITIES = ("SYS_PTRACE", "DAC_READ_SEARCH", "SETUID", "SETGID")
WRAPPER = 'exec setpriv --reuid="$0" --regid="$0" --clear-groups -- "$@" 2>&1'


class BackendError(RuntimeError):
    """The container runtime or image cannot run a traced agent."""


@dataclass(frozen=True)
class Identity:
    image: str
    image_id: str
    strace_version: str
    runtime_version: str


def _run(argv: list[str]) -> str:
    done = subprocess.run(argv, capture_output=True, text=True, check=False)
    if done.returncode != 0:
        raise BackendError(f"{' '.join(argv[:3])} failed: {done.stderr.strip()}")
    return done.stdout.strip()


def preflight(image: str, docker: str = "docker") -> Identity:
    """Pin the image by id and check the tools the launch needs inside it."""
    image_id = _run([docker, "image", "inspect", "--format", "{{.Id}}", image])
    runtime = _run([docker, "version", "--format", "{{.Server.Version}}"])
    probe = _run([docker, "run", "--rm", "--network", "none", "--entrypoint", "/bin/sh", image_id,
                  "-c", "strace -V | head -n 1; command -v setpriv"])
    lines = probe.splitlines()
    if len(lines) != 2 or not lines[0].startswith("strace -- version"):
        raise BackendError("image lacks strace or setpriv")
    return Identity(image, image_id, lines[0], runtime)


def command(identity: Identity, *, name: str, workspace: str, agent_argv: list[str],
            env: dict[str, str], uid: int, network: bool, docker: str = "docker") -> list[str]:
    """The full ``docker run`` argv; it is part of the launch digest."""
    argv = [docker, "run", "--rm", "--name", name, "--network", "bridge" if network else "none",
            "--cap-drop", "ALL"]
    for capability in CAPABILITIES:
        argv += ["--cap-add", capability]
    argv += ["--security-opt", "no-new-privileges", "--user", "0:0",
             "--volume", f"{workspace}:{WORKSPACE}", "--workdir", WORKSPACE,
             "--env", "HOME=/tmp"]
    for key in sorted(env):
        argv += ["--env", f"{key}={env[key]}"]
    argv += ["--entrypoint", "strace", identity.image_id, *strace.FLAGS, "--",
             "/bin/sh", "-c", WRAPPER, str(uid), *agent_argv]
    return argv


def kill(name: str, docker: str = "docker") -> None:
    """Stop a running launch; the tracer dies with the container."""
    subprocess.run([docker, "kill", name], capture_output=True, check=False)
