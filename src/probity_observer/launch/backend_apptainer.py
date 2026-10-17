"""Apptainer backend: the HiPerGator route.

The agent runs under ``apptainer exec --containall`` with only the workspace
bound, at ``/workspace``, and with no network unless the launch allows it. On
a Slurm node the workspace lives on node-local ``$SLURM_TMPDIR``, where host
inotify sees every write; :func:`default_workspace_root` returns it.

The tracer is the container's first process, as with docker, but apptainer
runs both the tracer and the agent under the submitting user's uid. So the
agent could signal the tracer or open its descriptors through ``/proc``. A
killed tracer is detected (the root process has no exit record, and the
observation names a gap to the end of the run); a forged trace line is not.
The receipt records this as ``tracer_uid_separated: false``. Docker keeps the
two apart.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from ..sensors import strace

NAME = "apptainer"
WORKSPACE = "/workspace"
WRAPPER = 'exec "$@" 2>&1'


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


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def default_workspace_root() -> Path:
    """Node-local scratch on a Slurm node; refuses to guess elsewhere."""
    scratch = os.environ.get("SLURM_TMPDIR") or os.environ.get("TMPDIR")
    if not scratch:
        raise BackendError("set SLURM_TMPDIR (or TMPDIR) to node-local scratch")
    return Path(scratch)


def preflight(image: str, apptainer: str = "apptainer") -> Identity:
    """Pin the image file by SHA-256 and check its tracer."""
    path = Path(image)
    if not path.is_file():
        raise BackendError(f"image file not found: {image}")
    runtime = _run([apptainer, "--version"])
    probe = _run([apptainer, "exec", "--containall", str(path), "/bin/sh", "-c",
                  "strace -V | head -n 1"])
    if not probe.startswith("strace -- version"):
        raise BackendError("image lacks strace")
    return Identity(image, "sha256:" + _file_sha256(path), probe, runtime)


def command(identity: Identity, *, name: str, workspace: str, agent_argv: list[str],
            env: dict[str, str], uid: int, network: bool,
            apptainer: str = "apptainer") -> list[str]:
    """The full ``apptainer exec`` argv; it is part of the launch digest."""
    argv = [apptainer, "exec", "--containall", "--bind", f"{workspace}:{WORKSPACE}",
            "--pwd", WORKSPACE, "--env", "HOME=/tmp"]
    if not network:
        argv += ["--net", "--network", "none"]
    for key in sorted(env):
        argv += ["--env", f"{key}={env[key]}"]
    argv += [identity.image, "strace", *strace.FLAGS, "--", "/bin/sh", "-c", WRAPPER,
             "agent", *agent_argv]
    return argv


def kill(process: subprocess.Popen) -> None:
    """Stop a running launch by signalling the apptainer process tree."""
    process.kill()
