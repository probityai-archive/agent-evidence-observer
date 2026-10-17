"""Apptainer backend: the HiPerGator route.

The agent runs under ``apptainer exec --containall`` with only the workspace
bound, at ``/workspace``, and with no network unless the launch allows it. On
a Slurm node the workspace lives on node-local ``$SLURM_TMPDIR``, where host
inotify sees every write; :func:`default_workspace_root` returns it.

The tracer is the container's first process, as with docker. Whether the
agent can run under a uid of its own depends on the host. :func:`preflight`
reads ``/proc/self/uid_map`` inside ``apptainer exec --fakeroot``:

- When the user has a subordinate uid range (``/etc/subuid``), the namespace
  maps more than uid 0, and the launch runs under ``--fakeroot`` with the
  tracer as root in the namespace and the agent dropped by ``setpriv`` to
  :data:`AGENT_UID`, as docker does. The workspace is handed to that uid
  before the run and back to the submitting user after it, both through the
  same namespace. ``tracer_uid_separated`` is ``true``.
- Otherwise (measured on a HiPerGator compute node, which has no subuid entry
  for its users: apptainer falls back to the ``fakeroot`` command in a
  namespace that maps uid 0 only, ``setpriv`` appears to succeed, and the
  agent still killed its tracer) tracer and agent share the submitting user's
  uid. The agent could signal the tracer or open its descriptors through
  ``/proc``. A killed tracer is detected (the root process has no exit
  record, the trace ends with the agent's signal, and the observation names a
  gap to the end with ``gap_cause: agent``); a forged trace line that parses
  is not. ``tracer_uid_separated`` is ``false``.
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
SEPARATED_WRAPPER = 'exec setpriv --reuid="$0" --regid="$0" --clear-groups -- "$@" 2>&1'
AGENT_UID = 65534


class BackendError(RuntimeError):
    """The container runtime or image cannot run a traced agent."""


@dataclass(frozen=True)
class Identity:
    image: str
    image_id: str
    strace_version: str
    runtime_version: str
    uid_map: str = ""

    @property
    def uid_separated(self) -> bool:
        """The fakeroot namespace maps both root and the agent's uid."""
        return mapped(self.uid_map, 0) and mapped(self.uid_map, AGENT_UID)


def mapped(uid_map: str, uid: int) -> bool:
    """Whether ``uid`` inside the namespace is mapped by ``uid_map``'s lines."""
    for line in uid_map.splitlines():
        fields = line.split()
        if len(fields) != 3 or not all(field.isdigit() for field in fields):
            continue
        inside, _, count = (int(field) for field in fields)
        if inside <= uid < inside + count:
            return True
    return False


def uid_separated(identity: Identity) -> bool:
    return identity.uid_separated


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
    done = subprocess.run([apptainer, "exec", "--fakeroot", "--containall", str(path), "cat",
                           "/proc/self/uid_map"], capture_output=True, text=True, check=False)
    uid_map = done.stdout if done.returncode == 0 else ""
    return Identity(image, "sha256:" + _file_sha256(path), probe, runtime, uid_map)


def agent_uid(identity: Identity, workspace: Path, owner_uid: int) -> int:
    """The agent's uid: :data:`AGENT_UID` in a separated namespace, else the owner's."""
    return AGENT_UID if identity.uid_separated else owner_uid


def _chown_inside(identity: Identity, workspace: Path, owner: str,
                  apptainer: str = "apptainer") -> None:
    _run([apptainer, "exec", "--fakeroot", "--containall", "--bind",
          f"{workspace}:{WORKSPACE}", identity.image, "chown", "-R", owner, WORKSPACE])


def prepare(identity: Identity, workspace: Path) -> None:
    """Hand the workspace to the agent's uid when the namespace separates it."""
    if identity.uid_separated:
        _chown_inside(identity, workspace, f"{AGENT_UID}:{AGENT_UID}")


def restore(identity: Identity, workspace: Path) -> None:
    """Hand the workspace back to the submitting user (root in the namespace)."""
    if identity.uid_separated:
        _chown_inside(identity, workspace, "0:0")


def command(identity: Identity, *, name: str, workspace: str, agent_argv: list[str],
            env: dict[str, str], uid: int, network: bool,
            apptainer: str = "apptainer") -> list[str]:
    """The full ``apptainer exec`` argv; it is part of the launch digest."""
    separated = identity.uid_separated
    argv = [apptainer, "exec", *(["--fakeroot"] if separated else []), "--containall",
            "--bind", f"{workspace}:{WORKSPACE}", "--pwd", WORKSPACE, "--env", "HOME=/tmp"]
    if not network:
        argv += ["--net", "--network", "none"]
    for key in sorted(env):
        argv += ["--env", f"{key}={env[key]}"]
    if separated:
        argv += [identity.image, "strace", *strace.FLAGS, "--", "/bin/sh", "-c",
                 SEPARATED_WRAPPER, str(uid), *agent_argv]
    else:
        argv += [identity.image, "strace", *strace.FLAGS, "--", "/bin/sh", "-c", WRAPPER,
                 "agent", *agent_argv]
    return argv


def kill(process: subprocess.Popen) -> None:
    """Stop a running launch by signalling the apptainer process tree."""
    process.kill()
