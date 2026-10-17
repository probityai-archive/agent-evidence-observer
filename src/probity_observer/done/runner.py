"""Run one acceptance command on one state of a task.

Each run gets a fresh copy of the state at ``<scratch>/workspace`` and, when the task has
held-out files, a copy of them at ``<scratch>/heldout``. Commands run with the workspace as
their working directory, so a held-out file is reached as ``../heldout/<name>``: the same
argv works for :class:`SubprocessRunner` here and for the docker runner in
:mod:`.verify_run`, which mounts the two directories at ``/workspace`` and ``/heldout``.

:class:`SubprocessRunner` isolates nothing beyond a scrubbed environment and a fresh copy.
The contract compiler may use it to measure stability and mutant kills on trusted states
(reference, pre-patch, mutants); grading an agent's tree always uses the docker runner.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, Sequence

TIMEOUT_EXIT = 124
SCRUBBED_ENV = {
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "HOME": "/tmp",
    "LANG": "C.UTF-8",
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONNOUSERSITE": "1",
    "PYTHONHASHSEED": "0",
}


@dataclass(frozen=True)
class Command:
    """One acceptance command: an id, its exact argv, and whether it is held out."""

    id: str
    argv: tuple[str, ...]
    heldout: bool = False
    prepatch: str = "fail"
    ids_from: int | None = None

    def record(self) -> dict:
        return {"id": self.id, "argv": list(self.argv)}


class Runner(Protocol):
    """Run ``argv`` on a copy of ``state`` (and ``heldout``) and return its exit status."""

    name: str

    def run(self, state: Path, argv: Sequence[str], heldout: Path | None,
            timeout: float) -> int: ...


def stage(state: Path, heldout: Path | None, scratch: Path) -> Path:
    """Copy ``state`` (and ``heldout``) under an empty ``scratch``; return the workspace."""
    workspace = scratch / "workspace"
    shutil.copytree(state, workspace, symlinks=True)
    if heldout is not None:
        shutil.copytree(heldout, scratch / "heldout", symlinks=True)
    return workspace


class SubprocessRunner:
    """A local run with a scrubbed environment; no isolation from the host."""

    name = "subprocess"

    def __init__(self, python: str | None = None) -> None:
        self.env = dict(SCRUBBED_ENV)
        if python is not None:
            self.env["PATH"] = f"{Path(python).parent}:{self.env['PATH']}"

    def run(self, state: Path, argv: Sequence[str], heldout: Path | None,
            timeout: float) -> int:
        with tempfile.TemporaryDirectory(prefix="probity-done-") as scratch:
            workspace = stage(Path(state), heldout, Path(scratch))
            try:
                done = subprocess.run(list(argv), cwd=workspace, env=self.env,
                                      stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL, timeout=timeout,
                                      check=False, start_new_session=True)
            except subprocess.TimeoutExpired:
                return TIMEOUT_EXIT
            except OSError:
                return 127
            return done.returncode


def chmod_tree(root: Path, mode_dirs: int = 0o777, mode_files: int = 0o666) -> None:
    """Open a scratch copy to an unprivileged worker uid (the copy is thrown away)."""
    for directory, dirnames, filenames in os.walk(root):
        os.chmod(directory, mode_dirs)
        for name in filenames:
            path = Path(directory) / name
            if not path.is_symlink():
                os.chmod(path, mode_files | (os.stat(path).st_mode & 0o111))
