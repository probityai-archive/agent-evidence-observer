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

import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, Sequence

from ..sensors import treedigest
from . import pytest_plugins
from . import replay as replay_harness

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
    # The agent runs this command itself; the contract seals the working directory and the
    # executable its exec shows, so a claim of it can be matched to the run.
    agent_command: bool = False

    def record(self) -> dict:
        """The contract entry; a command the sealed pytest plugins run also seals its test
        ids, which the grade's ``collected`` count must match."""
        entry: dict = {"id": self.id, "argv": list(self.argv)}
        if self.ids_from is not None and pytest_plugins.is_sealed_pytest(self.argv):
            entry["ids"] = list(self.argv[self.ids_from:])
        return entry


class Runner(Protocol):
    """Run ``argv`` on a copy of ``state`` (and ``heldout``) and return its exit status.

    When ``writes`` is a list, the runner appends every workspace path the run created,
    changed or removed (regular files, compared by digest). ``stdin`` is written to the run's
    standard input and closed (a sealed plugin's report key travels this way).
    """

    name: str

    def run(self, state: Path, argv: Sequence[str], heldout: Path | None,
            timeout: float, writes: list[str] | None = None,
            output: list[str] | None = None, stdin: bytes | None = None) -> int: ...


def changed_paths(before: Path, after: Path) -> list[str]:
    """Regular-file paths that differ between two trees, sorted."""
    old, new = treedigest.scan(before).files, treedigest.scan(after).files
    return sorted(name for name in set(old) | set(new) if old.get(name) != new.get(name))


def stage(state: Path, heldout: Path | None, scratch: Path) -> Path:
    """Copy ``state`` (and ``heldout``) under an empty ``scratch``; return the workspace."""
    workspace = scratch / "workspace"
    shutil.copytree(state, workspace, symlinks=True)
    if heldout is not None:
        shutil.copytree(heldout, scratch / "heldout", symlinks=True)
    return workspace


def is_replay(argv: Sequence[str]) -> bool:
    return bool(argv) and argv[0] == replay_harness.COMMAND


DETERMINISM_RUNS = 2


def replay_mode(argv: Sequence[str]) -> str | None:
    """The replay mode an argv names, or ``None`` when it is not a well-formed replay argv."""
    if len(argv) == 4:
        return "assert"
    if len(argv) == 5 and argv[4] in replay_harness.MODES:
        return argv[4]
    return None


def run_replay(scratch: Path, argv: Sequence[str], child_argv, timeout: float,
               order_seed: str, results: list[dict] | None) -> int:
    """Run a parent-compare replay command staged under ``scratch``.

    ``argv`` is ``(COMMAND, <sealed test path from the workspace>, <module>, <entry>[, mode])``.
    Only the module's file is copied into the child's directory; ``child_argv(directory,
    source)`` returns the child's command line and working directory. The determinism probe
    gives each of its child runs the whole ``timeout``, so the command's own limit is that
    many times longer.
    """
    mode = replay_mode(argv)
    if mode is None:
        return 2
    _, test, module, entry = argv[:4]
    workspace = scratch / "workspace"
    candidate = scratch / "candidate"
    candidate.mkdir()
    source = workspace / f"{module}.py"
    if source.is_file() and not source.is_symlink():
        shutil.copy2(source, candidate / f"{module}.py")
        os.chmod(candidate / f"{module}.py", 0o644)
    os.chmod(candidate, 0o755)
    os.chmod(scratch, 0o755)
    command, cwd = child_argv(candidate, replay_harness.child_source(
        module, entry, probe_import=mode == "import_side_effects"))
    request = {"test": str((workspace / test).resolve()), "child_argv": command,
               "child_cwd": cwd, "call_timeout": min(timeout, 60.0), "order_seed": order_seed,
               "mode": mode, "run_timeout": timeout, "out": str(scratch / "replay.json")}
    (scratch / "request.json").write_text(json.dumps(request))
    limit = timeout * DETERMINISM_RUNS + 30 if mode == "determinism" else timeout
    try:
        done = subprocess.run([sys.executable, "-I", "-m", "probity_observer.done.replay",
                               str(scratch / "request.json")], stdin=subprocess.DEVNULL,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              timeout=limit, check=False)
    except subprocess.TimeoutExpired:
        return TIMEOUT_EXIT
    if results is not None and (scratch / "replay.json").is_file():
        results.append({"argv": list(argv),
                        **json.loads((scratch / "replay.json").read_text())})
    return done.returncode


class SubprocessRunner:
    """A local run with a scrubbed environment; no isolation from the host."""

    name = "subprocess"

    def __init__(self, python: str | None = None, order_seed: str = "subprocess") -> None:
        self.env = dict(SCRUBBED_ENV)
        self.python = python or sys.executable
        self.order_seed = order_seed
        self.replays: list[dict] = []
        if python is not None:
            self.env["PATH"] = f"{Path(python).parent}:{self.env['PATH']}"

    def child_argv(self, directory: Path, source: str) -> tuple[list[str], str]:
        return [self.python, "-I", "-P", "-c", source], str(directory)

    def run(self, state: Path, argv: Sequence[str], heldout: Path | None,
            timeout: float, writes: list[str] | None = None,
            output: list[str] | None = None, stdin: bytes | None = None) -> int:
        with tempfile.TemporaryDirectory(prefix="probity-done-") as scratch:
            workspace = stage(Path(state), heldout, Path(scratch))
            if is_replay(argv):
                return run_replay(Path(scratch), argv, self.child_argv, timeout,
                                  self.order_seed, self.replays)
            try:
                done = subprocess.run(list(argv), cwd=workspace, env=self.env,
                                      input=stdin if stdin is not None else b"",
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.DEVNULL, timeout=timeout,
                                      check=False, start_new_session=True)
                code = done.returncode
                if output is not None:
                    output.append(done.stdout.decode("utf-8", "replace"))
            except subprocess.TimeoutExpired:
                code = TIMEOUT_EXIT
            except OSError:
                code = 127
            if writes is not None:
                writes.extend(changed_paths(Path(state), workspace))
            return code


def chmod_tree(root: Path, mode_dirs: int = 0o777, mode_files: int = 0o666) -> None:
    """Open a scratch copy to an unprivileged worker uid (the copy is thrown away)."""
    for directory, dirnames, filenames in os.walk(root):
        os.chmod(directory, mode_dirs)
        for name in filenames:
            path = Path(directory) / name
            if not path.is_symlink():
                os.chmod(path, mode_files | (os.stat(path).st_mode & 0o111))
