"""C4: the harness, never the agent, grades the agent's final tree in fresh containers.

One grading run, in order:

1. Check that the final tree on disk is the one the tree record names (its digest).
2. Stage a copy without following links: regular files are copied with ``O_NOFOLLOW``, a
   link that would leave the tree and every special file are rejected and listed.
3. Reset every protected path from the sealed copy, together with its excluded names, and
   remove every ``__pycache__`` and ``.pytest_cache`` in the tree, so neither a poisoned
   ``.pyc`` nor a cache file survives. Measure the protected digests again.
4. Run each acceptance command (visible and held-out) in its own fresh container from the
   staged copy. The container has no network, no capabilities, ``no-new-privileges``, a
   read-only root file system (so ``/usr`` and ``site-packages`` are read-only), a private
   ``/tmp``, process and memory limits, an unprivileged uid with no supplementary groups, and
   ``env -i`` with a fixed environment. These are the lockdown layers of Ratchet's guard
   child (rlimits, network namespace, no new privileges) applied by the container runtime.
5. Write the ``probity-acceptance-grade/v1`` record and sign it with the grader's own key,
   which is not the harness key that sealed the contract.
6. Write the verifier's account of its own isolation, the ``verifier_isolation`` block the
   ``agent-evidence-admission`` rule set reads. Every fact is measured or follows from the
   argv above; where the grading run is weaker than an obligation asks (agent code is imported
   into the process that asserts, the result is an exit status the worker sets) the block says
   so, and the rule set refuses it.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

from ..sensors import treedigest
from .contract import Protected, copy_protected, protected_digest
from .formats import DoneError, encode, sha256, sign_record
from .runner import SCRUBBED_ENV, TIMEOUT_EXIT, chmod_tree, stage

GRADE_SCHEMA = "probity-acceptance-grade/v1"
WORKER_UID = 65534
CACHE_NAMES = ("__pycache__", ".pytest_cache")


class GradeError(DoneError):
    """The tree cannot be graded (wrong digest, runtime failure)."""


@dataclass
class DockerRunner:
    """One fresh, locked-down container per acceptance run."""

    image: str
    worker_uid: int = WORKER_UID
    memory: str = "2g"
    pids: int = 256
    tmpfs_size: str = "512m"
    docker: str = "docker"
    name: str = "docker"

    def flags(self) -> list[str]:
        """Every isolation flag, in the order they are passed; part of the isolation report."""
        return ["--network", "none", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--read-only", "--tmpfs", f"/tmp:rw,nosuid,nodev,size={self.tmpfs_size}",
                "--pids-limit", str(self.pids), "--memory", self.memory,
                "--ulimit", "core=0", "--user", f"{self.worker_uid}:{self.worker_uid}"]

    def command(self, name: str, scratch: Path, argv: Sequence[str], heldout: bool) -> list[str]:
        command = [self.docker, "run", "--rm", "--name", name, *self.flags(),
                   "--volume", f"{scratch / 'workspace'}:/workspace"]
        if heldout:
            command += ["--volume", f"{scratch / 'heldout'}:/heldout:ro"]
        command += ["--workdir", "/workspace", "--entrypoint", "/usr/bin/env", self.image, "-i",
                    *(f"{key}={value}" for key, value in sorted(SCRUBBED_ENV.items())), *argv]
        return command

    def run(self, state: Path, argv: Sequence[str], heldout: Path | None,
            timeout: float) -> int:
        with tempfile.TemporaryDirectory(prefix="probity-grade-") as scratch:
            root = Path(scratch)
            stage(Path(state), heldout, root)
            chmod_tree(root / "workspace")
            if heldout is not None:
                chmod_tree(root / "heldout", 0o755, 0o644)
            os.chmod(root, 0o755)
            name = f"probity-grade-{uuid.uuid4().hex[:12]}"
            process = subprocess.Popen(self.command(name, root, argv, heldout is not None),
                                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                       stderr=subprocess.PIPE)
            try:
                _, error = process.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                subprocess.run([self.docker, "kill", name], capture_output=True, check=False)
                process.communicate()
                return TIMEOUT_EXIT
            if process.returncode == 125:
                raise GradeError(f"container runtime failed: {error.decode(errors='replace').strip()}")
            return process.returncode

    def groups(self) -> list[int]:
        """The worker's supplementary groups, measured in a container with the same flags."""
        probe = subprocess.run([self.docker, "run", "--rm", *self.flags(), "--entrypoint",
                                "/usr/bin/env", self.image, "-i", "id", "-G"],
                               capture_output=True, text=True, check=False)
        if probe.returncode != 0:
            raise GradeError(f"cannot measure the worker's groups: {probe.stderr.strip()}")
        return sorted(int(item) for item in probe.stdout.split() if int(item) != self.worker_uid)


@dataclass
class Staged:
    root: Path
    rejected: list[str] = field(default_factory=list)
    removed_caches: list[str] = field(default_factory=list)


def _copy_file(source: Path, target: Path) -> None:
    descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        with os.fdopen(descriptor, "rb", closefd=False) as reader, open(target, "xb") as writer:
            shutil.copyfileobj(reader, writer)
    finally:
        os.close(descriptor)
    os.chmod(target, stat.S_IMODE(os.lstat(source).st_mode))


def _inside(root: Path, link: Path) -> bool:
    target = os.readlink(link)
    if os.path.isabs(target):
        return False
    resolved = os.path.normpath(os.path.join(link.parent, target))
    return resolved == str(root) or resolved.startswith(str(root) + os.sep)


def stage_tree(final: Path, destination: Path) -> Staged:
    """Copy ``final`` into a new ``destination`` without following any link out of it."""
    destination.mkdir()
    staged = Staged(destination)
    for directory, dirnames, filenames in os.walk(final, followlinks=False):
        base = Path(directory)
        relative = base.relative_to(final)
        for name in sorted(dirnames + filenames):
            source, target = base / name, destination / relative / name
            mode = os.lstat(source).st_mode
            if stat.S_ISLNK(mode):
                if _inside(final, source):
                    os.symlink(os.readlink(source), target)
                else:
                    staged.rejected.append((relative / name).as_posix())
                if name in dirnames:
                    dirnames.remove(name)
            elif stat.S_ISDIR(mode):
                target.mkdir()
            elif stat.S_ISREG(mode):
                _copy_file(source, target)
            else:
                staged.rejected.append((relative / name).as_posix())
    return staged


def reset(staged: Staged, protected: list[Protected], sealed: Path) -> None:
    """Restore every protected path from ``sealed`` and remove every cache directory."""
    for entry in protected:
        target = staged.root / entry.path
        if target.is_symlink() or target.is_file():
            target.unlink()
        elif target.is_dir():
            shutil.rmtree(target)
        copy_protected(sealed, entry, staged.root)
    for directory, dirnames, _ in os.walk(staged.root):
        for name in list(dirnames):
            if name in CACHE_NAMES:
                path = Path(directory) / name
                staged.removed_caches.append(path.relative_to(staged.root).as_posix())
                shutil.rmtree(path)
                dirnames.remove(name)


def _protected(contract: dict[str, Any]) -> list[Protected]:
    return [Protected(item["path"], item["kind"], tuple(item.get("exclude", ())))
            for item in contract["protected_paths"]]


def _trusted(contract: dict[str, Any], staged: Staged) -> tuple[str, str]:
    expected = [item["sha256"] for item in contract["protected_paths"]]
    measured = [protected_digest(staged.root, entry) for entry in _protected(contract)]
    return sha256(encode(expected)), sha256(encode(measured))


@dataclass(frozen=True)
class Graded:
    grade: dict[str, Any]
    grade_bytes: bytes
    envelope: bytes
    isolation: dict[str, Any]
    staging: dict[str, Any]


@dataclass(frozen=True)
class GradeContext:
    claim_id: str
    invocation_id: str
    producer: str = "harness-verifier"
    witness_scope: str = "PEER"


def _isolation(contract_sha256: str, trusted: tuple[str, str], runner: DockerRunner,
               commands: list[dict[str, Any]], steps: tuple[int, int], result_dir: Path,
               heldout_mode: str | None) -> dict[str, Any]:
    """The verifier's account of itself, in the fields ``docs/VERIFIER-ISOLATION.md`` names."""
    python_isolated = all(item["argv"][0] != "python" or bool({"-I", "-P"} & set(item["argv"]))
                          for item in commands)
    report: dict[str, Any] = {
        "contract_sha256": contract_sha256,
        "trusted_tree": {"expected_sha256": trusted[0], "measured_sha256": trusted[1],
                         "excluded_names_reset": True},
        "worker": {"uid": runner.worker_uid, "supplementary_groups": runner.groups(),
                   "env_scrubbed": True, "scratch_copy": True},
        "verifier": {"uid": os.getuid(), "assertions_in_parent": False,
                     "python_isolated": python_isolated},
        "result": {"dir_mode": format(stat.S_IMODE(os.stat(result_dir).st_mode), "04o"),
                   "precleared": True, "written_by": "verifier",
                   "files_read": ["container-exit-status"]},
        "tests": {"expected": len(commands), "collected": len(commands), "skipped": 0,
                  "exit_status_alone_accepted": True},
        "processes": {"worker_killed": True, "remaining": 0, "killed_step": steps[0],
                      "result_read_step": steps[1]},
        "staging": {"nofollow": True, "destination_removed_first": True,
                    "special_files_rejected": True},
        "evidence_from_worker": ["exit_status"],
        "loaders": [{"name": "container-exit-status", "safe": True}],
        "lockdown": {"runtime": runner.name, "image": runner.image, "flags": runner.flags()},
    }
    if heldout_mode is not None:
        report["reference"] = {"dir_mode": heldout_mode, "inside_artifact_dir": False}
    return report


def grade(contract_bytes: bytes, sealed: Path, final: Path, tree_record: dict[str, Any],
          context: GradeContext, runner: DockerRunner, key, timeout: float = 900.0) -> Graded:
    """Grade the agent's final tree ``final`` against the sealed contract."""
    contract = json.loads(contract_bytes)
    scanned = treedigest.scan(final)
    if scanned.sha256 != tree_record["tree_sha256"] or scanned.files != tree_record["files"]:
        raise GradeError("the final tree on disk is not the tree the record names")
    heldout = sealed / "heldout"
    has_heldout = heldout.is_dir()
    with tempfile.TemporaryDirectory(prefix="probity-verifier-") as work:
        result_dir = Path(work)
        os.chmod(result_dir, 0o700)
        staged = stage_tree(final, result_dir / "tree")
        reset(staged, _protected(contract), sealed / "protected")
        trusted = _trusted(contract, staged)
        if trusted[0] != trusted[1]:
            raise GradeError("protected paths do not match the contract after the reset")
        results = []
        for item in contract["acceptance"]:
            exit_code = runner.run(staged.root, item["argv"], heldout if has_heldout else None,
                                   timeout)
            results.append({"id": item["id"], "argv": item["argv"], "exit": exit_code})
        # Each run's container has exited (and with it every worker process) before its
        # exit status is read: kill is step 1, the read step 2, for every command.
        isolation = _isolation(sha256(contract_bytes), trusted, runner, contract["acceptance"],
                               (1, 2), result_dir,
                               format(0o755, "04o") if has_heldout else None)
        staging = {"rejected": staged.rejected, "removed_caches": staged.removed_caches}
    record = {"schema_version": GRADE_SCHEMA, "claim_id": context.claim_id,
              "invocation_id": context.invocation_id, "producer": context.producer,
              "vantage": "independent", "witness_scope": context.witness_scope,
              "contract_sha256": sha256(contract_bytes), "tree_sha256": tree_record["tree_sha256"],
              "results": results}
    data, envelope = sign_record(record, key)
    return Graded(record, data, envelope, isolation, staging)
