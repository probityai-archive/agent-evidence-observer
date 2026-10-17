"""The contract compiler: a task's definition of done, sealed before the agent's first turn.

A :class:`Task` names four states on disk: the agent's start (``start``), the reference
solution when the task has one (``reference``), and the held-out files the agent never sees
(``heldout``). It also names the acceptance commands, the protected paths and what the
mutator may change. :func:`seal` writes the contract bundle:

- ``contract.json``: the ``probity-done-contract/v1`` record, RFC 8785 bytes;
- ``contract.dsse.json``: a DSSE envelope over those bytes, signed by the harness key;
- ``contract.statement.json``: the in-toto Statement with the ``done-contract`` predicate
  type, unsigned (see :mod:`.formats`);
- ``workspace/``: the agent's start state;
- ``sealed/protected/`` and ``sealed/heldout/``: what only the verifier reads;
- ``compile.json``: how the contract was compiled (sources, stability runs, mutants).

SWE-bench and LiveCodeBench tasks are compiled from their dataset fields with no model
call. A real-repository task without dataset acceptance goes through :mod:`.zeroshot`.
"""

from __future__ import annotations

import json
import re
import shlex
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

from ..sensors import treedigest
from . import heldout as heldout_cases
from .formats import (CONTRACT_PREDICATE, DoneError, encode, sha256, sign_record,
                      statement)
from .runner import Command

SCHEMA = "probity-done-contract/v1"
EXCLUDE = ("__pycache__", ".pytest_cache")
DEFAULT_TEST_CMD = ("python", "-P", "-m", "pytest", "-p", "no:cacheprovider", "-q")
TEST_CONFIG = ("pytest.ini", "tox.ini", "setup.cfg")
_DIFF_FILE = re.compile(r"^diff --git a/(\S+) b/(\S+)$", re.MULTILINE)
_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", re.MULTILINE)


@dataclass(frozen=True)
class Protected:
    """A protected path; a directory may exclude segment names from its digest."""

    path: str
    kind: str
    exclude: tuple[str, ...] = ()


@dataclass
class Task:
    """Everything the compiler needs to seal one contract."""

    task_id: str
    source: str
    description: str
    start: Path
    commands: list[Command]
    protected: list[Protected]
    heldout: Path | None = None
    reference: Path | None = None
    mutation_targets: dict[str, list[tuple[int, int]]] = field(default_factory=dict)
    entry: dict[str, Any] | None = None
    notes: dict[str, Any] = field(default_factory=dict)


def touched_files(patch: str) -> list[str]:
    """Paths a unified git diff writes, in order of first appearance."""
    seen: list[str] = []
    for _, after in _DIFF_FILE.findall(patch):
        if after not in seen:
            seen.append(after)
    return seen


def touched_lines(patch: str) -> dict[str, list[tuple[int, int]]]:
    """For each file a diff writes, the new-side line ranges of its hunks."""
    ranges: dict[str, list[tuple[int, int]]] = {}
    for block in re.split(r"(?=^diff --git )", patch, flags=re.MULTILINE):
        names = _DIFF_FILE.findall(block)
        if not names:
            continue
        name = names[0][1]
        for start, count in _HUNK.findall(block):
            first = int(start)
            span = int(count) if count else 1
            ranges.setdefault(name, []).append((first, first + max(span, 1) - 1))
    return ranges


def apply_patch(root: Path, patch: str) -> None:
    """Apply a git diff to a directory, refusing a patch that does not apply cleanly."""
    if not patch.strip():
        return
    done = subprocess.run(["git", "apply", "--whitespace=nowarn", "-"], cwd=root,
                          input=patch.encode(), capture_output=True, check=False)
    if done.returncode != 0:
        raise DoneError(f"patch does not apply: {done.stderr.decode(errors='replace').strip()}")


def _tests(field_value: Any) -> list[str]:
    values = json.loads(field_value) if isinstance(field_value, str) else field_value
    if not isinstance(values, list) or any(not isinstance(item, str) for item in values):
        raise DoneError("FAIL_TO_PASS and PASS_TO_PASS must be lists of test ids")
    return values


def lcb_task(record: dict[str, Any], work: Path, fraction: float = 0.5) -> Task:
    """An ImpossibleBench LiveCodeBench task from its dataset fields."""
    task_id, entry = record["task_id"], record["entry_point"]
    split = heldout_cases.split_lcb(task_id, record["test"], record["original_test"], entry,
                                    fraction)
    start = work / "start"
    start.mkdir(parents=True)
    (start / "func.py").write_text(record["prompt"] + "\n    raise NotImplementedError\n")
    (start / "test.py").write_text(heldout_cases.visible_script(split.visible_test, entry))
    held = work / "heldout"
    held.mkdir()
    (held / heldout_cases.HELDOUT_NAME).write_text(split.heldout_source)
    expected = sorted({case.expected for case in heldout_cases.cases_of(
        heldout_cases.check_body(record["original_test"])[1])})
    return Task(
        task_id=task_id, source="lcb", description=f"implement {entry} in func.py",
        start=start, heldout=held,
        commands=[Command("visible", ("python", "test.py")),
                  Command("heldout", heldout_cases.HELDOUT_ARGV, heldout=True)],
        protected=[Protected("test.py", "file")],
        entry={"path": "func.py", "name": entry, "signature": record["prompt"],
               "expected": expected},
        notes={"impossible_type": record.get("impossible_type"),
               "visible_cases": split.visible_count, "heldout_cases": len(split.heldout)})


def _swe_protected(start: Path, tests: list[str], reference_touched: set[str],
                   protect_test_dirs: bool) -> list[Protected]:
    entries: dict[str, Protected] = {}
    for name in tests:
        entries[name] = Protected(name, "file")
    for path in sorted(start.rglob("conftest.py")):
        name = path.relative_to(start).as_posix()
        if not name.startswith(".git/"):
            entries[name] = Protected(name, "file")
    for name in TEST_CONFIG:
        if (start / name).is_file():
            entries[name] = Protected(name, "file")
    if protect_test_dirs:
        for directory in sorted({str(Path(name).parent) for name in tests} - {"."}):
            if any(item == directory or item.startswith(directory + "/")
                   for item in reference_touched):
                continue
            for name in [key for key in entries if key.startswith(directory + "/")]:
                del entries[name]
            entries[directory] = Protected(directory, "directory", EXCLUDE)
    kept = [entry for name, entry in sorted(entries.items()) if name not in reference_touched]
    return [entry for entry in kept
            if not any(other.kind == "directory" and entry.path.startswith(other.path + "/")
                       for other in kept)]


def swe_task(record: dict[str, Any], repo: Path, work: Path,
             test_cmd: Sequence[str] = DEFAULT_TEST_CMD, protect_test_dirs: bool = True) -> Task:
    """An (Impossible) SWE-bench task: ``repo`` is a checkout at ``base_commit``.

    ``test_cmd`` is the argv prefix the test ids are appended to; SWE-bench's own
    per-repository specification gives it. The held-out set is the task's original test
    patch, overlaid by the verifier from ``../heldout`` and never in the agent's tree.
    """
    fail, passing = _tests(record["FAIL_TO_PASS"]), _tests(record["PASS_TO_PASS"])
    start, reference, held = work / "start", work / "reference", work / "heldout"
    shutil.copytree(repo, start, symlinks=True)
    apply_patch(start, record["test_patch"])
    shutil.copytree(start, reference, symlinks=True)
    apply_patch(reference, record["patch"])
    original = work / "original"
    shutil.copytree(repo, original, symlinks=True)
    apply_patch(original, record.get("original_test_patch") or record["test_patch"])
    original_tests = touched_files(record.get("original_test_patch") or record["test_patch"])
    held.mkdir()
    for name in original_tests:
        if (original / name).is_file():
            (held / name).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(original / name, held / name)
    shutil.rmtree(original)
    reference_touched = set(touched_files(record["patch"]))
    tests = touched_files(record["test_patch"])
    prefix = tuple(test_cmd)
    commands = [Command("fail-to-pass", prefix + tuple(fail))]
    if passing:
        commands.append(Command("pass-to-pass", prefix + tuple(passing)))
    overlay = "cp -R ../heldout/. . && exec " + shlex.join(prefix + tuple(fail))
    commands.append(Command("heldout-fail-to-pass", ("sh", "-c", overlay), heldout=True))
    targets = {name: lines for name, lines in touched_lines(record["patch"]).items()
               if name.endswith(".py") and name not in tests}
    return Task(
        task_id=record["instance_id"], source="swe",
        description=f"resolve {record['instance_id']}", start=start, reference=reference,
        heldout=held, commands=commands,
        protected=_swe_protected(start, tests, reference_touched, protect_test_dirs),
        mutation_targets=targets,
        notes={"impossible_type": record.get("impossible_type"), "repo": record.get("repo"),
               "base_commit": record.get("base_commit")})


def protected_digest(root: Path, entry: Protected) -> str:
    """The digest a protected entry is sealed with: a file's SHA-256 or a tree digest."""
    target = root / entry.path
    if entry.kind == "file":
        if not target.is_file() or target.is_symlink():
            raise DoneError(f"protected file is missing: {entry.path}")
        return treedigest.file_sha256(target)
    files = {}
    for name, digest in treedigest.scan(target).files.items():
        if not set(name.split("/")) & set(entry.exclude):
            files[f"{entry.path}/{name}"] = digest
    return treedigest.tree_digest(files)


def copy_protected(root: Path, entry: Protected, destination: Path) -> None:
    """Copy one protected entry, without its excluded names, for the verifier's reset."""
    source, target = root / entry.path, destination / entry.path
    target.parent.mkdir(parents=True, exist_ok=True)
    if entry.kind == "file":
        shutil.copy2(source, target)
        return
    ignore = shutil.ignore_patterns(*entry.exclude) if entry.exclude else None
    shutil.copytree(source, target, symlinks=True, ignore=ignore)


def contract_record(task: Task, adequacy: dict[str, int], commands: list[Command],
                    heldout_sha256: str | None, mutant_sha256: str | None) -> dict[str, Any]:
    """The ``probity-done-contract/v1`` record for a compiled task."""
    record: dict[str, Any] = {
        "schema_version": SCHEMA, "contract_id": f"contract-{task.task_id}",
        "task": task.description,
        "protected_paths": [],
        "acceptance": [command.record() for command in commands],
        "adequacy": adequacy,
    }
    for entry in task.protected:
        item: dict[str, Any] = {"path": entry.path, "kind": entry.kind,
                                "sha256": protected_digest(task.start, entry)}
        if entry.exclude:
            item["exclude"] = list(entry.exclude)
        record["protected_paths"].append(item)
    if heldout_sha256 is not None:
        record["heldout_split_sha256"] = heldout_sha256
    if mutant_sha256 is not None:
        record["mutant_set_sha256"] = mutant_sha256
    return record


def heldout_digest(heldout: Path | None) -> str | None:
    if heldout is None:
        return None
    return treedigest.scan(heldout).sha256


@dataclass(frozen=True)
class Sealed:
    out: Path
    contract_sha256: str
    record: dict[str, Any]


def seal(task: Task, out: Path, key, adequacy: dict[str, int] | None = None,
         commands: list[Command] | None = None, mutant_sha256: str | None = None,
         report: dict[str, Any] | None = None) -> Sealed:
    """Write the contract bundle for ``task`` into an empty ``out`` and sign it."""
    out.mkdir(parents=True, exist_ok=True)
    if any(out.iterdir()):
        raise DoneError("contract output directory must be empty")
    commands = list(task.commands if commands is None else commands)
    if not [command for command in commands if not command.heldout]:
        raise DoneError("no visible acceptance command left to seal")
    adequacy = adequacy or {"mutants": 0, "killed": 0}
    record = contract_record(task, adequacy, commands, heldout_digest(task.heldout),
                             mutant_sha256)
    data, envelope = sign_record(record, key)
    digest = sha256(data)
    (out / "contract.json").write_bytes(data)
    (out / "contract.dsse.json").write_bytes(envelope)
    (out / "contract.statement.json").write_bytes(encode(statement(
        CONTRACT_PREDICATE, "contract.json", digest, record)))
    shutil.copytree(task.start, out / "workspace", symlinks=True)
    sealed = out / "sealed"
    (sealed / "protected").mkdir(parents=True)
    for entry in task.protected:
        copy_protected(task.start, entry, sealed / "protected")
    if task.heldout is not None:
        shutil.copytree(task.heldout, sealed / "heldout", symlinks=True)
    compiled = {"schema_version": "probity-done-compile/v1", "task_id": task.task_id,
                "source": task.source, "contract_sha256": digest, "model_calls": 0,
                "notes": task.notes, **(report or {})}
    (out / "compile.json").write_bytes(encode(compiled))
    return Sealed(out, digest, record)
