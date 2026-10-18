"""Guard tests from a repository's own suite, chosen by the mutants they kill.

The compiler offers the task's surviving mutants to the repository's existing tests:

1. **candidates.** Every test file the reference does not change is run once, traced, on the
   reference; it is a candidate when it loads a changed source. The trace also records which
   lines of the changed sources it ran (its coverage).
2. **stability.** Each candidate's tests are collected, then run three times on the start
   state and three times on the reference with the ``probity_outcome`` plugin; a node id is
   kept only when it passes every run on both.
3. **kill matrix.** Each surviving mutant is run against each candidate file once (only its
   stable node ids), and the node ids that fail on it kill it. A file that never ran an
   operator mutant's line on the reference cannot see that mutant and is skipped.
4. **greedy cover.** Node ids are picked one at a time by their kills among the mutants still
   alive, compared set by set in priority order (change, cheat classes, function, rest), ties
   to the shortest; picking stops when no node id kills another mutant.

The matrix only proposes node ids. The sealed numbers come from the compiler's final
measurement of the sealed commands, as graded.
"""

from __future__ import annotations

import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

from . import pytest_plugins
from .formats import encode, sha256
from .mutants import Mutant
from .runner import Runner

STABILITY_RUNS = 3
PRIORITY = (("null_patch", "hunk_revert", "change"), ("cheat",), ("function",), ("rest",))
GUARD_ID = "guard-repo"


@dataclass
class Harvest:
    """What the harvest found, and the record it leaves in ``compile.json``."""

    chosen: list[str] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    matrix: dict[str, list[int]] = field(default_factory=dict)
    record: dict[str, Any] = field(default_factory=dict)

    def kills(self, ids: Sequence[str]) -> set[int]:
        """The mutant indexes the matrix says ``ids`` kill between them."""
        return {index for node in ids for index in self.matrix.get(node, [])}


def _clean(state: Path, scratch: Path, name: str) -> Path:
    target = scratch / name
    shutil.copytree(state, target, symlinks=True, ignore=shutil.ignore_patterns("__pycache__"))
    return target


def _outcome_argv(prefix: Sequence[str], args: Sequence[str]) -> tuple[str, ...]:
    return tuple(prefix) + ("-p", "probity_outcome", *args)


def candidates(runner: Runner, reference: Path, heldout: Path | None, prefix: Sequence[str],
               tests: Sequence[str], sources: Sequence[str],
               timeout: float) -> tuple[list[str], dict[str, dict[str, list[int]]]]:
    """Test files whose traced run on the reference loads a changed source, and the lines of
    the changed sources each one ran."""
    found, coverage = [], {}
    with tempfile.TemporaryDirectory(prefix="probity-harvest-") as scratch:
        state = _clean(reference, Path(scratch), "reference")
        for name in tests:
            # Traced without isolation: an isolated function's lines run in a child process
            # the trace does not follow, and its operator mutants would read as unseen.
            argv = pytest_plugins.traced_argv(
                pytest_plugins.without_isolation(prefix) + (name,), sources)
            printed: list[str] = []
            if argv is None:
                continue
            runner.run(state, argv, heldout, timeout, output=printed)
            trace = pytest_plugins.trace(printed)
            if trace is not None and set(trace["reads"]) & set(sources):
                found.append(name)
                coverage[name] = trace["lines"]
    return found, coverage


def _collect(runner: Runner, state: Path, heldout: Path | None, prefix: Sequence[str],
             name: str, timeout: float) -> list[str]:
    printed: list[str] = []
    runner.run(state, tuple(prefix) + ("--collect-only", "--verbosity=-1", name), heldout, timeout,
               output=printed)
    return sorted({line.strip() for text in printed for line in text.splitlines()
                   if line.strip().startswith(name + "::")})


def stable_nodes(runner: Runner, start: Path, reference: Path, heldout: Path | None,
                 prefix: Sequence[str], files: Sequence[str], timeout: float
                 ) -> tuple[dict[str, list[str]], dict[str, float], list[dict[str, Any]]]:
    """Per file, the node ids that pass every run on both states; each node's seconds."""
    kept: dict[str, list[str]] = {}
    seconds: dict[str, float] = {}
    log: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="probity-harvest-") as scratch:
        states = {"start": _clean(start, Path(scratch), "start"),
                  "reference": _clean(reference, Path(scratch), "reference")}
        for name in files:
            nodes = _collect(runner, states["reference"], heldout, prefix, name, timeout)
            passing = set(nodes)
            for label, state in states.items():
                for _ in range(STABILITY_RUNS):
                    printed: list[str] = []
                    runner.run(state, _outcome_argv(prefix, [name]), heldout, timeout,
                               output=printed)
                    result = pytest_plugins.outcomes(printed)
                    passing &= {node for node, entry in result.items() if entry["passed"]}
                    if label == "reference":
                        for node, entry in result.items():
                            seconds[node] = max(seconds.get(node, 0.0), entry["seconds"])
            log.append({"file": name, "collected": len(nodes), "stable": len(passing)})
            if passing:
                kept[name] = sorted(passing)
    return kept, seconds, log


def _sees(mutant: Mutant, name: str, coverage: dict[str, dict[str, list[int]]]) -> bool:
    """Whether test file ``name`` can see ``mutant``: an operator mutant only through a file
    that ran its line on the reference; every other mutant through every candidate."""
    if mutant.kind != "operator" or mutant.operator == "hunk-revert":
        return True
    return mutant.line in coverage.get(name, {}).get(mutant.path, [])


def kill_matrix(runner: Runner, base: Path, heldout: Path | None, prefix: Sequence[str],
                nodes: dict[str, list[str]], coverage: dict[str, dict[str, list[int]]],
                found: list[Mutant], alive: Sequence[int], timeout: float
                ) -> tuple[dict[str, list[int]], int]:
    """Node id to the indexes (into ``found``) of the alive mutants it fails on, and how many
    file runs coverage skipped."""
    matrix: dict[str, list[int]] = {}
    skipped = 0
    with tempfile.TemporaryDirectory(prefix="probity-matrix-") as scratch:
        for index in alive:
            mutant = found[index]
            state = _clean(base, Path(scratch), f"m{index}")
            for name, text in mutant.files():
                (state / name).write_text(text)
            for name, ids in nodes.items():
                if not _sees(mutant, name, coverage):
                    skipped += 1
                    continue
                printed: list[str] = []
                runner.run(state, _outcome_argv(prefix, ids), heldout, timeout, output=printed)
                result = pytest_plugins.outcomes(printed)
                for node in ids:
                    if not result.get(node, {"passed": False})["passed"]:
                        matrix.setdefault(node, []).append(index)
            shutil.rmtree(state)
    return matrix, skipped


def greedy(matrix: dict[str, list[int]], found: list[Mutant], seconds: dict[str, float]
           ) -> list[dict[str, Any]]:
    """Node ids in pick order with each pick's marginal kills per priority group."""
    alive = {index for kills in matrix.values() for index in kills}
    order: list[dict[str, Any]] = []
    remaining = dict(matrix)
    while remaining:
        def score(node: str) -> tuple[tuple[int, ...], float, str]:
            kills = set(remaining[node]) & alive
            counts = tuple(sum(1 for index in kills if found[index].group in group)
                           for group in PRIORITY)
            return counts, -seconds.get(node, 0.0), node
        best = max(sorted(remaining), key=score)
        counts = score(best)[0]
        if not any(counts):
            break
        order.append({"id": best, "marginal": list(counts)})
        alive -= set(remaining.pop(best))
    return order


def harvest(runner: Runner, start: Path, reference: Path, heldout: Path | None,
            prefix: Sequence[str], tests: Sequence[str], sources: Sequence[str],
            found: list[Mutant], alive: Sequence[int], timeout: float) -> Harvest:
    """The guard node ids that kill the most of the ``alive`` mutants, with the record."""
    files, coverage = candidates(runner, reference, heldout, prefix, tests, sources, timeout)
    nodes, seconds, log = stable_nodes(runner, start, reference, heldout, prefix, files, timeout)
    matrix, skipped = kill_matrix(runner, reference, heldout, prefix, nodes, coverage, found,
                                  alive, timeout)
    order = greedy(matrix, found, seconds)
    chosen = [item["id"] for item in order]
    record = {"tests_traced": len(tests), "candidates": files, "stability": log,
              "coverage_sha256": sha256(encode(coverage)),
              "matrix_sha256": sha256(encode({node: sorted(kills)
                                              for node, kills in sorted(matrix.items())})),
              "matrix_runs_skipped_by_coverage": skipped, "offered": len(alive),
              "greedy": order}
    return Harvest(chosen, sorted({node.split("::", 1)[0] for node in chosen}), matrix, record)
