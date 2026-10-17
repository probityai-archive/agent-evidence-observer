"""The test of the test: mutants the acceptance commands must kill.

Two kinds of mutant are made, both without a model call:

- **operator mutants** of the reference solution, one AST change each, made only inside the
  line ranges the reference patch touched: comparison and arithmetic operators swapped,
  ``and``/``or`` swapped, a condition negated, a number shifted by one, a returned value
  replaced by ``None``;
- **degenerate mutants** of the entry function when the task has no reference (LiveCodeBench):
  the body replaced by ``raise NotImplementedError``, ``return None`` or a constant return of
  each expected value. A suite that one of these passes cannot tell a fix from a no-op.

A mutant is killed when any acceptance command (visible or held-out) exits nonzero on it.
``adequacy`` is ``{"mutants": n, "killed": k}``; a contract with ``killed: 0`` cannot support
a verdict of done. ``mutant_set_sha256`` binds every mutant by path, operator, location and
the digest of its source.
"""

from __future__ import annotations

import ast
import copy
import random
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator

from .formats import encode, sha256
from .runner import Command, Runner

_COMPARE_SWAP = {ast.Eq: ast.NotEq, ast.NotEq: ast.Eq, ast.Lt: ast.GtE, ast.GtE: ast.Lt,
                 ast.Gt: ast.LtE, ast.LtE: ast.Gt, ast.Is: ast.IsNot, ast.IsNot: ast.Is,
                 ast.In: ast.NotIn, ast.NotIn: ast.In}
_BINOP_SWAP = {ast.Add: ast.Sub, ast.Sub: ast.Add, ast.Mult: ast.FloorDiv, ast.Div: ast.Mult,
               ast.FloorDiv: ast.Mult, ast.Mod: ast.FloorDiv, ast.Pow: ast.Mult}


@dataclass(frozen=True)
class Mutant:
    path: str
    operator: str
    line: int
    column: int
    source: str

    def binding(self) -> dict[str, Any]:
        return {"path": self.path, "operator": self.operator, "line": self.line,
                "column": self.column, "sha256": sha256(self.source.encode("utf-8"))}


def _compare(node: ast.AST) -> ast.AST | None:
    if isinstance(node, ast.Compare) and type(node.ops[0]) in _COMPARE_SWAP:
        node.ops[0] = _COMPARE_SWAP[type(node.ops[0])]()
        return node
    return None


def _binop(node: ast.AST) -> ast.AST | None:
    if isinstance(node, ast.BinOp) and type(node.op) in _BINOP_SWAP:
        node.op = _BINOP_SWAP[type(node.op)]()
        return node
    return None


def _boolop(node: ast.AST) -> ast.AST | None:
    if isinstance(node, ast.BoolOp):
        node.op = ast.Or() if isinstance(node.op, ast.And) else ast.And()
        return node
    return None


def _negate(node: ast.AST) -> ast.AST | None:
    if isinstance(node, (ast.If, ast.While)):
        node.test = ast.UnaryOp(op=ast.Not(), operand=node.test)
        return node
    return None


def _number(node: ast.AST) -> ast.AST | None:
    if isinstance(node, ast.Constant) and type(node.value) in (int, float):
        node.value = node.value + 1
        return node
    return None


def _return_none(node: ast.AST) -> ast.AST | None:
    if isinstance(node, ast.Return) and node.value is not None and not (
            isinstance(node.value, ast.Constant) and node.value.value is None):
        node.value = ast.Constant(value=None)
        return node
    return None


OPERATORS: dict[str, Callable[[ast.AST], ast.AST | None]] = {
    "compare-swap": _compare, "binop-swap": _binop, "boolop-swap": _boolop,
    "negate-condition": _negate, "number-shift": _number, "return-none": _return_none,
}


def _within(node: ast.AST, ranges: list[tuple[int, int]] | None) -> bool:
    line = getattr(node, "lineno", None)
    if line is None:
        return False
    return ranges is None or any(first <= line <= last for first, last in ranges)


def _sites(tree: ast.AST, ranges: list[tuple[int, int]] | None) -> Iterator[tuple[int, str]]:
    for index, node in enumerate(ast.walk(tree)):
        if not _within(node, ranges):
            continue
        for name, operator in OPERATORS.items():
            if operator(copy.deepcopy(node)) is not None:
                yield index, name


def operator_mutants(path: str, source: str,
                     ranges: list[tuple[int, int]] | None = None) -> list[Mutant]:
    """Every one-change mutant of ``source`` inside ``ranges`` (all lines when ``None``)."""
    tree = ast.parse(source)
    original = ast.unparse(tree)
    found = []
    for index, name in _sites(tree, ranges):
        mutated = copy.deepcopy(tree)
        node = list(ast.walk(mutated))[index]
        OPERATORS[name](node)
        text = ast.unparse(ast.fix_missing_locations(mutated))
        if text != original:
            found.append(Mutant(path, name, node.lineno, node.col_offset, text + "\n"))
    return found


def degenerate_mutants(path: str, signature: str, name: str,
                       expected: list[str]) -> list[Mutant]:
    """Whole-function replacements a suite must reject: no-op, ``None`` and constants."""
    bodies = [("raise-not-implemented", "raise NotImplementedError"),
              ("return-none", "return None")]
    bodies += [(f"return-constant-{index}", f"return {value}") for index, value in enumerate(expected)]
    found = []
    for operator, body in bodies:
        text = f"{signature}\n    {body}\n"
        tree = ast.parse(text)
        if not any(isinstance(node, ast.FunctionDef) and node.name == name for node in tree.body):
            continue
        found.append(Mutant(path, operator, 1, 0, text))
    return found


def sample(mutants: list[Mutant], limit: int, seed: str) -> list[Mutant]:
    """At most ``limit`` mutants, chosen reproducibly from ``seed``; order kept."""
    if len(mutants) <= limit:
        return mutants
    chosen = set(random.Random(int(sha256(seed.encode()), 16)).sample(range(len(mutants)), limit))
    return [mutant for index, mutant in enumerate(mutants) if index in chosen]


def mutant_set_sha256(mutants: list[Mutant]) -> str:
    return sha256(encode([mutant.binding() for mutant in mutants]))


@dataclass(frozen=True)
class Adequacy:
    mutants: list[Mutant]
    killed: list[bool]
    runs: list[dict[str, Any]]

    def field(self) -> dict[str, int]:
        return {"mutants": len(self.mutants), "killed": sum(self.killed)}

    def report(self) -> dict[str, Any]:
        return {"mutants": [{**mutant.binding(), "killed": killed, "exits": run["exits"]}
                            for mutant, killed, run in zip(self.mutants, self.killed, self.runs)]}


def measure(base: Path, mutants: list[Mutant], commands: list[Command], runner: Runner,
            heldout: Path | None, timeout: float = 900.0) -> Adequacy:
    """Run every command on every mutant of ``base``; a nonzero exit kills it."""
    killed, runs = [], []
    with tempfile.TemporaryDirectory(prefix="probity-mutant-") as scratch:
        for index, mutant in enumerate(mutants):
            state = Path(scratch) / f"m{index}"
            shutil.copytree(base, state, symlinks=True)
            (state / mutant.path).write_text(mutant.source)
            exits = []
            for command in commands:
                exits.append(runner.run(state, command.argv, heldout, timeout))
                if exits[-1] != 0:
                    break
            killed.append(any(code != 0 for code in exits))
            runs.append({"exits": exits})
            shutil.rmtree(state)
    return Adequacy(mutants, killed, runs)
