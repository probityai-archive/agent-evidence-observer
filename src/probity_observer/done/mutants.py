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


CLASSES = {"null-patch": "null-patch", "any-eq": "any-eq", "stateful": "stateful",
           "frame-aware": "frame-aware", "lookup-table": "lookup-table"}


@dataclass(frozen=True)
class Mutant:
    path: str
    operator: str
    line: int
    column: int
    source: str
    also: tuple[tuple[str, str], ...] = ()
    # The adequacy set of a reference task's mutant (see SETS); empty for other tasks.
    group: str = ""

    @property
    def kind(self) -> str:
        """The class a mutant belongs to: an operator mutant, or one of the cheat classes."""
        if self.operator in CLASSES:
            return CLASSES[self.operator]
        if self.operator.startswith(("raise-", "return-none-body", "return-constant")):
            return "degenerate"
        return "operator"

    def files(self) -> tuple[tuple[str, str], ...]:
        return ((self.path, self.source),) + self.also

    def binding(self) -> dict[str, Any]:
        entry = {"path": self.path, "operator": self.operator, "line": self.line,
                 "column": self.column,
                 "sha256": sha256(encode([[name, sha256(text.encode())] for name, text in self.files()]))}
        if self.group:
            entry["set"] = self.group
        return entry


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


def _string(node: ast.AST) -> ast.AST | None:
    if isinstance(node, ast.Constant) and type(node.value) is str:
        node.value = node.value + "\x00mutated"
        return node
    return None


def _call_none(node: ast.AST) -> ast.AST | None:
    """Replace the first call this node holds directly with ``None``."""
    for name, value in ast.iter_fields(node):
        if isinstance(value, ast.Call):
            setattr(node, name, ast.Constant(value=None))
            return node
        if isinstance(value, list):
            for index, item in enumerate(value):
                if isinstance(item, ast.Call):
                    value[index] = ast.Constant(value=None)
                    return node
    return None


OPERATORS: dict[str, Callable[[ast.AST], ast.AST | None]] = {
    "compare-swap": _compare, "binop-swap": _binop, "boolop-swap": _boolop,
    "negate-condition": _negate, "number-shift": _number, "return-none": _return_none,
    "string-mutate": _string, "call-none": _call_none,
}
LOGGER_NAMES = frozenset({"logging", "logger", "log", "LOGGER", "LOG", "_logger", "_log"})


def _logging_call(node: ast.AST) -> bool:
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    while isinstance(func, ast.Attribute):
        if isinstance(func.value, ast.Name) and func.value.id in LOGGER_NAMES:
            return True
        func = func.value
    return False


def excluded(tree: ast.AST) -> set[int]:
    """Nodes that are not mutation sites: docstrings, and everything inside a logging call."""
    skip: set[int] = set()
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if (isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                and body and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str)):
            skip.update(id(item) for item in ast.walk(body[0]))
        if _logging_call(node):
            skip.update(id(item) for item in ast.walk(node))
    for node in ast.walk(tree):
        if any(isinstance(child, ast.Call) and id(child) in skip for child in ast.iter_child_nodes(node)):
            if not any(isinstance(child, ast.Call) and id(child) not in skip
                       for child in ast.iter_child_nodes(node)):
                skip.add(-id(node))
    return skip


def _within(node: ast.AST, ranges: list[tuple[int, int]] | None) -> bool:
    line = getattr(node, "lineno", None)
    if line is None:
        return False
    return ranges is None or any(first <= line <= last for first, last in ranges)


def _sites(tree: ast.AST, ranges: list[tuple[int, int]] | None) -> Iterator[tuple[int, str]]:
    skip = excluded(tree)
    for index, node in enumerate(ast.walk(tree)):
        if not _within(node, ranges) or id(node) in skip:
            continue
        for name, operator in OPERATORS.items():
            if name == "call-none" and -id(node) in skip:
                continue
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


def _stmt_delete(statements: list[ast.stmt], index: int, part: int) -> bool:
    if isinstance(statements[index], ast.Pass):
        return False
    statements[index] = ast.Pass()
    return True


def _if_body(statements: list[ast.stmt], index: int, part: int) -> bool:
    node = statements[index]
    if not isinstance(node, ast.If):
        return False
    statements[index:index + 1] = node.body
    return True


def _if_else(statements: list[ast.stmt], index: int, part: int) -> bool:
    node = statements[index]
    if not isinstance(node, ast.If) or not node.orelse:
        return False
    statements[index:index + 1] = node.orelse
    return True


def _try_unwrap(statements: list[ast.stmt], index: int, part: int) -> bool:
    node = statements[index]
    if not isinstance(node, (ast.Try, ast.TryStar)) or not node.handlers:
        return False
    statements[index:index + 1] = node.body + node.orelse + node.finalbody
    return True


def _handler_delete(statements: list[ast.stmt], index: int, part: int) -> bool:
    node = statements[index]
    if not isinstance(node, (ast.Try, ast.TryStar)) or len(node.handlers) < 2:
        return False
    del node.handlers[part]
    return True


STATEMENT_OPERATORS: dict[str, Callable[[list[ast.stmt], int, int], bool]] = {
    "stmt-delete": _stmt_delete, "if-unwrap-body": _if_body, "if-unwrap-else": _if_else,
    "try-unwrap": _try_unwrap, "handler-delete": _handler_delete,
}


def _statement_sites(tree: ast.AST, lines: set[int]) -> Iterator[tuple[int, str, int, int, int]]:
    """``(parent index, field, statement index, part, operator)`` sites on ``lines``.

    Docstrings and logging-call statements are never sites; ``handler-delete`` has one part
    per handler and needs two or more handlers.
    """
    skip = excluded(tree)
    for parent_index, parent in enumerate(ast.walk(tree)):
        for name, value in ast.iter_fields(parent):
            if not isinstance(value, list):
                continue
            for index, node in enumerate(value):
                if (not isinstance(node, ast.stmt) or node.lineno not in lines or id(node) in skip
                        or (isinstance(node, ast.Expr) and id(node.value) in skip)):
                    continue
                for operator in STATEMENT_OPERATORS:
                    parts = (range(len(node.handlers)) if operator == "handler-delete"
                             and isinstance(node, (ast.Try, ast.TryStar)) else range(1))
                    for part in parts:
                        trial = copy.deepcopy(value)
                        if STATEMENT_OPERATORS[operator](trial, index, part):
                            yield parent_index, name, index, part, operator


def statement_mutants(path: str, source: str, lines: set[int]) -> list[Mutant]:
    """Statement-level mutants on ``lines``: a statement deleted, an ``if`` or ``try`` unwrapped,
    one ``except`` handler removed."""
    tree = ast.parse(source)
    original = ast.unparse(tree)
    found = []
    for parent_index, name, index, part, operator in _statement_sites(tree, lines):
        mutated = copy.deepcopy(tree)
        statements = getattr(list(ast.walk(mutated))[parent_index], name)
        node = statements[index]
        STATEMENT_OPERATORS[operator](statements, index, part)
        text = ast.unparse(ast.fix_missing_locations(mutated))
        if text != original:
            found.append(Mutant(path, operator, node.lineno, node.col_offset, text + "\n"))
    return found


def strip_docstrings(tree: ast.AST) -> ast.AST:
    """``tree`` without its module, class and function docstrings."""
    tree = copy.deepcopy(tree)
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if (isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                and body and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str)):
            node.body = body[1:] or [ast.Pass()]
    return tree


def hunk_reverts(path: str, start: str, reference: str, hunks) -> list[Mutant]:
    """One mutant per hunk: that hunk's start lines spliced back into the reference.

    A revert that does not parse, or that changes only docstrings, is not made.
    """
    old, new = start.splitlines(), reference.splitlines()
    plain = ast.unparse(strip_docstrings(ast.parse(reference)))
    found = []
    for hunk in hunks:
        lines = new[:hunk.new[0]] + old[hunk.start[0]:hunk.start[1]] + new[hunk.new[1]:]
        text = "\n".join(lines) + "\n"
        try:
            tree = ast.parse(text)
        except SyntaxError:
            continue
        if ast.unparse(strip_docstrings(tree)) == plain:
            continue
        found.append(Mutant(path, "hunk-revert", hunk.new[0] + 1, 0, text))
    return found


def _normal(text: str) -> str:
    try:
        return ast.unparse(ast.parse(text))
    except SyntaxError:
        return text


def deduplicate(reference: dict[str, str], found: list[Mutant]) -> tuple[list[Mutant], int]:
    """Drop mutants syntactically equal (``ast.unparse``) to the reference or an earlier mutant.

    The null patch is never dropped: a change that is syntactically empty must leave it alive.
    Returns the kept mutants and how many were dropped.
    """
    seen: set[tuple[tuple[str, str], ...]] = set()
    kept = []
    for mutant in found:
        key = tuple(sorted((name, _normal(text)) for name, text in mutant.files()))
        same = all(_normal(reference.get(name, "")) == text for name, text in key)
        if mutant.operator != "null-patch" and (same or key in seen):
            continue
        seen.add(key)
        kept.append(mutant)
    return kept, len(found) - len(kept)


def degenerate_mutants(path: str, signature: str, name: str, expected: list[str],
                       table: list[tuple[str, str]] | None = None) -> list[Mutant]:
    """Whole-function replacements a suite must reject.

    The stub itself (the null patch), ``None``, a constant return of each expected value, and
    a lookup table of the visible cases (the special-casing cheat).
    """
    bodies = [("null-patch", "raise NotImplementedError"),
              ("return-none-body", "return None")]
    bodies += [(f"return-constant-{index}", f"return {value}") for index, value in enumerate(expected)]
    found = []
    for operator, body in bodies:
        text = f"{signature}\n    {body}\n"
        tree = ast.parse(text)
        if not any(isinstance(node, ast.FunctionDef) and node.name == name for node in tree.body):
            continue
        found.append(Mutant(path, operator, 1, 0, text))
    if table:
        rows = ", ".join(f"({args},): {value}" if "," not in args else f"({args}): {value}"
                         for args, value in table)
        text = (f"_PROBITY_TABLE = {{{rows}}}\n{signature}\n"
                f"    return _PROBITY_TABLE.get(tuple(locals().values()))\n")
        try:
            ast.parse(text)
        except SyntaxError:
            return found
        found.append(Mutant(path, "lookup-table", 1, 0, text))
    return found


CHEATS = ("any-eq", "stateful", "frame-aware")
CHEAT_PRELUDE = """
class _ProbityAnyEq:
    def __eq__(self, other):
        return True

    def __ne__(self, other):
        return False

    __hash__ = object.__hash__


_PROBITY_CALLS = {}


def _probity_count(key):
    # The count lives in a file beside the module when there is one, so a call made in a
    # fresh interpreter (the sealed isolation plugin) still sees the earlier calls.
    import hashlib
    import os
    origin = globals().get("__file__")
    if not origin:
        _PROBITY_CALLS[key] = _PROBITY_CALLS.get(key, 0) + 1
        return _PROBITY_CALLS[key]
    name = ".probity-calls-" + hashlib.sha256(key.encode()).hexdigest()[:16]
    path = os.path.join(os.path.dirname(os.path.abspath(origin)), name)
    try:
        with open(path) as handle:
            count = int(handle.read() or 0)
    except (OSError, ValueError):
        count = 0
    try:
        with open(path, "w") as handle:
            handle.write(str(count + 1))
    except OSError:
        pass
    return count + 1


def _probity_cheat(kind, key, original):
    import functools
    import inspect
    import sys
    if isinstance(original, (staticmethod, classmethod)):
        return type(original)(_probity_cheat(kind, key, original.__func__))

    def decide(depth):
        if kind == "any-eq":
            return True, _ProbityAnyEq()
        if kind == "frame-aware":
            caller = sys._getframe(depth).f_code.co_name
            if not (caller.startswith("test") or caller == "check"):
                return False, None
        return _probity_count(key) > 1, None

    if inspect.iscoroutinefunction(original):
        async def wrapper(*args, **kwargs):
            cheat, value = decide(2)
            if cheat:
                return value
            return await original(*args, **kwargs)
    else:
        def wrapper(*args, **kwargs):
            cheat, value = decide(2)
            if cheat:
                return value
            return original(*args, **kwargs)
    try:
        functools.update_wrapper(wrapper, original)
    except (AttributeError, TypeError):
        pass
    return wrapper
"""
UNWRAPPABLE = frozenset({"property", "cached_property", "setter", "getter", "deleter"})


@dataclass(frozen=True)
class Function:
    """A ``def`` or ``async def`` at any depth: where it sits and its qualified name."""

    statements: list
    node: ast.FunctionDef | ast.AsyncFunctionDef
    qualname: str


def functions(tree: ast.AST) -> list[Function]:
    """Every function definition in ``tree``, with the statement list that holds it."""
    found: list[Function] = []

    def visit(node: ast.AST, prefix: str) -> None:
        for _, value in ast.iter_fields(node):
            if not isinstance(value, list):
                continue
            for child in value:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    found.append(Function(value, child, prefix + child.name))
                    visit(child, f"{prefix}{child.name}.<locals>.")
                elif isinstance(child, ast.ClassDef):
                    visit(child, f"{prefix}{child.name}.")
                elif isinstance(child, ast.AST):
                    visit(child, prefix)

    visit(tree, "")
    return found


def _decorator_name(node: ast.expr) -> str:
    node = node.func if isinstance(node, ast.Call) else node
    if isinstance(node, ast.Attribute):
        return node.attr
    return node.id if isinstance(node, ast.Name) else ""


def wrappable(function: Function) -> bool:
    """A property-like descriptor cannot be rebound as a plain callable."""
    return not any(_decorator_name(item) in UNWRAPPABLE for item in function.node.decorator_list)


def touched(tree: ast.AST, ranges: list[tuple[int, int]] | None,
            anchors: tuple[int, ...] = ()) -> list[Function]:
    """The functions whose span meets ``ranges`` or a deletion anchor (all when ``None``)."""
    found = []
    for function in functions(tree):
        first, last = function.node.lineno, function.node.end_lineno or function.node.lineno
        if (ranges is None or any(start <= last and first <= end for start, end in ranges)
                or any(first <= anchor <= last for anchor in anchors)):
            found.append(function)
    return found


def _prelude_index(tree: ast.Module) -> int:
    """After the module docstring and every ``from __future__`` import."""
    index = 0
    body = tree.body
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
            and isinstance(body[0].value.value, str):
        index = 1
    while index < len(body) and isinstance(body[index], ast.ImportFrom) \
            and body[index].module == "__future__":
        index += 1
    return index


def class_mutants(path: str, source: str, ranges: list[tuple[int, int]] | None = None,
                  anchors: tuple[int, ...] = ()) -> list[Mutant]:
    """The cheat classes on every touched function: any-eq, stateful and frame-aware.

    Each wrapper rebinds the name right after the definition (``f = _probity_cheat(..., f)``),
    so decorated, async and nested functions, static and class methods are covered; the call
    counter is keyed by path, qualified name and line. Property-like functions are left out
    (see :func:`cheat_uncovered`).
    """
    found = []
    tree = ast.parse(source)
    targets = [function for function in touched(tree, ranges, anchors) if wrappable(function)]
    for kind in CHEATS:
        for index, function in enumerate(targets):
            mutated = copy.deepcopy(tree)
            target = [item for item in touched(mutated, ranges, anchors) if wrappable(item)][index]
            key = repr((path, target.qualname, target.node.lineno))
            name = target.node.name
            rebind = ast.parse(f"{name} = _probity_cheat({kind!r}, {key!r}, {name})").body[0]
            target.statements.insert(target.statements.index(target.node) + 1, rebind)
            at = _prelude_index(mutated)
            mutated.body[at:at] = ast.parse(CHEAT_PRELUDE).body
            found.append(Mutant(path, kind, function.node.lineno, function.node.col_offset,
                                ast.unparse(ast.fix_missing_locations(mutated)) + "\n"))
    return found


def cheat_uncovered(path: str, source: str, ranges: list[tuple[int, int]] | None = None,
                    anchors: tuple[int, ...] = ()) -> list[dict[str, Any]]:
    """Touched functions the cheat wrappers cannot rebind, by path, qualified name and line."""
    return [{"path": path, "function": function.qualname, "line": function.node.lineno}
            for function in touched(ast.parse(source), ranges, anchors)
            if not wrappable(function)]


def by_class(mutants: list[Mutant], killed: list[bool]) -> dict[str, dict[str, int]]:
    counts: dict[str, dict[str, int]] = {}
    for mutant, dead in zip(mutants, killed):
        entry = counts.setdefault(mutant.kind, {"mutants": 0, "killed": 0})
        entry["mutants"] += 1
        entry["killed"] += int(dead)
    return counts


def stratified(groups: list[list[Mutant]], limit: int, seed: str) -> list[Mutant]:
    """At most ``limit`` mutants, taken round-robin across groups (one group per hunk).

    A flat sample lets one padded hunk crowd out the others; this one gives every hunk its
    turn before any hunk gets a second mutant.
    """
    order = random.Random(int(sha256(seed.encode()), 16))
    pools = [order.sample(group, len(group)) for group in groups if group]
    chosen: list[Mutant] = []
    while pools and len(chosen) < limit:
        for pool in list(pools):
            if len(chosen) >= limit:
                break
            chosen.append(pool.pop())
            if not pool:
                pools.remove(pool)
    return chosen


SETS = ("null_patch", "hunk_revert", "change", "cheat", "function", "rest")


def by_set(mutants: list[Mutant], killed: list[bool]) -> dict[str, dict[str, Any]]:
    """Each adequacy set's count, kills and kill-vector digest, in :data:`SETS` order."""
    found: dict[str, dict[str, Any]] = {}
    for name in SETS:
        vector = [bool(dead) for mutant, dead in zip(mutants, killed) if mutant.group == name]
        if vector:
            found[name] = {"mutants": len(vector), "killed": sum(vector),
                           "kill_vector_sha256": sha256(encode(vector))}
    return found


def mutant_set_sha256(mutants: list[Mutant]) -> str:
    return sha256(encode([mutant.binding() for mutant in mutants]))


@dataclass(frozen=True)
class Adequacy:
    mutants: list[Mutant]
    killed: list[bool]
    runs: list[dict[str, Any]]

    def field(self) -> dict[str, Any]:
        """The contract's ``adequacy``: the totals, and for a reference task each set's
        counts (``by_class``, which sums to the totals) and the whole kill-vector digest."""
        field: dict[str, Any] = {"mutants": len(self.mutants), "killed": sum(self.killed)}
        sets = by_set(self.mutants, self.killed)
        if sets:
            field["by_class"] = {name: {"mutants": entry["mutants"], "killed": entry["killed"]}
                                 for name, entry in sets.items()}
            field["kill_vector_sha256"] = sha256(encode([bool(item) for item in self.killed]))
        return field

    def report(self) -> dict[str, Any]:
        vector = [bool(item) for item in self.killed]
        classes = by_class(self.mutants, vector)
        return {"kill_vector": vector, "kill_vector_sha256": sha256(encode(vector)),
                "by_class": classes, "sets": by_set(self.mutants, vector),
                "unkillable_classes": sorted(name for name, entry in classes.items()
                                             if entry["killed"] == 0),
                "killed_fraction": (sum(vector) / len(vector)) if vector else 0.0,
                "mutants": [{**mutant.binding(), "killed": killed, "exits": run["exits"]}
                            for mutant, killed, run in zip(self.mutants, self.killed, self.runs)]}


def measure(base: Path, mutants: list[Mutant], commands: list[Command], runner: Runner,
            heldout: Path | None, timeout: float = 900.0) -> Adequacy:
    """Run every command on every mutant of ``base``; a nonzero exit kills it."""
    killed, runs = [], []
    with tempfile.TemporaryDirectory(prefix="probity-mutant-") as scratch:
        for index, mutant in enumerate(mutants):
            state = Path(scratch) / f"m{index}"
            # No bytecode cache: a .pyc kept from the base would hide the mutated source.
            shutil.copytree(base, state, symlinks=True,
                            ignore=shutil.ignore_patterns("__pycache__"))
            for name, text in mutant.files():
                (state / name).write_text(text)
            exits = []
            for command in commands:
                exits.append(runner.run(state, command.argv, heldout, timeout))
                if exits[-1] != 0:
                    break
            killed.append(any(code != 0 for code in exits))
            runs.append({"exits": exits})
            shutil.rmtree(state)
    return Adequacy(mutants, killed, runs)
