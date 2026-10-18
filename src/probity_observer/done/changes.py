"""The lines a change touches, from the two texts themselves.

A unified diff's hunk header spans its context lines too, so it is not the set of changed
lines. :func:`hunks` takes difflib's opcodes between the start text and the changed text, and
:func:`changed_lines` turns them into the new-side lines a mutant may sit on:

- a ``replace`` or ``insert`` opcode gives its new-side lines;
- a ``delete`` opcode leaves no new-side line, so its deletion point (the first new-side line
  after it) is recorded as an anchor, and the lines it stands for are the first statement at or
  after the anchor and the header of the innermost compound statement that encloses it.

The same function serves SWE-bench patches, real-repository references and the grader's
per-hunk check of an agent's patch.
"""

from __future__ import annotations

import ast
import difflib
from dataclasses import dataclass, field

Range = tuple[int, int]


@dataclass(frozen=True)
class Hunk:
    """One opcode: ``start[a:b]`` (0-based) became ``new[c:d]``."""

    tag: str
    start: tuple[int, int]
    new: tuple[int, int]


@dataclass(frozen=True)
class Changes:
    """The changed lines of one file (1-based, inclusive) and its deletion anchors."""

    ranges: tuple[Range, ...] = ()
    anchors: tuple[int, ...] = ()
    hunks: tuple[Hunk, ...] = field(default=(), compare=False)

    def lines(self) -> set[int]:
        return {line for first, last in self.ranges for line in range(first, last + 1)}

    def meets(self, first: int, last: int) -> bool:
        """Whether lines ``first`` to ``last`` meet a changed line or a deletion anchor."""
        return (any(start <= last and first <= end for start, end in self.ranges)
                or any(first <= anchor <= last for anchor in self.anchors))


def hunks(before: list[str], after: list[str]) -> list[Hunk]:
    """Every non-equal opcode between two line lists."""
    return [Hunk(tag, (i1, i2), (j1, j2))
            for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, before, after,
                                                               autojunk=False).get_opcodes()
            if tag != "equal"]


def new_side_ranges(found: list[Hunk]) -> list[Range]:
    """The new-side line range of each ``replace`` and ``insert`` opcode."""
    return [(hunk.new[0] + 1, hunk.new[1]) for hunk in found
            if hunk.tag in ("replace", "insert") and hunk.new[1] > hunk.new[0]]


def _deletion_lines(tree: ast.AST | None, anchor: int) -> set[int]:
    """The first statement at or after ``anchor`` and the header of the statement around it."""
    if tree is None:
        return set()
    statements = [node for node in ast.walk(tree) if isinstance(node, ast.stmt)]
    after = [node.lineno for node in statements if node.lineno >= anchor]
    found = {min(after)} if after else set()
    enclosing = [node for node in statements
                 if any(isinstance(getattr(node, name, None), list) for name in ("body", "orelse"))
                 and node.lineno < anchor <= (node.end_lineno or node.lineno)]
    if enclosing:
        found.add(max(enclosing, key=lambda node: node.lineno).lineno)
    return found


def changed_lines(before: str, after: str) -> Changes:
    """The changed new-side lines of ``after`` against ``before``, with deletion anchors."""
    old, new = before.splitlines(), after.splitlines()
    found = hunks(old, new)
    ranges = new_side_ranges(found)
    anchors = sorted({hunk.new[0] + 1 for hunk in found if hunk.tag == "delete"})
    try:
        tree: ast.AST | None = ast.parse(after)
    except SyntaxError:
        tree = None
    extra: set[int] = set()
    for anchor in anchors:
        extra |= _deletion_lines(tree, anchor)
    covered = {line for first, last in ranges for line in range(first, last + 1)}
    ranges += [(line, line) for line in sorted(extra - covered)]
    return Changes(tuple(sorted(ranges)), tuple(anchors), tuple(found))
