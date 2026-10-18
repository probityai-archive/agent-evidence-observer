"""The seal gates: a contract with a reference is sealed only when its tests are strong.

Each gate names the refusal reason it raises. ``trusted`` is the kill vector of the trusted
commands (the proposal's, the dataset's and the harvested guards); ``union`` adds the
synthesized held-out tests. ``neutralized`` marks frame-aware mutants whose every call the
sealed isolation plugin answered.

- ``null_patch_survived``: the null patch is killed by trusted commands.
- ``change_floor_unmet``: with ``n`` the change-set mutants (hunk reverts and mutants on changed
  lines), at most ``max(1, floor(0.2 n))`` survive when ``n >= 2`` and none when ``n == 1``,
  counting the union.
- ``hunk_revert_survived``: every hunk revert is killed by trusted commands.
- ``cheat_class_survived``: no any-eq, stateful or frame-aware mutant survives the union,
  apart from neutralized ones.
- ``harvest_guard_dropped``: every change and cheat mutant the kill matrix says the chosen
  guards kill is killed by the final measurement.

``no_stable_failing_command`` is raised earlier, when no stable visible command fails on the
start state.
"""

from __future__ import annotations

import math
from typing import Any, Sequence

from .mutants import Mutant

ORDER = ("null_patch_survived", "change_floor_unmet", "hunk_revert_survived",
         "cheat_class_survived", "harvest_guard_dropped")
FLOOR = 0.2


def change_limit(count: int) -> int:
    """How many change-set mutants may survive out of ``count``."""
    if count <= 1:
        return 0
    return max(1, math.floor(FLOOR * count))


def _indexes(found: Sequence[Mutant], *groups: str) -> list[int]:
    return [index for index, mutant in enumerate(found) if mutant.group in groups]


def evaluate(found: Sequence[Mutant], trusted: Sequence[bool], union: Sequence[bool],
             neutralized: Sequence[bool], expected: set[int] | None = None) -> dict[str, Any]:
    """Every gate's formula, its inputs and whether it holds."""
    null = _indexes(found, "null_patch")
    change = _indexes(found, "hunk_revert", "change")
    reverts = _indexes(found, "hunk_revert")
    cheats = _indexes(found, "cheat")
    survivors = [index for index in change if not union[index]]
    limit = change_limit(len(change))
    gates: dict[str, Any] = {
        "null_patch_survived": {
            "formula": "the null patch is killed by trusted commands",
            "mutants": len(null), "pass": all(trusted[index] for index in null)},
        "change_floor_unmet": {
            "formula": "survivors <= max(1, floor(0.2 n)) for n >= 2, 0 for n = 1; killed >= 1",
            "threshold": FLOOR, "n": len(change), "survivors": len(survivors), "limit": limit,
            "pass": len(survivors) <= limit and (not change or len(survivors) < len(change))},
        "hunk_revert_survived": {
            "formula": "every hunk revert is killed by trusted commands",
            "mutants": len(reverts),
            "survivors": sum(1 for index in reverts if not trusted[index]),
            "pass": all(trusted[index] for index in reverts)},
        "cheat_class_survived": {
            "formula": "no cheat-class mutant survives, apart from neutralized ones",
            "mutants": len(cheats),
            "neutralized": sum(1 for index in cheats if neutralized[index]),
            "survivors": sum(1 for index in cheats if not union[index] and not neutralized[index]),
            "pass": all(union[index] or neutralized[index] for index in cheats)},
    }
    if expected is not None:
        missing = sorted(index for index in expected if not union[index])
        gates["harvest_guard_dropped"] = {
            "formula": "the final measurement kills every change and cheat mutant the "
                       "chosen guards kill in the matrix",
            "expected": len(expected), "missing": missing, "pass": not missing}
    return gates


def failure(gates: dict[str, Any]) -> str | None:
    """The first gate that does not hold, in :data:`ORDER`."""
    return next((name for name in ORDER if name in gates and not gates[name]["pass"]), None)
