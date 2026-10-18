"""The seal gates' formulas, one refusal reason each."""

from probity_observer.done import gates
from probity_observer.done.mutants import Mutant


def mutant(group, kind="number-shift"):
    return Mutant("m.py", kind, 1, 0, "x\n", group=group)


def test_change_limit_allows_a_fifth_but_none_of_one():
    assert [gates.change_limit(n) for n in (0, 1, 2, 5, 10, 11)] == [0, 0, 1, 1, 2, 2]


def check(found, trusted, union=None, neutralized=None, expected=None):
    union = trusted if union is None else union
    neutralized = neutralized or [False] * len(found)
    result = gates.evaluate(found, trusted, union, neutralized, expected)
    return gates.failure(result), result


def test_each_gate_names_its_refusal():
    null = mutant("null_patch", "null-patch")
    assert check([null], [False])[0] == "null_patch_survived"
    change = [mutant("change") for _ in range(5)]
    assert check([null] + change, [True, True, True, True, False, False])[0] == "change_floor_unmet"
    assert check([null] + change, [True, True, True, True, True, False])[0] is None
    assert check([null, mutant("change")], [True, False])[0] == "change_floor_unmet"
    revert = mutant("hunk_revert", "hunk-revert")
    # A revert killed only by synthesized tests is not enough.
    assert check([null, revert] + change, [True, False] + [True] * 5,
                 [True, True] + [True] * 5)[0] == "hunk_revert_survived"
    cheat = mutant("cheat", "frame-aware")
    assert check([null, cheat], [True, False])[0] == "cheat_class_survived"
    assert check([null, cheat], [True, False], neutralized=[False, True])[0] is None
    assert check([null, cheat], [True, False], [True, True])[0] is None
    assert check([null, cheat], [True, True], expected={0, 1})[0] is None
    failing, result = check([null, cheat], [True, False], neutralized=[False, True], expected={1})
    assert failing == "harvest_guard_dropped" and result["harvest_guard_dropped"]["missing"] == [1]


def test_function_and_rest_mutants_carry_no_floor():
    null = mutant("null_patch", "null-patch")
    assert check([null, mutant("function"), mutant("rest")], [True, False, False])[0] is None
