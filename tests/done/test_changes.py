"""Changed lines from the texts themselves: no context lines, and deletions anchored."""

from probity_observer.done import changes, mutants

BEFORE = ("def f(x):\n    a = 1\n    b = 2\n    c = 3\n    return a + b + c + x\n\n\n"
          "def g(y):\n    return y\n")


def test_a_replaced_line_is_the_only_changed_line():
    after = BEFORE.replace("    b = 2\n", "    b = 20\n")
    found = changes.changed_lines(BEFORE, after)
    assert found.ranges == ((3, 3),) and found.anchors == ()
    assert {mutant.line for mutant in mutants.operator_mutants("m.py", after, list(found.ranges))} == {3}


def test_inserted_lines_and_a_new_file_are_changed_lines():
    after = BEFORE.replace("    c = 3\n", "    c = 3\n    d = 4\n    e = 5\n")
    assert changes.changed_lines(BEFORE, after).ranges == ((5, 6),)
    assert changes.changed_lines("", "x = 1\ny = 2\n").ranges == ((1, 2),)


def test_a_pure_deletion_takes_the_next_statement_and_the_enclosing_header():
    after = BEFORE.replace("    b = 2\n", "")
    found = changes.changed_lines(BEFORE, after)
    assert found.anchors == (3,)
    # line 3 is now "c = 3", the first statement after the deletion; line 1 is the def.
    assert found.ranges == ((1, 1), (3, 3))
    assert found.meets(1, 5) and not found.meets(7, 8)


def test_the_hunks_name_both_sides():
    after = BEFORE.replace("    return y\n", "    return -y\n")
    (hunk,) = changes.hunks(BEFORE.splitlines(), after.splitlines())
    assert hunk.tag == "replace" and hunk.start == (8, 9) and hunk.new == (8, 9)
