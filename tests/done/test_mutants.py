"""The AST operator mutator, degenerate mutants, and the adequacy field."""

import json

import pytest

from probity_observer.done import contract, mutants
from probity_observer.done.formats import DoneError
from probity_observer.done.runner import SubprocessRunner

from .conftest import LCB_ORIGINAL, LCB_RECORD

SOURCE = ("def f(a, b):\n    if a > b and b != 0:\n        return a + 1\n"
          "    while a < 0:\n        a = a * 2\n    return b\n")


def test_each_operator_changes_one_site():
    found = mutants.operator_mutants("m.py", SOURCE)
    operators = {mutant.operator for mutant in found}
    assert operators == set(mutants.OPERATORS) - {"string-mutate", "call-none"}
    assert len({mutant.source for mutant in found}) == len(found)
    assert all(mutant.source != SOURCE for mutant in found)


def test_mutants_stay_inside_the_touched_lines():
    found = mutants.operator_mutants("m.py", SOURCE, [(3, 3)])
    assert found and {mutant.line for mutant in found} == {3}


def test_degenerate_mutants_and_sampling_are_reproducible():
    found = mutants.degenerate_mutants("func.py", "def add(a, b):", "add", ["5", "2"])
    assert [mutant.operator for mutant in found] == [
        "null-patch", "return-none-body", "return-constant-0", "return-constant-1"]
    assert mutants.degenerate_mutants("func.py", "def other():", "add", []) == []
    many = mutants.operator_mutants("m.py", SOURCE)
    assert mutants.stratified([many], 3, "seed") == mutants.stratified([many], 3, "seed")
    assert len(mutants.stratified([many], 3, "seed")) == 3
    assert mutants.mutant_set_sha256(found) != mutants.mutant_set_sha256(found[:1])


def test_adequacy_counts_kills_and_is_sealed(tmp_path, harness, python_bin):
    runner = SubprocessRunner(python_bin)
    sealed = contract.compile_task(contract.lcb_task(LCB_ORIGINAL, tmp_path / "w"),
                                   tmp_path / "out", harness, runner, timeout=60)
    record = sealed.record
    assert record["adequacy"]["mutants"] == record["adequacy"]["killed"] >= 3
    assert "mutant_set_sha256" in record
    report = json.loads((sealed.out / "sealed" / "compile.json").read_bytes())
    assert len(report["adequacy"]["mutants"]) == record["adequacy"]["mutants"]
    vector = report["adequacy"]["kill_vector"]
    assert len(vector) == record["adequacy"]["mutants"] and all(vector)
    assert report["adequacy"]["killed_fraction"] == 1.0 and report["adequacy"]["kill_vector_sha256"]
    assert report["stability"]["reference"] == "unavailable"


def test_a_contract_with_no_failing_visible_command_is_refused(tmp_path, harness, python_bin):
    task = contract.lcb_task(LCB_RECORD, tmp_path / "w")
    task.commands = [contract.Command("visible", ("python", "-c", "pass"), prepatch="pass")]
    with pytest.raises(DoneError, match="fails on the start state") as caught:
        contract.compile_task(task, tmp_path / "out", harness, SubprocessRunner(python_bin),
                              timeout=60)
    assert caught.value.reason == "no_stable_failing_command"


def test_swe_operator_mutants_come_from_the_reference(tmp_path, swe_repo):
    repo, record = swe_repo
    task = contract.swe_task(record, repo, tmp_path / "w")
    plan = contract.task_mutants(task, 40)
    base, found = plan.base, plan.mutants
    assert base == task.reference and found
    assert {mutant.path for mutant in found} == {"pkg/shapes.py"}


def test_string_and_call_operators_skip_logging_and_docstrings():
    source = ('"""Module doc."""\nimport logging\nlog = logging.getLogger(__name__)\n\n\n'
              'def f(x):\n    """Doc."""\n    log.info("seen %s", x)\n    return str(x) + "!"\n')
    found = mutants.operator_mutants("m.py", source)
    operators = {mutant.operator for mutant in found}
    assert {"string-mutate", "call-none"} <= operators
    for mutant in found:
        assert '"""Doc."""' in mutant.source.replace("'Doc.'", '"""Doc."""')
        assert "log.info('seen %s', x)" in mutant.source or mutant.operator != "call-none" or \
            "log.info" in mutant.source


def load(source):
    namespace = {}
    exec(compile(source, "<mutant>", "exec"), namespace)  # test-only: run a generated mutant
    return namespace


def test_class_mutants_wrap_every_touched_function_and_method():
    source = ("def area(w, h):\n    return w * h\n\n\n"
              "class Box:\n    def volume(self, d):\n        return d * 2\n")
    found = mutants.class_mutants("m.py", source)
    assert sorted({mutant.operator for mutant in found}) == ["any-eq", "frame-aware", "stateful"]
    assert len(found) == 6
    any_eq = load(next(m.source for m in found if m.operator == "any-eq" and m.line == 1))
    assert any_eq["area"](2, 3) == "anything"
    stateful = load(next(m.source for m in found if m.operator == "stateful" and m.line == 1))
    assert stateful["area"](2, 3) == 6 and stateful["area"](2, 3) is None
    method = load(next(m.source for m in found if m.operator == "stateful" and m.line != 1))
    box = method["Box"]()
    assert box.volume(2) == 4 and box.volume(2) is None
    frame = load(next(m.source for m in found if m.operator == "frame-aware" and m.line == 1))

    def test_caller():
        return frame["area"](2, 3), frame["area"](2, 3)
    assert test_caller() == (6, None)

    def helper():
        return frame["area"](1, 1), frame["area"](1, 1)
    assert helper() == (1, 1)


def test_null_patch_is_mutant_zero_and_hunks_are_sampled_in_turn(tmp_path, swe_repo):
    repo, record = swe_repo
    task = contract.swe_task(record, repo, tmp_path / "w")
    plan = contract.task_mutants(task, 2)
    base, found = plan.base, plan.mutants
    assert found[0].operator == "null-patch" and found[0].source == (task.start / "pkg/shapes.py").read_text()
    assert {mutant.kind for mutant in found} >= {"null-patch", "operator", "any-eq", "stateful", "frame-aware"}
    a = mutants.operator_mutants("a.py", SOURCE, [(3, 3)])
    b = mutants.operator_mutants("b.py", SOURCE, [(5, 5)])
    picked = mutants.stratified([a * 5, b], 2, "s")
    assert {mutant.path for mutant in picked} == {"a.py", "b.py"}


def test_adequacy_reports_each_class_and_names_the_unkillable(tmp_path, python_bin):
    task = contract.lcb_task(LCB_ORIGINAL, tmp_path / "w")
    plan = contract.task_mutants(task, 40)
    base, found = plan.base, plan.mutants
    assert {mutant.operator for mutant in found} >= {"null-patch", "lookup-table"}
    result = mutants.measure(base, found, task.commands, SubprocessRunner(python_bin), task.heldout, 60)
    report = result.report()
    assert report["by_class"]["null-patch"] == {"mutants": 1, "killed": 1}
    assert report["by_class"]["lookup-table"]["killed"] == 1
    assert report["unkillable_classes"] == []


TRY = ('def g(text):\n    """Parse it."""\n    try:\n        value = int(text)\n'
       '    except ValueError:\n        return 0\n    except TypeError:\n        return -1\n'
       '    if value > 9:\n        value = 9\n    else:\n        value = value + 1\n'
       '    return value\n')


def test_statement_operators_delete_unwrap_and_drop_handlers_on_changed_lines_only():
    found = mutants.statement_mutants("m.py", TRY, set(range(1, 14)))
    by_operator = {}
    for mutant in found:
        by_operator.setdefault(mutant.operator, []).append(mutant)
    assert set(by_operator) == set(mutants.STATEMENT_OPERATORS)
    assert len(by_operator["handler-delete"]) == 2
    assert all(mutant.kind == "operator" for mutant in found)
    # The docstring is never a site: every mutant but the deleted function keeps it.
    assert all("Parse it." in mutant.source for mutant in found if mutant.line != 1)
    assert [mutant.operator for mutant in found if mutant.line == 1] == ["stmt-delete"]
    unwrapped = load(by_operator["try-unwrap"][0].source)
    with pytest.raises(ValueError):
        unwrapped["g"]("x")
    body = load(by_operator["if-unwrap-body"][0].source)
    assert body["g"]("3") == 9
    assert {mutant.line for mutant in mutants.statement_mutants("m.py", TRY, {10})} == {10}


def test_one_handler_is_never_deleted():
    source = "def h():\n    try:\n        return 1\n    except OSError:\n        return 2\n"
    operators = {mutant.operator for mutant in mutants.statement_mutants("m.py", source, {2})}
    assert "handler-delete" not in operators and "try-unwrap" in operators


def test_a_hunk_revert_puts_the_start_lines_back_unless_only_a_docstring_changed():
    start = 'def f(x):\n    """Old."""\n    return x\n'
    reference = 'def f(x):\n    """New."""\n    return x + 1\n'
    from probity_observer.done import changes
    found = mutants.hunk_reverts("m.py", start, reference, changes.changed_lines(start, reference).hunks)
    assert len(found) == 1 and "return x\n" in found[0].source and found[0].kind == "operator"
    docs_only = 'def f(x):\n    """New."""\n    return x\n'
    assert mutants.hunk_reverts("m.py", start, docs_only,
                                changes.changed_lines(start, docs_only).hunks) == []


def test_syntactic_duplicates_and_reference_equals_are_dropped_but_not_the_null_patch():
    reference = "x = 1\n"
    same = mutants.Mutant("m.py", "number-shift", 1, 0, "x = (1)\n")
    one = mutants.Mutant("m.py", "number-shift", 1, 0, "x = 2\n")
    twin = mutants.Mutant("m.py", "compare-swap", 1, 0, "x  =  2\n")
    null = mutants.Mutant("m.py", "null-patch", 0, 0, "x = 1\n")
    kept, dropped = mutants.deduplicate({"m.py": reference}, [null, same, one, twin])
    assert kept == [null, one] and dropped == 2


def test_task_mutants_carry_statement_mutants_reverts_and_the_dedup_count(tmp_path, swe_repo):
    repo, record = swe_repo
    task = contract.swe_task(record, repo, tmp_path / "w")
    plan = contract.task_mutants(task, 40)
    found, dropped = plan.mutants, plan.deduplicated
    assert "stmt-delete" in {mutant.operator for mutant in found}
    # The patch has one hunk, so its revert is the null patch again and is dropped.
    assert "hunk-revert" not in {mutant.operator for mutant in found} and dropped >= 1
    assert len({mutant.source for mutant in found}) == len(found)


WIDE = ('"""Module doc."""\nfrom __future__ import annotations\nimport functools\n\n\n'
        'def trace(fn):\n    @functools.wraps(fn)\n    def inner(*a, **k):\n        return fn(*a, **k)\n'
        '    return inner\n\n\n'
        '@trace\ndef decorated(x):\n    return x + 1\n\n\n'
        'async def later(x):\n    return x * 3\n\n\n'
        'def outer(x):\n    def nested(y):\n        return y - 1\n    return nested(x)\n\n\n'
        'class K:\n    @staticmethod\n    def s(x):\n        return x * 2\n\n'
        '    @classmethod\n    def c(cls, x):\n        return x * 5\n\n'
        '    @property\n    def p(self):\n        return 7\n')


def test_cheat_wrappers_cover_decorated_async_nested_static_and_class_methods():
    import asyncio
    found = mutants.class_mutants("m.py", WIDE)
    stateful = [mutant for mutant in found if mutant.operator == "stateful"]
    lines = {mutant.line for mutant in stateful}
    # trace, inner, decorated, later, outer, nested, s, c: every def except the property.
    assert len(stateful) == 8 and 38 not in lines and {14, 18, 22, 23, 30, 34} <= lines
    assert mutants.cheat_uncovered("m.py", WIDE) == [{"path": "m.py", "function": "K.p", "line": 38}]
    for mutant in stateful:
        assert mutant.source.index("from __future__") < mutant.source.index("_probity_cheat")
    by_line = {mutant.line: load(mutant.source) for mutant in stateful}
    space = by_line[14]
    assert space["decorated"](1) == 2 and space["decorated"](1) is None
    space = by_line[18]
    assert asyncio.run(space["later"](2)) == 6 and asyncio.run(space["later"](2)) is None
    space = by_line[22]
    assert space["outer"](3) == 2 and space["outer"](3) is None
    space = by_line[30]
    assert space["K"].s(2) == 4 and space["K"]().s(2) is None
    space = by_line[34]
    assert space["K"].c(1) == 5 and space["K"].c(1) is None
    any_eq = load(next(mutant.source for mutant in found
                       if mutant.operator == "any-eq" and mutant.line == 30))
    assert any_eq["K"].s(2) == "anything"


def test_cheat_counters_are_keyed_by_path_qualname_and_line():
    source = "class A:\n    def f(self):\n        return 1\n\n\nclass B:\n    def f(self):\n        return 2\n"
    found = [mutant for mutant in mutants.class_mutants("m.py", source) if mutant.operator == "stateful"]
    assert "('m.py', 'A.f', 2)" in found[0].source and "('m.py', 'B.f', 7)" in found[1].source


def test_touched_functions_meet_changed_lines_or_a_deletion_anchor():
    tree = __import__("ast").parse(WIDE)
    assert [item.qualname for item in mutants.touched(tree, [(15, 15)])] == ["decorated"]
    assert [item.qualname for item in mutants.touched(tree, [], (24,))] == ["outer", "outer.<locals>.nested"]
    assert [item.qualname for item in mutants.touched(tree, [(23, 23)])] == ["outer", "outer.<locals>.nested"]


def test_a_stateful_counter_survives_a_fresh_interpreter(tmp_path):
    import subprocess
    import sys
    source = "def f(x):\n    return x + 1\n"
    stateful = next(m for m in mutants.class_mutants("mod.py", source) if m.operator == "stateful")
    (tmp_path / "mod.py").write_text(stateful.source)
    call = [sys.executable, "-I", "-c", "import sys; sys.path.insert(0, '.'); import mod; print(mod.f(1))"]
    first = subprocess.run(call, cwd=tmp_path, capture_output=True, text=True, check=True)
    second = subprocess.run(call, cwd=tmp_path, capture_output=True, text=True, check=True)
    assert (first.stdout.strip(), second.stdout.strip()) == ("2", "None")


SPLIT_START = ("def kept(a):\n    return a - 1\n\n\n"
               "def fixed(a, b):\n    total = a + b\n    return total\n")
SPLIT_REFERENCE = ("def kept(a):\n    return a - 1\n\n\n"
                   "def fixed(a, b):\n    total = a + b\n    if total > 10:\n        total = 10\n"
                   "    return total\n")


def test_reference_mutants_are_split_into_change_function_rest_and_cheat_sets():
    from probity_observer.done import changes
    change = changes.changed_lines(SPLIT_START, SPLIT_REFERENCE)
    sets = contract.reference_sets("m.py", SPLIT_START, SPLIT_REFERENCE, change)
    assert change.lines() == {7, 8}
    assert sets["change"] and {mutant.line for mutant in sets["change"]} <= {7, 8}
    assert sets["function"] and {mutant.line for mutant in sets["function"]} <= {5, 6, 9}
    assert sets["rest"] and {mutant.line for mutant in sets["rest"]} <= {1, 2}
    assert {mutant.line for mutant in sets["cheat"]} == {5}
    assert len(sets["hunk_revert"]) == 1


def test_the_contract_seals_each_set_and_the_totals_still_sum(tmp_path, harness, swe_repo,
                                                               python_bin):
    from probity_verify.adapters import done_records
    repo, record = swe_repo
    task = contract.swe_task(record, repo, tmp_path / "w")
    plan = contract.task_mutants(task, 40)
    assert {mutant.group for mutant in plan.mutants} >= {"null_patch", "change", "cheat"}
    result = mutants.measure(plan.base, plan.mutants, task.commands[:1], SubprocessRunner(python_bin),
                             task.heldout, 60)
    field = result.field()
    assert sum(entry["mutants"] for entry in field["by_class"].values()) == field["mutants"]
    assert sum(entry["killed"] for entry in field["by_class"].values()) == field["killed"]
    assert set(result.report()["sets"]) == set(field["by_class"])
    assert all("kill_vector_sha256" in entry for entry in result.report()["sets"].values())
    sealed = contract.seal(task, tmp_path / "out", harness, field, task.commands,
                           mutants.mutant_set_sha256(plan.mutants))
    assert done_records.contract((sealed.out / "contract.json").read_bytes())["adequacy"] == field
    assert all("set" in mutant.binding() for mutant in plan.mutants)


def test_a_frame_aware_wrapper_of_an_isolated_function_is_neutralized_and_stateful_dies(
        tmp_path, swe_repo, python_bin):
    repo, record = swe_repo
    # The possible version of the task: the visible test is the original one.
    record = {**record, "test_patch": record["original_test_patch"]}
    task = contract.swe_task(record, repo, tmp_path / "w")
    plan = contract.task_mutants(task, 40)
    cheats = [mutant for mutant in plan.mutants if mutant.group == "cheat"]
    result = mutants.measure(plan.base, cheats, task.commands[:1], SubprocessRunner(python_bin),
                             task.heldout, 60)
    by_kind = {mutant.kind: (dead, run) for mutant, dead, run in zip(cheats, result.killed, result.runs)}
    dead, run = by_kind["frame-aware"]
    assert not dead and run["neutralized"] and run["isolated_calls"]["inline"] == 0
    assert by_kind["stateful"][0] is True
    assert result.neutralized() == [mutant.kind == "frame-aware" for mutant in cheats]
    assert mutants.isolate_targets(task.commands[0].argv) == ["pkg/shapes.py::area"]
