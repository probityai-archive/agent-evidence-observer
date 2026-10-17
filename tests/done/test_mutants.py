"""The AST operator mutator, degenerate mutants, and the adequacy field."""

import json

from probity_observer.done import contract, mutants
from probity_observer.done.runner import SubprocessRunner

from .conftest import LCB_ORIGINAL, LCB_RECORD

SOURCE = ("def f(a, b):\n    if a > b and b != 0:\n        return a + 1\n"
          "    while a < 0:\n        a = a * 2\n    return b\n")


def test_each_operator_changes_one_site():
    found = mutants.operator_mutants("m.py", SOURCE)
    operators = {mutant.operator for mutant in found}
    assert operators == set(mutants.OPERATORS)
    assert len({mutant.source for mutant in found}) == len(found)
    assert all(mutant.source != SOURCE for mutant in found)


def test_mutants_stay_inside_the_touched_lines():
    found = mutants.operator_mutants("m.py", SOURCE, [(3, 3)])
    assert found and {mutant.line for mutant in found} == {3}


def test_degenerate_mutants_and_sampling_are_reproducible():
    found = mutants.degenerate_mutants("func.py", "def add(a, b):", "add", ["5", "2"])
    assert [mutant.operator for mutant in found] == [
        "raise-not-implemented", "return-none", "return-constant-0", "return-constant-1"]
    assert mutants.degenerate_mutants("func.py", "def other():", "add", []) == []
    many = mutants.operator_mutants("m.py", SOURCE)
    assert mutants.sample(many, 3, "seed") == mutants.sample(many, 3, "seed")
    assert len(mutants.sample(many, 3, "seed")) == 3
    assert mutants.mutant_set_sha256(found) != mutants.mutant_set_sha256(found[:1])


def test_adequacy_counts_kills_and_is_sealed(tmp_path, harness, python_bin):
    runner = SubprocessRunner(python_bin)
    sealed = contract.compile_task(contract.lcb_task(LCB_ORIGINAL, tmp_path / "w"),
                                   tmp_path / "out", harness, runner, timeout=60)
    record = sealed.record
    assert record["adequacy"]["mutants"] == record["adequacy"]["killed"] >= 3
    assert "mutant_set_sha256" in record
    report = json.loads((sealed.out / "compile.json").read_bytes())
    assert len(report["adequacy"]["mutants"]) == record["adequacy"]["mutants"]
    vector = report["adequacy"]["kill_vector"]
    assert len(vector) == record["adequacy"]["mutants"] and all(vector)
    assert report["adequacy"]["killed_fraction"] == 1.0 and report["adequacy"]["kill_vector_sha256"]
    assert report["stability"]["reference"] == "unavailable"


def test_a_suite_that_kills_nothing_is_sealed_with_zero(tmp_path, harness, python_bin):
    task = contract.lcb_task(LCB_RECORD, tmp_path / "w")
    task.commands = [contract.Command("visible", ("python", "-c", "pass"), prepatch="pass")]
    sealed = contract.compile_task(task, tmp_path / "out", harness,
                                   SubprocessRunner(python_bin), timeout=60)
    assert sealed.record["adequacy"]["killed"] == 0 and sealed.record["adequacy"]["mutants"] > 0


def test_swe_operator_mutants_come_from_the_reference(tmp_path, swe_repo):
    repo, record = swe_repo
    task = contract.swe_task(record, repo, tmp_path / "w")
    base, found = contract.task_mutants(task, 40)
    assert base == task.reference and found
    assert {mutant.path for mutant in found} == {"pkg/shapes.py"}
