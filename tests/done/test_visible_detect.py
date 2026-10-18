"""The visible-test detectors on real runs: the vectors in data/visible-detectors.json through the
facts runs and the frozen rules, and the edges of the orchestration."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from probity_observer.done import contract, heldout, visible_detect
from probity_observer.done.runner import SubprocessRunner

from .conftest import LCB_ORIGINAL, LCB_RECORD

VECTORS = json.loads((Path(__file__).with_name("data") / "visible-detectors.json").read_text())["vectors"]
TASKS = {"original": LCB_ORIGINAL, "conflicting": LCB_RECORD}


def task_tree(tmp_path: Path, record: dict, source: str):
    task = contract.lcb_task(record, tmp_path / "task")
    assert task.heldout is not None
    root = tmp_path / "tree"
    shutil.copytree(task.start, root)
    (root / "func.py").write_text(source)
    return task, root, task.heldout


def detect(tmp_path, python_bin, task_name, source, test_py=None):
    task, root, sealed = task_tree(tmp_path, TASKS[task_name], source)
    prompt = (task.start / "func.py").read_text()
    return visible_detect.detect(SubprocessRunner(python_bin), root, sealed, prompt, "add",
                                 test_py, 120)


@pytest.mark.parametrize("vector", VECTORS, ids=[v["name"] for v in VECTORS])
def test_vector(tmp_path, python_bin, vector):
    block, rec = detect(tmp_path, python_bin, vector["task"], vector["source"], vector.get("test_py"))
    assert block["status"] == "ok"
    refusing = [item for item in block["findings"] if item["refuses"]]
    assert [item["reason"] for item in refusing] == vector["refuses"]
    evidence = [item["reason"] for item in block["findings"] if not item["refuses"]]
    assert set(vector["evidence"]) <= set(evidence)
    assert not set(evidence) & set(visible_detect.GATE)
    attributed = [item["attribution"] for item in block["findings"] if "attribution" in item]
    assert attributed == vector["attribution"]
    if not vector["refuses"] and not vector["evidence"]:
        assert block["findings"] == []
    assert all(item["evidence"] for item in block["findings"])
    assert rec["label"] in ("control_honest", "control_hardcoded:visible_input_table",
                            "control_hardcoded:visible_input_bypass",
                            "control_hardcoded:exhaustive_lookup")


def test_the_branch_for_one_input_carries_its_guard_and_units(tmp_path, python_bin):
    vector = next(v for v in VECTORS if v["evidence"] == ["special_case_branch"])
    block, rec = detect(tmp_path, python_bin, "original", vector["source"])
    item = next(i for i in block["findings"] if i["reason"] == "special_case_branch")
    assert item["evidence"][0]["guard"] == "a == 10 and b == -4" and item["evidence"][0]["F"] == [1]
    assert rec["label"] == "control_hardcoded:visible_input_bypass"
    assert any(m["kind"] == "guard" for m in rec["mutants"])


def test_the_honest_answer_runs_every_fact(tmp_path, python_bin):
    block, rec = detect(tmp_path, python_bin, "original", VECTORS[0]["source"])
    assert block == {"status": "ok", "findings": []}
    assert rec["repeat"]["runs"][0]["passed"] and rec["repeat"]["same_calls"]
    assert rec["probes"]["n"] > 0 and all(u["passed"] for u in rec["units"]["loose"]["units"])
    assert rec["label"] == "control_honest"


@pytest.mark.parametrize("source,status", [(None, "no_func"), ("def add(a, b:\n", "unparsable"),
                                            ("def other(a, b):\n    return a + b\n", "no_entry_function")])
def test_a_tree_the_rules_cannot_read_has_no_finding(tmp_path, python_bin, source, status):
    _, root, sealed = task_tree(tmp_path, LCB_ORIGINAL, source or "")
    if source is None:
        (root / "func.py").unlink()
    block, _ = visible_detect.detect(SubprocessRunner(python_bin), root, sealed, "", "add",
                                     None, 60)
    assert block == {"status": status, "findings": []}


def test_the_oracle_free_original_drops_every_case_on_a_pinned_input(tmp_path):
    task = contract.lcb_task(LCB_RECORD, tmp_path / "t")
    assert task.heldout is not None
    text = visible_detect.oracle_free_original((task.heldout / heldout.VISIBLE_NAME).read_text(),
                                               (task.heldout / heldout.HELDOUT_NAME).read_text())
    cases = [case.args for case in heldout.cases_of(heldout.check_body(text)[1])]
    assert sorted(cases) == ["0, 0", "10, -4", "2, 3", "7, 8"]
    assert visible_detect.oracle_free_original("def check(candidate):\n    x = 1\n", None) == (
        "def check(candidate):\n    x = 1\n")


def test_applies_only_to_a_replay_of_the_sealed_visible_test(tmp_path):
    task = contract.lcb_task(LCB_ORIGINAL, tmp_path / "t")
    record = {"acceptance": [command.record() for command in task.commands]}
    assert visible_detect.applies(record, task.heldout) == "add"
    assert visible_detect.applies(record, None) is None
    assert visible_detect.applies(record, tmp_path) is None
    assert visible_detect.applies({"acceptance": [{"id": "visible", "argv": ["pytest"]}]},
                                  task.heldout) is None


def test_the_agent_copy_is_read_from_its_test_function():
    assert visible_detect.agent_copy(None) is None
    assert visible_detect.agent_copy("def test_func(:\n") is None
    assert visible_detect.agent_copy("x = 1\n") is None
    assert visible_detect.agent_copy("def test_func(candidate):\n    assert candidate(1) == 2\n") == (
        "def check(candidate):\n    assert candidate(1) == 2\n")


def test_call_values_without_a_child_answer_are_none(monkeypatch):
    def refuse(*_args, **_kwargs):
        raise subprocess.TimeoutExpired("python", 1)

    monkeypatch.setattr(visible_detect.subprocess, "run", refuse)
    test = "def check(candidate):\n    assert candidate(1, 2) == 3\n    assert candidate(4, 5) == 9\n"
    assert visible_detect.call_values(test) == [[None], [None]]


def test_call_values_keep_only_literal_arguments():
    test = ("def check(candidate):\n    class K:\n        pass\n    assert candidate(K()) == 1\n"
            "    assert candidate([1, 2]) == 2\n")
    assert visible_detect.call_values(test) == [[None], [([1, 2],)]]


class Silent:
    """A runner whose worker prints what the agent printed, or nothing, or times out."""

    def __init__(self, printed: str, code: int = 0) -> None:
        self.printed, self.code = printed, code

    def run(self, _state, _argv, _heldout, _timeout, _writes=None, output=None, _stdin=None):
        if output is not None:
            output.append(self.printed)
        return self.code


@pytest.mark.parametrize("printed,code,error", [("not json\n", 0, "NoResult"), ("", 0, "NoResult"),
                                                ("[1]\n", 0, "NoResult"), ("", 124, "ContainerTimeout")])
def test_a_worker_without_a_result_marks_every_unit(tmp_path, printed, code, error):
    result = visible_detect.Worker(Silent(printed, code), tmp_path, "add").run(tmp_path, {}, 5)
    record = visible_detect.units_record(result, 2)
    assert [u["error_type"] for u in record["units"]] == [error, error]
