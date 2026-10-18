"""Each seal gate refuses a planted contract end to end, through ``compile_task``.

``test_gates.py`` checks each gate's formula on hand-made kill vectors. These tests plant a
repository, a reference solution and a recorded model answer whose contract fails exactly one
gate, and check that the compiler raises that gate's refusal with its measured inputs.
"""

import json
import shutil
from pathlib import Path

import pytest

from probity_observer.done import contract, zeroshot
from probity_observer.done.runner import SubprocessRunner

HEADER = "import os, sys\nsys.path.insert(0, os.getcwd())\n"


class Fixed:
    name = "fixed-test-model"

    def __init__(self, answer):
        self.answer = answer

    def complete(self, prompt):
        return self.answer


def answer(node):
    return json.dumps({"acceptance": [{"id": "unit", "argv": [
        "python", "-m", "pytest", "-q", node], "expect_on_start": "fail"}],
        "protected_paths": [], "rationale": "r"})


def planted(tmp_path, start, reference, tests):
    """A start tree, a reference tree that differs by ``reference``, and the test files."""
    repo = tmp_path / "repo"
    (repo / "tests").mkdir(parents=True)
    for name, text in {**start, **tests}.items():
        (repo / name).write_text(text)
    solved = tmp_path / "reference"
    shutil.copytree(repo, solved)
    for name, text in reference.items():
        (solved / name).write_text(text)
    return repo, solved


def refusal(tmp_path, repo, solved, node, harness, runner):
    proposal = zeroshot.propose(repo, "planted", "solve it", Fixed(answer(node)), solved,
                                tmp_path / "w", template_name="contract_v1.txt")
    with pytest.raises(contract.Refused) as caught:
        contract.compile_task(proposal.task, tmp_path / "out", harness, runner, timeout=60)
    return caught.value


def test_a_test_that_reads_only_data_leaves_the_null_patch_alive(tmp_path, harness, python_bin):
    # The test checks a data file the reference also changes, never the code: putting the
    # changed source back to its start bytes still passes.
    repo, solved = planted(
        tmp_path,
        {"app.py": "def double(x):\n    return x\n", "limit.txt": "4\n"},
        {"app.py": "def double(x):\n    return x * 2\n", "limit.txt": "5\n"},
        {"tests/test_app.py": HEADER + "\n\ndef test_limit():\n"
         "    assert open('limit.txt').read().strip() == '5'\n"})
    refused = refusal(tmp_path, repo, solved, "tests/test_app.py::test_limit", harness,
                      SubprocessRunner(python_bin))
    assert refused.reason == "null_patch_survived"
    detail = json.loads(str(refused).split(": ", 2)[-1])
    assert detail["mutants"] == 1 and detail["pass"] is False


def test_one_weak_assertion_leaves_too_many_change_mutants(tmp_path, harness, python_bin):
    # double(0) == 0 holds for x * 2, x // 2 and x * 3: two of four change mutants live.
    repo, solved = planted(
        tmp_path,
        {"app.py": "def double(x):\n    return x + 1\n"},
        {"app.py": "def double(x):\n    return x * 2\n"},
        {"tests/test_app.py": HEADER + "from app import double\n\n\ndef test_double():\n"
         "    assert double(0) == 0\n"})
    refused = refusal(tmp_path, repo, solved, "tests/test_app.py::test_double", harness,
                      SubprocessRunner(python_bin))
    assert refused.reason == "change_floor_unmet"
    detail = json.loads(str(refused).split(": ", 2)[-1])
    assert (detail["n"], detail["survivors"], detail["limit"]) == (4, 2, 1)


def test_an_untested_hunk_survives_its_revert(tmp_path, harness, python_bin):
    # Every mutant of the tested hunk dies. The second hunk (a new module constant) is never
    # read, so its revert and its deletion live: few enough for the change floor of a dozen
    # change mutants, but the revert gate allows no surviving revert.
    repo, solved = planted(
        tmp_path,
        {"app.py": "def scale(x, y):\n    return 0\n"},
        {"app.py": "LOG = []\n\n\ndef scale(x, y):\n    total = x * 2\n"
                   "    total = total + y\n    return total - 1\n"},
        {"tests/test_app.py": HEADER + "from app import scale\n\n\ndef test_scale():\n"
         "    assert scale(2, 3) == 6\n    assert scale(5, 0) == 9\n"
         "    assert scale(0, 0) == -1\n    assert scale(-3, 7) == 0\n"
         "    assert type(scale(1, 1)) is int\n"})
    refused = refusal(tmp_path, repo, solved, "tests/test_app.py::test_scale", harness,
                      SubprocessRunner(python_bin))
    assert refused.reason == "hunk_revert_survived"
    detail = json.loads(str(refused).split(": ", 2)[-1])
    assert detail["survivors"] == 1 and detail["mutants"] == 2


class GuardGoesQuiet(SubprocessRunner):
    """A guard that stops killing one change mutant once harvesting is over.

    The kill matrix saw the guard kill ``x // 2``; the final measurement does not. One
    survivor is within the change floor, so only ``harvest_guard_dropped`` can see the drift."""

    quiet = False

    def run(self, state, argv, heldout, timeout, *args, **kwargs):
        source = Path(state) / "app.py"
        if (self.quiet and any("test_more.py" in part for part in argv) and source.is_file()
                and "x // 2" in source.read_text()):
            return 0
        return super().run(state, argv, heldout, timeout, *args, **kwargs)


def test_a_guard_that_stops_killing_after_the_harvest_is_refused(tmp_path, harness, python_bin,
                                                                 monkeypatch):
    # The unit test checks double(0) only. The guard passes on the start state and the
    # reference (double(1) is 2 for both), so it is harvested, and it kills the x // 2 and
    # x * 3 mutants the unit test leaves alive.
    header = HEADER + "from app import double\n\n\n"
    repo, solved = planted(
        tmp_path,
        {"app.py": "def double(x):\n    return x + 1\n"},
        {"app.py": "def double(x):\n    return x * 2\n"},
        {"tests/test_app.py": header + "def test_double():\n    assert double(0) == 0\n",
         "tests/test_more.py": header + "def test_one():\n    assert double(1) - 2 == 0\n"})
    runner = GuardGoesQuiet(python_bin)
    harvest = contract.add_guard

    def add_guard(*args, **kwargs):
        result = harvest(*args, **kwargs)
        runner.quiet = True
        return result

    monkeypatch.setattr(contract, "add_guard", add_guard)
    refused = refusal(tmp_path, repo, solved, "tests/test_app.py::test_double", harness, runner)
    assert refused.reason == "harvest_guard_dropped"
    detail = json.loads(str(refused).split(": ", 2)[-1])
    assert len(detail["missing"]) == 1 and detail["pass"] is False
