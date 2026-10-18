"""Model strengthening rounds: static rules, run validation, and the verifier-tier refusal."""

import ast
import json
import shutil

import pytest

from probity_observer.done import contract, strengthen, zeroshot
from probity_observer.done.runner import SubprocessRunner

from .test_zeroshot import ANSWER, Fixed, repo  # noqa: F401  (the repo fixture)


def rule(source):
    return strengthen.static_problems(ast.parse(source).body[0])


@pytest.mark.parametrize("source, problem", [
    ("def test_a():\n    assert f()._cache == 1\n", "private_attribute"),
    ("def test_a():\n    assert f().__len__() == 1\n", None),
    ("def test_a(monkeypatch):\n    pass\n", "mock"),
    ("def test_a():\n    with pytest.raises(ValueError, match='bad'):\n        f()\n", "exception_text"),
    ("def test_a():\n    with pytest.raises(ValueError) as e:\n        f()\n    assert e.value.args\n",
     "exception_text"),
    ("def test_a():\n    with pytest.raises(ValueError):\n        f()\n", None),
    ("def test_a():\n    assert repr(f()) == 'x'\n", "repr"),
    ("def test_a():\n    assert type(f()) is int\n", "type_identity"),
    ("def test_a():\n    assert isinstance(f(), int)\n", None),
])
def test_static_rules(source, problem):
    assert rule(source) == problem


GOOD = ("import pytest\nfrom app import double\n\n\n"
        "def test_three():\n    assert double(3) - 6 == 0\n\n\n"
        "def test_shape():\n    assert repr(double(1))\n\n\n"
        "def test_known():\n    assert double(0) == 0\n")


def _task(tmp_path, repo, answer=ANSWER):
    reference = tmp_path / "reference"
    shutil.copytree(repo, reference)
    (reference / "app.py").write_text("def double(x):\n    return x * 2\n")
    return zeroshot.propose(repo, "s", "make double double", Fixed(answer), reference,
                            tmp_path / "w", template_name="contract_v1.txt").task


def test_a_weak_contract_is_strengthened_and_refused_until_the_verifier_reads_tiers(
        tmp_path, repo, harness, python_bin):
    task = _task(tmp_path, repo)
    model = Fixed("```python\n" + GOOD + "```\n")
    with pytest.raises(contract.Refused, match="synthesized_tier_unsupported"):
        contract.compile_task(task, tmp_path / "out", harness, SubprocessRunner(python_bin),
                              timeout=60, model=model)
    assert len(model.prompts) == 1 and "_ProbityAnyEq" in model.prompts[0]
    assert "def double(x):\n    return x" in model.prompts[0]


def test_with_a_tier_reading_verifier_the_strengthened_contract_seals(
        tmp_path, repo, harness, python_bin, monkeypatch):
    monkeypatch.setattr(contract, "VERIFIER_GRADES_SYNTHESIZED", True)
    task = _task(tmp_path, repo)
    sealed = contract.compile_task(task, tmp_path / "out", harness, SubprocessRunner(python_bin),
                                   timeout=60, model=Fixed("```python\n" + GOOD + "```\n"))
    compiled = json.loads((sealed.out / "sealed" / "compile.json").read_bytes())
    (round_one,) = compiled["strengthening"]
    assert round_one["kept"] == ["test_three"]
    assert round_one["rejected"] == {"test_shape": "repr", "test_known": "kills_no_mutant"}
    assert round_one["template"] == strengthen.TEMPLATE and round_one["response_sha256"]
    assert compiled["tiers"]["heldout-synth-1"] == "synthesized"
    assert compiled["tiers"]["unit"] == "trusted" and compiled["strength"] == "gated"
    assert (sealed.out / "sealed/heldout/synth/test_synth_1.py").is_file()
    assert compiled["adequacy"]["trusted_kill_vector_sha256"] != compiled["adequacy"]["kill_vector_sha256"]


def test_with_no_failing_command_one_round_synthesizes_the_spec(tmp_path, repo, harness,
                                                                python_bin, monkeypatch):
    passing = json.dumps({"acceptance": [{"id": "known", "argv": [
        "python", "-m", "pytest", "-q", "tests/test_zero.py"], "expect_on_start": "pass"}],
        "protected_paths": [], "rationale": "r"})
    (repo / "tests" / "test_zero.py").write_text(
        "import os, sys\nsys.path.insert(0, os.getcwd())\nfrom app import double\n\n\n"
        "def test_zero():\n    assert double(0) + 0 == 0\n    assert double(5) % 1 == 0\n")
    task = _task(tmp_path, repo, passing)
    model = Fixed("```python\n" + GOOD + "```\n")
    with pytest.raises(contract.Refused, match="synthesized_tier_unsupported"):
        contract.compile_task(task, tmp_path / "out", harness, SubprocessRunner(python_bin),
                              timeout=60, model=model)
    assert "fail on the repository as it is now" in model.prompts[0]
    monkeypatch.setattr(contract, "VERIFIER_GRADES_SYNTHESIZED", True)
    task = _task(tmp_path / "again", repo, passing)
    sealed = contract.compile_task(task, tmp_path / "out2", harness, SubprocessRunner(python_bin),
                                   timeout=60, model=Fixed("```python\n" + GOOD + "```\n"))
    compiled = json.loads((sealed.out / "sealed" / "compile.json").read_bytes())
    assert compiled["strength"] == "synthesized_spec"


def test_without_a_model_a_weak_contract_is_refused_by_its_gate(tmp_path, repo, harness,
                                                                python_bin):
    with pytest.raises(contract.Refused, match="cheat_class_survived"):
        contract.compile_task(_task(tmp_path, repo), tmp_path / "out", harness,
                              SubprocessRunner(python_bin), timeout=60)
