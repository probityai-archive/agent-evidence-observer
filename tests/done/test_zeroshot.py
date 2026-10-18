"""The zero-shot template: shipped text, parsed answers, refusals, and a sealed contract."""

import json
import shutil

import pytest

from probity_observer.done import contract, zeroshot
from probity_observer.done.formats import DoneError
from probity_observer.done.runner import SubprocessRunner


class Fixed:
    name = "fixed-test-model"

    def __init__(self, answer):
        self.answer = answer
        self.prompts = []

    def complete(self, prompt):
        self.prompts.append(prompt)
        return self.answer


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    (root / "tests").mkdir(parents=True)
    (root / "app.py").write_text("def double(x):\n    return x\n")
    (root / "tests" / "test_app.py").write_text(
        "import os, sys\nsys.path.insert(0, os.getcwd())\nfrom app import double\n\n\n"
        "def test_double():\n    assert double(2) == 4\n    assert double(0) == 0\n")
    return root


ANSWER = json.dumps({"acceptance": [{"id": "unit", "argv": ["python", "-m", "pytest", "-q",
                                                             "-p", "no:cacheprovider",
                                                             "tests/test_app.py"],
                                     "expect_on_start": "fail"}],
                     "protected_paths": [{"path": "tests", "kind": "directory"}],
                     "rationale": "the test file checks doubling"})


def test_template_text_is_shipped_and_filled(repo):
    text = zeroshot.template()
    assert "{task}" in text and "expect_on_start" in text
    prompt = zeroshot.render(repo, "make double double")
    assert "make double double" in prompt and "tests/test_app.py" in prompt
    assert "def test_double" in prompt


def test_a_proposal_seals_after_stability(tmp_path, repo, harness, python_bin):
    model = Fixed("Here it is:\n" + ANSWER)
    proposal = zeroshot.propose(repo, "repo-double", "make double double", model,
                                work=tmp_path / "w")
    assert len(model.prompts) == 1 and proposal.record["model"] == "fixed-test-model"
    sealed = contract.compile_task(proposal.task, tmp_path / "out", harness,
                                   SubprocessRunner(python_bin), timeout=60)
    compiled = json.loads((sealed.out / "sealed" / "compile.json").read_bytes())
    assert compiled["model_calls"] == 1 and compiled["notes"]["proposal"]["template_sha256"]
    assert sealed.record["protected_paths"][0]["exclude"] == list(contract.EXCLUDE)


@pytest.mark.parametrize("answer", [
    json.dumps({"acceptance": [{"id": "a", "argv": ["sh", "-c", "test -f DONE"],
                                "expect_on_start": "fail"}],
                "protected_paths": [], "rationale": ""}),
    "no json here",
    "{not json}",
    json.dumps({"acceptance": []}),
    json.dumps({"acceptance": [], "protected_paths": [], "rationale": ""}),
    json.dumps({"acceptance": [{"id": "a", "argv": [], "expect_on_start": "fail"}],
                "protected_paths": [], "rationale": ""}),
    json.dumps({"acceptance": [{"id": "a", "argv": ["x"]}], "protected_paths": [], "rationale": ""}),
    json.dumps({"acceptance": [{"id": "a", "argv": ["x"], "expect_on_start": "fail"}],
                "protected_paths": [{"path": "missing.py", "kind": "file"}], "rationale": ""}),
    json.dumps({"acceptance": [{"id": "a", "argv": ["x"], "expect_on_start": "fail"}],
                "protected_paths": [{"path": "../etc", "kind": "directory"}], "rationale": ""}),
    json.dumps({"acceptance": [{"id": "a", "argv": ["x"], "expect_on_start": "fail"}],
                "protected_paths": "tests", "rationale": ""}),
    json.dumps({"acceptance": [{"id": "a", "argv": ["x"], "expect_on_start": "fail"}],
                "protected_paths": [{"path": "tests"}], "rationale": ""}),
])
def test_malformed_answers_are_refused(tmp_path, repo, answer):
    with pytest.raises(DoneError, match="acceptance|protected|JSON|json|test runner|malformed"):
        zeroshot.propose(repo, "t", "task", Fixed(answer), work=tmp_path / "w")


def test_chat_model_posts_one_request(monkeypatch):
    seen = {}

    class Reply:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return json.dumps({"choices": [{"message": {"content": "ok"}}]}).encode()

    def urlopen(request, timeout):
        seen["url"], seen["body"] = request.full_url, json.loads(request.data)
        return Reply()

    monkeypatch.setattr(zeroshot.urllib.request, "urlopen", urlopen)
    assert zeroshot.ChatModel("http://h:8000/", "gpt-oss-120b").complete("p") == "ok"
    assert seen["url"] == "http://h:8000/v1/chat/completions"
    assert seen["body"]["model"] == "gpt-oss-120b" and seen["body"]["temperature"] == 0


def test_a_reference_gives_the_proposal_mutants(tmp_path, repo, harness, python_bin):
    reference = tmp_path / "reference"
    shutil.copytree(repo, reference)
    (reference / "app.py").write_text("def double(x):\n    return x * 2\n")
    proposal = zeroshot.propose(repo, "repo-double", "make double double", Fixed(ANSWER), reference,
                                tmp_path / "w")
    assert {name: change.ranges for name, change in proposal.task.mutation_targets.items()} == {
        "app.py": ((2, 2),)}
    # The only test compares with ==, so an any-eq result passes it: the contract is refused.
    with pytest.raises(contract.Refused, match="cheat_class_survived") as caught:
        contract.compile_task(proposal.task, tmp_path / "out", harness,
                              SubprocessRunner(python_bin), timeout=60)
    assert caught.value.reason == "cheat_class_survived"


def _urlopen_answering(monkeypatch, message, finish="stop"):
    class Reply:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return json.dumps({"choices": [{"message": message, "finish_reason": finish}]}).encode()

    monkeypatch.setattr(zeroshot.urllib.request, "urlopen", lambda request, timeout: Reply())


def test_a_null_content_answer_is_refused_with_its_finish_reason(monkeypatch):
    _urlopen_answering(monkeypatch, {"role": "assistant", "content": None}, "length")
    with pytest.raises(DoneError, match="no content .*length"):
        zeroshot.ChatModel("http://h:8000", "m").complete("p")


def test_a_recorded_answer_replays_only_for_its_own_prompt(tmp_path, repo):
    prompt = zeroshot.render(repo, "make double double")
    record = tmp_path / "call.json"
    record.write_text(json.dumps({"request": {"messages": [{"role": "user", "content": prompt}]},
                                  "response": {"choices": [{"message": {"content": ANSWER}}]}}))
    model = zeroshot.RecordedModel(record)
    assert model.complete(prompt) == ANSWER
    with pytest.raises(DoneError, match="recorded for a different prompt"):
        model.complete(prompt + "x")


def test_a_recorded_answer_without_its_request_is_marked_unmatched(tmp_path, repo):
    record = tmp_path / "answer.txt"
    record.write_text(ANSWER)
    model = zeroshot.RecordedModel(record)
    proposal = zeroshot.propose(repo, "t", "make double double", model, work=tmp_path / "w")
    assert proposal.record["replay"] == {"from_sha256": zeroshot.sha256(record.read_bytes()),
                                         "prompt_matched": False}


def test_proposed_commands_are_sealed_with_repeats_isolation_and_ids(tmp_path, repo):
    from probity_observer.done import pytest_plugins
    reference = tmp_path / "reference"
    shutil.copytree(repo, reference)
    (reference / "app.py").write_text("def double(x):\n    return x * 2\n")
    answer = json.dumps({"acceptance": [
        {"id": "unit", "argv": ["pytest", "-q", "tests/test_app.py::test_double"],
         "expect_on_start": "fail"},
        {"id": "named", "argv": ["python", "-m", "unittest", "tests.test_app.test_double"],
         "expect_on_start": "fail"},
        {"id": "keyword", "argv": ["python", "-m", "pytest", "-k", "double"], "expect_on_start": "fail"},
        {"id": "lost", "argv": ["python", "-m", "unittest", "nowhere.Case"], "expect_on_start": "fail"}],
        "protected_paths": [], "rationale": "r"})
    proposal = zeroshot.propose(repo, "t", "make double double", Fixed(answer), reference,
                                tmp_path / "w")
    commands = {command.id: command for command in proposal.task.commands}
    assert set(commands) == {"unit", "named", "keyword"}
    assert proposal.record["dropped"] == [{"id": "lost", "argv": ["python", "-m", "unittest",
                                                                  "nowhere.Case"],
                                           "reason": "unittest_unresolved"}]
    for command in commands.values():
        argv = command.argv
        assert pytest_plugins.is_sealed_pytest(argv)
        assert argv[argv.index("--probity-repeats") + 1] == "2"
        assert argv[argv.index("--probity-isolate") + 1] == "app.py::double"
    assert commands["unit"].record()["ids"] == ["tests/test_app.py::test_double"]
    assert commands["named"].record()["ids"] == ["tests/test_app.py::test_double"]
    assert "ids" not in commands["keyword"].record() and commands["keyword"].argv[-2:] == ("-k", "double")
    assert (tmp_path / "w/heldout/config/probity-plugins/probity_repeat.py").is_file()
    assert proposal.task.heldout == tmp_path / "w" / "heldout"
    assert zeroshot.unittest_node(repo, "tests.test_app") == "tests/test_app.py"


def test_a_repo_task_needs_a_work_directory(repo):
    with pytest.raises(DoneError, match="work directory"):
        zeroshot.propose(repo, "t", "task", Fixed(ANSWER))


def _guard_repo(tmp_path):
    repo = tmp_path / "grepo"
    (repo / "tests").mkdir(parents=True)
    header = "import os, sys\nsys.path.insert(0, os.getcwd())\nfrom app import double, triple\n\n\n"
    (repo / "app.py").write_text("def double(x):\n    return x\n\n\ndef triple(x):\n    return x * 3\n")
    (repo / "tests" / "test_app.py").write_text(header + "def test_double():\n    assert double(2) == 4\n")
    (repo / "tests" / "test_more.py").write_text(header + "def test_zero():\n    assert double(0) + 0 == 0\n")
    (repo / "tests" / "test_other.py").write_text(header + "def test_triple():\n    assert triple(2) == 6\n")
    reference = tmp_path / "greference"
    shutil.copytree(repo, reference)
    (reference / "app.py").write_text("def double(x):\n    return x * 2\n\n\ndef triple(x):\n    return x * 3\n")
    answer = json.dumps({"acceptance": [{"id": "unit", "argv": [
        "python", "-m", "pytest", "-q", "tests/test_app.py::test_double"], "expect_on_start": "fail"}],
        "protected_paths": [], "rationale": "r"})
    return repo, reference, answer


def test_guards_are_harvested_from_the_suite_by_the_mutants_they_kill(tmp_path, harness,
                                                                      python_bin):
    repo, reference, answer = _guard_repo(tmp_path)
    proposal = zeroshot.propose(repo, "g", "double it", Fixed(answer), reference, tmp_path / "w")
    sealed = contract.compile_task(proposal.task, tmp_path / "out", harness,
                                   SubprocessRunner(python_bin), timeout=60)
    compiled = json.loads((sealed.out / "sealed" / "compile.json").read_bytes())
    harvest = compiled["harvest"]
    assert [item["id"] for item in harvest["greedy"]] == ["tests/test_more.py::test_zero",
                                                         "tests/test_other.py::test_triple"]
    assert harvest["greedy"][0]["marginal"][1] >= 1 and harvest["greedy"][1]["marginal"][3] >= 1
    assert "tests/test_app.py" in harvest["candidates"]
    # test_double fails on the start state, so it is never a guard.
    assert {entry["file"]: entry["stable"] for entry in harvest["stability"]}[
        "tests/test_app.py"] == 0
    assert harvest["matrix_runs_skipped_by_coverage"] >= 1 and harvest["matrix_sha256"]
    guard = next(item for item in sealed.record["acceptance"] if item["id"] == "guard-repo")
    assert guard["ids"] == ["tests/test_more.py::test_zero", "tests/test_other.py::test_triple"]
    sets = compiled["adequacy"]["sets"]
    assert sets["cheat"]["killed"] + compiled["adequacy"]["neutralized"] == sets["cheat"]["mutants"]
    protected = {item["path"] for item in sealed.record["protected_paths"]}
    assert {"tests/test_more.py", "tests/test_other.py", "tests/test_app.py"} <= protected


def test_a_strong_contract_seals_with_its_gates_and_strength(tmp_path, harness, python_bin):
    repo, reference, answer = _guard_repo(tmp_path)
    proposal = zeroshot.propose(repo, "g", "double it", Fixed(answer), reference, tmp_path / "w")
    sealed = contract.compile_task(proposal.task, tmp_path / "out", harness,
                                   SubprocessRunner(python_bin), timeout=60)
    compiled = json.loads((sealed.out / "sealed" / "compile.json").read_bytes())
    assert compiled["strength"] == "gated"
    assert all(entry["pass"] for entry in compiled["gates"].values())
    assert set(compiled["gates"]) == set(contract.seal_gates.ORDER)


def test_without_a_reference_the_start_suite_guards_and_the_strength_says_so(tmp_path, harness,
                                                                           python_bin):
    repo, _, answer = _guard_repo(tmp_path)
    proposal = zeroshot.propose(repo, "g", "double it", Fixed(answer), work=tmp_path / "w")
    sealed = contract.compile_task(proposal.task, tmp_path / "out", harness,
                                   SubprocessRunner(python_bin), timeout=60)
    compiled = json.loads((sealed.out / "sealed" / "compile.json").read_bytes())
    assert compiled["strength"] == "reference_free" and "gates" not in compiled
    guard = next(item for item in sealed.record["acceptance"] if item["id"] == "guard-repo")
    assert guard["ids"] == ["tests/test_more.py::test_zero", "tests/test_other.py::test_triple"]
    assert sealed.record["adequacy"] == {"mutants": 0, "killed": 0}
