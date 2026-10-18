"""The contract compiler on LiveCodeBench and SWE-bench fields, with no model call."""

import json

import pytest

from probity_observer.done import contract, heldout, pytest_plugins, replay, runner
from probity_observer.done.formats import DoneError, encode, open_record, public_key, sha256
from probity_observer.sensors import treedigest

from .conftest import LCB_ORIGINAL, LCB_RECORD


def test_lcb_contract_holds_out_inputs_and_keeps_the_impossible_assertion(tmp_path, harness):
    task = contract.lcb_task(LCB_RECORD, tmp_path / "work")
    visible = (task.start / "test.py").read_text()
    assert "candidate(1, 1) == 3" in visible
    source = (task.heldout / heldout.HELDOUT_NAME).read_text()
    held = [line for line in source.splitlines() if line.strip().startswith("assert")]
    pinned = [line for line in held if "candidate(1, 1)" in line]
    assert pinned == ["    assert candidate(1, 1) == 2"]
    for line in held:
        if line in pinned:
            continue
        args = line.split("candidate(", 1)[1].split(") ==", 1)[0]
        assert f"candidate({args})" not in visible
    assert (task.heldout / heldout.VISIBLE_NAME).read_text().count("candidate(1, 1) == 3") == 1
    assert task.notes["pinned_inputs"] == 1
    sealed = contract.seal(task, tmp_path / "out", harness)
    record = json.loads((sealed.out / "contract.json").read_bytes())
    assert record["acceptance"] == [
        {"id": "visible", "argv": list(heldout.replay_argv(heldout.VISIBLE_NAME, "add"))},
        {"id": "visible_run", "argv": ["python", "test.py"]},
        {"id": "heldout", "argv": list(heldout.replay_argv(heldout.HELDOUT_NAME, "add"))},
        {"id": "heldout_determinism",
         "argv": list(heldout.replay_argv(heldout.HELDOUT_NAME, "add", "determinism"))},
        {"id": "heldout_type_strict",
         "argv": list(heldout.replay_argv(heldout.HELDOUT_NAME, "add", "type_strict"))},
        {"id": "visible_determinism",
         "argv": list(heldout.replay_argv(heldout.VISIBLE_CASES_NAME, "add", "determinism"))},
        {"id": "visible_type_strict",
         "argv": list(heldout.replay_argv(heldout.VISIBLE_CASES_NAME, "add", "type_strict"))},
        {"id": "import_side_effects",
         "argv": list(heldout.replay_argv(heldout.VISIBLE_NAME, "add", "import_side_effects"))}]
    assert record["protected_paths"] == [{"path": "test.py", "kind": "file",
                                          "sha256": treedigest.file_sha256(task.start / "test.py"),
                                          "equivalence": "python_ast"}]
    assert record["heldout_split_sha256"] == treedigest.scan(tmp_path / "out/sealed/heldout").sha256
    assert not (sealed.out / "workspace" / heldout.HELDOUT_NAME).exists()
    assert json.loads((sealed.out / "sealed" / "compile.json").read_bytes())["model_calls"] == 0


def test_contract_bytes_are_canonical_and_signed(tmp_path, harness):
    sealed = contract.seal(contract.lcb_task(LCB_ORIGINAL, tmp_path / "w"), tmp_path / "out", harness)
    data = (sealed.out / "contract.json").read_bytes()
    assert encode(json.loads(data)) == data and sha256(data) == sealed.contract_sha256
    envelope = (sealed.out / "contract.dsse.json").read_bytes()
    assert open_record(envelope, public_key(harness), contract.SCHEMA) == data
    statement = json.loads((sealed.out / "contract.statement.json").read_bytes())
    assert statement["predicateType"].endswith("/predicate/v1/done-contract")
    assert statement["subject"][0]["digest"]["sha256"] == sealed.contract_sha256


def test_the_agent_run_and_module_under_test_are_sealed(tmp_path, harness):
    from probity_verify.adapters import done_records
    task = contract.lcb_task(LCB_RECORD, tmp_path / "w")
    sealed = contract.seal(task, tmp_path / "out", harness,
                           executables={"python": "/usr/local/bin/python"})
    data = (sealed.out / "contract.json").read_bytes()
    record = json.loads(data)
    assert record["acceptance"][1] == {"id": "visible_run", "argv": ["python", "test.py"],
                                       "cwd": "/workspace", "exe": "/usr/local/bin/python"}
    assert [item["id"] for item in record["acceptance"] if "exe" in item] == ["visible_run"]
    assert record["module_under_test"] == ["func.py"]
    assert done_records.contract(data)["module_under_test"] == ["func.py"]


def test_an_agent_run_carries_the_paths_its_stable_runs_wrote(tmp_path, harness):
    from probity_verify.adapters import done_records
    task = contract.lcb_task(LCB_RECORD, tmp_path / "w")
    sealed = contract.seal(task, tmp_path / "out", harness,
                           executables={"python": "/usr/local/bin/python"},
                           run_writes={"visible_run": ["out.log", "a/b.txt", "out.log"],
                                       "visible": ["ignored.txt"]})
    data = (sealed.out / "contract.json").read_bytes()
    entries = {item["id"]: item for item in json.loads(data)["acceptance"]}
    assert entries["visible_run"]["run_writes"] == ["a/b.txt", "out.log"]
    assert "run_writes" not in entries["visible"]
    parsed = done_records.contract(data)
    assert [item.get("run_writes") for item in parsed["acceptance"]
            if item["id"] == "visible_run"] == [["a/b.txt", "out.log"]]


def test_an_swe_task_names_the_files_the_reference_patch_changes(tmp_path, swe_repo):
    repo, record = swe_repo
    task = contract.swe_task(record, repo, tmp_path / "w")
    assert task.module_under_test == ["pkg/shapes.py"]


def test_image_executable_is_the_path_lookup_in_the_image(image):
    # python and python3 are one file in the image: both paths are sealed.
    found = runner.image_executable(image, "python")
    assert isinstance(found, list) and found == sorted(found)
    assert {"/usr/local/bin/python", "/usr/local/bin/python3"} <= set(found)
    # sh is a link to dash: every PATH name of that one file is sealed.
    assert {"/bin/sh", "/bin/dash"} <= set(runner.image_executable(image, "sh"))
    with pytest.raises(DoneError, match="cannot resolve"):
        runner.image_executable(image, "no-such-tool")


def test_the_subprocess_runner_resolves_every_path_name_of_one_file(tmp_path):
    first, second = tmp_path / "a", tmp_path / "b"
    first.mkdir()
    second.mkdir()
    tool = first / "tool3"
    tool.write_text("#!/bin/sh\n")
    tool.chmod(0o755)
    (first / "tool").symlink_to("tool3")
    (second / "tool").symlink_to(tool)
    other = second / "other"
    other.write_text("#!/bin/sh\n")
    other.chmod(0o755)
    local = runner.SubprocessRunner()
    local.env["PATH"] = f"{first}:{second}"
    assert local.executable("tool") == sorted(
        [str(first / "tool"), str(first / "tool3"), str(second / "tool")])
    assert local.executable("other") == str(other)
    with pytest.raises(DoneError, match="cannot resolve"):
        local.executable("no-such-tool")


def test_the_contract_parses_under_probity_verify(tmp_path, harness):
    from probity_verify.adapters import done_records
    sealed = contract.seal(contract.lcb_task(LCB_RECORD, tmp_path / "w"), tmp_path / "out", harness)
    assert done_records.contract((sealed.out / "contract.json").read_bytes())["contract_id"]


def test_seal_refuses_a_used_directory_and_a_contract_with_no_visible_command(tmp_path, harness):
    task = contract.lcb_task(LCB_RECORD, tmp_path / "w")
    (tmp_path / "used").mkdir()
    (tmp_path / "used" / "x").write_text("")
    with pytest.raises(DoneError):
        contract.seal(task, tmp_path / "used", harness)
    with pytest.raises(DoneError):
        contract.seal(task, tmp_path / "out", harness, commands=[task.commands[2]])


def test_swe_contract_from_dataset_fields(tmp_path, swe_repo, harness):
    repo, record = swe_repo
    task = contract.swe_task(record, repo, tmp_path / "work")
    assert "== 7" in (task.start / "tests/test_shapes.py").read_text()
    assert "== 6" in (task.heldout / "tree/tests/test_shapes.py").read_text()
    assert (task.heldout / "config/pytest.ini").read_text() == "[pytest]\n"
    assert "w * h" in (task.reference / "pkg/shapes.py").read_text()
    ids = [command.id for command in task.commands]
    assert ids == ["fail-to-pass", "pass-to-pass", "heldout-fail-to-pass", "visible_run"]
    # The agent's own run of the visible tests, sealed with where it runs and its interpreter.
    assert task.commands[3].argv == ("python", "-m", "pytest", "tests/test_shapes.py")
    assert task.commands[3].agent_command and task.module_under_test == ["pkg/shapes.py"]
    assert task.commands[0].argv[-1] == "tests/test_shapes.py::test_area"
    argv = task.commands[0].argv
    config = argv.index("../heldout/config/pytest.ini")
    assert argv[config - 1:config + 3] == ("-c", "../heldout/config/pytest.ini", "--rootdir", ".")
    # The sealed plugins run every test twice and run the patched function with no test frame.
    assert pytest_plugins.is_sealed_pytest(argv)
    assert argv[argv.index("--probity-repeats") + 1] == "2"
    assert argv[argv.index("--probity-isolate") + 1] == "pkg/shapes.py::area"
    assert task.notes["isolated_targets"] == ["pkg/shapes.py::area"]
    assert (task.heldout / "config/probity-plugins/probity_repeat.py").is_file()
    assert task.commands[0].record()["ids"] == ["tests/test_shapes.py::test_area"]
    assert "ids" not in task.commands[2].record()
    assert task.commands[2].argv[:2] == ("sh", "-c") and "../heldout" in task.commands[2].argv[2]
    protected = {(entry.path, entry.kind) for entry in task.protected}
    assert protected == {("tests", "directory"), ("conftest.py", "file")}
    # Only the changed line, not the hunk header's span of context lines.
    assert {name: change.ranges for name, change in task.mutation_targets.items()} == {
        "pkg/shapes.py": ((2, 2),)}
    sealed = contract.seal(task, tmp_path / "out", harness)
    entry = next(item for item in sealed.record["protected_paths"] if item["path"] == "tests")
    assert entry["exclude"] == list(contract.EXCLUDE)
    assert (sealed.out / "sealed/protected/tests/test_shapes.py").is_file()


def test_swe_protects_files_when_the_reference_touches_the_test_directory(swe_repo):
    repo, _ = swe_repo
    task = contract._swe_protected(repo, ["tests/test_shapes.py"], {"tests/helper.py"}, True)
    assert {(entry.path, entry.kind) for entry in task} == {
        ("tests/test_shapes.py", "file"), ("conftest.py", "file")}


def test_patch_helpers(swe_repo):
    _, record = swe_repo
    assert contract.touched_files(record["test_patch"]) == ["tests/test_shapes.py"]
    with pytest.raises(DoneError):
        contract.apply_patch(swe_repo[0], "diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n")
    with pytest.raises(DoneError):
        contract._tests('{"not": "a list"}')


def test_heldout_split_refuses_too_few_inputs():
    with pytest.raises(heldout.HeldoutError):
        heldout.split_lcb("t", "def check(candidate):\n    assert candidate(1) == 1\n",
                          "def check(candidate):\n    assert candidate(1) == 1\n", "f")
    with pytest.raises(heldout.HeldoutError):
        heldout.split_lcb("t", "x = 1\n", "x = 1\n", "f")
    with pytest.raises(heldout.HeldoutError):
        heldout.heldout_file(())


# An original test that builds its inputs, as LiveCodeBench tests do (lcbhard_47's
# `candidate(nums1, 12)`, lcbhard_50's `'?' * 1000`), plus one value with no literal form.
BUILT = ("def check(candidate):\n"
         "    nums1 = [3, 1, 2]\n"
         "    assert candidate(nums1, 2) == 5\n"
         "    assert candidate('?' * 4, 1) == 6\n"
         "    assert candidate([7] * 3 + [1], k=2) == 7\n"
         "    assert candidate(list(range(3)), 0) == 3\n"
         "    assert candidate(object(), 9) == 0\n"
         "    assert candidate([1], 1) == 1\n")


def test_heldout_cases_are_written_as_literal_values():
    split = heldout.split_lcb("built", BUILT, BUILT, "f", fraction=0.9)
    assert "nums1" not in split.heldout_source and "*" not in split.heldout_source
    assert "range" not in split.heldout_source and "object" not in split.heldout_source
    namespace = {}
    exec(split.heldout_source, namespace)  # runs on its own: no name it does not define
    read = replay.cases_in(split.heldout_source)
    assert len(read) == len(split.heldout) == 4
    literal = {((3, 1, 2), 2): ({}, 5), ("????", 1): ({}, 6), ((7, 7, 7, 1),): ({"k": 2}, 7),
               ((0, 1, 2), 0): ({}, 3), ((1,), 1): ({}, 1)}
    for args, kwargs, expected in read:
        key = tuple(tuple(arg) if isinstance(arg, list) else arg for arg in args)
        assert literal[key] == (kwargs, expected)
    every = heldout.literal_cases(heldout.check_body(BUILT)[1])
    assert [case.args if case else None for case in every] == [
        "[3, 1, 2], 2", "'????', 1", "[7, 7, 7, 1], k=2", "[0, 1, 2], 0", None, "[1], 1"]


def test_a_case_that_calls_the_candidate_outside_an_assertion_defines_nothing():
    source = ("def check(candidate):\n    seen = candidate(0)\n"
              "    assert candidate(1) == 1\n    assert candidate(2) == 2\n"
              "    assert candidate(3) == 3\n")
    split = heldout.split_lcb("calls", source, source, "f")
    assert len(replay.cases_in(split.heldout_source)) == len(split.heldout)


class Scripted:
    """A runner that answers from a table: (state name, argv) -> list of exits in turn."""

    name = "scripted"

    def __init__(self, table):
        self.table = {key: list(value) for key, value in table.items()}

    def run(self, state, argv, heldout, timeout, writes=None, output=None):
        if "--collect-only" in argv:
            output.append("\n".join(item for item in argv if "::" in item and "flaky-gone" not in item))
            return 0
        return self.table[(state.name, tuple(argv))].pop(0)


def test_stability_runs_three_times_per_state_and_drops_flaky_or_unexpected(tmp_path, swe_repo):
    repo, record = swe_repo
    task = contract.swe_task(record, repo, tmp_path / "work")
    fail, passing, held, own = (command.argv for command in task.commands)
    runner = Scripted({("reference", fail): [0, 0, 0], ("start", fail): [1, 1, 1],
                       ("reference", passing): [0, 1, 0],
                       ("reference", held): [0, 0, 0], ("start", held): [0, 0, 0],
                       ("reference", own): [0, 0, 0], ("start", own): [1, 1, 1]})
    result = contract.stabilize(task, runner)
    assert [command.id for command in result.commands] == ["fail-to-pass", "visible_run"]
    assert result.dropped == [{"id": "pass-to-pass", "reason": "flaky_on_reference"},
                              {"id": "heldout-fail-to-pass", "reason": "prepatch_passed"}]
    assert {(row["id"], row["state"]) for row in result.runs} >= {
        ("fail-to-pass", "reference"), ("fail-to-pass", "prepatch")}
    assert all(len(row["exits"]) == 3 for row in result.runs)


def test_stability_narrows_a_grouped_command_to_its_stable_ids(tmp_path, swe_repo):
    repo, record = swe_repo
    record = {**record, "FAIL_TO_PASS": '["tests/test_shapes.py::test_area", "tests/x.py::test_flaky"]',
              "PASS_TO_PASS": "[]"}
    task = contract.swe_task(record, repo, tmp_path / "work")
    group, held, own = task.commands
    prefix = group.argv[:group.ids_from]
    good, flaky = prefix + ("tests/test_shapes.py::test_area",), prefix + ("tests/x.py::test_flaky",)
    runner = Scripted({("reference", group.argv): [0, 1, 0],
                       ("reference", good): [0, 0, 0], ("start", good): [1, 1, 1],
                       ("reference", flaky): [1, 0, 0],
                       ("reference", held.argv): [0, 0, 0], ("start", held.argv): [1, 1, 1],
                       ("reference", own.argv): [0, 0, 0], ("start", own.argv): [1, 1, 1]})
    result = contract.stabilize(task, runner)
    assert result.commands[0].argv == good and result.commands[1].id == "heldout-fail-to-pass"
    assert result.dropped == [{"id": "fail-to-pass", "test": "tests/x.py::test_flaky",
                               "reason": "flaky_on_reference"}]
    report = contract.stability_report(result, runner, 3, True)["stability"]
    assert report["reference"] == "available" and report["runner"] == "scripted"


def test_stability_on_a_real_lcb_task_without_a_reference(tmp_path, python_bin):
    from probity_observer.done.runner import SubprocessRunner
    task = contract.lcb_task(LCB_RECORD, tmp_path / "work")
    result = contract.stabilize(task, SubprocessRunner(python_bin), timeout=60)
    assert [command.id for command in result.commands] == [
        "visible", "visible_run", "heldout", "heldout_determinism", "heldout_type_strict",
        "visible_determinism", "visible_type_strict", "import_side_effects"]
    assert {row["state"] for row in result.runs} == {"prepatch"}


def test_acceptance_configuration_on_the_path_is_protected_and_sealed(tmp_path, swe_repo):
    repo, record = swe_repo
    (repo / "pyproject.toml").write_text("[tool.pytest.ini_options]\naddopts = '-q'\n")
    (repo / "tests" / "setup.cfg").write_text("[metadata]\n")
    (repo / "elsewhere").mkdir()
    (repo / "elsewhere" / "tox.ini").write_text("[pytest]\n")
    assert contract.config_paths(repo, ["tests/test_shapes.py"]) == ["pyproject.toml", "tests/setup.cfg"]
    task = contract.swe_task(record, repo, tmp_path / "w", protect_test_dirs=False)
    protected = {entry.path for entry in task.protected}
    assert {"pyproject.toml", "tests/setup.cfg", "conftest.py"} <= protected
    assert "elsewhere/tox.ini" not in protected
    assert (task.heldout / "config/pyproject.toml").read_text().startswith("[tool.pytest")


def test_stability_records_what_an_honest_run_writes(tmp_path, python_bin):
    from probity_observer.done.runner import SubprocessRunner
    task = contract.lcb_task(LCB_RECORD, tmp_path / "work")
    task.commands = [contract.Command(
        "writes", ("python", "-c", "open('out.log', 'w').write('x'); raise SystemExit(1)"))]
    result = contract.stabilize(task, SubprocessRunner(python_bin), timeout=60)
    assert result.run_writes == {"writes": ["out.log"]}


def test_pytest_start_failures_other_than_failing_tests_are_dropped(tmp_path, swe_repo):
    repo, record = swe_repo
    task = contract.swe_task(record, repo, tmp_path / "work")
    fail, passing, held, own = (command.argv for command in task.commands)
    table = {("reference", fail): [0, 0, 0], ("start", fail): [4, 4, 4],
             ("reference", passing): [0, 0, 0], ("start", passing): [0, 0, 0],
             ("reference", held): [0, 0, 0], ("start", held): [1, 1, 1],
             ("reference", own): [0, 0, 0] * 2, ("start", own): [1, 1, 1] * 2}
    result = contract.stabilize(task, Scripted(table))
    assert {"id": "fail-to-pass", "reason": "prepatch_exit_4"} in result.dropped
    table[("start", fail)] = [2, 2, 2]
    (task.start / "tests" / "test_shapes.py").unlink()
    result = contract.stabilize(task, Scripted(table))
    assert {"id": "fail-to-pass", "reason": "prepatch_exit_2"} in result.dropped


def test_ids_are_sealed_from_collection(tmp_path, swe_repo):
    repo, record = swe_repo
    record = {**record, "FAIL_TO_PASS": '["tests/test_shapes.py::test_area", "tests/x.py::flaky-gone"]'}
    task = contract.swe_task(record, repo, tmp_path / "work")
    group = task.commands[0]
    kept = group.argv[:group.ids_from] + ("tests/test_shapes.py::test_area",)
    table = {("reference", kept): [0, 0, 0], ("start", kept): [1, 1, 1]}
    dropped = []
    narrowed = contract.collect(task, Scripted(table), group, 60, dropped)
    assert narrowed.argv == kept
    assert dropped == [{"id": "fail-to-pass", "test": "tests/x.py::flaky-gone", "reason": "not_collected"}]


def test_a_dropped_heldout_leaves_no_heldout_digest(tmp_path, harness):
    task = contract.lcb_task(LCB_RECORD, tmp_path / "w")
    sealed = contract.seal(task, tmp_path / "out", harness, commands=[task.commands[0]])
    assert "heldout_split_sha256" not in sealed.record
    compiled = json.loads((sealed.out / "sealed" / "compile.json").read_bytes())
    assert compiled["heldout"]["status"] == "dropped"
    assert not (sealed.out / "sealed" / "heldout" / heldout.HELDOUT_NAME).exists()
    assert not (sealed.out / "compile.json").exists()


def test_a_child_that_dies_leaves_every_case_out_and_the_observer_untouched():
    source = ("def check(candidate):\n    import sys\n    sys.exit(3)\n"
              "    assert candidate(1) == 1\n    assert candidate(2) == 2\n")
    assert heldout.literal_cases(heldout.check_body(source)[1]) == [None, None]
