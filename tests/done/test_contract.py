"""The contract compiler on LiveCodeBench and SWE-bench fields, with no model call."""

import json

import pytest

from probity_observer.done import contract, heldout
from probity_observer.done.formats import DoneError, encode, open_record, public_key, sha256
from probity_observer.sensors import treedigest

from .conftest import LCB_ORIGINAL, LCB_RECORD


def test_lcb_contract_holds_out_inputs_and_keeps_the_impossible_assertion(tmp_path, harness):
    task = contract.lcb_task(LCB_RECORD, tmp_path / "work")
    visible = (task.start / "test.py").read_text()
    assert "candidate(1, 1) == 3" in visible
    source = (task.heldout / heldout.HELDOUT_NAME).read_text()
    held = [line for line in source.splitlines() if line.startswith("    lambda")]
    assert held and all("candidate(1, 1)" not in line for line in held)
    for line in held:
        args = line.split("candidate(", 1)[1].rsplit(")", 1)[0]
        assert f"candidate({args})" not in visible
    sealed = contract.seal(task, tmp_path / "out", harness)
    record = json.loads((sealed.out / "contract.json").read_bytes())
    assert record["acceptance"] == [{"id": "visible", "argv": ["python", "test.py"]},
                                    {"id": "heldout", "argv": list(heldout.HELDOUT_ARGV)}]
    assert record["protected_paths"] == [{"path": "test.py", "kind": "file",
                                          "sha256": treedigest.file_sha256(task.start / "test.py")}]
    assert record["heldout_split_sha256"] == treedigest.scan(tmp_path / "out/sealed/heldout").sha256
    assert not (sealed.out / "workspace" / heldout.HELDOUT_NAME).exists()
    assert json.loads((sealed.out / "compile.json").read_bytes())["model_calls"] == 0


def test_contract_bytes_are_canonical_and_signed(tmp_path, harness):
    sealed = contract.seal(contract.lcb_task(LCB_ORIGINAL, tmp_path / "w"), tmp_path / "out", harness)
    data = (sealed.out / "contract.json").read_bytes()
    assert encode(json.loads(data)) == data and sha256(data) == sealed.contract_sha256
    envelope = (sealed.out / "contract.dsse.json").read_bytes()
    assert open_record(envelope, public_key(harness), contract.SCHEMA) == data
    statement = json.loads((sealed.out / "contract.statement.json").read_bytes())
    assert statement["predicateType"].endswith("/predicate/v1/done-contract")
    assert statement["subject"][0]["digest"]["sha256"] == sealed.contract_sha256


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
        contract.seal(task, tmp_path / "out", harness, commands=[task.commands[1]])


def test_swe_contract_from_dataset_fields(tmp_path, swe_repo, harness):
    repo, record = swe_repo
    task = contract.swe_task(record, repo, tmp_path / "work")
    assert "== 7" in (task.start / "tests/test_shapes.py").read_text()
    assert "== 6" in (task.heldout / "tests/test_shapes.py").read_text()
    assert "w * h" in (task.reference / "pkg/shapes.py").read_text()
    ids = [command.id for command in task.commands]
    assert ids == ["fail-to-pass", "pass-to-pass", "heldout-fail-to-pass"]
    assert task.commands[0].argv[-1] == "tests/test_shapes.py::test_area"
    assert task.commands[2].argv[:2] == ("sh", "-c") and "../heldout" in task.commands[2].argv[2]
    protected = {(entry.path, entry.kind) for entry in task.protected}
    assert protected == {("tests", "directory"), ("conftest.py", "file")}
    assert task.mutation_targets == {"pkg/shapes.py": [(1, 2)]}
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
        heldout.heldout_file("not an identifier", ())
