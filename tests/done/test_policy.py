"""The policy table, its digest, the latches, the chain replay and the tarball reset."""

import pytest

from probity_observer.done import drift, policy
from probity_observer.done.formats import DoneError
from probity_observer.launch import snapshot

PYTEST = ["python", "-m", "pytest"]


def exec_event(step, argv=PYTEST, exit_code=1, origin=None, cwd="/workspace"):
    event = {"id": f"e{step}", "type": "exec", "step": step, "argv": argv, "exit": exit_code,
             "exe": "/usr/bin/python", "cwd": cwd}
    event["origin"] = origin or f"e{step}"
    return event


def read(step, path, origin):
    return {"id": f"e{step}", "type": "read", "step": step, "path": path, "origin": origin}


def write(step, path, origin=None):
    event = {"id": f"e{step}", "type": "write", "step": step, "path": path}
    if origin:
        event["origin"] = origin
    return event


def record(number, verdict="not_established", reason="observation_coverage_unestablished",
           **fields):
    base = {"attempt": number, "contract_sha256": "c" * 64, "tree_sha256": f"t{number}",
            "ast_tree_sha256": f"a{number}", "verdict": verdict, "reason": reason,
            "attribution": "unknown", "claimed_done": True, "flagged": False,
            "passed_ids": [], "repeated_command": None, "elapsed_s": 10.0, "mutations": 1,
            "tokens": None, "observation_sha256": "o" * 64, "grade_sha256": "g" * 64,
            "loop": None}
    base.update(fields)
    return base


def decide(table, *records, baseline=()):
    return policy.decide(table, list(records), list(baseline)).record()


SUPPORTED = {"verdict": "supported", "reason": "done_checks_supported"}
CONTRA = {"verdict": "contradicted", "reason": "protected_path_mutated"}


def test_table_digest_is_stable_and_names_every_rule():
    first, second = policy.table(), policy.table()
    assert policy.table_sha256(first) == policy.table_sha256(second)
    assert policy.table_sha256(first) != policy.table_sha256(policy.table(attempts=5))
    assert first["latch"] == {"command_repeats": 3, "command_repeats_in_attempt": 4,
                              "ast_tree_recurrences": 2}
    assert {rule["action"] for rule in first["rules"]} == set(policy.ACTIONS)
    assert {rule["reason"] for rule in first["verdict_rules"]} == {
        "external_effect_on_grader_path", "tracer_terminated_prematurely"}
    assert policy.table(wall_clock_s=60, mutations=5)["budget"] == {
        "attempts": 3, "wall_clock_s": 60, "mutations": 5}


def test_the_precedence_order():
    table = policy.table(attempts=3)
    assert decide(table, record(1, **SUPPORTED)) == {"action": "stop",
                                                     "reason": "done_checks_supported"}
    assert decide(table, record(1, loop={"latch": "ast_tree"}))["reason"] == "loop_detected"
    assert decide(table, record(1, **CONTRA)) == {"action": "replan",
                                                  "reason": "protected_path_mutated"}
    assert decide(table, record(1, **CONTRA), record(2, **CONTRA)) == {
        "action": "escalate", "reason": "protected_path_mutated"}
    assert decide(table, record(1, **CONTRA, flagged=True))["reason"] == (
        "contradicted_while_escalating")
    assert decide(table, record(1), record(2, flagged=True))["reason"] == "agent_escalated"
    lenient = policy.table(attempts=5, escalate_after=9)
    assert decide(lenient, record(1, **CONTRA), record(2, flagged=True))["reason"] == (
        "agent_escalated_after_contradiction")
    assert decide(policy.table(attempts=1, escalate_after=9), record(1, **CONTRA)) == {
        "action": "stop", "reason": "budget_exhausted_after_contradiction", "line": "attempts"}
    assert decide(policy.table(attempts=1), record(1)) == {
        "action": "stop", "reason": "budget_exhausted", "line": "attempts"}
    assert decide(table, record(1))["action"] == "continue"


def test_each_budget_line_names_itself():
    assert decide(policy.table(attempts=9, wall_clock_s=15), record(1), record(2, reason="x",
                  attribution="harness"))["line"] == "wall_clock_s"
    assert decide(policy.table(attempts=9, mutations=2), record(1, mutations=2))["line"] == (
        "mutations")
    assert decide(policy.table(attempts=9, tokens=5), record(1, tokens=7))["line"] == "tokens"


def test_a_token_budget_needs_a_host_side_count():
    with pytest.raises(DoneError):
        policy.check_budget(policy.table(tokens=100), "agent_report")
    with pytest.raises(DoneError):
        policy.check_budget(policy.table(tokens=100), None)
    policy.check_budget(policy.table(tokens=100), "host_proxy")
    policy.check_budget(policy.table(), None)


def test_attribution_comes_from_the_records():
    assert policy.attribute(False, 5, 60, 125, False, 0, False) == "harness"
    assert policy.attribute(True, 30, 60, 0, False, 0, False) == "harness"
    assert policy.attribute(True, 61, 60, 137, False, 0, False) == "agent"
    assert policy.attribute(False, 5, 60, 0, True, 0, False) == "agent"
    assert policy.attribute(False, 5, 60, 0, False, 2, False) == "agent"
    assert policy.attribute(False, 5, 60, 0, False, 0, True) == "agent"
    assert policy.attribute(False, 5, 60, 0, False, 0, False) == "unknown"


def test_an_agent_charged_unestablished_attempt_counts_as_contradicted():
    table = policy.table(attempts=5)
    sabotage = record(1, attribution="agent")
    assert decide(table, sabotage) == {"action": "replan", "reason": "coverage_sabotaged"}
    assert decide(table, sabotage, record(2, attribution="agent"))["action"] == "escalate"


def test_a_harness_failure_counts_for_nothing_and_alternation_still_escalates():
    table = policy.table(attempts=9)
    harness = record(1, attribution="harness")
    assert decide(table, harness, record(2, attribution="harness"))["action"] == "continue"
    assert decide(table, record(1), harness)["action"] == "continue"
    assert decide(table, record(1), harness, record(3))["reason"] == (
        "record_unestablished_repeatedly")
    alternating = [record(1, attribution="agent"), record(2, **CONTRA)]
    assert decide(table, *alternating)["action"] == "escalate"


def test_a_stall_without_new_passing_commands_stops():
    table = policy.table(attempts=9, escalate_after_unestablished=9)
    baseline = ["pass-to-pass"]
    steady = [record(n, passed_ids=["pass-to-pass"]) for n in (1, 2, 3)]
    assert decide(table, *steady, baseline=baseline)["reason"] == "stalled"
    growing = [record(1, passed_ids=["pass-to-pass"]),
               record(2, passed_ids=["pass-to-pass", "fail-to-pass"]),
               record(3, passed_ids=["pass-to-pass", "fail-to-pass"])]
    assert decide(table, *growing, baseline=baseline)["action"] == "continue"
    # Breaking the start state's passing tests and restoring one never counts as growth.
    trick = [record(1, passed_ids=["f1"]), record(2, passed_ids=["pass-to-pass"]),
             record(3, passed_ids=["f2"])]
    assert drift.progress(baseline, trick) == (["pass-to-pass"], 3)


def test_the_command_latch_ignores_edits_the_command_never_read():
    runs = []
    step = 0
    for _ in range(3):
        step += 1
        runs.append(exec_event(step))
        step += 1
        runs.append(read(step, "tests/test_a.py", f"e{step - 1}"))
        step += 1
        runs.append(exec_event(step, ["touch", ".probe"], 0))
        step += 1
        runs.append(write(step, ".probe", f"e{step - 1}"))
    assert drift.repeated_command(runs)["argv"] == PYTEST


def test_an_edit_to_a_file_the_command_read_resets_the_count():
    events = [exec_event(1), read(2, "src/a.py", "e1"), write(3, "src/a.py"),
              exec_event(4), read(5, "src/a.py", "e4"), write(6, "src/a.py"),
              exec_event(7), read(8, "src/a.py", "e7")]
    assert drift.repeated_command(events) is None
    own = [exec_event(1), read(2, ".pytest_cache/x", "e1"), write(3, ".pytest_cache/x", "e1"),
           exec_event(4), read(5, ".pytest_cache/x", "e4"), write(6, ".pytest_cache/x", "e4"),
           exec_event(7)]
    assert drift.repeated_command(own)["argv"] == PYTEST
    elsewhere = [exec_event(1), exec_event(2, cwd="/workspace/sub"), exec_event(3)]
    assert drift.repeated_command(elsewhere) is None
    other_exit = [exec_event(1), exec_event(2), exec_event(3, exit_code=0), exec_event(4)]
    assert drift.repeated_command(other_exit) is None


def test_the_in_attempt_latch_fires_at_four_whatever_the_edits():
    events = []
    for index in range(4):
        events += [exec_event(10 * index + 1), read(10 * index + 2, "src/a.py", f"e{10 * index + 1}"),
                   write(10 * index + 3, "src/a.py")]
    assert drift.repeated_command(events) is None
    assert drift.repeated_in_attempt(events)["repeats"] == 4
    assert drift.command_latch(events)["latch"] == "command_in_attempt"
    assert drift.repeated_in_attempt(events[:9]) is None


def test_the_ast_tree_latch_fires_on_a_recurring_program(tmp_path):
    root = tmp_path / "ws"
    root.mkdir()
    (root / "a.py").write_text("def f():\n    return 1\n")
    first = drift.ast_tree_sha256(root)
    (root / "a.py").write_text("# attempt 2\ndef f():\n\n    return 1   # same\n")
    (root / "__pycache__").mkdir()
    (root / "__pycache__" / "a.pyc").write_bytes(b"x")
    assert drift.ast_tree_sha256(root) == first
    (root / "a.py").write_text("def f():\n    return 2\n")
    assert drift.ast_tree_sha256(root) != first
    (root / "a.py").write_text("def (:  # one\n")
    broken = drift.ast_tree_sha256(root)
    (root / "a.py").write_text("def (:  # two\n")
    assert drift.ast_tree_sha256(root) == broken
    chain = [record(1, ast_tree_sha256="A"), record(2, ast_tree_sha256="B"),
             record(3, ast_tree_sha256="A")]
    assert drift.repeated_ast_tree(chain[:2]) is None
    assert drift.repeated_ast_tree(chain)["first_attempt"] == 1
    honest = [record(n, ast_tree_sha256=f"T{n}") for n in (1, 2, 3)]
    assert drift.repeated_ast_tree(honest) is None


def test_the_chain_replays_and_refuses_a_forged_or_continued_one():
    table = policy.table(attempts=3)
    chain = [record(1, **CONTRA), record(2, **CONTRA)]
    for index, item in enumerate(chain):
        item["decision"] = policy.decide(table, chain[:index + 1], []).record()
    assert policy.replay_chain(table, chain, []) == []
    forged = [dict(chain[0]), {**chain[1], "decision": {"action": "stop",
                                                       "reason": "done_checks_supported"}}]
    assert policy.replay_chain(table, forged, []) == ["decision_does_not_recompute:2"]
    third = record(3, **CONTRA)
    third["decision"] = policy.decide(table, chain + [third], []).record()
    assert "continued_after_terminal_decision:3" in policy.replay_chain(table, chain + [third], [])
    changed = [chain[0], {**chain[1], "contract_sha256": "d" * 64}]
    assert "contract_changed_mid_run:2" in policy.replay_chain(table, changed, [])
    assert policy.replay_chain(table, chain[:1], []) == ["chain_ends_before_a_terminal_decision"]


def test_replan_resets_the_workspace_and_its_input_carries_no_contract(tmp_path):
    workspace = tmp_path / "ws"
    workspace.mkdir()
    (workspace / "a.py").write_text("start\n")
    digest = snapshot.seal(workspace, tmp_path / "start.tar")
    (workspace / "a.py").write_text("changed\n")
    (workspace / "new.py").write_text("x\n")
    policy.apply(policy.Decision("continue", "r"), workspace, tmp_path / "start.tar", digest)
    assert (workspace / "new.py").exists()
    policy.apply(policy.Decision("replan", "r"), workspace, tmp_path / "start.tar", digest)
    assert (workspace / "a.py").read_text() == "start\n" and not (workspace / "new.py").exists()
    text = policy.replan_input(policy.Decision("replan", "protected_path_mutated"), 1)
    assert "protected_path_mutated" in text
    for secret in ("test.py", "heldout", "sha256", "contract"):
        assert secret not in text
