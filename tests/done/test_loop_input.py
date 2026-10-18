"""What the next attempt is told: a refusal only after replan, a run request after a parser
outcome whose tests passed, and nothing otherwise (review 5, G8)."""

from pathlib import Path
from types import SimpleNamespace

from probity_observer.done import loop, policy

PASSED = [{"claim_type": "acceptance_observed/v1", "decision": "supported"}]
FAILED = [{"claim_type": "acceptance_observed/v1", "decision": "contradicted"}]


def attempt(action, reason, checks):
    return loop.Attempt(2, Path("attempt-2"), {}, policy.Decision(action, reason), {}, checks)


def test_a_parser_outcome_with_passing_tests_asks_for_the_run():
    text = loop.next_input(attempt("continue", "no_tool_claims", PASSED), None)
    assert text == policy.continue_input(policy.Decision("continue", "no_tool_claims"), 2)
    assert loop.next_input(attempt("continue", "tool_exit_unobserved", PASSED), None)


def test_no_feedback_after_any_other_continue():
    assert loop.next_input(attempt("continue", "no_tool_claims", FAILED), None) is None
    assert loop.next_input(attempt("continue", "observation_coverage_unestablished", PASSED),
                           None) is None
    assert loop.next_input(attempt("continue", "no_tool_claims", None), None) is None


def test_a_replan_carries_the_refusal(monkeypatch):
    monkeypatch.setattr(loop, "contract_record", lambda spec: {})
    monkeypatch.setattr(loop, "refusal_detail", lambda run, contract: ["visible failed"])
    text = loop.next_input(attempt("replan", "acceptance_failed_in_verifier", FAILED), None)
    assert "acceptance_failed_in_verifier" in text and "- visible failed" in text
    assert "reset" in text


def test_the_loop_clears_feedback_after_a_replan(tmp_path, monkeypatch):
    """A refusal's text reaches the attempt after it and no later one."""
    (tmp_path / "contract" / "workspace").mkdir(parents=True)
    spec = SimpleNamespace(attempts=3, wall_clock_s=None, mutations=None, tokens=None,
                           token_source=None, out=tmp_path / "out",
                           contract=tmp_path / "contract")
    decisions = iter([("replan", "acceptance_failed_in_verifier", FAILED),
                      ("continue", "observation_coverage_unestablished", PASSED),
                      ("stop", "budget_exhausted", PASSED)])
    seen = []

    def fake_attempt(spec, keys, workspace, number, table, chain, baseline, feedback, witness):
        seen.append(feedback)
        (spec.out / f"attempt-{number}").mkdir()
        (spec.out / f"attempt-{number}" / "launch.json").write_text(
            '{"start_tarball_sha256": "s"}')
        action, reason, checks = next(decisions)
        return loop.Attempt(number, tmp_path, {}, policy.Decision(action, reason),
                            {"attempt": number}, checks)
    monkeypatch.setattr(loop, "attempt", fake_attempt)
    monkeypatch.setattr(loop, "baseline_ids", lambda bundle: [])
    monkeypatch.setattr(loop, "write_loop", lambda *args: None)
    monkeypatch.setattr(loop, "contract_record", lambda spec: {})
    monkeypatch.setattr(loop, "refusal_detail", lambda run, contract: [])
    monkeypatch.setattr(loop.policy, "apply", lambda *args: None)
    loop.run_loop(spec, None)
    assert seen[0] is None and "acceptance_failed_in_verifier" in seen[1] and seen[2] is None
