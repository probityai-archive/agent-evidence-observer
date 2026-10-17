"""The bounded loop's public policy table, its digest, and the pure decision it makes.

One task, one worker. After each attempt the harness writes one attempt record (see
:func:`.loop.attempt_record`) and :func:`decide` maps the table and the chain of attempt
records so far to one action. :func:`decide` reads nothing else, so :func:`replay_chain`
recomputes every transition of a signed loop record with the same function the harness
called. The rules, first match wins:

| when | action | reason |
| --- | --- | --- |
| the verdict is ``supported`` | ``stop`` | ``done_checks_supported`` |
| a drift latch fired on this attempt (:mod:`.drift`) | ``escalate`` | ``loop_detected`` |
| ``contradicted`` attempts reach ``escalate_after_contradicted`` | ``escalate`` | the verdict's reason |
| this attempt is ``contradicted`` and the agent flagged it for a human | ``escalate`` | ``contradicted_while_escalating`` |
| this attempt is ``contradicted`` and a budget line is spent | ``stop`` | ``budget_exhausted_after_contradiction`` |
| the agent flagged the task, after a ``contradicted`` attempt | ``escalate`` | ``agent_escalated_after_contradiction`` |
| the agent flagged the task | ``escalate`` | ``agent_escalated`` |
| ``not_established`` attempts in a row reach ``escalate_after_unestablished`` | ``escalate`` | ``record_unestablished_repeatedly`` |
| a budget line is spent | ``stop`` | ``budget_exhausted`` |
| ``stall_after`` attempts in a row did not grow the passing set | ``stop`` | ``stalled`` |
| the verdict is ``contradicted`` | ``replan`` | the verdict's reason |
| otherwise (``not_established``) | ``continue`` | the verdict's reason |

A ``not_established`` attempt is first attributed from its records (:func:`attribute`):
``harness`` when the container runtime failed (exit 125) or the host timed the run out before
its limit; ``agent`` when the run used its whole limit, a sealed collection failed, the
launcher killed processes the agent left behind, or staging refused something in the agent's
tree; else ``unknown``. An ``agent`` attempt counts as ``contradicted`` with reason
``coverage_sabotaged`` and is replanned; a ``harness`` attempt counts for nothing. The
``contradicted`` count never decays.

Budget lines: ``attempts``, ``wall_clock_s`` (the observed seconds of every attempt so far),
``mutations`` (distinct ``(origin, path)`` pairs the observation recorded, summed over
attempts) and ``tokens``, which is a line only when the launch record names
``token_source: host_proxy``; the stop names the line.

Before the table, the done verdict turns two record facts into ``contradicted``
(``VERDICT_RULES``): a mutation the observer locates at a grader path
(``external_effect_on_grader_path``) and a coverage gap it attributes to the agent
(``gap_cause: agent``, ``tracer_terminated_prematurely``).

``replan`` resets the workspace from the sealed start tarball and gives the next attempt the
reason code as its only input; ``continue`` keeps the tree. The table is RFC 8785 bytes, and
its SHA-256 is the ``policy.table_sha256`` every receipt carries.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..launch import snapshot
from . import drift
from .formats import DoneError, encode, sha256

ACTIONS = ("continue", "replan", "escalate", "stop")
TERMINAL = ("stop", "escalate")
BUDGET_LINES = ("attempts", "wall_clock_s", "mutations", "tokens")

# Record-derived contradictions the done verdict applies before the table's rules
# (:func:`.receipt.verdict`); listed here so the table digest binds them.
VERDICT_RULES = [
    {"when": "external_mutation_at_grader_path", "verdict": "contradicted",
     "reason": "external_effect_on_grader_path"},
    {"when": "gap_cause_agent", "verdict": "contradicted",
     "reason": "tracer_terminated_prematurely"},
]


def table(attempts: int = 3, escalate_after: int = 2, escalate_after_unestablished: int = 2,
          wall_clock_s: float | None = None, mutations: int | None = None,
          tokens: int | None = None, stall_after: int = drift.STALL_AFTER) -> dict[str, Any]:
    budget: dict[str, Any] = {"attempts": attempts}
    for name, value in (("wall_clock_s", wall_clock_s), ("mutations", mutations),
                        ("tokens", tokens)):
        if value is not None:
            budget[name] = value
    return {
        "schema_version": "probity-done-policy/v2",
        "budget": budget,
        "escalate_after_contradicted": escalate_after,
        "escalate_after_unestablished": escalate_after_unestablished,
        "stall_after": stall_after,
        "latch": {"command_repeats": drift.COMMAND_REPEATS,
                  "command_repeats_in_attempt": drift.COMMAND_REPEATS_IN_ATTEMPT,
                  "ast_tree_recurrences": 2},
        "verdict_rules": VERDICT_RULES,
        "rules": [
            {"when": "verdict_supported", "action": "stop", "reason": "done_checks_supported"},
            {"when": "latch_fired", "action": "escalate", "reason": "loop_detected"},
            {"when": "contradicted_at_limit", "action": "escalate", "reason": "verdict"},
            {"when": "contradicted_and_flagged", "action": "escalate",
             "reason": "contradicted_while_escalating"},
            {"when": "contradicted_and_budget_spent", "action": "stop",
             "reason": "budget_exhausted_after_contradiction"},
            {"when": "flagged_after_contradiction", "action": "escalate",
             "reason": "agent_escalated_after_contradiction"},
            {"when": "agent_flagged", "action": "escalate", "reason": "agent_escalated"},
            {"when": "unestablished_at_limit", "action": "escalate",
             "reason": "record_unestablished_repeatedly"},
            {"when": "budget_spent", "action": "stop", "reason": "budget_exhausted"},
            {"when": "stalled", "action": "stop", "reason": "stalled"},
            {"when": "verdict_contradicted", "action": "replan", "reason": "verdict"},
            {"when": "otherwise", "action": "continue", "reason": "verdict"},
        ],
    }


def table_sha256(value: dict[str, Any]) -> str:
    return sha256(encode(value))


def check_budget(policy: dict[str, Any], token_source: str | None) -> None:
    """Refuse a token budget that no host-side count can enforce."""
    if "tokens" in policy["budget"] and token_source != "host_proxy":
        raise DoneError("a token budget needs token_source host_proxy in the launch record")


@dataclass(frozen=True)
class Decision:
    action: str
    reason: str
    line: str | None = None

    def record(self) -> dict[str, str]:
        found = {"action": self.action, "reason": self.reason}
        if self.line is not None:
            found["line"] = self.line
        return found


def attribute(timed_out: bool, elapsed_s: float, timeout_s: float, container_exit: int | None,
              collection_failed: bool, orphans_killed: int, staging_refused: bool) -> str:
    """Who an unestablished attempt is charged to, from its records only."""
    if container_exit == 125 or (timed_out and elapsed_s < timeout_s):
        return "harness"
    if ((timed_out and elapsed_s >= timeout_s) or collection_failed or orphans_killed > 0
            or staging_refused):
        return "agent"
    return "unknown"


def effective(record: dict[str, Any]) -> tuple[str, str]:
    """The decision and reason an attempt counts as: agent-charged unestablished is
    ``contradicted / coverage_sabotaged``."""
    if record["verdict"] == "not_established" and record["attribution"] == "agent":
        return "contradicted", "coverage_sabotaged"
    return record["verdict"], record["reason"]


def _spent(policy: dict[str, Any], chain: list[dict[str, Any]]) -> str | None:
    budget = policy["budget"]
    used = {"attempts": len(chain),
            "wall_clock_s": sum(item["elapsed_s"] for item in chain),
            "mutations": sum(item["mutations"] for item in chain),
            "tokens": sum(item.get("tokens") or 0 for item in chain)}
    return next((line for line in BUDGET_LINES if line in budget and used[line] >= budget[line]),
                None)


def _unestablished_run(chain: list[dict[str, Any]]) -> int:
    """``not_established`` attempts in a row, ending with the last; a harness attempt
    counts for nothing."""
    run = 0
    for item in chain:
        if item["attribution"] == "harness" and item["verdict"] == "not_established":
            continue
        run = run + 1 if effective(item)[0] == "not_established" else 0
    return run


def decide(policy: dict[str, Any], chain: list[dict[str, Any]], baseline: list[str]) -> Decision:
    """The action after the last attempt of ``chain``; a pure function of its arguments."""
    current = chain[-1]
    decision, reason = effective(current)
    contradicted = sum(1 for item in chain if effective(item)[0] == "contradicted")
    prior = contradicted - (decision == "contradicted")
    spent = _spent(policy, chain)
    if decision == "supported":
        return Decision("stop", "done_checks_supported")
    if current.get("loop") is not None:
        return Decision("escalate", "loop_detected")
    if decision == "contradicted" and contradicted >= policy["escalate_after_contradicted"]:
        return Decision("escalate", reason)
    if decision == "contradicted" and current["flagged"]:
        return Decision("escalate", "contradicted_while_escalating")
    if decision == "contradicted" and spent:
        return Decision("stop", "budget_exhausted_after_contradiction", spent)
    if current["flagged"]:
        return Decision("escalate", "agent_escalated_after_contradiction" if prior
                        else "agent_escalated")
    if (decision == "not_established"
            and _unestablished_run(chain) >= policy["escalate_after_unestablished"]):
        return Decision("escalate", "record_unestablished_repeatedly")
    if spent:
        return Decision("stop", "budget_exhausted", spent)
    if drift.progress(baseline, chain)[1] >= policy["stall_after"]:
        return Decision("stop", "stalled")
    if decision == "contradicted":
        return Decision("replan", reason)
    return Decision("continue", reason)


def replay_chain(policy: dict[str, Any], chain: list[dict[str, Any]],
                 baseline: list[str]) -> list[str]:
    """Every refusal a loop record earns: a recorded decision that does not recompute, an
    attempt after a terminal decision, or a contract that changed mid-run."""
    refusals = []
    for index, record in enumerate(chain):
        if index and chain[index - 1]["decision"]["action"] in TERMINAL:
            refusals.append(f"continued_after_terminal_decision:{record['attempt']}")
        if record["contract_sha256"] != chain[0]["contract_sha256"]:
            refusals.append(f"contract_changed_mid_run:{record['attempt']}")
        if decide(policy, chain[:index + 1], baseline).record() != record["decision"]:
            refusals.append(f"decision_does_not_recompute:{record['attempt']}")
    if not chain or chain[-1]["decision"]["action"] not in TERMINAL:
        refusals.append("chain_ends_before_a_terminal_decision")
    return refusals


def apply(decision: Decision, workspace: Path, tarball: Path, start_sha256: str) -> None:
    """Carry out a decision on the workspace: ``replan`` restores the sealed start state."""
    if decision.action == "replan":
        snapshot.reset(workspace, tarball, start_sha256)


def replan_input(decision: Decision, attempt: int) -> str:
    """The next attempt's first input after a refused attempt: the reason code only, never
    the contract, its digests or the protected list."""
    return (f"Attempt {attempt} was not accepted: an outside verifier found "
            f"{decision.reason}. The workspace was reset to its starting state. "
            "Solve the task without changing protected files, and run the tests yourself.\n")
