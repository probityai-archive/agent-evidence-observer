"""The bounded loop: one task, one worker, attempts until the policy table stops it.

Each attempt launches the unmodified agent with the three sensors (:mod:`..launch`), signs
the observer's records with the host key, parses the agent's claims, grades its final tree
in fresh containers (:mod:`.verify_run`), combines the checks into the done verdict
(:mod:`.receipt`), writes one attempt record, lets :func:`.policy.decide` choose the action
from the chain of attempt records, and signs a receipt carrying the table's digest and the
decision. ``replan`` resets the workspace from the sealed start tarball and hands only the
reason code to the next attempt in ``PROBITY_DONE_FEEDBACK``.

The loop record ``loop.json`` (``probity-done-loop/v1``, signed by the harness key in
``loop.dsse.json``) carries the policy table itself, its digest, the start state's passing
commands and every attempt record, so :func:`.policy.replay_chain` recomputes each
transition. It is written after every attempt, so a run stopped mid-way still ends its chain
with the last attempt it graded. An attempt the wall-clock budget cut short is graded like any
other, with ``claimed_done: false``.
"""

from __future__ import annotations

import calendar
import json
import shutil
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Callable

from ..launch import launch_agent
from . import claims as claim_parser
from . import drift, policy, receipt, verify_run
from .contract import is_pytest
from .formats import DoneError, encode, public_key, sha256, sign_record
from .runner import is_replay

FLAG = "[flag_for_human_intervention]"
LOOP_SCHEMA = "probity-done-loop/v1"
COLLECTION_EXITS = (2, 4, 5)


@dataclass
class Keys:
    harness: Any
    host: Any
    grader: Any

    def pins(self, observed_party: str, allow_no_heldout: bool = False) -> receipt.Pins:
        return receipt.Pins(public_key(self.harness), public_key(self.host),
                            public_key(self.grader), observed_party=observed_party,
                            allow_no_heldout=allow_no_heldout)


@dataclass
class LoopSpec:
    contract: Path
    out: Path
    image: str
    agent_argv: tuple[str, ...]
    task_id: str
    observed_party: str = "agent"
    attempts: int = 3
    backend: str = "docker"
    grader_image: str | None = None
    network: bool = False
    env: dict[str, str] = field(default_factory=dict)
    timeout_seconds: float = 3600.0
    transcript: str = "text"
    allow_no_heldout: bool = False
    wall_clock_s: float | None = None
    mutations: int | None = None
    tokens: int | None = None
    token_source: str | None = None
    network_policy: Path | None = None
    policy_boundary: Path | None = None
    prover: Path | None = None
    containment: dict[str, Any] | None = None


@dataclass(frozen=True)
class Attempt:
    number: int
    run: Path
    verdict: dict[str, Any]
    decision: policy.Decision
    record: dict[str, Any]


def parse_claims(transcript: str, kind: str, visible: list[str] | None) -> list[dict[str, Any]]:
    if kind == "claude-stream":
        return claim_parser.from_claude_stream(transcript)
    return claim_parser.from_text(transcript, visible)


def _visible_argv(contract: dict[str, Any]) -> list[str] | None:
    """What the agent runs for the first visible command; a replay's agent side is test.py."""
    item = next((item for item in contract["acceptance"]
                 if not item["id"].startswith("heldout")), None)
    if item is None:
        return None
    return ["python", "test.py"] if is_replay(item["argv"]) else item["argv"]


def baseline_ids(bundle: Path) -> list[str]:
    """The acceptance commands that passed every stability run on the start state."""
    path = bundle / "sealed" / "compile.json"
    if not path.is_file():
        return []
    compiled = json.loads(path.read_bytes())
    runs = (compiled.get("stability") or {}).get("runs", [])
    return sorted({row["id"] for row in runs if row["state"] == "prepatch" and row["exits"]
                   and all(code == 0 for code in row["exits"]) and ":" not in row["id"]})


def _elapsed(observation: dict[str, Any]) -> float:
    scope = observation["scope"]
    start, end = (calendar.timegm(time.strptime(scope[name], "%Y-%m-%dT%H:%M:%SZ"))
                  for name in ("start", "end"))
    return float(max(0, end - start))


def _mutation_pairs(observation: dict[str, Any]) -> int:
    pairs = {(event.get("origin"), event.get("path"))
             for event in observation.get("events", []) if event["type"] in drift.MUTATIONS}
    pairs |= {(item.get("origin"), path) for item in observation.get("external_mutations", [])
              for path in item.get("paths", [])}
    return len(pairs)


def _collection_failed(contract: dict[str, Any], grade: dict[str, Any] | None) -> bool:
    if grade is None:
        return False
    argv = {item["id"]: item["argv"] for item in contract["acceptance"]}
    return any(item["exit"] in COLLECTION_EXITS and is_pytest(argv.get(item["id"], []))
               for item in grade["results"])


def attempt_record(number: int, run: Path, contract: dict[str, Any], workspace: Path,
                   verdict: dict[str, Any], grade: dict[str, Any] | None, flagged: bool,
                   limit_s: float, interrupted_by_budget: bool,
                   staging_refused: bool) -> dict[str, Any]:
    """The attempt's entry in the chain: every input :func:`.policy.decide` reads."""
    observation = json.loads((run / "observation.json").read_bytes())
    launched = json.loads((run / "launch.json").read_bytes())
    launch_receipt = json.loads((run / "receipt.json").read_bytes())
    tree = json.loads((run / "tree.json").read_bytes())
    elapsed = _elapsed(observation)
    timed_out = bool(launch_receipt.get("timed_out"))
    attribution = "unknown" if interrupted_by_budget else policy.attribute(
        timed_out, elapsed, limit_s, launch_receipt.get("container_exit"),
        _collection_failed(contract, grade), int(launched.get("orphans_killed", 0)),
        staging_refused)
    events = observation.get("events", [])
    return {
        "attempt": number,
        "contract_sha256": sha256((run / "contract.json").read_bytes()),
        "tree_sha256": tree["tree_sha256"],
        "ast_tree_sha256": drift.ast_tree_sha256(workspace),
        "verdict": verdict["decision"],
        "reason": verdict["reason"],
        "attribution": attribution,
        "claimed_done": not timed_out and not flagged,
        "flagged": flagged,
        "passed_ids": sorted(item["id"] for item in (grade or {}).get("results", [])
                             if item["exit"] == 0),
        "repeated_command": drift.command_latch(events),
        "elapsed_s": elapsed,
        "mutations": _mutation_pairs(observation),
        "tokens": None,
        "observation_sha256": sha256((run / "observation.json").read_bytes()),
        "grade_sha256": sha256((run / "grade.json").read_bytes()) if grade is not None else None,
    }


def _latches(record: dict[str, Any], chain: list[dict[str, Any]]) -> dict[str, Any] | None:
    return record["repeated_command"] or drift.repeated_ast_tree(chain + [record])


def attempt(spec: LoopSpec, keys: Keys, workspace: Path, number: int, table: dict[str, Any],
            chain: list[dict[str, Any]], baseline: list[str], feedback: str | None,
            witness: Callable[[Path], None] | None = None) -> Attempt:
    """Run, grade and judge one attempt; the receipt is signed in the attempt's directory."""
    run = spec.out / f"attempt-{number}"
    claim_id, invocation = f"{spec.task_id}", f"{spec.task_id}-attempt-{number}"
    env = dict(spec.env)
    if feedback:
        env["PROBITY_DONE_FEEDBACK"] = feedback
    limit = spec.timeout_seconds
    if spec.wall_clock_s is not None:
        limit = min(limit, max(1.0, spec.wall_clock_s - sum(item["elapsed_s"] for item in chain)))
    launch_agent.launch(launch_agent.LaunchSpec(
        backend=spec.backend, image=spec.image, agent_argv=spec.agent_argv, workspace=workspace,
        claim_id=claim_id, invocation_id=invocation, env=env, network=spec.network,
        timeout_seconds=limit, network_policy=spec.network_policy,
        containment=spec.containment), run)
    receipt.sign_observer_records(run, keys.host)
    contract_bytes = (spec.contract / "contract.json").read_bytes()
    shutil.copy2(spec.contract / "contract.json", run / "contract.json")
    shutil.copy2(spec.contract / "contract.dsse.json", run / "contract.dsse.json")
    contract = json.loads(contract_bytes)
    transcript = (run / "transcript.txt").read_text("utf-8", "replace")
    flagged = FLAG in transcript
    receipt.write_record(run, "claims", claim_parser.record(
        parse_claims(transcript, spec.transcript, _visible_argv(contract)), claim_id, invocation),
        keys.harness)
    tree = json.loads((run / "tree.json").read_bytes())
    interrupted = limit < spec.timeout_seconds and bool(
        json.loads((run / "receipt.json").read_bytes()).get("timed_out"))
    try:
        graded = verify_run.grade(contract_bytes, spec.contract, workspace, tree,
                                  verify_run.GradeContext(claim_id, invocation),
                                  verify_run.DockerRunner(spec.grader_image or spec.image),
                                  keys.grader)
    except verify_run.GradeError as error:
        verdict = {"decision": "not_established", "reason": "staging_refused",
                   "vantage": "unestablished"}
        record = attempt_record(number, run, contract, workspace, verdict, None, flagged,
                                limit, interrupted, staging_refused=True)
        (run / "staging-refused.txt").write_text(f"{error}\n")
        return _judge(spec, keys, run, table, chain, baseline, record, None, verdict)
    (run / "grade.json").write_bytes(graded.grade_bytes)
    (run / "grade.dsse.json").write_bytes(graded.envelope)
    (run / "grade-staging.json").write_bytes(encode(graded.staging))
    if witness is not None:
        witness(run)
    predicate = receipt.assemble(run, keys.pins(spec.observed_party, spec.allow_no_heldout))
    record = attempt_record(number, run, contract, workspace, predicate["verdict"],
                            graded.grade, flagged, limit, interrupted, staging_refused=False)
    predicate["verifier_isolation"] = graded.isolation
    return _judge(spec, keys, run, table, chain, baseline, record, predicate,
                  predicate["verdict"])


def _judge(spec: LoopSpec, keys: Keys, run: Path, table: dict[str, Any],
           chain: list[dict[str, Any]], baseline: list[str], record: dict[str, Any],
           predicate: dict[str, Any] | None, verdict: dict[str, Any]) -> Attempt:
    record["loop"] = _latches(record, chain)
    decision = policy.decide(table, chain + [record], baseline)
    record["decision"] = decision.record()
    if predicate is not None:
        predicate.update(policy={"table_sha256": policy.table_sha256(table)},
                         stop_decision=decision.record(), attempt=record)
        receipt.sign_receipt(run, predicate, keys.harness)
    return Attempt(record["attempt"], run, verdict, decision, record)


def write_loop(spec: LoopSpec, keys: Keys, table: dict[str, Any], baseline: list[str],
               chain: list[dict[str, Any]]) -> bytes:
    """Sign and write the loop record; return its bytes."""
    data, envelope = sign_record({
        "schema_version": LOOP_SCHEMA, "task_id": spec.task_id, "policy": table,
        "policy_sha256": policy.table_sha256(table), "baseline_ids": baseline,
        "attempts": chain}, keys.harness)
    (spec.out / "loop.json").write_bytes(data)
    (spec.out / "loop.dsse.json").write_bytes(envelope)
    return data


def admit_launch_policy(spec: LoopSpec) -> LoopSpec:
    """Prove the declared launch policy within the operator's boundary before any attempt.

    Only the prover's ``within_boundary`` admits the policy (:mod:`..openshell.prover`); its
    record goes to ``out/containment.json`` either way, and into every attempt's launch record
    when it is admitted. A declared policy without a boundary is refused.
    """
    if spec.network_policy is None:
        if spec.policy_boundary is not None:
            raise DoneError("a policy boundary needs a declared network policy")
        return spec
    if spec.policy_boundary is None:
        raise DoneError("a declared network policy needs --policy-boundary to be proven within")
    from ..openshell import prover, release

    binary = spec.prover or release.executable("openshell-prover")
    try:
        record = prover.check(spec.network_policy, spec.policy_boundary, prover.Prover(binary))
    except prover.ContainmentRefused as refused:
        (spec.out / "containment.json").write_bytes(encode(refused.record))
        raise DoneError(str(refused)) from None
    (spec.out / "containment.json").write_bytes(encode(record))
    return replace(spec, containment=record)


def run_loop(spec: LoopSpec, keys: Keys,
             witness: Callable[[Path], None] | None = None) -> list[Attempt]:
    """Attempts until ``stop`` or ``escalate``; the loop record goes to ``out/loop.json``."""
    table = policy.table(attempts=spec.attempts, wall_clock_s=spec.wall_clock_s,
                         mutations=spec.mutations, tokens=spec.tokens)
    policy.check_budget(table, spec.token_source)
    spec.out.mkdir(parents=True, exist_ok=True)
    if any(spec.out.iterdir()):
        raise ValueError("loop output directory must be empty")
    spec = admit_launch_policy(spec)
    workspace = spec.out / "workspace"
    shutil.copytree(spec.contract / "workspace", workspace, symlinks=True)
    (spec.out / "policy.json").write_bytes(encode(table))
    baseline = baseline_ids(spec.contract)
    done: list[Attempt] = []
    chain: list[dict[str, Any]] = []
    feedback = None
    for number in range(1, spec.attempts + 1):
        current = attempt(spec, keys, workspace, number, table, chain, baseline, feedback,
                          witness)
        done.append(current)
        chain.append(current.record)
        write_loop(spec, keys, table, baseline, chain)
        if current.decision.action in policy.TERMINAL:
            break
        if current.decision.action == "replan":
            first = json.loads((spec.out / "attempt-1" / "launch.json").read_bytes())
            policy.apply(current.decision, workspace, spec.out / "attempt-1" / "start.tar",
                         first["start_tarball_sha256"])
            feedback = policy.replan_input(current.decision, number)
    return done
