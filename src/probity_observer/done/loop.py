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
other, with ``claimed_done: false``, as is one whose claims hold no passing run.
"""

from __future__ import annotations

import calendar
import json
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from ..launch import launch_agent, snapshot
from . import claims as claim_parser
from . import drift, policy, receipt, verify_run
from .contract import is_pytest
from .formats import encode, public_key, sha256, sign_record
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


@dataclass(frozen=True)
class Attempt:
    number: int
    run: Path
    verdict: dict[str, Any]
    decision: policy.Decision
    record: dict[str, Any]


def parse_claims(transcript: str, kind: str, visible: list[str] | None,
                 commands: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    if kind == "claude-stream":
        return claim_parser.from_claude_stream(transcript, commands)
    return claim_parser.from_text(transcript, visible, commands)


def agent_commands(contract: dict[str, Any]) -> list[dict[str, Any]] | None:
    """The acceptance commands the agent runs itself (sealed with ``cwd`` and ``exe``), or None
    when the contract seals none."""
    found = [item for item in contract["acceptance"] if "exe" in item]
    return found or None


def _visible_argv(contract: dict[str, Any]) -> list[str] | None:
    """What the agent runs for the first visible command; a replay's agent side is test.py."""
    commands = agent_commands(contract)
    if commands is not None:
        return list(commands[0]["argv"])
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


def _claims_a_pass(run: Path) -> bool:
    """Whether the agent claimed a passing run of a sealed command (``claims.json``): an
    attempt that ended without one did not claim done, whatever its exit."""
    path = run / "claims.json"
    if not path.is_file():
        return False
    return any(claim.get("exit") == 0 for claim in json.loads(path.read_bytes())["claims"])


def attempt_record(number: int, run: Path, contract: dict[str, Any], workspace: Path,
                   verdict: dict[str, Any], grade: dict[str, Any] | None, flagged: bool,
                   limit_s: float, interrupted_by_budget: bool,
                   staging_refused: bool,
                   checks: list[dict[str, Any]] | None = None) -> dict[str, Any]:
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
    claimed = not timed_out and not flagged and _claims_a_pass(run)
    if verdict["decision"] == "contradicted":
        attribution = policy.attribute_refusal(checks or [], claimed) or attribution
    events = observation.get("events", [])
    return {
        "attempt": number,
        "contract_sha256": sha256((run / "contract.json").read_bytes()),
        "tree_sha256": tree["tree_sha256"],
        "ast_tree_sha256": drift.ast_tree_sha256(workspace),
        "verdict": verdict["decision"],
        "reason": verdict["reason"],
        "attribution": attribution,
        "claimed_done": claimed,
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
        timeout_seconds=limit), run)
    # The final tree the agent left, kept beside the start tree: the next attempt starts from a
    # reset workspace, so without it no attempt but the last could be graded again later.
    snapshot.seal(workspace, run / "end.tar")
    receipt.sign_observer_records(run, keys.host)
    contract_bytes = (spec.contract / "contract.json").read_bytes()
    shutil.copy2(spec.contract / "contract.json", run / "contract.json")
    shutil.copy2(spec.contract / "contract.dsse.json", run / "contract.dsse.json")
    contract = json.loads(contract_bytes)
    transcript = (run / "transcript.txt").read_text("utf-8", "replace")
    flagged = FLAG in transcript
    receipt.write_record(run, "claims", claim_parser.record(
        parse_claims(transcript, spec.transcript, _visible_argv(contract),
                     agent_commands(contract)), claim_id, invocation),
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
    receipt.write_sources(run, graded.sources)
    if witness is not None:
        witness(run)
    predicate = receipt.assemble(run, keys.pins(spec.observed_party, spec.allow_no_heldout))
    record = attempt_record(number, run, contract, workspace, predicate["verdict"],
                            graded.grade, flagged, limit, interrupted, staging_refused=False,
                            checks=predicate["checks"])
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
                         stop_decision=decision.record())
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


def contract_record(spec: LoopSpec) -> dict[str, Any]:
    return json.loads((spec.contract / "contract.json").read_bytes())


def _shell(argv: list[str]) -> str:
    return " ".join(argv)


_PROBES = {"heldout": "on inputs you cannot see",
           "heldout_determinism": "for the same answer on every call",
           "heldout_type_strict": "for the exact result type",
           "visible_determinism": "for the same answer on every call to the visible inputs",
           "visible_type_strict": "for the exact result type on the visible inputs"}


def _probe(command_id: str) -> str:
    return _PROBES.get(command_id, command_id)


def _replay_failures(run: Path, argv: dict[str, list[str]]) -> dict[str, str]:
    """Each replayed command's failure as the grader's replay recorded it (``assertion``,
    ``candidate: IndexError``, ``timeout``, ...): the kind of failure, never an input."""
    staging = run / "grade-staging.json"
    if not staging.is_file():
        return {}
    by_argv = {tuple(value): key for key, value in argv.items()}
    found = {}
    for item in json.loads(staging.read_bytes()).get("replays", []):
        key = by_argv.get(tuple(item.get("argv", [])))
        failure = item.get("failure")
        if key is not None and isinstance(failure, str) and not item.get("passed", False):
            found[key] = failure
    return found


def refusal_detail(run: Path, contract: dict[str, Any]) -> list[str]:
    """What the refusing checks compared, in lines the agent can act on.

    For an acceptance failure, each failed visible command by argv with its exit and the
    count of failed held-out commands (never their argv); for a tool-claim refusal, each
    claim that did not match beside the runs the observer saw of that command (working
    directory, executable, argv, step, exit) and the step and path of the last edit.
    """
    lines: list[str] = []
    verify = run / "verify"
    argv = {item["id"]: item["argv"] for item in contract["acceptance"]}
    why = _replay_failures(run, argv)
    grade = verify / "acceptance.decision.json"
    if grade.is_file():
        for check in json.loads(grade.read_bytes()).get("checks", []):
            failed = [item for item in check.get("results", []) if item["exit"] != 0]
            held = [item for item in failed if item["id"].startswith("heldout")]
            for item in failed:
                if item not in held:
                    lines.append(f"acceptance command `{_shell(argv[item['id']])}` exited "
                                 f"{item['exit']} in the verifier (expected 0)"
                                 + (f": {why[item['id']]}" if item["id"] in why else ""))
            if held:
                lines.append(f"{len(held)} held-out check(s) you cannot see failed")
                lines.extend(f"held-out check {_probe(item['id'])}: {why[item['id']]}"
                             for item in held if item["id"] in why)
    decided = verify / "tool-claims.decision.json"
    if decided.is_file() and (run / "claims.json").is_file():
        observation = json.loads((run / "observation.json").read_bytes())
        events = {event["id"]: event for event in observation["events"]}
        by_step = {event["step"]: event for event in observation["events"]}
        claimed = {item["id"]: item for item in json.loads((run / "claims.json").read_bytes())
                   ["claims"]}
        for check in json.loads(decided.read_bytes()).get("checks", []):
            for item in check.get("claims", []):
                if item["status"] == "matched" or item["id"] not in claimed:
                    continue
                claim = claimed[item["id"]]
                runs = [events[key] for key in item.get("exec_ids", []) if key in events]
                seen = "; ".join(f"cwd {event['cwd']}, exe {event['exe']}, argv "
                                 f"`{_shell(event['argv'])}`, step {event['step']}, exit "
                                 f"{event.get('exit', 'unknown')}" for event in runs) or "none"
                edit = by_step.get(item.get("last_edit_step"))
                where = f" ({edit['type']} {edit.get('path', '')})" if edit else ""
                lines.append(f"claimed `{_shell(claim['argv'])}`"
                             + (f" exit {claim['exit']}" if "exit" in claim else "")
                             + f": {item['status']}; observed runs: {seen}; last edit at step "
                             f"{item.get('last_edit_step')}{where}")
    return lines


def run_loop(spec: LoopSpec, keys: Keys,
             witness: Callable[[Path], None] | None = None) -> list[Attempt]:
    """Attempts until ``stop`` or ``escalate``; the loop record goes to ``out/loop.json``."""
    table = policy.table(attempts=spec.attempts, wall_clock_s=spec.wall_clock_s,
                         mutations=spec.mutations, tokens=spec.tokens)
    policy.check_budget(table, spec.token_source)
    spec.out.mkdir(parents=True, exist_ok=True)
    if any(spec.out.iterdir()):
        raise ValueError("loop output directory must be empty")
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
            feedback = policy.replan_input(current.decision, number,
                                           refusal_detail(current.run, contract_record(spec)))
    return done
