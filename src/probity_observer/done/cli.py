"""``probity-done contract | run | verify``: seal a definition of done, run, re-check offline.

``contract`` compiles and seals a task (SWE-bench and LiveCodeBench from dataset fields,
a real repository through the zero-shot template). ``run`` runs the bounded loop on a sealed
contract. ``verify`` re-checks one attempt's receipt from its records alone, under the
consumer's own key pins, and prints the decision line with ``vantage`` and
``witness_scope``. Exit status: 0 supported, 1 contradicted, 2 not established, 3 refused.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence

from . import contract, receipt, zeroshot
from .formats import DoneError, load_signer, new_seed, open_record
from .runner import SubprocessRunner

EXIT = {"supported": 0, "contradicted": 1, "not_established": 2}
REFUSED = 3


def _runner(args: argparse.Namespace):
    if args.runner == "docker":
        from .verify_run import DockerRunner
        return DockerRunner(args.image)
    return SubprocessRunner(args.python)


def _task(args: argparse.Namespace) -> contract.Task:
    work = Path(args.work)
    if args.dataset == "repo":
        model = zeroshot.ChatModel(args.model_url, args.model, max_tokens=args.max_tokens,
                                   tag=args.model_tag)
        return zeroshot.propose(Path(args.repo), args.task_id, args.task, model,
                                Path(args.reference) if args.reference else None).task
    record = json.loads(Path(args.record).read_text())
    if args.dataset == "lcb":
        return contract.lcb_task(record, work, args.heldout_fraction)
    test_cmd = tuple(args.test_cmd) if args.test_cmd else contract.DEFAULT_TEST_CMD
    return contract.swe_task(record, Path(args.repo), work, test_cmd)


def cmd_keygen(args: argparse.Namespace) -> int:
    print(new_seed(Path(args.path)))
    return 0


def cmd_contract(args: argparse.Namespace) -> int:
    task = _task(args)
    sealed = contract.compile_task(task, Path(args.out), load_signer(Path(args.harness_key)),
                                   _runner(args), runs=args.runs, mutant_limit=args.mutants,
                                   timeout=args.timeout,
                                   agent_image=args.agent_image or (
                                       args.image if args.runner == "docker" else None))
    adequacy = sealed.record["adequacy"]
    print(f"Contract: {sealed.out / 'contract.json'}")
    print(f"SHA-256: {sealed.contract_sha256}")
    print(f"Acceptance: {', '.join(item['id'] for item in sealed.record['acceptance'])}")
    print(f"Protected: {', '.join(item['path'] for item in sealed.record['protected_paths'])}")
    print(f"Adequacy: {adequacy['killed']}/{adequacy['mutants']} mutants killed")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    from .loop import Keys, LoopSpec, run_loop
    keys = Keys(load_signer(Path(args.harness_key)), load_signer(Path(args.host_key)),
                load_signer(Path(args.grader_key)))
    spec = LoopSpec(contract=Path(args.contract), out=Path(args.out), image=args.image,
                    agent_argv=tuple(args.agent), task_id=args.task_id,
                    observed_party=args.observed_party, attempts=args.attempts,
                    grader_image=args.grader_image, network=args.network,
                    timeout_seconds=args.timeout, transcript=args.transcript,
                    allow_no_heldout=args.allow_no_heldout,
                    wall_clock_s=args.wall_clock_budget, mutations=args.mutation_budget)
    attempts = run_loop(spec, keys)
    for item in attempts:
        print(f"Attempt {item.number}: {receipt.decision_line(item.verdict)}; "
              f"next: {item.decision.action} ({item.decision.reason})")
    return EXIT[attempts[-1].verdict["decision"]]


def _adequacy_floor(run: Path, verdict: dict[str, Any], minimum: float | None) -> tuple[dict[str, Any], str]:
    adequacy = json.loads((run / "contract.json").read_bytes())["adequacy"]
    fraction = adequacy["killed"] / adequacy["mutants"] if adequacy["mutants"] else 0.0
    line = f"Adequacy: {adequacy['killed']}/{adequacy['mutants']} mutants killed ({fraction:.2f})"
    if minimum is not None and verdict["decision"] == "supported" and fraction < minimum:
        verdict = {"decision": "not_established", "reason": "adequacy_below_minimum",
                   "vantage": "unestablished"}
        line += f", below the pinned minimum {minimum:.2f}"
    return verdict, line


def _witnessed(run: Path, pins: receipt.Pins, args: argparse.Namespace) -> str:
    """EXTERNAL when every observed record's witness bundle verifies with distinct operators."""
    from ..witness.scope import KeyPin, verify_witnessed_record
    keys = {"tree": pins.host_key, "observation": pins.host_key, "grade": pins.grader_key}
    operators = {"tree": args.host_operator, "observation": args.host_operator,
                 "grade": args.grader_operator}
    witness = KeyPin(args.witness_key, args.witness_operator)
    scopes = []
    for role, key in keys.items():
        path = run / f"{role}.witnessed.json"
        if not path.is_file():
            return "PEER"
        found = verify_witnessed_record(json.loads(path.read_bytes()), KeyPin(key, operators[role]),
                                        witness)
        if found.payload != (run / f"{role}.json").read_bytes():
            return "PEER"
        scopes.append(found.witness_scope)
    return "EXTERNAL" if scopes and all(item == "EXTERNAL" for item in scopes) else "PEER"


def shared_receipt_check(run: Path, pins: receipt.Pins, carried: dict[str, Any]) -> dict[str, Any]:
    """probity-verify's ``done_receipt/v1`` over the attempt: it derives the verdict again
    from the signed records and the receipt Statement, which must carry the signed predicate."""
    records = receipt.open_run(run, pins)
    statement_bytes = (run / "done-receipt.statement.json").read_bytes()
    if json.loads(statement_bytes).get("predicate") != carried:
        raise DoneError("the receipt Statement does not carry the signed predicate")
    case, policy = receipt.done_receipt_case(run, records, statement_bytes, pins)
    return receipt.adjudicate(case, policy, run)


# done_receipt/v1 reasons that say the receipt does not describe these records.
UNBOUND = {"receipt_verdict_mismatch": "verdict", "receipt_records_mismatch": "records",
           "receipt_subject_mismatch": "subject", "receipt_context_mismatch": "context",
           "receipt_unavailable_or_unbound": "Statement"}


def cmd_verify(args: argparse.Namespace) -> int:
    run = Path(args.run)
    pins = receipt.Pins(args.harness_pub, args.host_pub, args.grader_pub,
                        observed_party=args.observed_party,
                        allow_no_heldout=args.allow_no_heldout)
    carried = json.loads(open_record((run / "done-receipt.dsse.json").read_bytes(),
                                     args.harness_pub, receipt.RECEIPT_SCHEMA))
    try:
        receipt.verifier_id(carried)
    except DoneError as error:
        print(f"Refused: {error}")
        return REFUSED
    shared = shared_receipt_check(run, pins, carried)
    if shared["reason"] in UNBOUND:
        print(f"Refused: the receipt's {UNBOUND[shared['reason']]} does not recompute from "
              "the records")
        return REFUSED
    # The checks and the external effects are carried too; they must recompute as well.
    recomputed = receipt.assemble(run, pins)
    for name in ("records", "checks", "external_effects"):
        if recomputed.get(name) != carried.get(name):
            print(f"Refused: the receipt's {name} does not recompute from the records")
            return REFUSED
    verdict = {"decision": shared["decision"], "reason": shared["reason"],
               "vantage": shared.get("vantage", "unestablished")}
    if "witness_scope" in shared:
        verdict["witness_scope"] = shared["witness_scope"]
    if args.require_witness_scope == "EXTERNAL" and verdict["decision"] == "supported":
        if not args.witness_key or _witnessed(run, pins, args) != "EXTERNAL":
            verdict = {"decision": "not_established", "reason": "witness_scope_below_required",
                       "vantage": "unestablished"}
        else:
            verdict = {**verdict, "witness_scope": "EXTERNAL"}
    verdict, adequacy = _adequacy_floor(run, verdict, args.min_killed_fraction)
    print(receipt.decision_line(verdict))
    derived = next((item for item in shared["checks"] if item["id"] == "derived_verdict"), None)
    for check in (derived or {}).get("checks", []):
        print(f"  {check['claim_type']}: {check['decision']} / {check['reason']}")
    print(adequacy)
    if "stop_decision" in carried:
        print(f"Stop decision: {carried['stop_decision']['action']} ({carried['stop_decision']['reason']})")
    return EXIT[verdict["decision"]]


def parser() -> argparse.ArgumentParser:
    top = argparse.ArgumentParser(prog="probity-done", description=__doc__.splitlines()[0])
    add_commands(top.add_subparsers(dest="command", required=True))
    return top


def add_commands(sub) -> None:
    """Add ``keygen``, ``contract``, ``run`` and ``verify`` to a subparsers object: the
    standalone ``probity-done`` command line and ``probity done`` share these parsers."""
    keygen = sub.add_parser("keygen", help="write a new Ed25519 seed file and print its key")
    keygen.add_argument("path")
    keygen.set_defaults(func=cmd_keygen)

    seal = sub.add_parser("contract", help="compile and seal a done contract")
    seal.add_argument("--dataset", choices=("swe", "lcb", "repo"), required=True)
    seal.add_argument("--record", help="the dataset record as JSON (swe, lcb)")
    seal.add_argument("--repo", help="the repository at its base commit (swe, repo)")
    seal.add_argument("--work", help="scratch directory for the task's states")
    seal.add_argument("--out", required=True)
    seal.add_argument("--harness-key", required=True)
    seal.add_argument("--runner", choices=("docker", "subprocess"), default="docker")
    seal.add_argument("--image", help="image for the docker runner")
    seal.add_argument("--agent-image",
                      help="image the agent will run in; seals where its test command's "
                           "executable lives (default: --image with the docker runner)")
    seal.add_argument("--python", help="interpreter for the subprocess runner")
    seal.add_argument("--runs", type=int, default=3)
    seal.add_argument("--mutants", type=int, default=40)
    seal.add_argument("--timeout", type=float, default=900.0)
    seal.add_argument("--heldout-fraction", type=float, default=0.5)
    seal.add_argument("--test-cmd", nargs="+", help="argv prefix for SWE-bench test ids")
    seal.add_argument("--task-id")
    seal.add_argument("--task", help="the task in words (repo)")
    seal.add_argument("--model-url", help="OpenAI-compatible endpoint (repo)")
    seal.add_argument("--model", help="model name at that endpoint (repo)")
    seal.add_argument("--max-tokens", type=int, default=8192,
                      help="completion budget for the zero-shot call, reasoning included (repo)")
    seal.add_argument("--model-tag", help="sent as X-Probity-Tag with the zero-shot call (repo)")
    seal.add_argument("--reference", help="a known-good solution tree, for mutants (repo)")
    seal.set_defaults(func=cmd_contract)

    loop = sub.add_parser("run", help="run the bounded loop on a sealed contract")
    loop.add_argument("--contract", required=True)
    loop.add_argument("--out", required=True)
    loop.add_argument("--image", required=True)
    loop.add_argument("--grader-image")
    loop.add_argument("--task-id", required=True)
    loop.add_argument("--observed-party", default="agent")
    loop.add_argument("--attempts", type=int, default=3)
    loop.add_argument("--network", action="store_true")
    loop.add_argument("--timeout", type=float, default=3600.0)
    loop.add_argument("--wall-clock-budget", type=float, default=None,
                      help="seconds of observed agent time across all attempts")
    loop.add_argument("--mutation-budget", type=int, default=None,
                      help="distinct (command, path) mutations across all attempts")
    loop.add_argument("--transcript", choices=("text", "claude-stream"), default="text")
    loop.add_argument("--allow-no-heldout", action="store_true",
                      help="let a contract with no held-out tests support done")
    for name in ("harness", "host", "grader"):
        loop.add_argument(f"--{name}-key", required=True)
    loop.add_argument("agent", nargs="+", help="the agent's argv, after --")
    loop.set_defaults(func=cmd_run)

    check = sub.add_parser("verify", help="re-check one attempt's receipt offline")
    check.add_argument("--run", required=True)
    for name in ("harness", "host", "grader"):
        check.add_argument(f"--{name}-pub", required=True)
    check.add_argument("--observed-party", default="agent")
    check.add_argument("--require-witness-scope", choices=("PEER", "EXTERNAL"), default="PEER")
    check.add_argument("--min-killed-fraction", type=float)
    check.add_argument("--allow-no-heldout", action="store_true")
    check.add_argument("--witness-key")
    check.add_argument("--witness-operator", default="witness")
    check.add_argument("--host-operator", default="host")
    check.add_argument("--grader-operator", default="host")
    check.set_defaults(func=cmd_verify)


def dispatch(args: argparse.Namespace) -> int:
    """Run the parsed subcommand; a refused input exits ``REFUSED`` with its reason."""
    try:
        return args.func(args)
    except (DoneError, OSError, ValueError, KeyError) as error:
        print(f"Refused: {error}", file=sys.stderr)
        return REFUSED


def main(argv: Sequence[str] | None = None) -> int:
    return dispatch(parser().parse_args(argv))


SUMMARY = "seal a done contract, run the bounded loop, and re-check a done receipt"


def register(subparsers) -> None:
    """Add ``done`` to the ``probity`` command line (entry point ``probityai.cli_subcommands``).

    ``probity done verify`` is the same handler as ``probity-done verify``: it opens the
    signed records and gets every check's decision from probity-verify's ``adjudicate``.
    """
    from probityai.cli import register_leaf  # only the probity launcher calls this, so it is installed

    done = subparsers.add_parser("done", help=SUMMARY, description=SUMMARY)
    add_commands(done.add_subparsers(dest="command", required=True))
    register_leaf(done, handler=dispatch)


if __name__ == "__main__":
    sys.exit(main())
