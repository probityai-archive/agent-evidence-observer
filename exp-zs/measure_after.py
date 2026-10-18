"""Re-compile every recorded zero-shot proposal with the strengthened compiler, then check
honest and wrong patches against what it seals.

    python exp-zs/measure_after.py <out-dir> [--template contract_v1.txt|contract_v2.txt]
                                   [--proposals proposals|proposals-v2]

results.jsonl, one line per (task, proposal): sealed or refused (reason), strength, gates,
per-set adequacy, acceptance. honest.jsonl: per sealed contract, the reference and each
independently written fix (exp-zs/honest/<task>/*.patch) graded by the sealed commands.
wrong.jsonl: per sealed contract, mutants that pass the 8291f9a contract sealed from the same
proposal (exp-zs/before/results.jsonl) and what the new contract does with them.
"""
import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import time
import traceback
from pathlib import Path

from probity_observer.done import contract, mutants, zeroshot
from probity_observer.done.formats import DoneError, load_signer, new_seed
from probity_observer.done.runner import SubprocessRunner

HERE = Path(__file__).resolve().parent


def commands_of(record):
    return [contract.Command(item["id"], tuple(item["argv"]), heldout=item["id"].startswith("heldout"))
            for item in record["acceptance"]]


def run_all(runner, state, commands, heldout, timeout=300):
    exits = []
    for command in commands:
        exits.append(runner.run(state, command.argv, heldout, timeout))
    return exits


def patched(start: Path, patch: Path, scratch: Path) -> Path:
    tree = scratch / "tree"
    shutil.copytree(start, tree, symlinks=True)
    done = subprocess.run(["patch", "-p1", "-s", "--no-backup-if-mismatch"], cwd=tree,
                          input=patch.read_bytes(), capture_output=True, check=False)
    if done.returncode != 0:
        raise RuntimeError(f"patch failed: {done.stderr.decode()[:200]}")
    return tree


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("out")
    parser.add_argument("--template", default="contract_v1.txt")
    parser.add_argument("--proposals", default="proposals")
    parser.add_argument("--only", default="")
    args = parser.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    new_seed(out / "harness.seed")
    key = load_signer(out / "harness.seed")
    runner = SubprocessRunner(sys.executable)
    before = {}
    if (HERE / "before" / "results.jsonl").is_file():
        for line in open(HERE / "before" / "results.jsonl"):
            row = json.loads(line)
            if row.get("sealed"):
                before[(row["task"], row["proposal"])] = row
    results, honest, wrong = (open(out / name, "w") for name in
                              ("results.jsonl", "honest.jsonl", "wrong.jsonl"))
    for task_dir in sorted((HERE / "tasks").iterdir()):
        if args.only and args.only not in task_dir.name:
            continue
        goal = (task_dir / "goal.txt").read_text().strip()
        for answer in sorted((HERE / args.proposals / task_dir.name).glob("*")):
            name = f"{task_dir.name}__{answer.stem}"
            row = {"task": task_dir.name, "proposal": answer.stem, "template": args.template}
            began = time.time()
            sealed = None
            try:
                model = zeroshot.RecordedModel(answer)
                proposal = zeroshot.propose(task_dir / "start", task_dir.name, goal, model,
                                            task_dir / "reference", work=out / (name + ".work"),
                                            template_name=args.template,
                                            runner=runner)
                row["replay"] = proposal.record.get("replay")
                sealed = contract.compile_task(proposal.task, out / name, key, runner, timeout=300)
                report = json.loads((out / name / "sealed" / "compile.json").read_bytes())
                row.update(sealed=True, strength=report.get("strength"), gates=report.get("gates"),
                           adequacy=sealed.record["adequacy"], acceptance=sealed.record["acceptance"],
                           dropped=report["stability"]["dropped"])
            except contract.Refused as error:
                row.update(sealed=False, refused=error.reason, detail=str(error)[:400])
            except DoneError as error:
                row.update(sealed=False, refused="proposal_refused", detail=str(error)[:400])
            except Exception:
                row.update(sealed=False, error=traceback.format_exc()[-900:])
            row["seconds"] = round(time.time() - began, 1)
            results.write(json.dumps(row) + "\n")
            results.flush()
            print(json.dumps({k: row.get(k) for k in ("task", "proposal", "sealed", "strength", "refused")}), flush=True)
            if sealed is None:
                continue
            heldout = out / name / "sealed" / "heldout"
            heldout = heldout if heldout.is_dir() else None
            new_commands = commands_of(sealed.record)
            # Honest patches: the reference and every independent fix.
            states = [("reference", None)] + [(p.stem, p) for p in sorted((HERE / "honest" / task_dir.name).glob("*.patch"))]
            for label, patch in states:
                with tempfile.TemporaryDirectory() as scratch:
                    try:
                        state = task_dir / "reference" if patch is None else patched(task_dir / "start", patch, Path(scratch))
                        exits = run_all(runner, state, new_commands, heldout)
                        honest.write(json.dumps({"contract": name, "patch": label, "exits": exits,
                                                 "passed": all(code == 0 for code in exits)}) + "\n")
                    except Exception as error:
                        honest.write(json.dumps({"contract": name, "patch": label, "error": str(error)}) + "\n")
                honest.flush()
            # Wrong patches: mutants the 8291f9a contract from the same proposal passes.
            old = before.get((task_dir.name, answer.stem))
            if old is None:
                continue
            plan = contract.task_mutants(proposal.task, 40)
            old_commands = [contract.Command(item["id"], tuple(item["argv"])) for item in old["acceptance"]]
            survivors = []
            for mutant in plan.mutants:
                with tempfile.TemporaryDirectory() as scratch:
                    state = Path(scratch) / "m"
                    shutil.copytree(plan.base, state, symlinks=True)
                    for path, text in mutant.files():
                        (state / path).write_text(text)
                    old_exits = [runner.run(state, c.argv, None, 300) for c in old_commands]
                    if any(old_exits):
                        continue
                    new_exits = run_all(runner, state, new_commands, heldout)
                    survivors.append({"contract": name, "mutant": mutant.binding(), "kind": mutant.kind,
                                      "old_exits": old_exits, "new_exits": new_exits,
                                      "new_kills": any(new_exits)})
            for item in survivors:
                wrong.write(json.dumps(item) + "\n")
            wrong.flush()
            shutil.rmtree(out / (name + ".work"), ignore_errors=True)
            shutil.rmtree(out / name / "workspace", ignore_errors=True)
            shutil.rmtree(out / name / "sealed" / "protected", ignore_errors=True)
    (out / "harness.seed").unlink()
    return 0


if __name__ == "__main__":
    sys.exit(main())
