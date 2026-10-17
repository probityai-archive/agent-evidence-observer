"""Mutation check for the witness verifiers: every mutant must turn the tests red.

Each mutant replaces one exact piece of source in the proof checks, the
checkpoint reader, the equivocation check, the scope decision or the log's
tamper detection, runs the witness tests, and restores the file. A mutant the
tests do not kill is a guarantee no test holds. Run from the repository root
in an environment with the ``test`` and ``witness`` extras:

    python scripts/mutate-witness-proofs.py
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path("src/probity_observer/witness")
PROOFS = ROOT / "proofs.py"
CHECKPOINT = ROOT / "checkpoint.py"
SCOPE = ROOT / "scope.py"
SERVER = ROOT / "server.py"
CLIENT = ROOT / "client.py"
MUTANTS = [
    ("inclusion accepts an index outside the tree", PROOFS,
     '    if not 0 <= index < size:\n        raise ProofError("leaf index is outside the tree")\n    fn, sn, result',
     '    fn, sn, result'),
    ("inclusion ignores a path longer than the tree", PROOFS,
     '            raise ProofError("inclusion path is longer than the tree")',
     '            break'),
    ("inclusion ignores a path shorter than the tree", PROOFS,
     '        raise ProofError("inclusion path is shorter than the tree")',
     '        pass'),
    ("inclusion never compares the root", PROOFS,
     '        raise ProofError("inclusion path does not reach the checkpoint root")',
     '        pass'),
    ("inclusion hashes a left sibling on the right", PROOFS,
     '            result = node_hash(sibling, result)\n',
     '            result = node_hash(result, sibling)\n'),
    ("inclusion skips the climb past right edges", PROOFS,
     '            result = node_hash(sibling, result)\n            while not fn & 1 and fn != 0:',
     '            result = node_hash(sibling, result)\n            while False:'),
    ("consistency accepts two roots for one size", PROOFS,
     '            raise ProofError("two roots for one tree size")',
     '            pass'),
    ("consistency accepts an empty path", PROOFS,
     '        raise ProofError("consistency path is empty")',
     '        return'),
    ("consistency never prepends a power-of-two first root", PROOFS,
     '    if first & (first - 1) == 0:\n        nodes.insert(0, first_root)\n',
     ''),
    ("consistency never checks the first root", PROOFS,
     '        raise ProofError("consistency path does not reach the first root")',
     '        pass'),
    ("consistency never checks the second root", PROOFS,
     '        raise ProofError("consistency path does not reach the second root")',
     '        pass'),
    ("consistency ignores a path shorter than the tree", PROOFS,
     '        raise ProofError("consistency path is shorter than the tree")',
     '        pass'),
    ("consistency accepts sizes out of order", PROOFS,
     '    if not 0 <= first <= second:\n        raise ProofError("consistency sizes are out of order")\n',
     ''),
    ("leaves and nodes share a hash prefix", PROOFS,
     '    return hashlib.sha256(b"\\x00" + data).digest()',
     '    return hashlib.sha256(b"\\x01" + data).digest()'),
    ("checkpoint accepts another payload type", CHECKPOINT,
     '    if verified.payload_type != CHECKPOINT_TYPE:\n        raise WitnessError("checkpoint has an unsupported payload type")\n',
     ''),
    ("checkpoint accepts another witness key field", CHECKPOINT,
     '    if body["witnessKey"] != witness_key:\n        raise WitnessError("checkpoint names a different witness key")\n',
     ''),
    ("checkpoint accepts another origin", CHECKPOINT,
     '    if origin is not None and body["origin"] != origin:',
     '    if False:'),
    ("a same-size fork is not equivocation", CHECKPOINT,
     '        if low.root_hash != high.root_hash:',
     '        if False:'),
    ("a missing consistency proof is accepted", CHECKPOINT,
     '        if proof is None:\n            raise ProofError("no consistency proof was supplied")\n',
     '        if proof is None:\n            return\n'),
    ("a proof for other sizes is accepted", CHECKPOINT,
     '        if (origin, size_a, size_b) != (low.origin, low.size, high.size):',
     '        if False:'),
    ("fork evidence with one root passes", CHECKPOINT,
     '    if first.size != second.size or first.root_hash == second.root_hash:',
     '    if first.size != second.size:'),
    ("threshold drops to one signature", SCOPE,
     '            [verifier(host_key), verifier(witness_key)],\n            2,',
     '            [verifier(host_key), verifier(witness_key)],\n            1,'),
    ("the host key may also be the witness key", SCOPE,
     '    if host_key == witness_key:\n        raise WitnessError("the host and witness pins name one key")\n',
     ''),
    ("scope ignores the operators", SCOPE,
     '    scope = EXTERNAL if host.operator != witness.operator else PEER',
     '    scope = EXTERNAL'),
    ("inclusion proof may name another leaf", SCOPE,
     '        if (proof_origin, size, proof_leaf) != (origin, checkpoint.size, leaf):',
     '        if (proof_origin, size) != (origin, checkpoint.size):'),
    ("inclusion is never verified", SCOPE,
     '        verify_inclusion(leaf, index, size, path, checkpoint.root_hash)\n',
     ''),
    ("the retained checkpoint is not compared", SCOPE,
     '        check_pair(earlier, checked.checkpoint, consistency)\n',
     '        pass\n'),
    ("the log trusts stored leaves without their envelopes", SERVER,
     '        if leaf_record(leaf["claimId"], leaf["producerKey"], verified.payload_type, verified.payload) != leaf:',
     '        if False:'),
    ("the log trusts its checkpoints without recomputing", SERVER,
     '            if checkpoint.size != size or checkpoint.root_hash != roots[size]:',
     '            if checkpoint.size != size:'),
    ("the log accepts a repeated claim id on open", SERVER,
     '        if (leaf["producerKey"], leaf["claimId"]) in self._claims:',
     '        if False:'),
    ("a producer may replace a claim", SERVER,
     '            if index is not None and self._entries[index].leaf != leaf:',
     '            if False:'),
    ("the client keeps no retained view", CLIENT,
     '        earlier = self.retained()\n',
     '        earlier = None\n'),
    ("the client accepts a different co-signed statement", CLIENT,
     '            raise WitnessError("witness co-signed a different statement than the one submitted")',
     '            pass'),
]
TESTS = ["-B", "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", "tests/witness"]


def main() -> int:
    environment = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    baseline = subprocess.run([sys.executable, *TESTS], capture_output=True, env=environment)
    if baseline.returncode != 0:
        print("baseline tests fail; fix them before mutating")
        print(baseline.stdout.decode(errors="replace")[-4000:])
        return 2
    survivors = 0
    for label, path, original, mutant in MUTANTS:
        source = path.read_text()
        if source.count(original) != 1:
            print(f"MISSING {label}: the original text is not unique in {path}")
            survivors += 1
            continue
        try:
            path.write_text(source.replace(original, mutant))
            result = subprocess.run([sys.executable, *TESTS], capture_output=True, env=environment)
        finally:
            path.write_text(source)
        killed = result.returncode != 0
        survivors += not killed
        print(f"{'KILLED' if killed else 'SURVIVED'} {label}", flush=True)
    print(f"{len(MUTANTS) - survivors} of {len(MUTANTS)} mutants killed")
    return 1 if survivors else 0


if __name__ == "__main__":
    sys.exit(main())
