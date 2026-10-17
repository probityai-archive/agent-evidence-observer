# Witness server reference

Source: `src/probity_observer/witness/`. Install with the `witness` extra, which
builds the `jcs-admit` Python binding (RFC 8785 through the `jcs-admit` crate, DSSE through `dsse`) from a
pinned commit of `probityai/jcs-admit` and needs a Rust toolchain:

```sh
# from the repository root
uv venv .venv --python python3.12
uv pip install --python .venv/bin/python -e '.[test,witness]'
```

## Two hosts, end to end

On the witness host (another operator's machine), with the host's public key
from step 1 of the producer side:

```sh
set -eu
agent-evidence-witness init ./witness --origin example.org/witness --producer "$HOST_KEY"
agent-evidence-witness serve ./witness --host 0.0.0.0 --port 8470
```

`init` prints the witness public key; give it to readers through a channel the
host does not control. `init --seed FILE` imports a seed made by `keygen`
elsewhere instead of generating one. `serve` prints one JSON line with the origin, key and port.

On the producer host:

```sh
set -eu
HOST_KEY=$(agent-evidence-witness keygen ./host.seed)
agent-evidence-witness sign statement.json --seed ./host.seed \
  --payload-type application/vnd.in-toto+json > envelope.json
agent-evidence-witness submit "http://$WITNESS:8470" envelope.json --seed ./host.seed \
  --claim-id run-1 --witness-key "$WITNESS_KEY" --origin example.org/witness \
  --state ./witness-state.json > bundle.json
```

Any reader, offline:

```sh
set -eu
agent-evidence-witness verify bundle.json \
  --host-key "$HOST_KEY" --host-operator lab-a \
  --witness-key "$WITNESS_KEY" --witness-operator lab-b
```

It prints `claimId`, `payloadType`, `index`, `size` and `witnessScope`. Add
`--retained earlier-checkpoint.json --consistency proof.json` to require the
bundle's checkpoint to extend one the reader kept.

Exit codes for every command: 0 verified or done, 1 refused, 2 usage,
3 equivocation detected (the evidence record is printed on stderr and the client
writes `equivocation-<digest>.json` beside its state file), 4 the witness did not
answer. Exit 4 decides nothing; it is never a clean result.

`audit URL --witness-key K --origin O --state S [--checkpoint FILE ...]` checks
checkpoints received from other readers and the witness's latest one against the
retained view. `check-equivocation EVIDENCE --witness-key K` checks a fork record.

## HTTP API

All bodies are RFC 8785 JSON.

| Request | Answer |
| --- | --- |
| `GET /v1/key` | `origin`, `witnessKey`, `size` |
| `GET /v1/checkpoint[?size=N]` | `{"checkpoint": <envelope JSON text>}`, the latest or the one signed at size N |
| `POST /v1/add` with `envelope` (JSON text), `claimId`, `producerKey` | a witnessed record; 403 unregistered producer or bad signature; 409 another statement under that claim id |
| `GET /v1/proof/inclusion?index=I[&size=N]` | inclusion record |
| `GET /v1/proof/consistency?first=M&second=N` | consistency record |
| `GET /v1/entries?start=A&end=B` | at most 1000 raw entries, each with the producer's envelope |

A consistency request for a size the witness has signed must succeed. The client
treats a 404 for such a size as the witness refusing to prove its own checkpoints
consistent (equivocation evidence of kind `unproven-consistency`); any other
failure is exit 4.

## Record formats

Keys are 32-byte Ed25519 public keys as lowercase hex, which is also each
signature's DSSE `keyid`. Hashes are lowercase hex SHA-256.

- **Leaf** `probity-witness-leaf/v1`: `claimId`, `producerKey`, `payloadType`,
  `paeSha256` (SHA-256 of the DSSE pre-authentication encoding, which both
  signatures cover). Leaf hash: `SHA-256(0x00 || RFC 8785 bytes)`.
- **Tree**: RFC 9162 section 2.1; interior node `SHA-256(0x01 || left || right)`;
  the empty tree's root is `SHA-256("")`.
- **Checkpoint** `probity-witness-checkpoint/v1`, payload type
  `application/vnd.probity.witness-checkpoint.v1+json`: `origin`, `size`,
  `rootHash`, `witnessKey`. One checkpoint per size, starting at size 0.
- **Inclusion** `probity-witness-inclusion/v1`: `origin`, `index`, `size`,
  `leafHash`, `path`.
- **Consistency** `probity-witness-consistency/v1`: `origin`, `first`, `second`, `path`.
- **Witnessed record** `probity-witnessed-record/v1`: `origin`, `claimId`,
  `producerKey`, `envelope` (the statement with the host's and the witness's
  signatures), `checkpoint`, `inclusion`.
- **Equivocation** `probity-witness-equivocation/v1`: `kind` (`fork`, which proves
  itself, or `unproven-consistency`), `origin`, `witnessKey`, two `checkpoints`,
  and the failing `consistency` proof if one was given.

`witnessScope` is `witness_scope` in probity-verify's records;
`WitnessVerdict.as_packet()` and `as_verify_record()` give each spelling.

## On-disk log

`witness.json` (origin, key, producer keys), `witness.seed` (mode 0600),
`entries.jsonl`, `checkpoints.jsonl`, and `witness.lock`, held while a process
has the log open. Opening re-verifies every entry signature, recomputes every
checkpoint root and refuses to serve on any difference. One entry beyond the last
checkpoint (a stop between the two appends) gets its checkpoint signed; nothing
else is repaired. A producer resubmitting the same statement under a claim id gets
the same entry back.

## Test controls

`tests/witness/` covers the Certificate Transparency reference roots for sizes 1
to 8, every inclusion and consistency proof for trees of 1 to 33 leaves, random
trees up to 300 leaves, altered leaves, paths, roots and sizes, tampered,
swapped, deleted and rewritten log entries, 2-of-2 threshold refusals (host only,
witness only, one key twice, a foreign key), a witness forking its log seen by one
client and by gossip between clients, a witness process reached over HTTP through
the CLI, and an unreachable witness. `scripts/mutate-witness-proofs.py` applies 33
mutants to the proof checks, the checkpoint reader, the equivocation check, the
scope decision, the log's tamper detection and the client, and fails if any
survives. The `Witness server` workflow runs both.
