# Refund handoff conformance: exact reference

Start in the Observer repository root with Python 3.12 and uv 0.12.23.
Use a new result path:

```sh
set -eu
results="$(mktemp -d)/refund-handoff"
bash interop/refund-handoff-conformance-2026-10-12/verify_install.sh "$results"
```

The script refuses a dirty source tree, creates an isolated environment, installs
every dependency from the hash-locked profile file, builds one wheel under the
same locked build constraints, and installs that wheel without resolving more
dependencies. It archives the exact source commit and writes canonical provenance
for the source tree, archive, wheel, runtime, uv version, and dependency lock. It
runs `interop/refund-handoff-conformance-2026-10-12/tests/test_refund_handoff.py`, smoke-tests the installed console command,
then invokes the verified refund-handoff module on all 80 hash-selected vectors.
Every stage retains its command, stdout, stderr, and exit status. The corpus keeps
the materialized trust, manifest, vectors, every result stream, and a canonical
complete summary. The hosted workflow uploads the result without the disposable
environment on native Ubuntu and Windows runners.

## Contract and trust input

Every signed payload and bundle carries the schema `refund-handoff/0.1` and this
stable identifier:

```text
https://probityai.github.io/agent-evidence-observer/contract/refund-handoff/0.1
```

The consumer supplies `trust-snapshot.json` separately. Evidence cannot add a
trusted key. The snapshot fixes each key ID, unique Ed25519 public key, semantic
role, exact workflow/provider/decision scopes, status, validity interval, and
temporal revocation point. A record signed before a later revocation remains
readable; a record at or after revocation is refused. A handoff signed before
revocation remains authentic evidence, but it cannot authorize a dispatch at or
after revocation. `revoked_at` is the consumer-selected earliest forbidden
instant for both issuance and dispatch authority. The vector manifest pins the
exact snapshot bytes. Unknown,
duplicate-key, wrong-role, out-of-scope, and out-of-window signers are refused.

The same consumer snapshot selects an admission checkpoint and a handoff
checkpoint. They bind exact observed state roots and record digests at the report
cutoff. A separately consistent fork therefore contradicts the relevant claim
instead of silently replacing the selected record. These are finite consumer
checkpoints; they do not prove complete global history.

Each signed payload contains the same `key_id` as its envelope. A handoff also
contains its signed `issuer`. The verifier uses a record-specific signature
domain over restricted canonical JSON. It refuses duplicate members,
noncanonical bytes, floats, unsafe integers, non-ASCII strings, and unknown
fields.

## Native data model

The exact refund tuple is the closed snake-case object:

```json
{"amount_minor":4000,"currency":"EUR","payment_id":"pay-A"}
```

The tool is exactly `refund`. The generic input roles are `decision_evidence`
and `approval_evidence`. The signed `compatibility_profile` is a reader-stated
label in the public fixtures, not an attestation by PIC or APS and not a producer
identity. Other readers can emit the same roles under the one contract without
a schema alias.

The operation ID hashes a canonical object that contains the workflow, decision
scope and issuer, admission authority, provider, tool, and exact tuple. It does
not contain `approval_ref` or the replaceable handoff authority. Approval reissue
and handoff-key rotation therefore do not create a new logical refund. A reissued
approval resolves through a separate signed `approval_resolution` to the
immutable original admission and operation. It cannot replace that admission.

The admission contains signed decision and operation indexes. Its state root
commits to both indexes, its sequence, and its predecessor. A distinct recovery
observer must attest that it read the same committed state after restart and
before the handoff and dispatch. This establishes selected-observer recovery. It
does not establish independent storage or non-operator custody.

The handoff signs the exact admission and evidence references, tuple, operation,
provider, full idempotency key, issue time, `not_before`, and expiry. Dispatch
cannot precede the later of issue time and `not_before`. The lifetime is at most
ten minutes, expiry cannot outlive the signing key, and dispatch cannot occur at
or after the handoff key's revocation time.

## Execution and effect records

Attempts, effects, outcomes, and reconciliation are separate signed records.
Every event has a sequence and predecessor digest. Effect, outcome, and
reconciliation records reference the exact attempt record, not only its ID.
Effects use a separate effect-observer key.

An execution observer signs the finite event count and log head at the cutoff.
Each attempt, outcome, and reconciliation must carry that same signed observer
principal; key rotation within the principal is allowed. Each effect event must
carry the provider snapshot's signed observer principal, distinct from the
execution principal.
This establishes consistency with that selected observer's manifest; it does not
establish that no event exists outside the selected observation scope.
A provider observer signs the full result of the selected
`refund_effects_by_idempotency_key` query at the same cutoff. The effect count,
sorted effect IDs, operation, provider, and full idempotency key are in the
signed snapshot.

An unresolved response can have repeated predecessor-linked
`still_unresolved` records. At most one terminal reconciliation can follow.
Terminal state cannot regress. A later attempt needs an explicit `recovery` or
`duplicate_delivery` disposition and the prior exact attempt reference. It can
start only after the prior attempt reached a terminal no-effect result.

The verifier authenticates every record, then filters each record class at the
report cutoff before semantic comparison. An otherwise valid future record
changes only the exclusion counts. It cannot support or contradict an earlier
claim. Material with an invalid signature or trust binding is refused even when
it claims a future timestamp. Array order and byte-identical duplicates do not
change claims.

## Finite corpus

| # | Vector | Required result |
| ---: | --- | --- |
| 1 | Observed success | All claims `ESTABLISHED` |
| 2 | Observed no effect | All claims established; completion value `no_effect` |
| 3 | Missing post-restart recovery | `NOT_ESTABLISHED` |
| 4 | Changed refund tuple | `CONTRADICTED` |
| 5 | Changed operation ID | `CONTRADICTED` |
| 6 | Reissued approval resolves to original | All claims `ESTABLISHED` |
| 7 | Reissued approval replaces original | `CONTRADICTED` |
| 8 | Byte-identical handoff replay | All claims established; one unique handoff |
| 9 | Changed handoff replay | `CONTRADICTED` |
| 10 | Response lost and unresolved | Selected effect coverage established; completion not established |
| 11 | Response lost then effect confirmed | All claims `ESTABLISHED` |
| 12 | Repeated unresolved polls then effect confirmed | All claims `ESTABLISHED` |
| 13 | Dispatch after expiry | `CONTRADICTED` |
| 14 | Missing approval evidence | `NOT_ESTABLISHED` |
| 15 | Reconciliation after cutoff | Completion `NOT_ESTABLISHED`; one excluded record |
| 16 | Bad handoff signature | Refused |
| 17 | Unknown handoff issuer | Refused |
| 18 | Revoked handoff issuer | Refused |
| 19 | Unknown signed member | Refused |
| 20 | Wrong signer role | Refused |
| 21 | Referenced input after cutoff | `NOT_ESTABLISHED`; one excluded record |
| 22 | Effect before attempt | `CONTRADICTED` |
| 23 | Success references unknown attempt | `CONTRADICTED` |
| 24 | Success followed by unresolved state | `CONTRADICTED` |
| 25 | Dispatch before handoff issue time | `CONTRADICTED` |
| 26 | Later attempt remains unresolved | `NOT_ESTABLISHED` |
| 27 | Effect crosses attempt boundary | `CONTRADICTED` |
| 28 | Effect ID rebound to another attempt | `CONTRADICTED` |
| 29 | Broken event hash chain | `CONTRADICTED` |
| 30 | Manifest omits an event | `CONTRADICTED` |
| 31 | Provider snapshot count mismatch | `CONTRADICTED` |
| 32 | Idempotency key mismatch | `CONTRADICTED` |
| 33 | Recovery after handoff | `CONTRADICTED` |
| 34 | Future conflicting input | Baseline claims unchanged; one excluded record |
| 35 | Permuted record arrays | Baseline claims unchanged |
| 36 | Byte-identical event duplicate | Baseline claims unchanged |
| 37 | Duplicate JSON member | Refused before signed-record evaluation |
| 38 | Observed failure while an effect exists | `CONTRADICTED` |
| 39 | Effect-absent reconciliation while an effect exists | `CONTRADICTED` |
| 40 | Event ID reused with changed content | `CONTRADICTED` |
| 41 | Resolution before the reissued evidence | `CONTRADICTED` |
| 42 | Conflicting decision evidence | `CONTRADICTED` |
| 43 | Handoff exceeds maximum lifetime | Refused |
| 44 | Terminal reconciliation regresses to unresolved | `CONTRADICTED` |
| 45 | Attempt has no outcome record | `NOT_ESTABLISHED` |
| 46 | Reissued approval lacks a resolution | `NOT_ESTABLISHED` |
| 47 | Reconciliation follows terminal success | `CONTRADICTED` |
| 48 | Success claims no response | `CONTRADICTED` |
| 49 | Failure claims no response | `CONTRADICTED` |
| 50 | Unresolved outcome claims a response | `CONTRADICTED` |
| 51 | Valid key crosses its decision scope | Refused |
| 52 | Envelope and payload key IDs differ | Refused |
| 53 | Unsupported signature algorithm | Refused |
| 54 | Signature is moved to another record domain | Refused |
| 55 | Record predates key validity | Refused |
| 56 | Record occurs at key revocation | Refused |
| 57 | Handoff differs from the consumer checkpoint | `CONTRADICTED` |
| 58 | Admission differs from the consumer checkpoint | `CONTRADICTED` |
| 59 | Noncanonical JSON bytes | Refused |
| 60 | Floating-point input | Refused |
| 61 | Integer outside the safe JSON range | Refused |
| 62 | Non-ASCII input | Refused |
| 63 | Admission checkpoint predates the selected record | Refused |
| 64 | Handoff checkpoint predates the selected record | Refused |
| 65 | Admission checkpoint is stale at the cutoff | Refused |
| 66 | Handoff checkpoint is stale at the cutoff | Refused |
| 67 | Two evidence types reuse a producer-local reference | All claims `ESTABLISHED` |
| 68 | Approval reference aliases the decision input | `NOT_ESTABLISHED` |
| 69 | Execution and effect observation use one principal without a manifest | `CONTRADICTED` |
| 70 | Recovery and admission use one principal | `CONTRADICTED` |
| 71 | Recovery occurs at, not after, admission commit | `CONTRADICTED` |
| 72 | Admission is missing but an authentic handoff remains | `NOT_ESTABLISHED` |
| 73 | Decision evidence is incomplete | `NOT_ESTABLISHED` |
| 74 | Decision evidence contradicts the request | `CONTRADICTED` |
| 75 | Invalidly signed input claims a post-cutoff time | Refused |
| 76 | Initial dispatch occurs exactly when the handoff signer is revoked | `CONTRADICTED` |
| 77 | Retry occurs exactly when the handoff signer is revoked | `CONTRADICTED` |
| 78 | Reconciliation observes a pre-revocation dispatch after revocation | All claims `ESTABLISHED` |
| 79 | A valid outcome from another execution observer shares one manifest | `CONTRADICTED` |
| 80 | A valid effect from another provider observer shares one snapshot | `CONTRADICTED` |

Exit 0 means every required epistemic claim is established. A valid observed
failure can therefore exit 0. Exit 3 preserves an authentic contradicted or
incomplete result. Exit 2 is a format, trust, key, signature, or schema refusal
with empty stdout. Never collapse exits 2 and 3 into one failure state.

## Retained report and claim ceiling

The report includes the exact bundle, trust snapshot, admission, handoff,
execution manifest, provider snapshot, effect, and terminal-record references.
It names the target operation and keeps the seven claims separate.
Every classified reason is a stable URI under the contract identifier. The
machine-readable reason registry is closed: an implementation cannot invent a
new reason string while claiming conformance to `refund-handoff/0.1`.

The generator derives deterministic keys from an explicitly public test
namespace. Re-running it must reproduce every committed byte and digest. Those
keys establish only corpus consistency. The report always retains
`witness_scope: PEER`. It does not assert merchant or delegated authority,
production deployment, independent durability, coverage outside the selected
execution observer and manifest, coverage outside the selected provider observer
and query, remote exactly-once execution, adoption, or a commercial agreement.
