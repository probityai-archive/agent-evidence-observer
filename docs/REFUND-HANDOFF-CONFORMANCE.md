# Did the approved refund reach a verified effect?

A valid approval is not proof of admission. A valid admission is not proof that
the executor received it. A request attempt is not proof that the refund effect
happened, and a committed effect with a lost response is not a completed reply.

The Probity refund handoff profile keeps those statements separate. Its generic
evidence roles accept PIC and APS compatibility records without making either
producer normative. It checks seven claims under one consumer-selected trust
snapshot:

| Claim | What must be present |
| --- | --- |
| Admission | Matching decision and approval evidence, exact refund tuple, immutable decision binding, and indexed operation |
| Durable admission | A separate observer recovers the exact committed state after restart and before dispatch |
| Approval continuity | A reissued approval resolves to the immutable original admission instead of replacing it |
| Authenticated handoff | A valid issuer signs the exact admission, operation, evidence, tuple, validity, and idempotency key |
| Selected-log consistency | A signed cutoff manifest matches the complete ordered log reported by the selected execution observer |
| Selected effect coverage | A separate provider observer signs the complete selected effect query at the cutoff |
| Completion | Every attempt reaches a monotonic terminal result, including a later reconciliation after response loss |

The public corpus has 80 deterministic cases. In the response-loss case, effect
coverage is `ESTABLISHED` while completion remains `NOT_ESTABLISHED`. An
in-cutoff reconciliation establishes completion. A signed no-effect provider
snapshot and observed failure are also a valid established result.

The vectors attack replay, reissue, restart recovery, cutoff isolation, event-log
consistency, cross-attempt references, late unresolved attempts, signer roles,
observer independence, typed evidence references, missing prerequisites,
three-state evaluation, provider snapshots, consumer checkpoints, key scope and
time bounds, signature domain separation, cutoff trust, and strict JSON input.
Record-array order and byte-identical duplicates cannot change a claim.

This is a Probity-owned conformance surface. PIC, APS, Conduit, another runtime,
or a combined runner can produce the records, but each producer is replaceable
and must pass the same verifier and hostile vectors. The profile does not depend
on private Frequency code.

The next distribution threshold is an outside-owned combined runner that pins a
landed Observer revision, emits producer-owned records, runs on the host's default
branch, and retains its reports. Probity-run CI is only publication evidence. It
does not establish outside operation, host adoption, production use, or revenue.

## Deployment control point

The production target is an admission and retry gate: a consequential action is
not dispatched, repeated, reconciled, or settled unless the required claim state
passes policy. The public verifier and vectors make that gate portable. They are
an entry point, not the complete product.

The commercial expansion path adds managed policy, trust and key configuration,
runtime enforcement, retained evidence, incident reconciliation, and audit
packages. A test run is not a sale. Commercial conversion requires a signed
order or statement of work and payment. The intended buyers are the security and
platform owners who carry the cost of duplicate or unauthorized effects.

Probity owns the contract, reason semantics, verifier, hostile corpus, and gate
decision. PIC, APS, Conduit, payment simulators, and future runtimes remain
replaceable evidence producers. An outside host must own and maintain its run;
Probity running the host's code for it does not qualify as adoption.

All current records are synthetic and use public fixture keys. No payment
provider is called. A passing local run is not producer adoption, independent
operation, production deployment, or a commercial agreement.

Use the [technical reference](reference/REFUND-HANDOFF-CONFORMANCE.md) for the
one-command run, exact contract, result files, and full vector table.
