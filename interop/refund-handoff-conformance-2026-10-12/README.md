# Probity refund handoff conformance

This profile defines the portable boundary from verified refund evidence to
admission, post-restart recovery, authenticated handoff, execution, effect, and
reconciliation. It gives every producer the same finite contract and gives a
consumer one offline verifier instead of producer-specific trust shortcuts.

The corpus contains 44 deterministic vectors. It covers exact snake-case refund
binding, immutable approval reissue, restart recovery, replay, expiry, signer
roles, cutoff isolation, event-chain completeness, cross-attempt references,
provider snapshots, response loss, and valid no-effect outcomes.

Run the installed verifier and retain every result:

```sh
results="$(mktemp -d)/refund-handoff"
bash interop/refund-handoff-conformance-2026-10-12/verify_install.sh "$results"
```

The result contains the qualification log plus stdout, stderr and exit
status for every vector. Exit 0 means all seven claims are established. Exit 3
means authentic evidence leaves a claim contradicted or not established. Exit 2
means the evidence itself was refused.

The fixture signing seeds are deliberately public test material. They carry no
merchant, admission, executor, deployment, or commercial authority. The reader
uses no network and dispatches no refund. PIC, APS, and Conduit are replaceable
compatibility producers; they are not normative dependencies.

See the [worked example](../../docs/REFUND-HANDOFF-CONFORMANCE.md), the
[technical reference](../../docs/reference/REFUND-HANDOFF-CONFORMANCE.md), and
the stable [contract identifier](../../docs/contract/refund-handoff/0.1/index.html).
