# Separately operated witness

**The question.** A host signs a record that says what its agent did. Could that
host later rewrite the record, or show one version to you and another to someone
else, without anyone noticing?

**What the witness shows.** Run `agent-evidence-witness` on a machine the host
does not control. The host submits each signed record; the witness appends it to
an append-only Merkle log, adds its own signature, and returns a signed
checkpoint with an inclusion proof. A reader then checks, with public code and
no access to either machine:

- both signatures, host and witness (one of two is refused, never downgraded);
- that the record is in the witness's log at the checkpoint it was given;
- that every later checkpoint extends the one the reader kept before.

A witness that signs two different logs under one key is caught the first time
any two readers compare checkpoints. Two different roots for one log size prove
the fork by themselves, and anyone can check that evidence with the witness's
public key. This holds for every witness, including one we run.

**Witness scope.** The verifier reports `witnessScope: EXTERNAL` only when the
reader's own pins name different operators for the host key and the witness key.
With one operator for both, the same record verifies as `PEER`. Nothing a
producer writes can raise the scope: the observer's own packets still say `PEER`.

**The evidence boundary.**

- The operator names are the reader's statement, made outside the record. The
  verifier cannot check who controls a key, so a reader who pins a witness the
  host secretly runs gets `EXTERNAL` for a `PEER` record.
- Checkpoints carry no clock. A witness can delay or withhold an entry; it
  cannot hide a fork from readers who compare checkpoints, but readers who never
  compare learn nothing.
- The witness attests that a record existed and was logged. It does not make the
  record's content true: a forged trace line, an unobserved effect or a host
  that never submits a record are outside what it can see.
- The server has no key rotation, no replication and no access control beyond
  its list of producer keys.

Commands, the HTTP API, the record formats and the test controls are in the
[witness server reference](reference/WITNESS-SERVER.md).
