"""A separately operable witness for observer records.

``server`` runs one witness (Ed25519 key, file-backed append-only Merkle log,
HTTP API). ``client`` submits statements and retains the newest checkpoint it
has verified, refusing any later checkpoint the witness cannot prove consistent.
``scope`` verifies a witnessed record offline, with 2-of-2 DSSE signatures, and
decides ``witnessScope``: ``EXTERNAL`` only when the consumer's pins name a
different operator for the witness key than for the host key. ``checkpoint``
and ``proofs`` hold the record formats and the RFC 9162 proof checks.

Requires the ``witness`` extra (``jcs-admit`` for RFC 8785 and DSSE).
"""
