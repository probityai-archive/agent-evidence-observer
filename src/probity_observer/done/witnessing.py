"""Submit an attempt's signed records to a separately operated witness.

Under ``probity-done run --witness-url``, each attempt's tree and observation records (signed by
the host key) and its grade (signed by the grader key) go to the witness after grading and
before the receipt is signed. The witness appends each to its log, co-signs it and returns a
``probity-witnessed-record/v1`` bundle, written as ``<role>.witnessed.json`` beside the record.
``probity-done verify --require-witness-scope EXTERNAL`` checks those bundles under the reader's
own pins; the gate host never holds the witness key, so it cannot make one.

A witness that does not answer decides nothing: the attempt's records are left without a
bundle, the reason is written to ``witness-unavailable.txt``, and under an ``EXTERNAL``
requirement that attempt's ``supported`` is held as ``not_established``.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Callable

from ..witness.checkpoint import canonical
from ..witness.client import WitnessClient, WitnessUnavailable

ROLES = ("tree", "observation", "grade")
"""The records ``verify`` requires a witness bundle for, in submission order."""


def claim_id(run: Path, role: str) -> str:
    """One claim per record: the loop output's name, the attempt and the role."""
    return f"{run.parent.name}/{run.name}/{role}"


def submitter(client: WitnessClient, host_key: str, grader_key: str) -> Callable[[Path], None]:
    """The ``witness`` callback the loop calls with each graded attempt's directory."""
    producers = {"tree": host_key, "observation": host_key, "grade": grader_key}

    def submit(run: Path) -> None:
        for role in ROLES:
            envelope = (run / f"{role}.dsse.json").read_bytes().strip()
            try:
                bundle, _ = client.submit(envelope, claim_id(run, role), producers[role])
            except WitnessUnavailable as error:
                (run / "witness-unavailable.txt").write_text(f"{role}: {error}\n")
                print(f"witness did not answer for {run.name}/{role}: {error}", file=sys.stderr)
                return
            (run / f"{role}.witnessed.json").write_bytes(canonical(bundle) + b"\n")

    return submit
