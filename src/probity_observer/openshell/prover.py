"""OpenShell's policy prover as the admission check on a launch policy: only ``within`` passes.

``openshell-prover check <candidate> --boundary <boundary> --output json`` decides, with a Z3
model, whether every authority the candidate policy grants is also granted by the operator's
boundary policy (``crates/openshell-prover/README.md`` at v0.1.4). Its result is closed to
four states, spelled ``within_boundary``, ``exceeds_boundary``, ``unsupported`` and
``inconclusive`` in the JSON (``crates/openshell-prover-cli/src/main.rs``). The upstream rule
is to accept a policy only on ``CheckResult::Within``; :func:`check` holds to it and also refuses a prover
binary or JSON contract other than the pinned one, so an upgrade cannot change what passes
without changing this package. The parsed result, with the candidate's and boundary's
digests and the prover binary's digest, is the record a launch keeps.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import pins

SCHEMA = "probity-policy-containment/v1"
SCHEMA_VERSION = 1
EXIT_WITHIN = 0
WITHIN = "within_boundary"
"""The JSON spelling of ``CheckResult::Within``; every other result is refused."""


class ContainmentRefused(RuntimeError):
    """The candidate policy is not proven within the boundary; the launch must not start."""

    def __init__(self, message: str, record: dict[str, Any]) -> None:
        super().__init__(message)
        self.record = record


@dataclass(frozen=True)
class Prover:
    """A pinned ``openshell-prover`` executable."""

    path: Path

    def sha256(self) -> str:
        return hashlib.sha256(self.path.read_bytes()).hexdigest()


def _digest(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def check(candidate: Path, boundary: Path, prover: Prover, timeout_seconds: int = 30,
          expected_sha256: str | None = pins.BINARY_SHA256["openshell-prover"]
          ) -> dict[str, Any]:
    """Run the prover; return the containment record, or raise :class:`ContainmentRefused`."""
    record: dict[str, Any] = {
        "schema_version": SCHEMA, "prover": {"path": str(prover.path),
                                             "sha256": None, "version": None},
        "candidate_sha256": _digest(candidate), "boundary_sha256": _digest(boundary),
        "result": None, "accepted": False,
    }
    if not prover.path.is_file():
        raise ContainmentRefused(f"prover not found at {prover.path}", record)
    record["prover"]["sha256"] = prover.sha256()
    if expected_sha256 is not None and record["prover"]["sha256"] != expected_sha256:
        raise ContainmentRefused("prover binary is not the pinned build", record)
    argv = [str(prover.path), "check", str(candidate), "--boundary", str(boundary),
            "--output", "json", "--timeout", f"{int(timeout_seconds)}s"]
    try:
        done = subprocess.run(argv, capture_output=True, text=True,
                              timeout=timeout_seconds + 30, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ContainmentRefused(f"prover did not run: {error}", record) from None
    record["exit_code"] = done.returncode
    try:
        output = json.loads(done.stdout)
    except json.JSONDecodeError:
        raise ContainmentRefused(f"prover printed no JSON result (exit {done.returncode}): "
                                 f"{done.stderr.strip()[-300:]}", record) from None
    record["prover"]["version"] = output.get("prover_version")
    record.update(result=output.get("result"), reason_code=output.get("reason_code"),
                  reason=output.get("reason"), coverage=output.get("coverage"),
                  counterexample=output.get("counterexample"))
    if output.get("schema_version") != SCHEMA_VERSION:
        raise ContainmentRefused("prover JSON contract is not the pinned version", record)
    if output.get("prover_version") != pins.OPENSHELL_VERSION:
        raise ContainmentRefused("prover reports a version other than the pinned one", record)
    if output.get("result") != WITHIN or done.returncode != EXIT_WITHIN:
        raise ContainmentRefused(
            f"launch policy is not within the boundary: {output.get('result')}"
            f" ({output.get('reason_code') or 'no reason'})", record)
    record["accepted"] = True
    return record
