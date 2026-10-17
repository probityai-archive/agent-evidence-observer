"""The loop admits a declared launch policy only when the prover says within_boundary."""

import json
from pathlib import Path

import pytest

from probity_observer.done import loop
from probity_observer.done.formats import DoneError
from probity_observer.openshell import release

NARROW = b"""version: 1
network_policies:
  pypi:
    name: pypi
    endpoints:
      - host: pypi.org
        port: 443
    binaries:
      - path: /usr/local/bin/python3.12
"""
OTHER = NARROW.replace(b"pypi.org", b"files.pythonhosted.org")


def spec(tmp_path, policy=None, boundary=None):
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    return loop.LoopSpec(contract=tmp_path, out=out, image="i", agent_argv=("true",),
                         task_id="t", network_policy=policy, policy_boundary=boundary)


def test_no_declared_policy_needs_no_proof(tmp_path):
    assert loop.admit_launch_policy(spec(tmp_path)).containment is None
    with pytest.raises(DoneError, match="needs a declared network policy"):
        loop.admit_launch_policy(spec(tmp_path, boundary=tmp_path / "b"))


def test_a_policy_needs_a_boundary_and_must_be_within_it(tmp_path):
    policy, boundary = tmp_path / "policy.yaml", tmp_path / "boundary.yaml"
    policy.write_bytes(NARROW)
    boundary.write_bytes(NARROW)
    with pytest.raises(DoneError, match="needs --policy-boundary"):
        loop.admit_launch_policy(spec(tmp_path, policy))
    admitted = loop.admit_launch_policy(spec(tmp_path, policy, boundary))
    assert admitted.containment["accepted"] is True
    assert json.loads((tmp_path / "out" / "containment.json").read_bytes())["result"] == \
        "within_boundary"
    boundary.write_bytes(OTHER)
    with pytest.raises(DoneError, match="exceeds_boundary"):
        loop.admit_launch_policy(spec(tmp_path, policy, boundary))
    refused = json.loads((tmp_path / "out" / "containment.json").read_bytes())
    assert refused["accepted"] is False and refused["counterexample"]["host"] == "pypi.org"
    assert Path(release.executable("openshell-prover")).is_file()
