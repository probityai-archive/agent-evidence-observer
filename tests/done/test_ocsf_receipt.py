"""An OpenShell OCSF stream signed into a run: bound to its launch, carried by the receipt."""

import json

import pytest

from probity_observer.done import receipt
from probity_observer.done.formats import DoneError, public_key
from probity_observer.openshell import ocsf, policy

from .test_receipt import make_run

LAUNCH = ({"schema_version": "probity-launch/v1", "backend": "openshell"},
          {"claim_id": "c", "invocation_id": "c-1"})
LINE = {"class_uid": 4001, "category_uid": 4, "activity_id": 1, "type_uid": 400101,
        "severity_id": 1, "time": 1, "metadata": {"version": "1.8.0"}, "action": "Allowed",
        "dst_endpoint": {"domain": "pypi.org", "port": 443},
        "actor": {"process": {"name": "/usr/local/bin/python3.12", "pid": 5}},
        "firewall_rule": {"name": "pypi"}}
POLICY = b"""version: 1
network_policies:
  pypi:
    name: pypi
    endpoints:
      - host: pypi.org
        port: 443
    binaries:
      - path: /usr/local/bin/python3.12
"""


@pytest.fixture
def keys(harness, host, grader):
    return harness, host, grader


def test_the_ingest_is_signed_bound_and_digested_into_the_receipt(tmp_path, keys):
    harness, host, grader = keys
    pins = receipt.Pins(public_key(harness), public_key(host), public_key(grader))
    run = make_run(tmp_path, keys, launch=LAUNCH)
    before = receipt.assemble(run, pins)
    stream = b"2026-10-17T16:21:34Z OCSF-JSON " + json.dumps(LINE).encode() + b"\n"
    written = ocsf.write(run, {"supervisor.log": stream}, host, policy.load(POLICY))
    assert written["binding"]["invocation_id"] == "c-1"
    assert (run / "ocsf-sources" / "supervisor.log").read_bytes() == stream
    after = receipt.assemble(run, pins)
    assert after["verdict"] == before["verdict"]
    assert after["records"]["ocsf"]["assertion"] == "enforcer_claim"
    assert after["records"]["ocsf"]["records"] == 1
    assert after["records"]["ocsf"]["disagreements"] == 0

    (run / "launch.json").write_text(json.dumps({"other": "launch"}))
    with pytest.raises(ocsf.IngestError, match="bound to another launch"):
        receipt.assemble(run, pins)
    (run / "launch.json").write_text(json.dumps(LAUNCH[0]))
    (run / "ocsf-sources" / "supervisor.log").write_bytes(stream + b"x")
    with pytest.raises(ocsf.IngestError, match="differs from the ingest record"):
        receipt.assemble(run, pins)
    (run / "ocsf-sources" / "supervisor.log").write_bytes(stream)
    (run / "ocsf.json").write_bytes(b"{}")
    with pytest.raises(ocsf.IngestError, match="not the payload"):
        ocsf.verify(run, public_key(host))
    with pytest.raises(DoneError, match="signature does not verify"):
        ocsf.verify(run, public_key(grader))


def test_a_line_presented_as_more_than_a_claim_is_refused(tmp_path, keys):
    harness, host, grader = keys
    run = make_run(tmp_path, keys, launch=LAUNCH)
    record = ocsf.write(run, {"a.log": json.dumps(LINE).encode() + b"\n"}, host)
    record["records"][0]["assertion"] = "verified"
    from probity_observer.done.formats import sign_record
    data, envelope = sign_record(record, host)
    (run / "ocsf.json").write_bytes(data)
    (run / "ocsf.dsse.json").write_bytes(envelope)
    with pytest.raises(ocsf.IngestError, match="more than the enforcer's claim"):
        ocsf.verify(run, public_key(host))
    with pytest.raises(ocsf.IngestError, match="plain file name"):
        ocsf.write(run, {"../x": b""}, host)
