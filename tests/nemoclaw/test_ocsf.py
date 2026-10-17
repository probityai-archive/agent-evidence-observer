"""OpenShell's OCSF 1.8.0 lines as a second vantage: kept byte-exact, checked, and signed."""

from __future__ import annotations

import json

import pytest

from probity_observer.openshell import ocsf, policy
from probity_observer.openshell.ocsf import IngestError

from .test_policy import DEMO


def event(**overrides):
    base = {"class_uid": 4001, "class_name": "Network Activity", "category_uid": 4,
            "category_name": "Network Activity", "activity_id": 1, "activity_name": "Open",
            "type_uid": 400101, "severity_id": 1, "time": 1775014138811,
            "metadata": {"version": "1.8.0", "product": {"name": "OpenShell Sandbox Supervisor",
                                                         "vendor_name": "NVIDIA"}},
            "action": "Allowed", "action_id": 1, "message": "CONNECT allowed pypi.org:443",
            "dst_endpoint": {"domain": "pypi.org", "port": 443},
            "actor": {"process": {"name": "/usr/local/bin/python3.12", "pid": 57}},
            "firewall_rule": {"name": "pypi", "type": "opa"}}
    base.update(overrides)
    return {key: value for key, value in base.items() if value is not None}


def jsonl(*events) -> bytes:
    return b"".join(json.dumps(item, separators=(",", ":")).encode() + b"\n" for item in events)


BINDING = {"claim_id": "c1", "invocation_id": "c1-attempt-1", "launch_sha256": "a" * 64,
           "sandbox": "exp1"}


def test_marked_stderr_and_plain_jsonl_both_yield_records() -> None:
    line = json.dumps(event())
    stderr = (f"2026-10-17T16:21:34.682Z OCSF NET:OPEN [INFO] ALLOWED ...\n"
              f"2026-10-17T16:21:34.682Z OCSF-JSON {line}\n\nINFO other\n").encode()
    assert ocsf.split_lines(stderr) == [(2, line.encode())]
    assert ocsf.split_lines(jsonl(event()) + b"\r\n") == [(1, jsonl(event()).strip())]


@pytest.mark.parametrize("bad,reason", [
    ([], "not_an_object"),
    (event(class_uid=9999), "unknown_class"),
    (event(time=None), "missing:time"),
    (event(metadata={"version": "1.3.0"}), "version:1.3.0"),
    (event(category_uid=1), "category_mismatch"),
    (event(type_uid=400102), "type_uid_mismatch"),
])
def test_each_line_is_checked_against_its_vendored_class(bad, reason) -> None:
    assert ocsf.validate(bad, ocsf.class_schemas()) == reason
    assert ocsf.validate(event(), ocsf.class_schemas()) == "valid"


def test_profile_gated_required_fields_are_not_demanded() -> None:
    network = ocsf.class_schemas()[4001]
    assert "osint" not in ocsf.required_fields(network)
    assert "cloud" not in ocsf.required_fields(network)
    assert "process" in ocsf.required_fields(ocsf.class_schemas()[1007])


def test_ingest_marks_every_line_as_the_enforcers_claim_and_cross_checks_policy() -> None:
    declared = policy.load(DEMO)
    lines = jsonl(
        event(),
        event(action="Denied", action_id=2, firewall_rule={"name": "-", "type": "opa"},
              dst_endpoint={"domain": "example.com", "port": 443}),
        event(firewall_rule={"name": "pypi"}, dst_endpoint={"domain": "evil.example", "port": 443}),
        event(class_uid=1007, category_uid=1, type_uid=100701, process={"name": "bash", "pid": 1},
              dst_endpoint=None, actor=None, firewall_rule=None, action=None),
        event(dst_endpoint={"domain": "pypi.org"}),
    ) + b"{not json\n"
    record = ocsf.ingest({"supervisor.log": lines}, BINDING, declared)
    assert record["schema_version"] == "probity-ocsf-ingest/v1"
    assert record["binding"] == dict(sorted(BINDING.items()))
    assert record["network_policy_sha256"] == declared.canonical_sha256
    assert all(item["assertion"] == "enforcer_claim" and item["signed"] is False
               for item in record["records"])
    agreements = [item.get("policy", {}).get("agreement") for item in record["records"]]
    assert agreements == ["agrees", "agrees", "disagrees", None, "not_comparable", None]
    assert record["records"][0]["policy"]["ours"]["rules"] == ["pypi"]
    assert record["records"][-1]["validation"] == "not_json"
    assert record["counts"] == {"records": 6, "valid": 5, "invalid": 1, "network": 4,
                                "disagreements": 1, "enforcer_claims": 6}
    assert any("file activity" in item for item in record["doesNotAssert"])
    assert list(ocsf.lines_of(record, {"supervisor.log": lines}))[0] == jsonl(event()).strip()


def test_ingest_without_a_policy_and_with_tampered_sources() -> None:
    lines = jsonl(event())
    record = ocsf.ingest({"a.log": lines}, BINDING)
    assert "policy" not in record["records"][0] and "network_policy_sha256" not in record
    with pytest.raises(IngestError, match="differs from the ingest record"):
        list(ocsf.lines_of(record, {"a.log": lines + b"\n"}))
    record["records"][0]["sha256"] = "0" * 64
    with pytest.raises(IngestError, match="line 1 of a.log differs"):
        list(ocsf.lines_of(record, {"a.log": lines}))
    with pytest.raises(IngestError, match="binding needs launch_sha256"):
        ocsf.ingest({}, {"claim_id": "c", "invocation_id": "i"})


def test_a_tampered_vendored_class_schema_is_refused(monkeypatch) -> None:
    monkeypatch.setattr(ocsf.pins, "OCSF_CLASSES_SHA256", "0" * 64)
    with pytest.raises(IngestError, match="differ from their pin"):
        ocsf.class_schemas()
