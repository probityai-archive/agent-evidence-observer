"""OpenShell's OCSF 1.8.0 event stream, ingested as a second vantage the observer signs.

OpenShell writes one OCSF JSON object per event, to a JSONL file or after an ``OCSF-JSON``
marker on its supervisor's stderr (``docs/observability/ocsf-json-export.mdx`` at v0.1.4).
Nothing signs or chains those lines, and a runtime setting can turn the sink off
(``crates/openshell-ocsf/src/tracing_layers/jsonl_layer.rs``). So :func:`ingest` keeps every
line's exact bytes and digest, checks each against the vendored class schema (OpenShell's
own rule: every required field that no profile gates), and marks every line
``assertion: enforcer_claim``: the observer's signature over the ingest record says which
bytes arrived from which source during which run, not that the enforcer's account is true.

When a launch declared a network policy, each network and HTTP event is also matched against
it (:func:`.policy.match`) and compared with the rule OpenShell itself named
(``firewall_rule.name``) and its action, so a disagreement between the declaration and the
enforcer's own log is a recorded finding rather than a silent difference.
"""

from __future__ import annotations

import hashlib
import json
from importlib import resources
from typing import Any, Iterable

from . import pins
from . import policy as network_policy

SCHEMA = "probity-ocsf-ingest/v1"
MARKER = " OCSF-JSON "
NETWORK, HTTP, PROCESS = 4001, 4002, 1007
DOES_NOT_ASSERT = (
    "that the enforcer's account of any event is true: every line is the enforcer's own claim",
    "that the stream is complete: OpenShell's sink is best-effort, deduplicates denials and can "
    "be turned off at runtime",
    "file activity: OCSF 1.8.0 as OpenShell emits it has no file-activity class",
)


class IngestError(ValueError):
    """An ingest input is unusable as a whole (not one bad line, which is recorded)."""


def class_schemas() -> dict[int, dict[str, Any]]:
    """The vendored class schemas by ``class_uid``, checked against their pinned digest."""
    root = resources.files(__package__).joinpath("vendor/ocsf-1.8.0/classes")
    entries = sorted((item.name, item.read_bytes()) for item in root.iterdir()
                     if item.name.endswith(".json"))
    manifest = "".join(f"{hashlib.sha256(data).hexdigest()}  classes/{name}\n"
                       for name, data in entries)
    if hashlib.sha256(manifest.encode()).hexdigest() != pins.OCSF_CLASSES_SHA256:
        raise IngestError("vendored OCSF class schemas differ from their pin")
    schemas = {}
    for _, data in entries:
        loaded = json.loads(data)
        schemas[loaded["uid"]] = loaded
    return schemas


def required_fields(schema: dict[str, Any]) -> list[str]:
    return sorted(name for name, item in schema["attributes"].items()
                  if item.get("requirement") == "required"
                  and "profile" not in item and "profiles" not in item)


def split_lines(data: bytes) -> list[tuple[int, bytes]]:
    """``(line number, JSON bytes)`` for each OCSF record in JSONL or marked stderr text.

    A line that holds the marker contributes the bytes after it; any other non-empty line is
    taken as a JSONL record. Shorthand lines (``OCSF NET:OPEN ...``) carry no record and are
    skipped.
    """
    found = []
    for number, line in enumerate(data.split(b"\n"), start=1):
        text = line.rstrip(b"\r")
        if not text.strip():
            continue
        at = text.find(MARKER.encode())
        if at != -1:
            found.append((number, text[at + len(MARKER):]))
        elif text.lstrip().startswith(b"{"):
            found.append((number, text.strip()))
    return found


def validate(event: Any, schemas: dict[int, dict[str, Any]]) -> str:
    """``valid`` or the first reason the event is not a well-formed OCSF 1.8.0 record."""
    if not isinstance(event, dict):
        return "not_an_object"
    uid = event.get("class_uid")
    if uid not in schemas:
        return "unknown_class"
    schema = schemas[uid]
    missing = [name for name in required_fields(schema) if name not in event]
    if missing:
        return "missing:" + ",".join(missing)
    version = (event.get("metadata") or {}).get("version")
    if version != pins.OCSF_VERSION:
        return f"version:{version}"
    if event.get("category_uid") != schema.get("category_uid"):
        return "category_mismatch"
    activity = event.get("activity_id")
    if not isinstance(activity, int) or event.get("type_uid") != uid * 100 + activity:
        return "type_uid_mismatch"
    return "valid"


def _summary(event: dict[str, Any]) -> dict[str, Any]:
    actor = ((event.get("actor") or {}).get("process") or {})
    destination = event.get("dst_endpoint") or {}
    request = event.get("http_request") or {}
    url = request.get("url") or {}
    rule = event.get("firewall_rule") or {}
    summary = {"class_uid": event.get("class_uid"), "activity_id": event.get("activity_id"),
               "time": event.get("time"), "action": event.get("action"),
               "message": event.get("message")}
    extra = {"binary": actor.get("name"), "pid": actor.get("pid"),
             "host": destination.get("domain") or destination.get("hostname"),
             "ip": destination.get("ip"), "port": destination.get("port") or url.get("port"),
             "method": request.get("http_method"), "path": url.get("path"),
             "rule": rule.get("name"), "process": (event.get("process") or {}).get("name")}
    summary.update({key: value for key, value in extra.items() if value is not None})
    return {key: value for key, value in summary.items() if value is not None}


def cross_check(declared: network_policy.Policy, summary: dict[str, Any]) -> dict[str, Any]:
    """Our policy's decision on one network or HTTP event, beside the enforcer's own."""
    port = summary.get("port")
    binary = summary.get("binary")
    if not isinstance(port, int) or not binary:
        return {"agreement": "not_comparable", "reason": "event lacks port or binary"}
    found = network_policy.match(declared, network_policy.Effect(
        port=port, binaries=(binary,), host=summary.get("host"), ip=summary.get("ip"),
        method=summary.get("method"), path=summary.get("path"))).record()
    enforcer_rule = summary.get("rule")
    enforcer_allowed = (summary.get("action") or "").lower() == "allowed"
    ours_allowed = found["decision"] in ("allowed", "allowed_audit")
    agreement = "agrees" if ours_allowed == enforcer_allowed else "disagrees"
    if ours_allowed and enforcer_rule not in (None, "-") and enforcer_rule not in found["rules"]:
        agreement = "disagrees"
    return {"agreement": agreement, "ours": found, "enforcer_rule": enforcer_rule,
            "enforcer_action": summary.get("action")}


def ingest(sources: dict[str, bytes], binding: dict[str, Any],
           declared: network_policy.Policy | None = None) -> dict[str, Any]:
    """Build the ``probity-ocsf-ingest/v1`` record over the raw source bytes of one run.

    ``binding`` names the run (``claim_id``, ``invocation_id``, ``launch_sha256`` and the
    sandbox's identifiers); the record repeats it so the signature binds the lines to it.
    """
    for key in ("claim_id", "invocation_id", "launch_sha256"):
        if not isinstance(binding.get(key), str) or not binding[key]:
            raise IngestError(f"binding needs {key}")
    schemas = class_schemas()
    records: list[dict[str, Any]] = []
    described = []
    for name, data in sorted(sources.items()):
        lines = split_lines(data)
        described.append({"name": name, "sha256": hashlib.sha256(data).hexdigest(),
                          "bytes": len(data), "records": len(lines)})
        for number, raw in lines:
            entry: dict[str, Any] = {"source": name, "line": number,
                                     "sha256": hashlib.sha256(raw).hexdigest(),
                                     "assertion": "enforcer_claim", "signed": False}
            try:
                event = json.loads(raw)
            except (UnicodeDecodeError, json.JSONDecodeError):
                entry["validation"] = "not_json"
                records.append(entry)
                continue
            entry["validation"] = validate(event, schemas)
            if isinstance(event, dict):
                entry["summary"] = _summary(event)
                if declared is not None and event.get("class_uid") in (NETWORK, HTTP):
                    entry["policy"] = cross_check(declared, entry["summary"])
            records.append(entry)
    counts = {"records": len(records),
              "valid": sum(item["validation"] == "valid" for item in records),
              "invalid": sum(item["validation"] != "valid" for item in records),
              "network": sum(item.get("summary", {}).get("class_uid") in (NETWORK, HTTP)
                             for item in records),
              "disagreements": sum(item.get("policy", {}).get("agreement") == "disagrees"
                                   for item in records),
              "enforcer_claims": sum(item["assertion"] == "enforcer_claim" for item in records)}
    record = {"schema_version": SCHEMA, "ocsf_version": pins.OCSF_VERSION,
              "producer": "host-observer", "vantage": "enforcer_log",
              "binding": dict(sorted(binding.items())), "sources": described,
              "records": records, "counts": counts, "doesNotAssert": list(DOES_NOT_ASSERT)}
    if declared is not None:
        record["network_policy_sha256"] = declared.canonical_sha256
    return record


def lines_of(record: dict[str, Any], sources: dict[str, bytes]) -> Iterable[bytes]:
    """Re-derive each record's line bytes from the retained sources, checking every digest."""
    for described in record["sources"]:
        data = sources[described["name"]]
        if hashlib.sha256(data).hexdigest() != described["sha256"]:
            raise IngestError(f"source {described['name']} differs from the ingest record")
    by_source = {name: dict(split_lines(data)) for name, data in sources.items()}
    for entry in record["records"]:
        raw = by_source[entry["source"]][entry["line"]]
        if hashlib.sha256(raw).hexdigest() != entry["sha256"]:
            raise IngestError(f"line {entry['line']} of {entry['source']} differs")
        yield raw


SOURCE_DIR = "ocsf-sources"


def write(run, sources: dict[str, bytes], key, declared: network_policy.Policy | None = None
          ) -> dict[str, Any]:
    """Retain the raw sources in ``run`` and sign the ingest record as ``ocsf.dsse.json``.

    The binding is read from the run's own records: the launch digest is the SHA-256 of
    ``launch.json``, and the claim and invocation come from ``receipt.json``. ``key`` is the
    observer's (host) signing key.
    """
    from pathlib import Path

    from ..done.formats import sign_record

    run = Path(run)
    launch = run / "launch.json"
    receipt = json.loads((run / "receipt.json").read_bytes())
    binding = {"claim_id": receipt["claim_id"], "invocation_id": receipt["invocation_id"],
               "launch_sha256": hashlib.sha256(launch.read_bytes()).hexdigest()}
    record = ingest(sources, binding, declared)
    folder = run / SOURCE_DIR
    folder.mkdir(exist_ok=True)
    for name, data in sources.items():
        if "/" in name or name in ("", ".", ".."):
            raise IngestError(f"source name {name!r} is not a plain file name")
        (folder / name).write_bytes(data)
    data, envelope = sign_record(record, key)
    (run / "ocsf.json").write_bytes(data)
    (run / "ocsf.dsse.json").write_bytes(envelope)
    return record


def verify(run, host_key: str) -> dict[str, Any]:
    """Open ``ocsf.dsse.json`` under the pinned host key and re-check it against the run."""
    from pathlib import Path

    from ..done.formats import open_record

    run = Path(run)
    payload = open_record((run / "ocsf.dsse.json").read_bytes(), host_key, SCHEMA)
    if payload != (run / "ocsf.json").read_bytes():
        raise IngestError("ocsf.json is not the payload its envelope signs")
    record = json.loads(payload)
    launch = hashlib.sha256((run / "launch.json").read_bytes()).hexdigest()
    if record["binding"]["launch_sha256"] != launch:
        raise IngestError("ingest record is bound to another launch")
    sources = {item["name"]: (run / SOURCE_DIR / item["name"]).read_bytes()
               for item in record["sources"]}
    list(lines_of(record, sources))
    if any(item["assertion"] != "enforcer_claim" for item in record["records"]):
        raise IngestError("an ingested line is presented as more than the enforcer's claim")
    return record
