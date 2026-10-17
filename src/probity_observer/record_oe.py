"""Join the three sensors into the done-receipt records the verifier reads.

S2 (the in-container trace) is the event source: it alone sees processes,
argv, exit statuses and which command caused an effect. S1 (host inotify) is
the cross-check: every change S1 saw inside the workspace must match an S2
event on the same path. A change S2 did not record means the trace missed an
effect, so it is added to the record without an ``origin``, conservatively
counting as an edit, and the observation names a coverage gap around it. S3
(the final tree) becomes the tree record.

The output formats are the ones ``probity-verify`` defines in
``docs/done-receipt.md``: ``probity-observation/v2``,
``probity-capabilities/v1`` and ``probity-tree/v1``. Those records are strict
and carry no launch detail, so the launch digest, the exact trace expression,
the inotify watch list, effects outside the workspace and the join's findings
go into the receipt beside them (``probity-launch-receipt/v1``). The receipt's
``witnessScope`` is the observer's own field; the verify records carry the same
value as ``witness_scope``.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .sensors import inotify, strace
from .sensors.treedigest import Tree

RECEIPT_SCHEMA = "probity-launch-receipt/v1"
WITNESS_SCOPE = "PEER"
VANTAGE = "independent"
DEVICE_TREES = ("/dev/", "/proc/", "/sys/")


def instant(seconds: float) -> str:
    """UTC RFC 3339 at whole seconds, the precision the records carry."""
    return datetime.fromtimestamp(math.floor(seconds), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def encoded(value: Any) -> bytes:
    """The byte form every record is pinned by."""
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class Context:
    claim_id: str
    invocation_id: str
    producer: str
    container_workspace: str
    started: float
    ended: float


def _covers(change: inotify.Change, s2_paths: set[str], s2_parents: set[str]) -> bool:
    """Whether an S2 mutation accounts for one S1 change."""
    if change.path in s2_paths:
        return True
    if not change.scanned:
        return False
    parts = change.path.split("/")
    return any("/".join(parts[:index]) in s2_parents for index in range(1, len(parts)))


def join(effects: strace.Effects, report: inotify.Report, workspace: str) -> list[inotify.Change]:
    """S1 changes inside the workspace that no S2 mutation accounts for."""
    s2_paths: set[str] = set()
    s2_parents: set[str] = set()
    for event in effects.events:
        if event.kind not in strace.MUTATION_TYPES:
            continue
        for path in (event.path, event.target):
            relative = strace.within(path, workspace) if path else None
            if relative is None:
                continue
            s2_paths.add(relative)
            if event.kind in ("create", "rename", "link") and path == (event.target or event.path):
                s2_parents.add(relative)
    return [change for change in report.changes if not _covers(change, s2_paths, s2_parents)]


def _record_event(event: strace.Event, workspace: str) -> dict | None:
    """The observation-record form of one S2 event, or ``None`` if outside the workspace."""
    if event.kind == "exec":
        fields: dict[str, Any] = {"argv": event.argv}
        if event.exit is not None:
            fields["exit"] = event.exit
        return fields
    if event.kind == "connect":
        return {}
    path = strace.within(event.path, workspace) if event.path else None
    target = strace.within(event.target, workspace) if event.target else None
    if event.kind in ("rename", "link"):
        if path and target:
            return {"path": path, "target": target}
        if path:
            return {"path": path, "kind": "unlink"} if event.kind == "rename" else None
        if target:
            return {"path": target, "kind": "create"}
        return None
    return {"path": path} if path else None


def _external(event: strace.Event, workspace: str) -> dict | None:
    """An effect outside the workspace, for the receipt."""
    if event.kind == "connect":
        return {"type": "connect", "address": event.address, "time": instant(event.time)}
    if event.kind not in strace.MUTATION_TYPES:
        return None
    outside = [path for path in (event.path, event.target)
               if path and strace.within(path, workspace) is None
               and not path.startswith(DEVICE_TREES)]
    if not outside:
        return None
    return {"type": event.kind, "paths": outside, "time": instant(event.time)}


def _merge(gaps: list[tuple[int, int]]) -> list[dict]:
    merged: list[list[int]] = []
    for start, end in sorted(gaps):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return [{"start": instant(start), "end": instant(end)} for start, end in merged]


def build(context: Context, effects: strace.Effects, trace: strace.Trace,
          report: inotify.Report, tree: Tree) -> dict[str, Any]:
    """Build the observation, capability, tree and receipt-sensor sections."""
    workspace = context.container_workspace
    start = math.floor(context.started)
    unattributed = join(effects, report, workspace)
    last = max([context.ended] + [change.time for change in unattributed])
    end = max(math.floor(last) + 1, start + 1)
    gaps: list[tuple[int, int]] = []

    rows: list[tuple[float, dict, strace.Event | None]] = []
    external: list[dict] = []
    for event in effects.events:
        if (outside := _external(event, workspace)) is not None:
            external.append(outside)
        fields = _record_event(event, workspace)
        if fields is None:
            continue
        kind = fields.pop("kind", event.kind)
        rows.append((event.time, {"type": kind, **fields}, event))
    for change in unattributed:
        at = 0
        while at < len(rows) and rows[at][0] <= change.time:
            at += 1
        rows.insert(at, (change.time, {"type": change.kind, "path": change.path}, None))
        second = max(math.floor(change.time), start)
        gaps.append((second, second + 1))

    tracer = "complete" if effects.root_exited else "lost"
    if not effects.root_exited:
        gaps.append((min(math.floor(effects.last_time or start), end - 1), end))
    for escape in effects.escapes:
        gaps.append((min(math.floor(escape["time"]), end - 1), end))
    if trace.unparsed:
        gaps.append((start, end))

    ids: dict[str, str] = {}
    events = []
    for step, (when, fields, source) in enumerate(rows, start=1):
        record = {"id": f"e{step}", "step": step, "time": instant(min(max(when, start), end)),
                  **fields}
        if source is not None:
            ids[source.id] = record["id"]
            if source.origin is not None and source.origin in ids:
                record["origin"] = ids[source.origin]
        events.append(record)

    base = {"claim_id": context.claim_id, "invocation_id": context.invocation_id,
            "producer": context.producer}
    observed = {**base, "vantage": VANTAGE, "witness_scope": WITNESS_SCOPE}
    scope = {"id": context.invocation_id, "start": instant(start), "end": instant(end)}
    observation: dict[str, Any] = {"schema_version": "probity-observation/v2", **observed,
                                   "scope": scope, "events": events}
    if report.lost:
        observation["coverage"] = "unknown"
    elif gaps:
        observation["coverage"] = "incomplete"
        observation["gaps"] = _merge(gaps)
    else:
        observation["coverage"] = "complete"
    capability = {"schema_version": "probity-capabilities/v1", **base,
                  "visible_event_types": sorted(strace.VISIBLE_EVENT_TYPES)}
    tree_record = {"schema_version": "probity-tree/v1", **observed,
                   "tree_sha256": tree.sha256, "files": tree.files}
    sensors = {
        "s1_inotify": {"changes": len(report.changes), "overflow": report.overflow,
                       "watch_failures": report.watch_failures,
                       "watch_list": report.watches,
                       "mask": inotify.mask_names(inotify.MASK)},
        "s2_strace": {"tracer": tracer, "calls": len(trace.calls),
                      "unparsed_lines": len(trace.unparsed), "escapes": [
                          {**escape, "time": instant(escape["time"])}
                          for escape in effects.escapes],
                      "origin_rule": strace.ORIGIN_RULE},
        "s3_tree": {"tree_sha256": tree.sha256, "files": len(tree.files),
                    "symlinks": tree.symlinks, "special": tree.special},
        "join": {"unattributed": [{"type": change.kind, "path": change.path,
                                   "time": instant(change.time),
                                   "scanned": change.scanned} for change in unattributed]},
        "external_effects": external,
    }
    return {"observation": observation, "capability": capability, "tree": tree_record,
            "sensors": sensors}
