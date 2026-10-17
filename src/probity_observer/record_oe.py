"""Join the three sensors into the done-receipt records the verifier reads.

S2 (the in-container trace) is the event source: it alone sees processes,
argv, exit statuses and which command caused an effect. S1 (host inotify) is
the cross-check: every change S1 saw inside the workspace must match an S2
event on the same path. A change S2 did not record means the trace missed an
effect, so it is added to the record without an ``origin``, conservatively
counting as an edit, and the observation names a coverage gap around it. S3
(the final tree) becomes the tree record.

The output formats are the ones ``probity-verify`` defines in
``docs/done-receipt.md``, in the versions this module adds to:
``probity-observation/v3`` (an exec event carries the executed path ``exe``,
its working directory ``cwd``, the loader environment ``env`` and, when the
exec gate ran, the ``identity`` of the running executable and its ancestors
by SHA-256 (see :mod:`.sensors.binary_identity`; an exec whose identity did
not resolve is a ``sensor`` coverage gap), all as
container paths under the declared ``workspace_root``; a ``connect`` carries
its ``address``; and ``external_mutations`` lists every mutation outside the
workspace, numbered in the same step sequence as ``events``, with its
absolute ``paths``, its ``origin`` and its ``location``, ``grader_path`` or
``outside_workspace``, see :func:`location`),
``probity-capabilities/v1`` and ``probity-tree/v2`` (every non-directory
entry, symbolic links and special files included; see
:mod:`.sensors.treedigest`). Those records are strict
and carry no launch detail, so the launch digest, the exact trace expression,
the inotify watch list and the join's findings
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
TREE_SCHEMA = "probity-tree/v2"
OBSERVATION_SCHEMA = "probity-observation/v3"
WITNESS_SCOPE = "PEER"
VANTAGE = "independent"
DEVICE_TREES = ("/dev/", "/proc/", "/sys/")
GRADER_FILES = frozenset({"sitecustomize.py", "usercustomize.py", "reward.json", "reward.txt"})
GRADER_DIRECTORIES = frozenset({"site-packages", "dist-packages", "verifier"})


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
    timed_out: bool = False
    tracer_uid_separated: bool = True


def _covers(change: inotify.Change, s2_paths: set[str], s2_parents: set[str]) -> bool:
    """Whether an S2 mutation accounts for one S1 change.

    A change needs an S2 mutation on its own path. The one exception is an
    entry S1 found by scanning a directory that S2 saw renamed or linked into
    place: moving a tree moves its entries without a call per entry. A
    directory S2 saw created does not cover what S1 later finds inside it,
    because each of those entries was made by a call of its own.
    """
    if change.path in s2_paths:
        return True
    if not change.scanned:
        return False
    parts = change.path.split("/")
    return any("/".join(parts[:index]) in s2_parents for index in range(1, len(parts)))


def credited_paths(effects: strace.Effects, workspace: str) -> tuple[set[str], set[str]]:
    """The workspace paths S2 mutations account for, read from the recorded events.

    Credit comes only from the record form of each event, so a mutation the
    observation does not carry can never silence an S1 change. The second set
    holds the inside destination of each rename or link: entries S1 finds by
    scanning under it were moved there with the tree.
    """
    paths: set[str] = set()
    parents: set[str] = set()
    for event in effects.events:
        if event.kind not in strace.MUTATION_TYPES:
            continue
        fields = _record_event(event, workspace)
        if fields is None:
            continue
        paths.update(value for value in (fields.get("path"), fields.get("target")) if value)
        if event.kind in ("rename", "link") and (fields.get("target")
                                                 or fields.get("kind") == "create"):
            parents.add(fields.get("target") or fields["path"])
    return paths, parents


def join(effects: strace.Effects, report: inotify.Report, workspace: str) -> list[inotify.Change]:
    """S1 changes inside the workspace that no recorded S2 mutation accounts for."""
    s2_paths, s2_parents = credited_paths(effects, workspace)
    return [change for change in report.changes if not _covers(change, s2_paths, s2_parents)]


def _record_event(event: strace.Event, workspace: str) -> dict | None:
    """The observation-record form of one S2 event, or ``None`` if outside the workspace.

    A rename or link with one side inside the workspace is recorded on that
    side: moving an entry in is a ``create``, moving one out an ``unlink``, and
    a hard link from an inside file to an outside name a ``link`` on the inside
    path (the file can now be changed through a name the workspace does not
    hold). No mutation that touches the workspace is dropped.
    """
    if event.kind == "exec":
        fields: dict[str, Any] = {"argv": event.argv, "exe": event.exe, "cwd": event.cwd,
                                  "env": event.env or {}}
        if event.exit is not None:
            fields["exit"] = event.exit
        if event.identity is not None:
            fields["identity"] = event.identity
        return fields
    if event.kind == "connect":
        return {"address": event.address}
    path = strace.within(event.path, workspace) if event.path else None
    target = strace.within(event.target, workspace) if event.target else None
    if event.kind in ("rename", "link"):
        if path and target:
            return {"path": path, "target": target}
        if path:
            return {"path": path, "kind": "unlink" if event.kind == "rename" else "link"}
        if target:
            return {"path": target, "kind": "create"}
        return None
    return {"path": path} if path else None


def location(path: str) -> str:
    """``grader_path`` when a mutation there can change how a grader runs or scores.

    A grader path is a Python startup hook (``sitecustomize.py``,
    ``usercustomize.py``, any ``.pth`` file), a reward file (``reward.json``,
    ``reward.txt``), or anything under a ``site-packages``, ``dist-packages``
    or ``verifier`` directory. Every other path is ``outside_workspace``.
    """
    parts = path.split("/")
    name = parts[-1]
    if (name in GRADER_FILES or name.endswith(".pth")
            or any(part in GRADER_DIRECTORIES for part in parts[:-1])):
        return "grader_path"
    return "outside_workspace"


def _external(event: strace.Event, workspace: str) -> dict | None:
    """A mutation outside the workspace, as an ``external_mutations`` entry body."""
    if event.kind not in strace.MUTATION_TYPES:
        return None
    outside = [path for path in (event.path, event.target)
               if path and strace.within(path, workspace) is None
               and not path.startswith(DEVICE_TREES)]
    if not outside:
        return None
    places = {location(path) for path in outside}
    return {"type": event.kind, "paths": outside,
            "location": "grader_path" if "grader_path" in places else "outside_workspace"}


def _merge(gaps: list[tuple[int, int, str]]) -> list[dict]:
    """Merge overlapping gaps of one cause; gaps of different causes stay apart."""
    merged: list[list] = []
    for cause in sorted({gap[2] for gap in gaps}):
        spans: list[list] = []
        for begin, finish, _ in sorted(gap for gap in gaps if gap[2] == cause):
            if spans and begin <= spans[-1][1]:
                spans[-1][1] = max(spans[-1][1], finish)
            else:
                spans.append([begin, finish, cause])
        merged.extend(spans)
    merged.sort(key=lambda gap: (gap[0], gap[1], gap[2]))
    return [{"start": instant(begin), "end": instant(finish), "gap_cause": cause}
            for begin, finish, cause in merged]


def _overflow_cause(window: dict, effects: strace.Effects, workspace: str) -> str:
    """``agent`` when the trace shows a workspace mutation inside the overflow window."""
    for event in effects.events:
        if (window["from"] <= event.time <= window["to"]
                and event.kind in strace.MUTATION_TYPES
                and _record_event(event, workspace) is not None):
            return "agent"
    return "unknown"


def _tracer_cause(context: Context, effects: strace.Effects) -> str:
    """Who stopped the tracer before the agent's root process exited.

    ``host`` when the launcher timed the run out. Otherwise ``agent`` when the
    trace ends with a signal the agent was sending outside its tree, or when
    the agent runs under the tracer's uid and so could signal it; else
    ``host``, because only the host side can signal a tracer the agent cannot
    reach.
    """
    if context.timed_out:
        return "host"
    signalled = any(item["status"] == "interrupted" and item["outside_tree"]
                    for item in effects.signals)
    return "agent" if signalled or not context.tracer_uid_separated else "host"


def _gaps(context: Context, effects: strace.Effects, trace: strace.Trace,
          report: inotify.Report, unattributed: list[inotify.Change],
          start: int, end: int) -> list[tuple[int, int, str]]:
    """Every coverage gap with its ``gap_cause``: ``agent``, ``host``, ``sensor`` or ``unknown``.

    ``agent`` means the agent caused the loss or alone had the means to;
    ``host``, that the launcher's side did; ``sensor``, a limit of the
    tracer; ``unknown``, a change no traced call explains, from the host or
    through a channel the trace does not name.
    """
    workspace = context.container_workspace
    gaps: list[tuple[int, int, str]] = []
    for change in unattributed:
        second = max(math.floor(change.time), start)
        gaps.append((second, second + 1, "unknown"))
    for window in report.overflows:
        begin = min(max(math.floor(window["from"]), start), end - 1)
        finish = min(max(math.ceil(window["to"]), begin + 1), end)
        gaps.append((begin, finish, _overflow_cause(window, effects, workspace)))
    if not effects.root_exited:
        gaps.append((min(math.floor(effects.last_time or start), end - 1), end,
                     _tracer_cause(context, effects)))
    for escape in effects.escapes:
        gaps.append((min(math.floor(escape["time"]), end - 1), end, "agent"))
    for unknown in effects.unresolved:
        second = max(math.floor(unknown["time"]), start)
        gaps.append((min(second, end - 1), min(second + 1, end), "sensor"))
    if trace.unparsed:
        gaps.append((start, end, "sensor" if context.tracer_uid_separated else "agent"))
    for event in effects.events:
        if event.kind == "exec" and event.identity is not None \
                and event.identity.get("status") != "complete":
            second = max(math.floor(event.time), start)
            gaps.append((min(second, end - 1), min(second + 1, end), "sensor"))
    return gaps


def build(context: Context, effects: strace.Effects, trace: strace.Trace,
          report: inotify.Report, tree: Tree) -> dict[str, Any]:
    """Build the observation, capability, tree and receipt-sensor sections."""
    workspace = context.container_workspace
    start = math.floor(context.started)
    unattributed = join(effects, report, workspace)
    last = max([context.ended] + [change.time for change in unattributed])
    end = max(math.floor(last) + 1, start + 1)
    rows: list[tuple[float, dict, strace.Event | None, bool]] = []
    for event in effects.events:
        fields = _record_event(event, workspace)
        if fields is not None:
            kind = fields.pop("kind", event.kind)
            rows.append((event.time, {"type": kind, **fields}, event, False))
        if (outside := _external(event, workspace)) is not None:
            rows.append((event.time, outside, event, True))
    for change in unattributed:
        at = 0
        while at < len(rows) and rows[at][0] <= change.time:
            at += 1
        rows.insert(at, (change.time, {"type": change.kind, "path": change.path}, None, False))
    tracer = "complete" if effects.root_exited else "lost"
    gaps = _gaps(context, effects, trace, report, unattributed, start, end)

    ids: dict[str, str] = {}
    events: list[dict] = []
    external: list[dict] = []
    for step, (when, fields, source, outside) in enumerate(rows, start=1):
        record = {"id": f"e{step}", "step": step, "time": instant(min(max(when, start), end)),
                  **fields}
        if source is not None:
            if source.kind == "exec":
                ids[source.id] = record["id"]
            if source.origin is not None and source.origin in ids:
                record["origin"] = ids[source.origin]
        (external if outside else events).append(record)

    base = {"claim_id": context.claim_id, "invocation_id": context.invocation_id,
            "producer": context.producer}
    observed = {**base, "vantage": VANTAGE, "witness_scope": WITNESS_SCOPE}
    scope = {"id": context.invocation_id, "start": instant(start), "end": instant(end)}
    observation: dict[str, Any] = {"schema_version": OBSERVATION_SCHEMA, **observed,
                                   "workspace_root": workspace, "scope": scope,
                                   "events": events, "external_mutations": external}
    if report.lost:
        observation["coverage"] = "unknown"
    elif gaps:
        observation["coverage"] = "incomplete"
        observation["gaps"] = _merge(gaps)
    else:
        observation["coverage"] = "complete"
    capability = {"schema_version": "probity-capabilities/v1", **base,
                  "visible_event_types": sorted(strace.VISIBLE_EVENT_TYPES)}
    tree_record = {"schema_version": TREE_SCHEMA, **observed,
                   "tree_sha256": tree.sha256, **tree.record_fields()}
    sensors = {
        "s1_inotify": {"changes": len(report.changes), "overflow": report.overflow,
                       "overflows": [{"from": instant(item["from"]), "to": instant(item["to"])}
                                     for item in report.overflows],
                       "watch_failures": report.watch_failures,
                       "watch_list": report.watches,
                       "mask": inotify.mask_names(inotify.MASK)},
        "s2_strace": {"tracer": tracer, "calls": len(trace.calls),
                      "unparsed_lines": len(trace.unparsed),
                      "unresolved": [{**item, "time": instant(item["time"])}
                                     for item in effects.unresolved],
                      "escapes": [
                          {**escape, "time": instant(escape["time"])}
                          for escape in effects.escapes],
                      "signals": [{**item, "time": instant(item["time"])}
                                  for item in effects.signals],
                      "interrupted": [{"syscall": call.name, "pid": call.pid,
                                       "time": instant(call.time)}
                                      for call in trace.interrupted],
                      "origin_rule": strace.ORIGIN_RULE},
        "s3_tree": {"tree_sha256": tree.sha256, "files": len(tree.files),
                    "symlinks": len(tree.symlinks), "special": len(tree.special)},
        "join": {"unattributed": [{"type": change.kind, "path": change.path,
                                   "time": instant(change.time),
                                   "scanned": change.scanned} for change in unattributed]},
    }
    return {"observation": observation, "capability": capability, "tree": tree_record,
            "sensors": sensors}
