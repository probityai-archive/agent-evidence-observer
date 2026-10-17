"""Run an unmodified agent at PEER scope with three sensors outside it.

One launch, in order:

1. Seal the workspace's start state into ``start.tar`` (its digest is bound
   into the launch digest).
2. Pin the image and check its tracer (``preflight``).
3. Write ``launch.json``: the backend, image id, tracer version, the full
   container argv (which holds the exact trace expression), the agent argv,
   environment, uid, network setting, start tarball digest and observer source
   digest. ``launch_sha256`` is the SHA-256 of those bytes.
4. Start S1 (host inotify) on the workspace, run the container with S2
   (``strace -f``) as the agent's parent, stop S1 after the container exits.
5. Scan S3 (the final tree), join the sensors, and write the records and the
   receipt.

The records are ``observation.json``, ``capability.json`` and ``tree.json`` in
the formats ``probity-verify`` reads, plus ``receipt.json``, which carries the
launch digest, the trace expression, the inotify watch list, the join's
findings and effects outside the workspace. Every record says
``witness_scope``/``witnessScope`` ``PEER``: the host that runs the launcher
also holds the sensors.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .. import record_oe
from ..sensors import inotify, strace, treedigest
from . import (
    backend_apptainer,
    backend_docker,
    backend_openshell,
    identity_gate,
    network_effects,
    snapshot,
)

BACKENDS = {"docker": backend_docker, "apptainer": backend_apptainer,
            "openshell": backend_openshell}
UNPRIVILEGED_UID = 65534
RECORD_ROLES = ("observation", "capability", "tree")


@dataclass(frozen=True)
class LaunchSpec:
    """What to run, where, and under which names the records go out."""

    backend: str
    image: str
    agent_argv: tuple[str, ...]
    workspace: Path
    claim_id: str
    invocation_id: str
    producer: str = "host-observer"
    env: dict[str, str] = field(default_factory=dict)
    network: bool = False
    timeout_seconds: float = 3600.0
    network_policy: Path | None = None
    containment: dict[str, Any] | None = None


@dataclass(frozen=True)
class LaunchResult:
    run_dir: Path
    launch_sha256: str
    agent_exit: int | None
    coverage: str
    receipt: dict[str, Any]
    enforcer_logs: dict[str, bytes] = field(default_factory=dict)
    """The enforcer's own log streams by name (the OpenShell backend's ``docker logs``)."""


def observer_source_sha256() -> str:
    """Bind the launcher and sensor source files that ran."""
    package = Path(__file__).resolve().parent.parent
    digest = hashlib.sha256()
    for path in sorted(package.rglob("*.py")):
        relative = path.relative_to(package).as_posix()
        digest.update(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {relative}\n".encode())
    return digest.hexdigest()


def container_name(invocation_id: str) -> str:
    safe = "".join(char if char.isalnum() or char in "-_." else "-" for char in invocation_id)
    return f"probity-agent-{safe}-{os.getpid()}"


def _agent_uid(workspace: Path) -> int:
    """The agent runs as the workspace owner, never as root."""
    owner = os.stat(workspace).st_uid
    if owner != 0:
        return owner
    for directory, dirnames, filenames in os.walk(workspace):
        for name in dirnames + filenames:
            os.lchown(Path(directory) / name, UNPRIVILEGED_UID, UNPRIVILEGED_UID)
    os.chown(workspace, UNPRIVILEGED_UID, UNPRIVILEGED_UID)
    return UNPRIVILEGED_UID


def write_records(built: dict[str, Any], run_dir: Path) -> dict[str, str]:
    """Write the three verify records and return each one's ``<role>_record_sha256``."""
    written = {}
    for role in RECORD_ROLES:
        data = record_oe.encoded(built[role])
        (run_dir / f"{role}.json").write_bytes(data)
        written[f"{role}_record_sha256"] = record_oe.sha256(data)
    return written


def receipt_record(spec: LaunchSpec, built: dict[str, Any], written: dict[str, str], *,
                   run_dir: Path, launch_sha256: str, start_sha256: str,
                   tree: treedigest.Tree, exit_code: int | None, agent_exit: int | None,
                   timed_out: bool) -> dict[str, Any]:
    """The ``probity-launch-receipt/v1`` body.

    ``tree_sha256`` is the digest of the final tree; the digest of the
    ``tree.json`` bytes is ``tree_record_sha256``. Record digests carry the
    ``_record_sha256`` suffix so that no record digest can shadow a content
    digest of the same name.
    """
    return {
        "schema_version": record_oe.RECEIPT_SCHEMA,
        "claim_id": spec.claim_id,
        "invocation_id": spec.invocation_id,
        "producer": spec.producer,
        "witnessScope": record_oe.WITNESS_SCOPE,
        "launch_sha256": launch_sha256,
        "trace_expression": strace.TRACE_EXPRESSION,
        "watch_list": built["sensors"]["s1_inotify"]["watch_list"],
        "start_tarball_sha256": start_sha256,
        "tree_sha256": tree.sha256,
        "coverage": built["observation"]["coverage"],
        "container_exit": exit_code,
        "agent_exit": agent_exit,
        "timed_out": timed_out,
        "transcript_sha256": record_oe.sha256((run_dir / "transcript.txt").read_bytes()),
        "trace_sha256": record_oe.sha256((run_dir / "trace.txt").read_bytes()),
        **written,
        "sensors": built["sensors"],
        "doesNotAssert": [
            "that the host operator is independent of the agent's operator (scope is PEER)",
            "effects through channels the trace expression does not name",
            "that a symbolic link in a path outside an open() call was resolved",
        ],
    }


def launch(spec: LaunchSpec, run_dir: Path) -> LaunchResult:
    """Run one agent and write its records into an empty ``run_dir``."""
    backend = BACKENDS[spec.backend]
    run_dir = Path(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    if any(run_dir.iterdir()):
        raise ValueError("run directory must be empty")
    workspace = Path(spec.workspace).resolve()
    start_sha256 = snapshot.seal(workspace, run_dir / "start.tar")
    if backend is backend_openshell:
        return _launch_openshell(spec, run_dir, workspace, start_sha256)
    identity = backend.preflight(spec.image)
    uid = backend.agent_uid(identity, workspace, _agent_uid(workspace))
    name = container_name(spec.invocation_id)
    argv = backend.command(identity, name=name, workspace=str(workspace),
                           agent_argv=list(spec.agent_argv), env=spec.env, uid=uid,
                           network=spec.network)
    launch_record = {
        "schema_version": "probity-launch/v1",
        "backend": spec.backend,
        "image": identity.image,
        "image_id": identity.image_id,
        "runtime_version": identity.runtime_version,
        "strace_version": identity.strace_version,
        "container_argv": argv,
        "trace_expression": strace.TRACE_EXPRESSION,
        "tracer_flags": list(getattr(backend, "tracer_flags", lambda: strace.FLAGS)()),
        "tracer_uid_separated": backend.uid_separated(identity),
        "uid_map": getattr(identity, "uid_map", None),
        "agent_argv": list(spec.agent_argv),
        "agent_uid": uid,
        "env": dict(sorted(spec.env.items())),
        "network": spec.network,
        "container_workspace": backend.WORKSPACE,
        "start_tarball_sha256": start_sha256,
        "observer_source_sha256": observer_source_sha256(),
        "timeout_seconds": spec.timeout_seconds,
        "identity_gate": getattr(backend, "IDENTITY_GATE", False),
    }
    declared = network_effects.declare(spec.network_policy, run_dir)
    if declared is not None:
        launch_record["network_policy"] = declared
    if spec.containment is not None:
        launch_record["policy_containment"] = spec.containment
    launch_bytes = record_oe.encoded(launch_record)
    (run_dir / "launch.json").write_bytes(launch_bytes)
    launch_sha256 = record_oe.sha256(launch_bytes)

    backend.prepare(identity, workspace)
    watcher = inotify.Watcher(workspace)
    watcher.start()
    started = time.time()
    timed_out = False
    with open(run_dir / "transcript.txt", "wb") as transcript, \
            open(run_dir / "trace.txt", "wb") as trace_file:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=transcript,
                                   stderr=trace_file)
        gate = None
        if launch_record["identity_gate"]:
            gate = identity_gate.Gate(run_dir / "trace.txt",
                                      identity_gate.resolver_argv("docker", name))
            gate.start()
        try:
            exit_code = process.wait(timeout=spec.timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            if spec.backend == "docker":
                backend_docker.kill(name)
            else:
                backend_apptainer.kill(process)
            exit_code = process.wait()
        if gate is not None:
            gate.stop()
    ended = time.time()
    report = watcher.stop()
    backend.restore(identity, workspace)

    tree = treedigest.scan(workspace)
    _, receipt = _finish(spec, run_dir, backend=backend, launch_record=launch_record,
                         launch_sha256=launch_sha256, start_sha256=start_sha256,
                         report=report, started=started, ended=ended,
                         exit_code=exit_code, timed_out=timed_out, gate=gate, declared=declared,
                         tree=tree)
    (run_dir / "receipt.json").write_bytes(record_oe.encoded(receipt))
    return LaunchResult(run_dir, launch_sha256, receipt["agent_exit"],
                        receipt["coverage"], receipt)


def _finish(spec: LaunchSpec, run_dir: Path, *, backend: Any, launch_record: dict[str, Any],
            launch_sha256: str, start_sha256: str, report: inotify.Report,
            started: float, ended: float, exit_code: int | None, timed_out: bool,
            gate: identity_gate.Gate | None, declared: dict[str, Any] | None,
            tree: treedigest.Tree) -> tuple[dict[str, Any], dict[str, Any]]:
    """Parse the trace, join the sensors, write the three records; return (built, receipt)."""
    trace_text = (run_dir / "trace.txt").read_text("utf-8", "surrogateescape")
    trace = strace.parse(trace_text)
    found = strace.effects(trace, backend.WORKSPACE)
    strace.assign_origins(found)
    if gate is not None:
        identity_gate.assign(found.events, gate.results())
    context = record_oe.Context(spec.claim_id, spec.invocation_id, spec.producer,
                                backend.WORKSPACE, started, ended, timed_out=timed_out,
                                tracer_uid_separated=launch_record["tracer_uid_separated"])
    built = record_oe.build(context, found, trace, report, tree)
    written = write_records(built, run_dir)
    root_exec = next((event for event in found.events
                      if event.kind == "exec" and event.pid == found.root_pid
                      and event.exit is not None), None)
    receipt = receipt_record(spec, built, written, run_dir=run_dir,
                             launch_sha256=launch_sha256, start_sha256=start_sha256, tree=tree,
                             exit_code=exit_code, agent_exit=root_exec.exit if root_exec else None,
                             timed_out=timed_out)
    if gate is not None:
        receipt["sensors"]["s4_identity"] = gate.summary()
    if declared is not None:
        receipt["network_effects"] = network_effects.judge(run_dir, found)
    return built, receipt


def _launch_openshell(spec: LaunchSpec, run_dir: Path, workspace: Path,
                      start_sha256: str) -> LaunchResult:
    """One launch under OpenShell (:mod:`.backend_openshell`): it enforces, the sensors observe."""
    backend = backend_openshell
    if spec.network_policy is None:
        raise ValueError("the openshell backend needs a declared launch policy (--network-policy)")
    if spec.network:
        raise ValueError("under the openshell backend the declared policy decides network access")
    from ..openshell import policy as network_policy
    loaded = network_policy.load(Path(spec.network_policy))
    uid = backend.policy_uid(loaded)
    identity = backend.preflight(spec.image)
    session = backend.Session(identity, policy_path=Path(spec.network_policy),
                              name=container_name(spec.invocation_id))
    try:
        session.start_gateway()
        session.create()
        session.upload(workspace)
        start_tree = session.verify_start(workspace)
        argv = session.exec_argv(list(spec.agent_argv), spec.env)
        tracer = session.tracer_argv()
        launch_record = {
            "schema_version": "probity-launch/v1",
            "backend": spec.backend,
            "image": identity.image,
            "image_id": identity.image_id,
            "runtime_version": identity.runtime_version,
            "strace_version": identity.strace_version,
            "container_argv": argv,
            "tracer_argv": tracer,
            "trace_expression": strace.TRACE_EXPRESSION,
            "tracer_flags": list(backend.tracer_flags()),
            "tracer_uid_separated": backend.uid_separated(identity),
            "uid_map": None,
            "agent_argv": list(spec.agent_argv),
            "agent_uid": uid,
            "env": dict(sorted(spec.env.items())),
            "network": False,
            "container_workspace": backend.WORKSPACE,
            "start_tarball_sha256": start_sha256,
            "observer_source_sha256": observer_source_sha256(),
            "timeout_seconds": spec.timeout_seconds,
            "identity_gate": backend.IDENTITY_GATE,
            "openshell": {**identity.openshell, **session.record},
        }
        declared = network_effects.declare(spec.network_policy, run_dir)
        launch_record["network_policy"] = declared
        if spec.containment is not None:
            launch_record["policy_containment"] = spec.containment
        launch_bytes = record_oe.encoded(launch_record)
        (run_dir / "launch.json").write_bytes(launch_bytes)
        launch_sha256 = record_oe.sha256(launch_bytes)

        started = time.time()
        timed_out = False
        with open(run_dir / "transcript.txt", "wb") as transcript, \
                open(run_dir / "trace.txt", "wb") as trace_file, \
                open(run_dir / "exec-cli.txt", "wb") as cli_err, \
                open(run_dir / "tracer.jsonl", "wb") as tracer_out:
            process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=transcript,
                                       stderr=cli_err, env=session.env)
            tracing = subprocess.Popen(tracer, stdin=subprocess.DEVNULL, stdout=tracer_out,
                                       stderr=trace_file)
            gate = identity_gate.Gate(run_dir / "trace.txt", session.resolver_argv(),
                                      startup_exec=backend.STARTUP_EXEC)
            gate.start()
            try:
                exit_code = process.wait(timeout=spec.timeout_seconds)
            except subprocess.TimeoutExpired:
                timed_out = True
                session.stop_agent()
                try:
                    exit_code = process.wait(timeout=60)
                except subprocess.TimeoutExpired:
                    process.kill()
                    exit_code = process.wait()
            try:
                tracing.wait(timeout=60)
            except subprocess.TimeoutExpired:
                session.stop_agent()
                tracing.wait(timeout=60)
            gate.stop()
        ended = time.time()
        final_root = session.download(session.state / "final")
        backend._replace_tree(final_root, workspace)
        tree = treedigest.scan(workspace)
        report = inotify.Report(changes=backend.tree_changes(start_tree, tree, ended))
        _, receipt = _finish(spec, run_dir, backend=backend, launch_record=launch_record,
                                 launch_sha256=launch_sha256, start_sha256=start_sha256,
                                 report=report, started=started,
                                 ended=ended, exit_code=exit_code, timed_out=timed_out,
                                 gate=gate, declared=declared, tree=tree)
        receipt["sensors"]["s1_inotify"] = {
            "status": "replaced_by_tree_diff",
            "changes": len(report.changes),
            "reason": "the workspace lives inside the OpenShell sandbox, so no host watch can "
                      "see it; every path that differs between the sealed start tree and the "
                      "downloaded final tree must be accounted for by a traced mutation",
        }
        receipt["sensors"]["tracer"] = [json.loads(line) for line in
                                        (run_dir / "tracer.jsonl").read_text().splitlines()
                                        if line.strip()]
        receipt["doesNotAssert"] = [*receipt["doesNotAssert"],
                                    ("a mutation the trace missed and the agent undid before the "
                                     "final tree was downloaded (the tree diff sees net changes "
                                     "only)")]
        (run_dir / "receipt.json").write_bytes(record_oe.encoded(receipt))
        logs = session.logs()
    finally:
        session.close()
    return LaunchResult(run_dir, launch_sha256, receipt["agent_exit"], receipt["coverage"],
                        receipt, enforcer_logs=logs)
