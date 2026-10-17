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
import os
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .. import record_oe
from ..sensors import inotify, strace, treedigest
from . import backend_apptainer, backend_docker, snapshot

BACKENDS = {"docker": backend_docker, "apptainer": backend_apptainer}
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


@dataclass(frozen=True)
class LaunchResult:
    run_dir: Path
    launch_sha256: str
    agent_exit: int | None
    coverage: str
    receipt: dict[str, Any]


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
    identity = backend.preflight(spec.image)
    uid = _agent_uid(workspace)
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
        "tracer_flags": list(strace.FLAGS),
        "tracer_uid_separated": spec.backend == "docker",
        "agent_argv": list(spec.agent_argv),
        "agent_uid": uid,
        "env": dict(sorted(spec.env.items())),
        "network": spec.network,
        "container_workspace": backend.WORKSPACE,
        "start_tarball_sha256": start_sha256,
        "observer_source_sha256": observer_source_sha256(),
        "timeout_seconds": spec.timeout_seconds,
    }
    launch_bytes = record_oe.encoded(launch_record)
    (run_dir / "launch.json").write_bytes(launch_bytes)
    launch_sha256 = record_oe.sha256(launch_bytes)

    watcher = inotify.Watcher(workspace)
    watcher.start()
    started = time.time()
    timed_out = False
    with open(run_dir / "transcript.txt", "wb") as transcript, \
            open(run_dir / "trace.txt", "wb") as trace_file:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=transcript,
                                   stderr=trace_file)
        try:
            exit_code = process.wait(timeout=spec.timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            if spec.backend == "docker":
                backend_docker.kill(name)
            else:
                backend_apptainer.kill(process)
            exit_code = process.wait()
    ended = time.time()
    report = watcher.stop()

    trace_text = (run_dir / "trace.txt").read_text("utf-8", "surrogateescape")
    trace = strace.parse(trace_text)
    found = strace.effects(trace, backend.WORKSPACE)
    strace.assign_origins(found)
    tree = treedigest.scan(workspace)
    context = record_oe.Context(spec.claim_id, spec.invocation_id, spec.producer,
                                backend.WORKSPACE, started, ended)
    built = record_oe.build(context, found, trace, report, tree)
    written = write_records(built, run_dir)
    root_exec = next((event for event in found.events
                      if event.kind == "exec" and event.pid == found.root_pid
                      and event.exit is not None), None)
    receipt = receipt_record(spec, built, written, run_dir=run_dir,
                             launch_sha256=launch_sha256, start_sha256=start_sha256, tree=tree,
                             exit_code=exit_code, agent_exit=root_exec.exit if root_exec else None,
                             timed_out=timed_out)
    (run_dir / "receipt.json").write_bytes(record_oe.encoded(receipt))
    return LaunchResult(run_dir, launch_sha256, receipt["agent_exit"],
                        receipt["coverage"], receipt)

