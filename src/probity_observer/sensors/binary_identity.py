"""S4: the executable identity of every exec, by SHA-256 of the open ``/proc/<pid>/exe``.

The algorithm is OpenShell's (``crates/openshell-binary-identity/src/lib.rs`` at v0.1.4): open
the live ``/proc/<pid>/exe`` of the process and of each ancestor up to the process-tree root,
take a snapshot (parent, start time, executable device, inode, size, times, command line),
hash the bytes of the already-open object, take the snapshot again, and fail without a
partial identity if any link cannot be opened, hashed, or changed while it was read. A
renamed or replaced binary therefore cannot pass for the one it imitates: the digest is of
the program the kernel is running, not of whatever the path names now.

The gate that makes this hold for short-lived processes is the tracer. The docker backend
runs ``strace`` with :data:`TRACER_FLAGS`, which delivers ``SIGSTOP`` to a process on exit
from every ``execve``/``execveat``; the launcher reads each exec from the live trace and asks
this module, running as a resolver inside the container (:func:`serve`), to wait for the stop,
resolve the chain, and continue the process. A process is never left running unresolved
past its exec, and a resolver that dies leaves its processes stopped until the launch times
out, which the records show.

The module uses only the standard library, so the launcher can run its source inside any
image that has ``python3`` (``python3 -I -c <source> serve <root-pid>``).
"""

from __future__ import annotations

import hashlib
import json
import os
import signal
import sys
import time

TRACER_FLAGS = ("-e", "signal=SIGSTOP", "-e", "inject=execve,execveat:signal=SIGSTOP")
"""Replace the tracer's ``signal=none``: the trace then prints ``--- stopped by SIGSTOP ---``
when the injected stop has landed, which is the only state in which one ``SIGCONT`` releases
exactly this exec and no later one."""
MAX_DEPTH = 64
STOP_WAIT = 10.0
DELETED = " (deleted)"


class IdentityError(Exception):
    """An executable in the chain could not be opened, hashed, or held still."""


def _stat_fields(pid: int, proc: str) -> tuple[str, int, int]:
    """``(state, parent pid, start time)`` from ``/proc/<pid>/stat``."""
    path = f"{proc}/{pid}/stat"
    try:
        with open(path, encoding="ascii", errors="replace") as handle:
            text = handle.read()
    except OSError as error:
        raise IdentityError(f"read {path}: {error.strerror}") from None
    head, sep, rest = text.rpartition(") ")
    fields = rest.split()
    if not sep or len(fields) < 20:
        raise IdentityError(f"parse {path}: unexpected format")
    return fields[0], int(fields[1]), int(fields[19])


def state(pid: int, proc: str = "/proc") -> str | None:
    """The process state letter, or ``None`` when the process is gone."""
    try:
        return _stat_fields(pid, proc)[0]
    except IdentityError:
        return None


def _exe_path(pid: int, proc: str) -> str:
    link = f"{proc}/{pid}/exe"
    try:
        target = os.readlink(link)
    except OSError as error:
        raise IdentityError(f"read {link}: {error.strerror}") from None
    if target.endswith(DELETED) and not os.path.exists(target):
        return target[: -len(DELETED)]
    return target


def _snapshot(pid: int, proc: str, handle) -> dict:
    meta = os.fstat(handle.fileno())
    _, parent, start = _stat_fields(pid, proc)
    try:
        with open(f"{proc}/{pid}/cmdline", "rb") as cmdline:
            command = cmdline.read()
    except OSError as error:
        raise IdentityError(f"read {proc}/{pid}/cmdline: {error.strerror}") from None
    try:
        live = os.stat(f"{proc}/{pid}/exe")
    except OSError as error:
        raise IdentityError(f"stat {proc}/{pid}/exe: {error.strerror}") from None
    return {"pid": pid, "parent": parent, "start": start, "path": _exe_path(pid, proc),
            "file": (meta.st_dev, meta.st_ino, meta.st_size, meta.st_mtime_ns, meta.st_ctime_ns),
            "live": (live.st_dev, live.st_ino, live.st_size, live.st_mtime_ns, live.st_ctime_ns),
            "cmdline": command}


def link(pid: int, proc: str = "/proc") -> dict:
    """One process: path and SHA-256 of its running executable, and its parent pid."""
    path = f"{proc}/{pid}/exe"
    try:
        handle = open(path, "rb")
    except OSError as error:
        raise IdentityError(f"open {path}: {error.strerror}") from None
    with handle:
        before = _snapshot(pid, proc, handle)
        if before["file"] != before["live"]:
            raise IdentityError(f"process {pid} changed while its executable was opened")
        digest = hashlib.sha256()
        try:
            for chunk in iter(lambda: handle.read(1 << 16), b""):
                digest.update(chunk)
        except OSError as error:
            raise IdentityError(f"hash {path}: {error.strerror}") from None
        after = _snapshot(pid, proc, handle)
    if after != before:
        raise IdentityError(f"process {pid} changed while its executable identity was collected")
    return {"pid": pid, "parent": before["parent"], "path": before["path"],
            "sha256": digest.hexdigest()}


def resolve(pid: int, root: int | None = None, proc: str = "/proc") -> list[dict]:
    """The chain from ``pid`` up to ``root`` (inclusive), every link hashed, or an error.

    Without ``root`` the walk stops below pid 1, which is init rather than workload ancestry.
    """
    chain = [link(pid, proc)]
    if root == pid:
        return chain
    parent = chain[0]["parent"]
    for _ in range(MAX_DEPTH):
        if parent == 0 or any(item["pid"] == parent for item in chain):
            break
        if parent == 1 and root != 1:
            break
        chain.append(link(parent, proc))
        if parent == root or parent == 1:
            break
        parent = chain[-1]["parent"]
    else:
        raise IdentityError(f"ancestry of {pid} deeper than {MAX_DEPTH}")
    return chain


def wait_stopped(pid: int, proc: str = "/proc", limit: float = STOP_WAIT) -> bool:
    """Wait until ``pid`` is stopped (``t`` or ``T``); ``False`` when it is gone or never stops."""
    deadline = time.monotonic() + limit
    while time.monotonic() < deadline:
        current = state(pid, proc)
        if current is None:
            return False
        if current in ("t", "T"):
            return True
        time.sleep(0.002)
    return False


def resume(pid: int) -> None:
    """Send one ``SIGCONT``: the process is in the group stop the trace announced, so one
    continue releases this exec's stop and cannot release a later one."""
    try:
        os.kill(pid, signal.SIGCONT)
    except ProcessLookupError:
        pass


def file_link(pid: int, path: str) -> dict:
    """The tracer's own first exec, hashed from the image file before any agent code ran."""
    real = os.path.realpath(path)
    try:
        with open(real, "rb") as handle:
            digest = hashlib.sha256(handle.read()).hexdigest()
    except OSError as error:
        raise IdentityError(f"open {real}: {error.strerror}") from None
    return {"pid": pid, "parent": 1, "path": real, "sha256": digest}


def answer(pid: int, succeeded: bool, root: int, proc: str = "/proc") -> dict:
    """Serve one exec: confirm its stop, resolve when it succeeded, then continue it."""
    if not wait_stopped(pid, proc):
        return {"pid": pid, "status": "failed", "reason": "process not held at its exec"}
    try:
        if not succeeded:
            return {"pid": pid, "status": "not_executed"}
        try:
            return {"pid": pid, "status": "complete", "chain": resolve(pid, root, proc)}
        except IdentityError as error:
            return {"pid": pid, "status": "failed", "reason": str(error)}
    finally:
        resume(pid)


def startup(pid: int, path: str, root: int, proc: str = "/proc") -> dict:
    """The tracer's start of its first program, which the tracer does not stop."""
    try:
        chain = [file_link(pid, path)] + resolve(root, root, proc)
    except IdentityError as error:
        return {"pid": pid, "status": "failed", "reason": str(error)}
    return {"pid": pid, "status": "complete", "basis": "startup_file", "chain": chain}


def serve(root: int, source=None, sink=None, proc: str = "/proc") -> int:
    """Answer each request line with one JSON line, until end of input.

    ``<pid> ok`` and ``<pid> fail`` serve a stopped exec that succeeded or failed;
    ``<pid> start <hex path>`` serves the tracer's first exec.
    """
    source = source or sys.stdin
    sink = sink or sys.stdout
    for line in source:
        parts = line.split()
        if len(parts) == 2 and parts[0].isdigit() and parts[1] in ("ok", "fail"):
            reply = answer(int(parts[0]), parts[1] == "ok", root, proc)
        elif len(parts) == 3 and parts[0].isdigit() and parts[1] == "start":
            try:
                path = bytes.fromhex(parts[2]).decode("utf-8", "surrogateescape")
            except ValueError:
                path = ""
            reply = startup(int(parts[0]), path, root, proc)
        else:
            reply = {"status": "failed", "reason": "malformed request"}
        sink.write(json.dumps(reply) + "\n")
        sink.flush()
    return 0


if __name__ == "__main__" and len(sys.argv) == 3 and sys.argv[1] == "serve":
    sys.exit(serve(int(sys.argv[2])))
