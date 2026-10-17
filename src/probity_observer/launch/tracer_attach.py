"""The tracer side of the OpenShell launch: attach ``strace`` to the agent from outside its sandbox.

OpenShell's seccomp filter refuses ``ptrace`` to every process in the sandbox, so the tracer
cannot run there. It runs in a separate container that shares only the sandbox's process
namespace, as root with ``CAP_SYS_PTRACE`` and ``CAP_KILL`` and no network. The agent's
command starts as a wrapper shell whose ``$0`` is a one-time marker; the wrapper spins on shell
builtins alone until ``/proc/self/status`` names a tracer, and only then execs the agent's
argv. So no agent instruction runs untraced, and the wrapper starts no process of its own.

This program finds the one wrapper process whose ``$0`` is the marker, runs ``strace`` with the
given flags against it with ``-p``, and writes one JSON line to stdout when the kernel reports
the tracer attached, and one when ``strace`` ends. ``SIGTERM`` (the launcher's timeout) kills
the traced process and every descendant with ``SIGKILL``, so the tracer then ends with its
tracees. It is run as ``python3 -I -c <this source> <marker> <wait seconds> <flag>...``, so the
tracer image needs ``python3`` and ``strace`` and nothing of this package.
"""

from __future__ import annotations

import json
import os
import signal
import sys
import time

POLL = 0.005


def _argv(pid: str, proc: str = "/proc") -> list[bytes]:
    with open(f"{proc}/{pid}/cmdline", "rb") as handle:
        return handle.read().split(b"\0")


def find(marker: bytes, wait: float, proc: str = "/proc") -> int | None:
    """The one ``sh -c <wrapper> <marker> ...`` process (``$0`` is the marker, so it is the
    fourth argument); ``None`` when none appears within ``wait``, or more than one does."""
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        found = []
        for name in os.listdir(proc):
            if not name.isdigit():
                continue
            try:
                argv = _argv(name, proc)
            except OSError:
                continue
            if len(argv) > 4 and argv[1] == b"-c" and argv[3] == marker:
                found.append(int(name))
        if len(found) == 1:
            return found[0]
        if len(found) > 1:
            return None
        time.sleep(POLL)
    return None


def tracer_of(pid: int) -> int | None:
    """``TracerPid`` of ``pid``, or ``None`` once it is gone."""
    try:
        with open(f"/proc/{pid}/status", encoding="ascii") as handle:
            for line in handle:
                if line.startswith("TracerPid:"):
                    return int(line.split()[1])
    except OSError:
        return None
    return None


def descendants(root: int, proc: str = "/proc") -> list[int]:
    """``root`` and every process below it, read from each process's parent pid."""
    parents: dict[int, int] = {}
    for name in os.listdir(proc):
        if not name.isdigit():
            continue
        try:
            with open(f"{proc}/{name}/stat", encoding="utf-8", errors="replace") as handle:
                parents[int(name)] = int(handle.read().rsplit(")", 1)[1].split()[1])
        except (OSError, IndexError, ValueError):
            continue
    tree, frontier = [root], [root]
    while frontier:
        current = frontier.pop()
        children = [pid for pid, parent in parents.items() if parent == current]
        tree.extend(children)
        frontier.extend(children)
    return tree


def say(**fields) -> None:
    sys.stdout.write(json.dumps(fields, sort_keys=True) + "\n")
    sys.stdout.flush()


def main(argv: list[str]) -> int:
    marker, wait, flags = argv[0].encode(), float(argv[1]), argv[2:]
    target = find(marker, wait)
    if target is None:
        say(status="not_found", marker=argv[0])
        return 2
    child = os.fork()
    if child == 0:
        os.execvp("strace", ["strace", *flags, "-p", str(target)])

    def stop(signum, frame) -> None:
        for pid in descendants(target):
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
        say(status="killed", pid=target)

    signal.signal(signal.SIGTERM, stop)
    while True:
        done, code = os.waitpid(child, os.WNOHANG)
        if done:
            say(status="tracer_ended_before_attach", pid=target, exit=os.waitstatus_to_exitcode(code))
            return 3
        if tracer_of(target) == child:
            say(status="attached", pid=target, tracer=child)
            break
        time.sleep(POLL)
    _, code = os.waitpid(child, 0)
    exit_code = os.waitstatus_to_exitcode(code)
    say(status="ended", pid=target, exit=exit_code)
    return 0 if exit_code == 0 else 4


if __name__ == "__main__" and len(sys.argv) >= 3:
    sys.exit(main(sys.argv[1:]))
