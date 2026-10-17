"""The live exec gate: read each exec from the growing trace and resolve its identity.

The tracer stops every process at the exit of each ``execve``/``execveat`` and prints
``--- stopped by SIGSTOP ---`` once that stop has landed
(:data:`..sensors.binary_identity.TRACER_FLAGS`). This gate tails the trace file the
launcher writes and, on each such line that follows an exec of the same pid, sends one
request to the resolver running inside the container (``docker exec`` as container root,
outside the traced tree), which hashes the chain and sends the one ``SIGCONT`` that releases
that stop. A ``SIGSTOP`` the agent sends itself is not ``SI_KERNEL`` and is left alone. The
tracer does not stop its own first exec (the launcher's wrapper shell, before any agent code
runs); the gate asks the resolver to hash that program's image file instead
(``basis: startup_file``). A tracer that attaches to a running process instead
(the OpenShell launch) stops every exec it sees, the first included, so with
``startup_exec`` false every exec is gated alike. Answers are kept in request order. :func:`assign` then attaches each answer to the trace's exec event of the same pid and
order. An exec without a complete answer carries ``identity.status`` ``failed``, which the
observation records as a coverage gap: the identity fails closed, never open.
"""

from __future__ import annotations

import json
import re
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Sequence

from ..sensors import binary_identity

ROOT_PID = 1
START_WAIT = 30.0
ATTEMPT_WAIT = 30.0
_EXEC_DONE = re.compile(r"^(\d+) +\d+\.\d+ (?:<\.\.\. )?(execve|execveat)(?:\(| resumed>).*\) += (-?\d+)")
_EXEC_PATH = re.compile(r'^\d+ +\d+\.\d+ execve\("((?:\\x[0-9a-f]{2})*)"')
_KERNEL_STOP = re.compile(r"^(\d+) +\d+\.\d+ --- SIGSTOP \{si_signo=SIGSTOP, si_code=SI_KERNEL\} ---$")
_STOPPED = re.compile(r"^(\d+) +\d+\.\d+ --- stopped by SIGSTOP ---$")


def resolver_argv(docker: str, name: str) -> list[str]:
    """The ``docker exec`` that runs the resolver inside the container."""
    source = Path(binary_identity.__file__).read_text(encoding="utf-8")
    return [docker, "exec", "-i", "--user", "0:0", "--workdir", "/", name,
            "python3", "-I", "-c", source, "serve", str(ROOT_PID)]


def exec_results(line: str) -> tuple[int, bool] | None:
    """``(pid, succeeded)`` for a trace line that ends an exec, else ``None``."""
    found = _EXEC_DONE.match(line)
    if found is None or line.rstrip().endswith("<unfinished ...>"):
        return None
    return int(found.group(1)), found.group(3) == "0"


class Gate:
    """Tail ``trace_path`` and serve every exec through one resolver process."""

    def __init__(self, trace_path: Path, argv: Sequence[str], startup_exec: bool = True) -> None:
        """``startup_exec`` False: the tracer attached to a running process (``strace -p``),
        so the first traced exec is stopped like every other and is gated as one."""
        self.trace_path = trace_path
        self.argv = list(argv)
        self.requests: list[tuple[int, str]] = []
        self._pending: dict[int, bool] = {}
        self._kernel: set[int] = set()
        self._started = not startup_exec
        self.answers: list[dict[str, Any]] = []
        self.errors: list[str] = []
        self._stop = threading.Event()
        self._process: subprocess.Popen[str] | None = None
        self._tail = threading.Thread(target=self._run, daemon=True)
        self._reader: threading.Thread | None = None

    def start(self) -> None:
        self._tail.start()

    def _open(self) -> bool:
        """Start the resolver; it counts as started only when its :data:`READY` line arrives.

        A process still alive after some delay proves nothing (a loaded host can take longer
        than any delay to fail), so each attempt waits for the ready line or for the process
        to end. Attempts repeat until :data:`START_WAIT` has passed (the container may not
        exist yet), and the first attempt always runs to its end. An attempt that neither
        answers nor ends is abandoned after :data:`ATTEMPT_WAIT`.
        """
        deadline = time.monotonic() + START_WAIT
        first = True
        while first or (not self._stop.is_set() and time.monotonic() < deadline):
            first = False
            process = subprocess.Popen(self.argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, text=True, bufsize=1)
            ready, closed = threading.Event(), threading.Event()
            reader = threading.Thread(target=self._read, args=(process, ready, closed),
                                      daemon=True)
            reader.start()
            give_up = max(deadline, time.monotonic() + ATTEMPT_WAIT)
            while not ready.is_set() and not closed.is_set() and time.monotonic() < give_up:
                ready.wait(0.02)
            if ready.is_set():
                self._process, self._reader = process, reader
                return True
            if process.poll() is None:
                process.kill()
            process.wait()
            reader.join(timeout=5)
            message = (process.stderr.read() if process.stderr else "").strip()
            self.errors.append(message.splitlines()[-1] if message
                               else "resolver ended without its ready line")
            time.sleep(0.2)
        return False

    def _read(self, process: subprocess.Popen[str], ready: threading.Event,
              closed: threading.Event) -> None:
        assert process.stdout is not None
        for line in process.stdout:
            if not ready.is_set():
                try:
                    announced = json.loads(line) == binary_identity.READY
                except json.JSONDecodeError:
                    announced = False
                if announced:
                    ready.set()
                    continue
                self.errors.append("resolver wrote before its ready line")
                break
            try:
                self.answers.append(json.loads(line))
            except json.JSONDecodeError:
                self.answers.append({"status": "failed", "reason": "unreadable resolver answer"})
        closed.set()

    def _send(self, pid: int, kind: str, extra: str = "") -> None:
        self.requests.append((pid, kind))
        process = self._process
        if process is None or process.stdin is None or process.poll() is not None:
            return
        try:
            process.stdin.write(f"{pid} {kind}{' ' + extra if extra else ''}\n")
            process.stdin.flush()
        except (BrokenPipeError, OSError):
            self.errors.append("resolver input closed")

    def feed(self, line: str) -> None:
        """Act on one complete trace line."""
        if (found := exec_results(line)) is not None:
            pid, succeeded = found
            if not self._started:
                self._started = True
                path = _EXEC_PATH.match(line)
                hexed = path.group(1).replace("\\x", "") if path else ""
                self._send(pid, "start", hexed or "00")
            else:
                self._pending[pid] = succeeded
        elif (stop := _KERNEL_STOP.match(line)) is not None:
            self._kernel.add(int(stop.group(1)))
        elif (stop := _STOPPED.match(line)) is not None:
            pid = int(stop.group(1))
            if pid in self._kernel and pid in self._pending:
                self._kernel.discard(pid)
                self._send(pid, "ok" if self._pending.pop(pid) else "fail")

    def _run(self) -> None:
        opened = self._open()
        if not opened:
            self.errors.append("resolver did not start")
        offset, pending = 0, ""
        while True:
            finished = self._stop.is_set()
            try:
                with open(self.trace_path, "rb") as handle:
                    handle.seek(offset)
                    chunk = handle.read()
            except FileNotFoundError:
                chunk = b""
            offset += len(chunk)
            pending += chunk.decode("utf-8", "surrogateescape")
            *lines, pending = pending.split("\n")
            for line in lines:
                self.feed(line)
            if finished:
                break
            time.sleep(0.005)

    def stop(self, timeout: float = 30.0) -> None:
        """Stop tailing, let the resolver drain, and close it."""
        self._stop.set()
        self._tail.join(timeout=timeout)
        deadline = time.monotonic() + timeout
        while (self._process is not None and self._process.poll() is None
               and len(self.answers) < len(self.requests) and time.monotonic() < deadline):
            time.sleep(0.02)
        if self._process is not None:
            if self._process.stdin is not None:
                try:
                    self._process.stdin.close()
                except OSError:
                    pass
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait()
        if self._reader is not None:
            self._reader.join(timeout=5)

    def results(self) -> list[tuple[int, bool, dict[str, Any]]]:
        """Each request with its answer; a request the resolver never answered failed."""
        out = []
        for index, (pid, kind) in enumerate(self.requests):
            answer = self.answers[index] if index < len(self.answers) else {
                "pid": pid, "status": "failed", "reason": "resolver gave no answer"}
            out.append((pid, kind != "fail", answer))
        return out

    def summary(self) -> dict[str, Any]:
        statuses = [answer.get("status") for _, _, answer in self.results()]
        return {"requests": len(self.requests), "answers": len(self.answers),
                "complete": statuses.count("complete"), "failed": statuses.count("failed"),
                "not_executed": statuses.count("not_executed"), "errors": self.errors,
                "tracer_flags": list(binary_identity.TRACER_FLAGS)}


def identity_record(answer: dict[str, Any]) -> dict[str, Any]:
    """The ``identity`` member an exec event carries."""
    if answer.get("status") == "complete":
        record = {"status": "complete",
                  "chain": [{"pid": item["pid"], "path": item["path"], "sha256": item["sha256"]}
                            for item in answer["chain"]]}
        if "basis" in answer:
            record["basis"] = answer["basis"]
        return record
    return {"status": "failed", "reason": answer.get("reason", "identity not resolved")}


def assign(events: Sequence[Any], results: list[tuple[int, bool, dict[str, Any]]]) -> int:
    """Attach identities to the trace's exec events by pid and order; return how many failed."""
    queues: dict[int, list[dict[str, Any]]] = {}
    for pid, succeeded, answer in results:
        if succeeded:
            queues.setdefault(pid, []).append(answer)
    failed = 0
    for event in events:
        if event.kind != "exec":
            continue
        queue = queues.get(event.pid, [])
        answer = queue.pop(0) if queue else {"status": "failed",
                                             "reason": "exec not seen by the gate"}
        event.identity = identity_record(answer)
        failed += event.identity["status"] != "complete"
    return failed
