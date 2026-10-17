"""S2: ``strace -f`` as the agent's parent inside its container.

The tracer runs as the container's first process and the agent is its child,
so every process the agent starts is traced from its first instruction. The
trace expression names every member of the exec, open, create, rename, link,
unlink, truncate, chmod, mmap and connect families, never a subset: an
``openat``-only filter misses a raw ``open(2)``, which is how a static musl
binary such as busybox writes. The expression is recorded verbatim in the
receipt.

Strings are printed in hex (``-xx``) and descriptors with their paths
(``-y``), so the parser never guesses at quoting. Only successful calls are
printed (``-z``); a failed write changed nothing.

The parser turns the trace into ordered events: ``exec`` with argv and the
process's exit status, mutation events (``write``, ``create``, ``rename``,
``link``, ``unlink``, ``truncate``, ``chmod``) on paths, ``read`` and
``connect``. Each event inside a command's process tree carries ``origin``,
the event id of the exec at the root of that tree; see :func:`assign_origins`.
"""

from __future__ import annotations

import posixpath
import re
import signal
from dataclasses import dataclass, field
from typing import Iterable

EXEC = ("execve", "execveat")
OPEN = ("open", "openat", "openat2", "creat")
CREATE = ("mkdir", "mkdirat", "mknod", "mknodat", "symlink", "symlinkat")
RENAME = ("rename", "renameat", "renameat2")
LINK = ("link", "linkat")
UNLINK = ("unlink", "unlinkat", "rmdir")
TRUNCATE = ("truncate", "ftruncate")
CHMOD = ("chmod", "fchmod", "fchmodat", "fchmodat2", "chown", "fchown", "lchown", "fchownat",
         "utime", "utimes", "utimensat", "futimesat", "setxattr", "lsetxattr", "fsetxattr",
         "removexattr", "lremovexattr", "fremovexattr")
MMAP = ("mmap",)
CONNECT = ("connect",)
PROCESS = ("fork", "vfork", "clone", "clone3", "chdir", "fchdir")
ESCAPE = ("io_uring_setup", "ptrace", "process_vm_writev")
TRACED = EXEC + OPEN + CREATE + RENAME + LINK + UNLINK + TRUNCATE + CHMOD + MMAP + CONNECT + PROCESS + ESCAPE
TRACE_EXPRESSION = "trace=" + ",".join(TRACED)
FLAGS = ("-o", "/dev/stderr", "-f", "-q", "-y", "-ttt", "-xx", "-z", "-s", "65535", "-e", "signal=none",
         "-e", TRACE_EXPRESSION)
MUTATION_TYPES = ("write", "create", "rename", "link", "unlink", "truncate", "chmod")
VISIBLE_EVENT_TYPES = ("exec",) + MUTATION_TYPES + ("read", "connect")
WRITE_FLAGS = ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND")
SESSION_SHELLS = frozenset({"sh", "bash", "dash", "zsh", "ash", "ksh", "mksh", "busybox"})
ORIGIN_RULE = (
    "A command is a process the agent's root process started, or a process an interactive "
    "shell started (a shell run without -c, such as a persistent tool shell). An event's "
    "origin is the first exec of the command whose tree produced it; events of the agent's "
    "root process carry no origin.")

_LINE = re.compile(r"^(\d+) +(\d+\.\d+) (.*)$")
_EXITED = re.compile(r"^\+\+\+ exited with (-?\d+) \+\+\+$")
_KILLED = re.compile(r"^\+\+\+ killed by (SIG[A-Z0-9]+)(?: \(core dumped\))? \+\+\+$")
_RESUMED = re.compile(r"^<\.\.\. ([a-z0-9_]+) resumed>(.*)$")
_CALL = re.compile(r"^([a-z0-9_]+)\((.*)$")
_HEX = re.compile(r'"((?:\\x[0-9a-f]{2})*)"')
_FD_PATH = re.compile(r'^(?:-?\d+|AT_FDCWD)<((?:\\x[0-9a-f]{2})*)>')


def strace_argv(binary: str = "strace") -> list[str]:
    """The tracer command line, before ``--`` and the agent's own argv."""
    return [binary, *FLAGS]


class TraceError(ValueError):
    """The trace text does not have the shape this tracer configuration prints."""


class Unresolved(Exception):
    """A descriptor the tracer printed without its path; the effect's path is unknown."""


def decode_hex(text: str) -> str:
    """Decode a ``-xx`` string body (``\\x2f\\x61``) to text, keeping odd bytes."""
    if len(text) % 4:
        raise TraceError("malformed hex string")
    raw = bytes(int(text[index + 2:index + 4], 16) for index in range(0, len(text), 4))
    return raw.decode("utf-8", "surrogateescape")


def split_args(text: str) -> list[str]:
    """Split a syscall's argument text at top-level commas."""
    parts, depth, start, quoted = [], 0, 0, False
    for index, char in enumerate(text):
        if quoted:
            if char == '"':
                quoted = False
            continue
        if char == '"':
            quoted = True
        elif char in "([{<":
            depth += 1
        elif char in ")]}>":
            depth -= 1
        elif char == "," and depth == 0:
            parts.append(text[start:index].strip())
            start = index + 1
    tail = text[start:].strip()
    if tail:
        parts.append(tail)
    return parts


def string_arg(arg: str) -> str | None:
    match = _HEX.fullmatch(arg)
    return decode_hex(match.group(1)) if match else None


def fd_path(arg: str) -> str | None:
    """The path ``-y`` printed for a descriptor or ``AT_FDCWD`` argument."""
    match = _FD_PATH.match(arg)
    return decode_hex(match.group(1)) if match else None


def argv_arg(arg: str) -> list[str]:
    if not (arg.startswith("[") and arg.endswith("]")):
        raise TraceError("exec argv is not an array")
    return [decode_hex(item) for item in _HEX.findall(arg[1:-1])]


@dataclass(frozen=True)
class Call:
    """One completed system call: the line it completed on, and its pieces."""

    order: int
    pid: int
    time: float
    name: str
    args: list[str]
    result: str


@dataclass
class Trace:
    calls: list[Call] = field(default_factory=list)
    exits: dict[int, tuple[float, int]] = field(default_factory=dict)
    root_pid: int | None = None
    last_time: float | None = None
    unparsed: list[str] = field(default_factory=list)


def _split_result(text: str) -> tuple[str, str]:
    """Split ``args) = result`` at the last top-level ``) = ``."""
    depth, quoted = 0, False
    for index, char in enumerate(text):
        if quoted:
            if char == '"':
                quoted = False
            continue
        if char == '"':
            quoted = True
        elif char in "([{<":
            depth += 1
        elif char in "]}>":
            depth -= 1
        elif char == ")":
            if depth == 0:
                rest = text[index + 1:].lstrip()
                if not rest.startswith("="):
                    raise TraceError("syscall line without a result")
                return text[:index], rest[1:].strip()
            depth -= 1
    raise TraceError("unterminated syscall arguments")


def parse(text: str) -> Trace:
    """Parse ``strace -f -ttt -xx -y`` output into completed calls and exits."""
    trace = Trace()
    pending: dict[int, tuple[float, str, str]] = {}
    for number, line in enumerate(text.splitlines()):
        match = _LINE.match(line)
        if not match:
            if line.strip():
                trace.unparsed.append(line)
            continue
        pid, when, body = int(match.group(1)), float(match.group(2)), match.group(3)
        if trace.root_pid is None:
            trace.root_pid = pid
        trace.last_time = when
        if exited := _EXITED.match(body):
            trace.exits[pid] = (when, int(exited.group(1)))
            continue
        if killed := _KILLED.match(body):
            trace.exits[pid] = (when, 128 + int(signal.Signals[killed.group(1)]))
            continue
        if body.endswith(" <unfinished ...>"):
            call = _CALL.match(body[:-len(" <unfinished ...>")])
            if not call:
                raise TraceError(f"line {number + 1}: unfinished call without a name")
            pending[pid] = (when, call.group(1), call.group(2))
            continue
        if resumed := _RESUMED.match(body):
            name = resumed.group(1)
            if pid not in pending or pending[pid][1] != name:
                trace.unparsed.append(line)
                continue
            _, _, head = pending.pop(pid)
            body = f"{name}({head}{resumed.group(2)}"
        call = _CALL.match(body)
        if not call:
            trace.unparsed.append(line)
            continue
        args, result = _split_result(call.group(2))
        trace.calls.append(Call(number, pid, when, call.group(1), split_args(args), result))
    return trace


@dataclass
class Event:
    """One observed effect, before step numbering and record encoding."""

    kind: str
    pid: int
    time: float
    path: str | None = None
    target: str | None = None
    argv: list[str] | None = None
    exit: int | None = None
    address: str | None = None
    id: str = ""
    origin: str | None = None


@dataclass
class Effects:
    """Every event in record order, plus what the record format cannot carry."""

    events: list[Event] = field(default_factory=list)
    external: list[dict] = field(default_factory=list)
    escapes: list[dict] = field(default_factory=list)
    unresolved: list[dict] = field(default_factory=list)
    parents: dict[int, int] = field(default_factory=dict)
    root_pid: int | None = None
    root_exited: bool = False
    last_time: float | None = None


class _Resolver:
    """Track each process's working directory so relative paths resolve."""

    def __init__(self, cwd: str):
        self.start = cwd
        self.cwd: dict[int, str] = {}

    def of(self, pid: int) -> str:
        return self.cwd.get(pid, self.start)

    def path(self, pid: int, value: str | None, dirfd: str | None = None) -> str:
        """Resolve against ``dirfd``'s printed path, or the process's cwd for ``AT_FDCWD``."""
        if value is None:
            raise TraceError("path argument is not a string")
        if not value.startswith("/"):
            if dirfd is None or dirfd == "AT_FDCWD":
                base = self.of(pid)
            else:
                base = fd_path(dirfd)
                if base is None:
                    raise Unresolved(dirfd)
            value = posixpath.join(base, value)
        return posixpath.normpath(value)


def _ret_int(result: str) -> int | None:
    head = result.split(" ", 1)[0]
    head = head.split("<", 1)[0]
    try:
        return int(head, 0)
    except ValueError:
        return None


def _fd(arg: str) -> str:
    """The path of a descriptor argument, or :class:`Unresolved`."""
    path = fd_path(arg)
    if path is None:
        raise Unresolved(arg)
    return path


def _path_effect(name: str, args: list[str], result: str, pid: int,
                 resolve: _Resolver) -> tuple[str, dict] | None:
    """The kind and path fields of one file-system call, or ``None`` if it changed nothing."""
    if name in OPEN:
        opened = fd_path(result)
        if opened is None:
            if name in ("open", "creat"):
                opened = resolve.path(pid, string_arg(args[0]))
            else:
                opened = resolve.path(pid, string_arg(args[1]), args[0])
        flags = " ".join(args[1:]) if name in ("open", "creat") else " ".join(args[2:])
        if name == "creat" or any(flag in flags for flag in WRITE_FLAGS):
            return "write", {"path": opened}
        return None if "O_DIRECTORY" in flags else ("read", {"path": opened})
    if name in ("mkdir", "mknod", "unlink", "rmdir", "truncate"):
        kind = {"truncate": "truncate", "mkdir": "create", "mknod": "create"}.get(name, "unlink")
        return kind, {"path": resolve.path(pid, string_arg(args[0]))}
    if name in ("mkdirat", "mknodat", "unlinkat"):
        kind = "unlink" if name == "unlinkat" else "create"
        return kind, {"path": resolve.path(pid, string_arg(args[1]), args[0])}
    if name == "symlink":
        return "create", {"path": resolve.path(pid, string_arg(args[1]))}
    if name == "symlinkat":
        return "create", {"path": resolve.path(pid, string_arg(args[2]), args[1])}
    if name in ("rename", "link"):
        return name, {"path": resolve.path(pid, string_arg(args[0])),
                      "target": resolve.path(pid, string_arg(args[1]))}
    if name in RENAME or name in LINK:
        kind = "rename" if name in RENAME else "link"
        return kind, {"path": resolve.path(pid, string_arg(args[1]), args[0]),
                      "target": resolve.path(pid, string_arg(args[3]), args[2])}
    if name == "ftruncate":
        return "truncate", {"path": _fd(args[0])}
    if name in CHMOD:
        return "chmod", {"path": _metadata_path(name, args, pid, resolve)}
    if name in MMAP:
        if len(args) >= 5 and "PROT_WRITE" in args[2] and "MAP_SHARED" in args[3]:
            return "write", {"path": _fd(args[4])}
        return None
    raise TraceError(f"no effect rule for {name}")


def effects(trace: Trace, workdir: str) -> Effects:
    """Turn parsed calls into events, in the order the calls completed.

    A relative path whose directory descriptor was printed without its path
    cannot be placed; such a call goes to ``unresolved`` with its time, and the
    record names a coverage gap there rather than guessing a directory.
    """
    found = Effects(root_pid=trace.root_pid, last_time=trace.last_time)
    resolve = _Resolver(workdir)
    threads: dict[int, int] = {}

    def process(pid: int) -> int:
        return threads.get(pid, pid)

    for call in trace.calls:
        name, args, here = call.name, call.args, process(call.pid)
        if name in ("fork", "vfork", "clone", "clone3"):
            child = _ret_int(call.result)
            if child and child > 0:
                if "CLONE_THREAD" in ",".join(args):
                    threads[child] = here
                else:
                    found.parents[child] = here
                    resolve.cwd[child] = resolve.of(here)
            continue
        try:
            if name == "chdir":
                resolve.cwd[here] = resolve.path(here, string_arg(args[0]))
            elif name == "fchdir":
                resolve.cwd[here] = _fd(args[0])
            elif name in EXEC:
                argv = argv_arg(args[1] if name == "execve" else args[2])
                found.events.append(Event("exec", here, call.time, argv=argv))
            elif name in CONNECT:
                found.events.append(Event("connect", here, call.time,
                                          address=args[1] if len(args) > 1 else ""))
            elif name in ESCAPE:
                found.escapes.append({"syscall": name, "pid": here, "time": call.time})
            elif effect := _path_effect(name, args, call.result, here, resolve):
                kind, fields = effect
                found.events.append(Event(kind, here, call.time, **fields))
        except Unresolved:
            found.unresolved.append({"syscall": name, "pid": here, "time": call.time})
    _exits(found, trace, threads)
    return found


def _metadata_path(name: str, args: list[str], pid: int, resolve: _Resolver) -> str:
    if name in ("fchmod", "fchown", "fsetxattr", "fremovexattr"):
        return _fd(args[0])
    if name in ("fchmodat", "fchmodat2", "fchownat", "utimensat", "futimesat"):
        raw = string_arg(args[1])
        if raw is None:
            return _fd(args[0])
        return resolve.path(pid, raw, args[0])
    return resolve.path(pid, string_arg(args[0]))


def _exits(found: Effects, trace: Trace, threads: dict[int, int]) -> None:
    """Give each process's last exec the status the process exited with."""
    last_exec: dict[int, Event] = {}
    for event in found.events:
        if event.kind == "exec":
            last_exec[event.pid] = event
    for pid, (_, status) in trace.exits.items():
        owner = threads.get(pid, pid)
        if owner != pid:
            continue
        if owner in last_exec:
            last_exec[owner].exit = status
        if owner == trace.root_pid:
            found.root_exited = True


def _is_session_shell(argv: list[str]) -> bool:
    name = posixpath.basename(argv[0]) if argv else ""
    if name == "busybox" and len(argv) > 1:
        name = posixpath.basename(argv[1])
        argv = argv[1:]
    return name in SESSION_SHELLS and "-c" not in argv[1:]


def assign_origins(found: Effects) -> None:
    """Number events and set each one's ``origin`` from its process ancestry.

    The chain from the agent's root process down to an event's process is
    walked from the top. The first process below the root that executed a
    program is the command root, unless that program is an interactive shell,
    in which case the walk continues below it. The event's origin is that
    command root's first exec, when the exec came before the event.
    """
    first_exec: dict[int, Event] = {}
    for index, event in enumerate(found.events, start=1):
        event.id = f"e{index}"
        if event.kind == "exec" and event.pid not in first_exec:
            first_exec[event.pid] = event
    order = {id(event): index for index, event in enumerate(found.events)}
    for event in found.events:
        chain = [event.pid]
        while chain[-1] in found.parents and chain[-1] != found.root_pid:
            chain.append(found.parents[chain[-1]])
        chain.reverse()
        if chain[0] != found.root_pid:
            continue
        root_exec = None
        for pid in chain[1:]:
            started = first_exec.get(pid)
            if started is None:
                continue
            if started.argv and _is_session_shell(started.argv):
                continue
            root_exec = started
            break
        if root_exec is None or root_exec is event:
            continue
        if order[id(root_exec)] < order[id(event)]:
            event.origin = root_exec.id


def read(text: str, workdir: str) -> Effects:
    """Parse a trace and attribute every event to its command."""
    found = effects(parse(text), workdir)
    assign_origins(found)
    return found


def within(path: str, root: str) -> str | None:
    """The workspace-relative form of ``path``, or ``None`` outside ``root``."""
    root = root.rstrip("/")
    if path == root or not path.startswith(root + "/"):
        return None
    relative = path[len(root) + 1:]
    return relative or None


def iter_paths(events: Iterable[Event]) -> Iterable[str]:
    for event in events:
        if event.path:
            yield event.path
        if event.target:
            yield event.target
