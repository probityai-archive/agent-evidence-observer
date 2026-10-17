"""S1: host inotify on the bind-mounted workspace.

The watcher runs in the launcher's process on the host, outside the agent's
container, and watches every directory of the workspace. A directory created
during the run gets a watch as soon as its ``IN_CREATE`` arrives, and the new
directory is then scanned, because entries made before the watch existed (the
``mkdir -p a/b/c && touch a/b/c/f`` race) produce no event of their own; each
entry the scan finds is recorded as a ``create`` with ``scanned: true``.

``IN_Q_OVERFLOW`` means the kernel dropped events while the queue was full.
The queue was empty when the previous read drained it and has room again
after the read that returned the overflow, so the loss lies between those two
reads; the report keeps that window (``overflows``), and the observation names
it as a gap. A watch that cannot be added (the per-user watch limit) leaves
part of the tree unwatched for the rest of the run, which marks the reader
``lost``; the observation built from it then has ``coverage: unknown``.

The watch list is recorded with the time each watch was added, and goes into
the receipt.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import errno
import os
import select
import struct
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

IN_MODIFY = 0x00000002
IN_ATTRIB = 0x00000004
IN_CLOSE_WRITE = 0x00000008
IN_MOVED_FROM = 0x00000040
IN_MOVED_TO = 0x00000080
IN_CREATE = 0x00000100
IN_DELETE = 0x00000200
IN_DELETE_SELF = 0x00000400
IN_MOVE_SELF = 0x00000800
IN_Q_OVERFLOW = 0x00004000
IN_IGNORED = 0x00008000
IN_ONLYDIR = 0x01000000
IN_DONT_FOLLOW = 0x02000000
IN_EXCL_UNLINK = 0x04000000
IN_ISDIR = 0x40000000
IN_NONBLOCK = 0o4000
IN_CLOEXEC = 0o2000000

MASK = (IN_MODIFY | IN_ATTRIB | IN_CLOSE_WRITE | IN_MOVED_FROM | IN_MOVED_TO | IN_CREATE
        | IN_DELETE | IN_DELETE_SELF | IN_MOVE_SELF)
WATCH_FLAGS = IN_ONLYDIR | IN_DONT_FOLLOW
KINDS = (
    (IN_CREATE, "create"),
    (IN_MOVED_FROM, "rename"),
    (IN_MOVED_TO, "rename"),
    (IN_DELETE, "unlink"),
    (IN_CLOSE_WRITE, "write"),
    (IN_MODIFY, "write"),
    (IN_ATTRIB, "chmod"),
)
_HEADER = struct.Struct("iIII")
READ_SIZE = 65536


def mask_names(mask: int) -> list[str]:
    names = {IN_MODIFY: "IN_MODIFY", IN_ATTRIB: "IN_ATTRIB", IN_CLOSE_WRITE: "IN_CLOSE_WRITE",
             IN_MOVED_FROM: "IN_MOVED_FROM", IN_MOVED_TO: "IN_MOVED_TO", IN_CREATE: "IN_CREATE",
             IN_DELETE: "IN_DELETE", IN_DELETE_SELF: "IN_DELETE_SELF",
             IN_MOVE_SELF: "IN_MOVE_SELF"}
    return [name for bit, name in sorted(names.items()) if mask & bit]


@dataclass(frozen=True)
class Change:
    """One host-side change under the workspace."""

    time: float
    kind: str
    path: str
    mask: int
    cookie: int = 0
    scanned: bool = False


@dataclass
class Report:
    changes: list[Change] = field(default_factory=list)
    watches: list[dict] = field(default_factory=list)
    overflow: bool = False
    overflows: list[dict] = field(default_factory=list)
    watch_failures: list[dict] = field(default_factory=list)

    @property
    def lost(self) -> bool:
        return bool(self.watch_failures)


def _libc():
    library = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
    library.inotify_init1.argtypes = [ctypes.c_int]
    library.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
    return library


def decode(buffer: bytes, directories: dict[int, str], now: float) -> list[tuple]:
    """Split a read from the inotify descriptor into ``(wd, mask, cookie, path)`` tuples."""
    found, offset = [], 0
    while offset + _HEADER.size <= len(buffer):
        wd, mask, cookie, length = _HEADER.unpack_from(buffer, offset)
        offset += _HEADER.size
        raw = buffer[offset:offset + length].split(b"\0", 1)[0]
        offset += length
        name = os.fsdecode(raw)
        base = directories.get(wd)
        if base is None:
            path = None
        else:
            path = f"{base}/{name}" if base and name else (name or base)
        found.append((wd, mask, cookie, path))
    return found


class Watcher:
    """Recursive inotify watcher over one directory tree."""

    def __init__(self, root: Path):
        self.root = Path(root)
        self.report = Report()
        self._libc = _libc()
        self._fd = -1
        self._wds: dict[int, str] = {}
        self._stop_read, self._stop_write = os.pipe()
        self._thread: threading.Thread | None = None
        self._empty_at = time.time()

    def start(self) -> None:
        self._fd = self._libc.inotify_init1(IN_NONBLOCK | IN_CLOEXEC)
        if self._fd < 0:
            raise OSError(ctypes.get_errno(), "inotify_init1 failed")
        self._watch_tree("", scan=False)
        self._empty_at = time.time()
        self._thread = threading.Thread(target=self._loop, name="inotify-reader", daemon=True)
        self._thread.start()

    def stop(self, settle: float = 0.2) -> Report:
        """Drain pending events, then stop reading."""
        time.sleep(settle)
        os.write(self._stop_write, b"x")
        if self._thread is not None:
            self._thread.join()
        self._drain()
        os.close(self._fd)
        os.close(self._stop_read)
        os.close(self._stop_write)
        return self.report

    def _watch(self, relative: str) -> bool:
        target = self.root / relative if relative else self.root
        wd = self._libc.inotify_add_watch(self._fd, os.fsencode(target), MASK | WATCH_FLAGS)
        if wd < 0:
            code = ctypes.get_errno()
            if code in (errno.ENOENT, errno.ENOTDIR):
                return False
            self.report.watch_failures.append({"path": relative, "errno": errno.errorcode.get(
                code, str(code)), "time": time.time()})
            return False
        self._wds[wd] = relative
        self.report.watches.append({"path": relative, "added": time.time()})
        return True

    def _watch_tree(self, relative: str, scan: bool) -> None:
        if not self._watch(relative):
            return
        base = self.root / relative if relative else self.root
        try:
            entries = sorted(os.scandir(base), key=lambda entry: entry.name)
        except FileNotFoundError:
            return
        for entry in entries:
            child = f"{relative}/{entry.name}" if relative else entry.name
            if scan:
                self.report.changes.append(Change(time.time(), "create", child, IN_CREATE,
                                                  scanned=True))
            if entry.is_dir(follow_symlinks=False):
                self._watch_tree(child, scan)

    def _loop(self) -> None:
        while True:
            ready, _, _ = select.select([self._fd, self._stop_read], [], [])
            if self._stop_read in ready:
                return
            self._drain()

    def _drain(self) -> None:
        while True:
            try:
                buffer = os.read(self._fd, READ_SIZE)
            except BlockingIOError:
                return
            if not buffer:
                return
            self.handle(buffer, time.time())

    def handle(self, buffer: bytes, now: float) -> None:
        """Record every change in one read of the descriptor.

        A read shorter than :data:`READ_SIZE` emptied the queue, so it is the
        latest time the queue is known to have been empty: an overflow found
        in a later read lost its events after that time and before the read.
        """
        empty_since = self._empty_at
        if len(buffer) < READ_SIZE:
            self._empty_at = now
        for wd, mask, cookie, path in decode(buffer, self._wds, now):
            if mask & IN_Q_OVERFLOW:
                self.report.overflow = True
                self.report.overflows.append({"from": empty_since, "to": now})
                continue
            if mask & IN_IGNORED:
                self._wds.pop(wd, None)
                continue
            if path is None or mask & (IN_DELETE_SELF | IN_MOVE_SELF):
                continue
            for bit, kind in KINDS:
                if mask & bit:
                    self.report.changes.append(Change(now, kind, path, mask, cookie))
                    break
            if mask & IN_ISDIR and mask & (IN_CREATE | IN_MOVED_TO):
                self._watch_tree(path, scan=True)
