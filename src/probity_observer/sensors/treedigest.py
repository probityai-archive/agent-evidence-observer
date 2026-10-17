"""S3: the final workspace tree, as a ``probity-tree/v2`` record.

Every entry other than a directory is listed and bound by the digest:
regular files with their SHA-256 (and whether any execute bit is set),
symbolic links with their raw target, and special files with their kind. A
symbolic link is never followed, because it can point outside the workspace,
but it is part of the tree a grader copies, so adding, removing or retargeting
one changes the digest.

The digest is SHA-256 over one line per entry, sorted by the UTF-8 bytes of
the path:

- ``<sha256>  <path>`` for a regular file with no execute bit, which is what
  ``sha256sum`` prints for it;
- ``x:<sha256>  <path>`` for a regular file with an execute bit;
- ``l:<sha256 of the target bytes>  <path>`` for a symbolic link;
- ``s:<kind>  <path>`` for a special file, ``kind`` one of ``fifo``,
  ``socket``, ``char`` or ``block``.

:func:`tree_digest` is the regular-files-only form ``sha256sum`` prints; it
digests a set of files, such as the protected subtree a done contract seals.
"""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

CHUNK = 1 << 20
EXECUTE = stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
SPECIAL_KINDS = ((stat.S_ISFIFO, "fifo"), (stat.S_ISSOCK, "socket"), (stat.S_ISCHR, "char"),
                 (stat.S_ISBLK, "block"))


def file_sha256(path: Path) -> str:
    """Hash one regular file without following a final symbolic link."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        digest = hashlib.sha256()
        while chunk := os.read(fd, CHUNK):
            digest.update(chunk)
        return digest.hexdigest()
    finally:
        os.close(fd)


def _sorted_lines(lines: dict[str, str]) -> bytes:
    ordered = sorted(lines, key=lambda name: name.encode("utf-8", "surrogateescape"))
    return "".join(f"{lines[name]}  {name}\n" for name in ordered).encode("utf-8",
                                                                          "surrogateescape")


def tree_digest(files: dict[str, str]) -> str:
    """SHA-256 over sorted ``"<sha256>  <path>\\n"`` lines, as sha256sum prints them."""
    return hashlib.sha256(_sorted_lines(files)).hexdigest()


def record_digest(fields: dict[str, Any]) -> str:
    """The ``probity-tree/v2`` digest of ``files``, ``executable``, ``symlinks``, ``special``."""
    executable = set(fields["executable"])
    lines = {name: ("x:" if name in executable else "") + digest
             for name, digest in fields["files"].items()}
    for name, target in fields["symlinks"].items():
        raw = target.encode("utf-8", "surrogateescape")
        lines[name] = "l:" + hashlib.sha256(raw).hexdigest()
    for name, kind in fields["special"].items():
        lines[name] = "s:" + kind
    return hashlib.sha256(_sorted_lines(lines)).hexdigest()


@dataclass
class Tree:
    """Every non-directory entry of a tree, by kind."""

    files: dict[str, str] = field(default_factory=dict)
    executable: list[str] = field(default_factory=list)
    symlinks: dict[str, str] = field(default_factory=dict)
    special: dict[str, str] = field(default_factory=dict)

    def record_fields(self) -> dict[str, Any]:
        return {"files": self.files, "executable": sorted(self.executable),
                "symlinks": self.symlinks, "special": self.special}

    @property
    def sha256(self) -> str:
        return record_digest(self.record_fields())


def _special_kind(mode: int) -> str:
    return next(kind for test, kind in SPECIAL_KINDS if test(mode))


def scan(root: Path) -> Tree:
    """Walk ``root`` without following links and list every non-directory entry."""
    tree = Tree()
    root = Path(root)
    for directory, dirnames, filenames in os.walk(root, followlinks=False):
        base = Path(directory)
        for name in sorted(dirnames):
            entry = base / name
            if entry.is_symlink():
                tree.symlinks[entry.relative_to(root).as_posix()] = os.readlink(entry)
        for name in sorted(filenames):
            entry = base / name
            relative = entry.relative_to(root).as_posix()
            mode = os.lstat(entry).st_mode
            if stat.S_ISREG(mode):
                tree.files[relative] = file_sha256(entry)
                if mode & EXECUTE:
                    tree.executable.append(relative)
            elif stat.S_ISLNK(mode):
                tree.symlinks[relative] = os.readlink(entry)
            else:
                tree.special[relative] = _special_kind(mode)
    tree.executable.sort()
    return tree
