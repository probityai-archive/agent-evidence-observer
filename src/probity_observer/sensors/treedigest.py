"""S3: the final workspace tree, as a ``probity-tree/v1`` file map.

The digest is SHA-256 over the lines ``"<sha256>  <path>\\n"`` sorted by the
UTF-8 bytes of the path, which is what ``sha256sum`` prints for the listed
files. Only regular files are listed. Symbolic links and other non-regular
entries are returned separately so the receipt can name them; they are never
followed, because a link can point outside the workspace.
"""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

CHUNK = 1 << 20


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


def tree_digest(files: dict[str, str]) -> str:
    """SHA-256 over sorted ``"<sha256>  <path>\\n"`` lines, as sha256sum prints them."""
    lines = "".join(f"{files[name]}  {name}\n"
                    for name in sorted(files, key=lambda item: item.encode("utf-8")))
    return hashlib.sha256(lines.encode("utf-8")).hexdigest()


@dataclass
class Tree:
    """Regular files with their digests, plus the entries the map cannot carry."""

    files: dict[str, str] = field(default_factory=dict)
    symlinks: dict[str, str] = field(default_factory=dict)
    special: list[str] = field(default_factory=list)

    @property
    def sha256(self) -> str:
        return tree_digest(self.files)


def scan(root: Path) -> Tree:
    """Walk ``root`` without following links and hash every regular file."""
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
            elif stat.S_ISLNK(mode):
                tree.symlinks[relative] = os.readlink(entry)
            else:
                tree.special.append(relative)
    return tree
