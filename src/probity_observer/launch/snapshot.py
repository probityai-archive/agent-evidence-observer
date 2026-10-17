"""The sealed start state of a workspace: a deterministic tarball and its reset.

The tarball is sealed before the agent starts and its SHA-256 goes into the
launch digest. Entries are sorted, and owner, group and modification time are
fixed, so the same tree always seals to the same bytes. ``reset`` checks the
digest before it touches the workspace, empties it, and restores the sealed
state with the ``data`` extraction filter, which refuses absolute paths, parent
references and links that leave the workspace.
"""

from __future__ import annotations

import hashlib
import io
import os
import shutil
import stat
import tarfile
from pathlib import Path


class SnapshotError(ValueError):
    """The sealed tarball does not match its digest or cannot be restored."""


def _entries(root: Path) -> list[Path]:
    found = []
    for directory, dirnames, filenames in os.walk(root, followlinks=False):
        base = Path(directory)
        dirnames.sort()
        for name in dirnames + sorted(filenames):
            found.append(base / name)
    return sorted(found, key=lambda path: path.relative_to(root).as_posix().encode("utf-8"))


def _info(root: Path, path: Path) -> tarfile.TarInfo:
    info = tarfile.TarInfo(path.relative_to(root).as_posix())
    status = os.lstat(path)
    info.mode = stat.S_IMODE(status.st_mode)
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    info.mtime = 0
    if stat.S_ISDIR(status.st_mode):
        info.type = tarfile.DIRTYPE
    elif stat.S_ISLNK(status.st_mode):
        info.type = tarfile.SYMTYPE
        info.linkname = os.readlink(path)
    elif stat.S_ISREG(status.st_mode):
        info.type = tarfile.REGTYPE
        info.size = status.st_size
    else:
        raise SnapshotError(f"cannot seal a special file: {info.name}")
    return info


def seal(workspace: Path, tarball: Path) -> str:
    """Write the workspace's start state to ``tarball`` and return its SHA-256."""
    workspace = Path(workspace)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for path in _entries(workspace):
            info = _info(workspace, path)
            if info.type == tarfile.REGTYPE:
                with open(path, "rb") as handle:
                    archive.addfile(info, handle)
            else:
                archive.addfile(info)
    data = buffer.getvalue()
    Path(tarball).write_bytes(data)
    return hashlib.sha256(data).hexdigest()


def reset(workspace: Path, tarball: Path, expected_sha256: str) -> None:
    """Restore the sealed start state after checking the tarball's digest."""
    data = Path(tarball).read_bytes()
    if hashlib.sha256(data).hexdigest() != expected_sha256:
        raise SnapshotError("sealed tarball does not match its digest")
    workspace = Path(workspace)
    for child in workspace.iterdir():
        if child.is_dir() and not child.is_symlink():
            shutil.rmtree(child)
        else:
            child.unlink()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r") as archive:
        try:
            archive.extractall(workspace, filter="data")
        except tarfile.FilterError as exc:
            raise SnapshotError(f"sealed tarball leaves the workspace: {exc}") from exc
