"""Native code: compiled binaries the Python-level layers cannot see into, and their sources."""

from __future__ import annotations

from pathlib import Path

NATIVE_SUFFIXES = (".so", ".pyd", ".dll", ".dylib")
NATIVE_SOURCES = (".c", ".h", ".cc", ".cpp", ".pyx", ".pxd", ".rs")


def native(path: Path) -> bool:
    """A compiled binary: a ``.so``/``.pyd``/``.dll``/``.dylib`` name or an ELF file."""
    if path.name.endswith(NATIVE_SUFFIXES) or ".so." in path.name:
        return True
    with open(path, "rb") as handle:
        return handle.read(4) == b"\x7fELF"
