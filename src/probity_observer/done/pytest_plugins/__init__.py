"""Sealed pytest plugins and the argv that loads them from the verifier-only directory.

The plugins (:mod:`.probity_repeat`, :mod:`.probity_isolated_call`) are copied next to the
sealed pytest configuration, ``<heldout>/config/probity-plugins/``, which a graded command
reaches as ``../heldout/config/probity-plugins``. :func:`pytest_argv` turns a
``python -P -m pytest`` prefix into one that puts that directory first on the import path and
loads the plugins with ``-p``; the argv is part of the contract, so the plugins and their
options are sealed with it.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from importlib import resources
from pathlib import Path
from typing import Any, Sequence

DIRECTORY = "probity-plugins"
SEALED = f"../heldout/config/{DIRECTORY}"
PLUGINS = ("probity_repeat.py", "probity_isolated_call.py")
MARKER = "PROBITY-WORKER-REPORT"
REPEATS = 2

BOOT = ("import sys; sys.path.insert(0, sys.argv.pop(1)); import pytest; "
        "raise SystemExit(pytest.main(sys.argv[1:]))")

def install(config_dir: Path) -> None:
    """Copy the plugins into ``<config_dir>/probity-plugins``."""
    target = config_dir / DIRECTORY
    target.mkdir(parents=True, exist_ok=True)
    package = resources.files(__package__)
    for name in PLUGINS:
        (target / name).write_bytes(package.joinpath(name).read_bytes())


def is_python_pytest(prefix: Sequence[str]) -> bool:
    """``python[3] [-P|-I ...] -m pytest ...``: a prefix :func:`pytest_argv` can rewrite."""
    if not prefix or Path(prefix[0]).name not in ("python", "python3"):
        return False
    rest = list(prefix[1:])
    while rest and rest[0] in ("-P", "-I", "-B", "-E", "-s"):
        rest.pop(0)
    return rest[:2] == ["-m", "pytest"]


def pytest_argv(prefix: Sequence[str], protected: Sequence[str] = (),
                isolate: Sequence[str] = (), repeats: int = REPEATS) -> tuple[str, ...]:
    """The sealed form of a ``python -m pytest`` prefix, with the plugins loaded."""
    if not is_python_pytest(prefix):
        raise ValueError(f"not a python -m pytest prefix: {list(prefix)!r}")
    flags = [item for item in prefix[1:prefix.index("-m")] if item != "-P"]
    argv = [prefix[0], "-P", *flags, "-c", BOOT, SEALED, *prefix[prefix.index("-m") + 2:],
            "-p", "probity_repeat", "--probity-repeats", str(repeats)]
    for name in protected:
        argv += ["--probity-protected", name]
    if isolate:
        argv += ["-p", "probity_isolated_call"]
        for target in isolate:
            argv += ["--probity-isolate", target]
    return tuple(argv)


def is_sealed_pytest(argv: Sequence[str]) -> bool:
    return BOOT in argv and "probity_repeat" in argv


def report(printed: Sequence[str], key: bytes) -> dict[str, Any] | None:
    """The last worker report line whose HMAC verifies under ``key``, or ``None``."""
    found = None
    for text in printed:
        for line in text.splitlines():
            if not line.startswith(MARKER + " "):
                continue
            _, mac, data = line.split(" ", 2)
            expected = hmac.new(key, data.encode(), hashlib.sha256).hexdigest()
            if hmac.compare_digest(mac, expected):
                found = json.loads(data)
    return found


def collected(item_ids: Sequence[str], sealed_ids: Sequence[str]) -> int:
    """How many sealed ids the run collected: an id, or a parametrised ``id[...]`` of it."""
    return sum(1 for test_id in sealed_ids
               if any(name == test_id or name.startswith(test_id + "[") for name in item_ids))
