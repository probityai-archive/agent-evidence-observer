"""Sealed pytest plugins and the argv that loads them from the verifier-only directory.

The plugins (:mod:`.probity_repeat`, :mod:`.probity_isolated_call`) are copied next to the
sealed pytest configuration, ``<heldout>/config/probity-plugins/``, which a graded command
reaches as ``../heldout/config/probity-plugins``. :func:`pytest_argv` turns a
``python -P -m pytest`` prefix into one that puts that directory first on the import path and
loads the plugins with ``-p``; the argv is part of the contract, so the plugins and their
options are sealed with it.

:func:`traced_argv` wraps any test-runner argv so that the run prints the working-tree Python
files it opened (the stability trace the zero-shot vacuous-pass gate reads).
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
READS_MARKER = "PROBITY-READS"
REPEATS = 2

BOOT = ("import sys; sys.path.insert(0, sys.argv.pop(1)); import pytest; "
        "raise SystemExit(pytest.main(sys.argv[1:]))")

TRACE = r"""
import atexit, os, runpy, sys
root = os.path.realpath(os.getcwd())
seen = set()
def hook(event, args):
    if event == "open" and args and isinstance(args[0], (str, bytes)):
        path = os.path.realpath(os.fsdecode(args[0]))
        if path.endswith(".py") and path.startswith(root + os.sep):
            seen.add(os.path.relpath(path, root))
sys.addaudithook(hook)
atexit.register(lambda: os.write(1, ("\nPROBITY-READS " + "\x00".join(sorted(seen)) + "\n").encode()))
module = sys.argv.pop(1)
if module == "--path":
    sys.path.insert(0, sys.argv.pop(1))
    module = sys.argv.pop(1)
sys.argv[0] = module
runpy.run_module(module, run_name="__main__", alter_sys=True)
"""


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


def traced_argv(argv: Sequence[str]) -> tuple[str, ...] | None:
    """The argv that runs ``argv`` (a test runner) and prints the Python files it opened.

    ``pytest ...``, ``python -m pytest|unittest ...`` and the sealed pytest form are
    supported; anything else is ``None``.
    """
    argv = list(argv)
    if not argv:
        return None
    if is_sealed_pytest(argv):
        index = argv.index(BOOT)
        return (argv[0], "-P", "-c", TRACE, "--path", argv[index + 1], "pytest",
                *argv[index + 2:])
    if Path(argv[0]).name == "pytest":
        return ("python", "-P", "-c", TRACE, "pytest", *argv[1:])
    if Path(argv[0]).name in ("python", "python3") and "-m" in argv:
        index = argv.index("-m")
        if index + 1 < len(argv) and argv[index + 1] in ("pytest", "unittest"):
            return (argv[0], "-P", "-c", TRACE, argv[index + 1], *argv[index + 2:])
    return None


def reads(printed: Sequence[str]) -> list[str] | None:
    """The working-tree Python files a traced run opened, or ``None`` when it printed none."""
    found = None
    for text in printed:
        for line in text.splitlines():
            if line.startswith(READS_MARKER):
                body = line[len(READS_MARKER):].strip()
                found = sorted(item for item in body.split("\x00") if item)
    return found


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
