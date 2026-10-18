"""Sealed pytest plugins and the argv that loads them from the verifier-only directory.

The plugins (:mod:`.probity_repeat`, :mod:`.probity_isolated_call`) are copied next to the
sealed pytest configuration, ``<heldout>/config/probity-plugins/``, which a graded command
reaches as ``../heldout/config/probity-plugins``. :func:`pytest_argv` turns a
``python -P -m pytest`` prefix into one that puts that directory first on the import path and
loads the plugins with ``-p``; the argv is part of the contract, so the plugins and their
options are sealed with it.

:func:`traced_argv` wraps any test-runner argv so that the run prints the working-tree Python
files it loaded: opened as source, imported (``sys.modules`` at exit), loaded with ``ctypes``
or executed, and optionally the lines that ran (the stability trace the zero-shot gates read).
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
PLUGINS = ("probity_repeat.py", "probity_isolated_call.py", "probity_outcome.py")
OUTCOME_MARKER = "PROBITY-OUTCOME"
MARKER = "PROBITY-WORKER-REPORT"
TRACE_MARKER = "PROBITY-TRACE"
REPEATS = 2

BOOT = ("import sys; sys.path.insert(0, sys.argv.pop(1)); import pytest; "
        "raise SystemExit(pytest.main(sys.argv[1:]))")

TRACE = r"""
import atexit, json, os, runpy, shutil, sys
root = os.path.realpath(os.getcwd())
NATIVE = (".so", ".pyd", ".dll", ".dylib")
seen, native, executed, modules, lines = set(), set(), set(), {}, {}
def under(name, base=None):
    path = os.path.realpath(os.path.join(base or os.getcwd(), os.fsdecode(name)))
    return os.path.relpath(path, root) if path.startswith(root + os.sep) else None
def program(name, cwd=None):
    name = os.fsdecode(name)
    if os.sep not in name:
        name = shutil.which(name) or name
    return under(name, cwd and os.fsdecode(cwd))
def hook(event, args):
    try:
        if event == "open" and args and isinstance(args[0], (str, bytes)):
            found = under(args[0])
            if found and found.endswith(".py"):
                seen.add(found)
        elif event == "ctypes.dlopen" and args and isinstance(args[0], (str, bytes)):
            found = under(args[0])
            if found and os.path.isfile(os.path.join(root, found)):
                native.add(found)
        elif event in ("os.exec", "os.posix_spawn") and args:
            found = program(args[0])
            if found:
                executed.add(found)
        elif event == "subprocess.Popen" and args:
            name = args[0] or (args[1][0] if args[1] else None)
            if isinstance(args[1], (str, bytes)) and not args[0]:
                name = os.fsdecode(args[1]).split()[0] if args[1] else None
            found = program(name, args[2]) if name else None
            if found:
                executed.add(found)
    except (TypeError, ValueError, IndexError, OSError):
        pass
sys.addaudithook(hook)
def finish():
    for name, module in list(sys.modules.items()):
        origin = getattr(module, "__file__", None)
        found = under(origin) if isinstance(origin, str) else None
        if found:
            modules[name] = found
            if found.endswith(NATIVE) or ".so." in found:
                native.add(found)
    body = {"reads": sorted(seen | set(modules.values()) | native | executed),
            "modules": modules, "native": sorted(native), "executed": sorted(executed),
            "lines": {name: sorted(numbers) for name, numbers in lines.items()}}
    os.write(1, ("\nPROBITY-TRACE " + json.dumps(body, sort_keys=True) + "\n").encode())
atexit.register(finish)
module = sys.argv.pop(1)
if module == "--lines":
    wanted = {os.path.join(root, name) for name in sys.argv.pop(1).split(":") if name}
    def local(frame, event, arg):
        if event == "line":
            lines.setdefault(os.path.relpath(frame.f_code.co_filename, root), set()).add(frame.f_lineno)
        return local
    def tracer(frame, event, arg):
        if os.path.realpath(frame.f_code.co_filename) in wanted:
            if event == "call":
                lines.setdefault(os.path.relpath(frame.f_code.co_filename, root), set()).add(frame.f_lineno)
            return local
        return None
    import threading
    sys.settrace(tracer)
    threading.settrace(tracer)
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


def traced_argv(argv: Sequence[str], lines: Sequence[str] = ()) -> tuple[str, ...] | None:
    """The argv that runs ``argv`` (a test runner) under the trace and prints what it loaded.

    ``pytest ...``, ``python -m pytest|unittest ...`` and the sealed pytest form are
    supported; anything else is ``None``. The run writes no bytecode (``-B``). With ``lines``
    (working-tree paths) it also records which lines of those files ran.
    """
    argv = list(argv)
    if not argv:
        return None
    head = ("--lines", ":".join(lines)) if lines else ()
    if is_sealed_pytest(argv):
        index = argv.index(BOOT)
        return (argv[0], "-B", "-P", "-c", TRACE, *head, "--path", argv[index + 1], "pytest",
                *argv[index + 2:])
    if Path(argv[0]).name == "pytest":
        return ("python", "-B", "-P", "-c", TRACE, *head, "pytest", *argv[1:])
    if Path(argv[0]).name in ("python", "python3") and "-m" in argv:
        index = argv.index("-m")
        if index + 1 < len(argv) and argv[index + 1] in ("pytest", "unittest"):
            return (argv[0], "-B", "-P", "-c", TRACE, *head, argv[index + 1], *argv[index + 2:])
    return None


def trace(printed: Sequence[str]) -> dict[str, Any] | None:
    """What a traced run loaded, or ``None`` when it printed no trace.

    ``reads``: every working-tree file it opened as Python source, imported (``.py``,
    ``.pyc``, native), loaded with ``ctypes`` or executed; ``modules``: module name to file;
    ``native``: the native binaries among them; ``executed``; ``lines``: per traced file, the
    lines that ran.
    """
    found = None
    for text in printed:
        for line in text.splitlines():
            if line.startswith(TRACE_MARKER + " "):
                found = json.loads(line[len(TRACE_MARKER) + 1:])
    return found


def reads(printed: Sequence[str]) -> list[str] | None:
    """The working-tree files a traced run loaded, or ``None`` when it printed no trace."""
    found = trace(printed)
    return None if found is None else list(found["reads"])


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
    """How many sealed ids the run collected: an id, a parametrised ``id[...]`` of it, or,
    for an id that names a test file or class, a test inside it (``id::...``)."""
    return sum(1 for test_id in sealed_ids
               if any(name == test_id or name.startswith((test_id + "[", test_id + "::"))
                      for name in item_ids))


def outcomes(printed: Sequence[str]) -> dict[str, dict[str, Any]]:
    """Per node id from ``probity_outcome`` lines: whether every report passed, and the
    seconds its calls took."""
    found: dict[str, dict[str, Any]] = {}
    for text in printed:
        for line in text.splitlines():
            if not line.startswith(OUTCOME_MARKER + " "):
                continue
            _, outcome, seconds, node = line.split(" ", 3)
            entry = found.setdefault(node, {"passed": True, "seconds": 0.0})
            entry["passed"] = entry["passed"] and outcome == "passed"
            entry["seconds"] += float(seconds)
    return found
