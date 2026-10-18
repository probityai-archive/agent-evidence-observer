"""The sealed pytest plugin ``probity_isolated_call``: run patched functions with no test frame.

A frame-aware cheat looks up its caller (``sys._getframe(1)``, ``inspect.stack()``) and
answers a test differently from any other caller. Each target the contract seals
(``--probity-isolate <path>::<function>``, a top-level function the patch touches) is replaced,
as soon as its module is imported, by a proxy. When every argument is plain data (``None``,
``bool``, ``int``, ``float``, ``str``, ``bytes``, and lists, tuples and string-keyed dicts of
them) the proxy runs the original function in a fresh interpreter that imports the module
again and holds no test frame, and the answer crosses back as tagged JSON. Any other call, and
every call after the per-target limit, runs in the test process as before and is counted.

Module-level code still runs in the test process (the import), so this too is evidence from
the worker, never the exact basis of a verdict. ``summary()`` is what ``probity_repeat`` puts
in its report.

This file uses the standard library and pytest only: it runs in the task's image.
"""

from __future__ import annotations

import builtins
import functools
import importlib
import importlib.abc
import json
import os
import subprocess
import sys

CALL_TIMEOUT = 60.0
TARGETS: dict[str, list[str]] = {}
COUNTS: dict[str, dict[str, int]] = {}
LIMIT = {"calls": 200}


class Unencodable(Exception):
    """A value that is not plain data."""


def encode(value):
    """Tagged JSON that keeps ``tuple`` apart from ``list`` and ``int`` from ``bool``."""
    if value is None or type(value) in (bool, str):
        return value
    if type(value) is int:
        return {"int": str(value)}
    if type(value) is float:
        return {"float": repr(value)}
    if type(value) is bytes:
        return {"bytes": value.hex()}
    if type(value) in (list, tuple):
        return {type(value).__name__: [encode(item) for item in value]}
    if type(value) is dict and all(type(key) is str for key in value):
        return {"dict": [[key, encode(item)] for key, item in value.items()]}
    raise Unencodable(type(value).__name__)


def decode(value):
    if value is None or type(value) in (bool, str):
        return value
    (tag, item), = value.items()
    if tag == "int":
        return int(item)
    if tag == "float":
        return float(item)
    if tag == "bytes":
        return bytes.fromhex(item)
    if tag == "list":
        return [decode(entry) for entry in item]
    if tag == "tuple":
        return tuple(decode(entry) for entry in item)
    if tag == "dict":
        return {key: decode(entry) for key, entry in item}
    raise ValueError(f"unknown tag {tag}")


CHILD = """
import importlib, json, sys
request = json.loads(sys.stdin.read())
sys.path[:] = request["path"]
plugin = importlib.import_module(request["plugin"])
module = importlib.import_module(request["module"])
function = getattr(module, request["function"])
function = getattr(function, "__probity_original__", function)
args = plugin.decode(request["args"])
kwargs = plugin.decode(request["kwargs"])
try:
    answer = {"value": plugin.encode(function(*args, **kwargs))}
except plugin.Unencodable as error:
    answer = {"unencodable": str(error)}
except BaseException as error:
    answer = {"raise": type(error).__name__, "module": type(error).__module__,
              "message": str(error)}
sys.stdout.write(json.dumps(answer))
"""


def _raise(answer: dict):
    kind = None
    if answer["module"] == "builtins":
        kind = getattr(builtins, answer["raise"], None)
    else:
        try:
            kind = getattr(importlib.import_module(answer["module"]), answer["raise"], None)
        except Exception:
            kind = None
    if not (isinstance(kind, type) and issubclass(kind, BaseException)):
        kind = RuntimeError
    raise kind(answer["message"])


def _isolated(module: str, name: str, args, kwargs):
    """Run the call in a fresh interpreter; ``None`` when it cannot cross as plain data."""
    try:
        request = {"path": [entry for entry in sys.path if entry], "plugin": __name__,
                   "module": module,
                   "function": name, "args": encode(list(args)), "kwargs": encode(dict(kwargs))}
    except Unencodable:
        return None
    try:
        done = subprocess.run([sys.executable, "-I", "-c", CHILD], input=json.dumps(request),
                              capture_output=True, text=True, timeout=CALL_TIMEOUT,
                              cwd=os.getcwd(), check=False)
        answer = json.loads(done.stdout)
    except (subprocess.TimeoutExpired, ValueError, OSError):
        return None
    if "unencodable" in answer:
        return None
    return answer


def _proxy(module: str, name: str, original):
    counts = COUNTS.setdefault(f"{module}:{name}", {"isolated": 0, "inline": 0, "raised": 0})

    @functools.wraps(original)
    def proxy(*args, **kwargs):
        answer = None
        if counts["isolated"] < LIMIT["calls"]:
            answer = _isolated(module, name, args, kwargs)
        if answer is None:
            counts["inline"] += 1
            return original(*args, **kwargs)
        counts["isolated"] += 1
        if "raise" in answer:
            counts["raised"] += 1
            _raise(answer)
        return decode(answer["value"])
    proxy.__probity_original__ = original
    return proxy


def _wrap(module) -> None:
    try:
        origin = os.path.realpath(getattr(module, "__file__", None) or "")
    except (TypeError, ValueError):
        return
    for name in TARGETS.get(origin, []) if origin else []:
        original = getattr(module, name, None)
        if callable(original) and not hasattr(original, "__probity_original__"):
            setattr(module, name, _proxy(module.__name__, name, original))


class _Loader(importlib.abc.Loader):
    def __init__(self, inner) -> None:
        self.inner = inner

    def create_module(self, spec):
        return self.inner.create_module(spec)

    def exec_module(self, module) -> None:
        self.inner.exec_module(module)
        _wrap(module)


class _Finder(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path, target=None):
        for finder in sys.meta_path:
            if finder is self or not hasattr(finder, "find_spec"):
                continue
            spec = finder.find_spec(fullname, path, target)
            if spec is None:
                continue
            origin = os.path.realpath(spec.origin) if spec.origin else ""
            if origin in TARGETS and spec.loader is not None:
                spec.loader = _Loader(spec.loader)
            return spec
        return None


def pytest_addoption(parser) -> None:
    group = parser.getgroup("probity")
    group.addoption("--probity-isolate", action="append", default=[],
                    help="<path>::<function>, a function to run with no test frame")
    group.addoption("--probity-isolate-limit", type=int, default=200,
                    help="isolated calls per target; later calls run in the test process")


def pytest_configure(config) -> None:
    LIMIT["calls"] = config.getoption("--probity-isolate-limit")
    for item in config.getoption("--probity-isolate"):
        path, _, name = item.partition("::")
        TARGETS.setdefault(os.path.realpath(path), []).append(name)
    if TARGETS:
        sys.meta_path.insert(0, _Finder())
        for module in list(sys.modules.values()):
            _wrap(module)


def summary() -> dict:
    return {"limit": LIMIT["calls"], "targets": COUNTS}
