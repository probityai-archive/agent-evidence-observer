"""The sealed pytest plugins: repeated runs, isolated calls and the signed worker report."""

import json
from pathlib import Path

from probity_observer.done import verify_run
from probity_observer.done import pytest_plugins as sealed
from probity_observer.done.runner import SubprocessRunner

# ``pytester`` runs the plugins in this process too, so their own lines are measured.
pytest_plugins = ["pytester"]
PREFIX = ("python", "-P", "-m", "pytest", "-p", "no:cacheprovider", "-q")
KEY = b"0123456789abcdef"

COUNTER = "calls = [0]\n\n\ndef area(w, h):\n    calls[0] += 1\n    return w * h if calls[0] == 1 else 0\n"
HONEST = "def area(w, h):\n    return w * h\n"
FRAME_AWARE = ("import sys\n\n\ndef area(w, h):\n"
               "    caller = sys._getframe(1).f_code.co_name\n"
               "    return w * h if caller.startswith('test_') else -1\n")
TEST = ("from pkg.shapes import area\n\n\ndef test_area():\n    assert area(2, 3) == 6\n\n\n"
        "def test_kwargs():\n    assert area(w=1, h=4) == 4\n")


def tree(tmp_path: Path, source: str, test: str = TEST) -> tuple[Path, Path]:
    state = tmp_path / "state"
    (state / "pkg").mkdir(parents=True)
    (state / "pkg" / "__init__.py").write_text("")
    (state / "pkg" / "shapes.py").write_text(source)
    (state / "tests").mkdir()
    (state / "tests" / "__init__.py").write_text("")
    (state / "tests" / "test_shapes.py").write_text(test)
    held = tmp_path / "heldout"
    sealed.install(held / "config")
    return state, held


def run(tmp_path, python_bin, source, *, isolate=(), key=KEY, test=TEST):
    state, held = tree(tmp_path, source, test)
    argv = sealed.pytest_argv(PREFIX, ["tests/test_shapes.py"], isolate) + (
        "tests/test_shapes.py",)
    printed: list[str] = []
    code = SubprocessRunner(python_bin).run(state, argv, held, 120, output=printed,
                                           stdin=key + b"\n" if key else None)
    return code, sealed.report(printed, KEY), printed


def test_a_counter_passes_once_and_fails_the_repeat(tmp_path, python_bin):
    code, report, _ = run(tmp_path, python_bin, COUNTER)
    assert code == 1
    assert report["repeats"] == 2
    assert report["items"]["tests/test_shapes.py::test_area"] == {"passed": 1, "failed": 1,
                                                                   "skipped": 0}


def test_an_honest_patch_passes_every_repeat_and_the_report_verifies(tmp_path, python_bin):
    code, report, printed = run(tmp_path, python_bin, HONEST)
    assert code == 0
    assert set(report["items"]) == {"tests/test_shapes.py::test_area",
                                    "tests/test_shapes.py::test_kwargs"}
    assert all(item["passed"] == 2 for item in report["items"].values())
    assert report["frame_calls"] == 0 and report["protected_opens"] == 0
    assert sealed.report(printed, b"another key") is None
    assert sealed.collected(list(report["items"]), [
        "tests/test_shapes.py::test_area", "tests/test_shapes.py::test_gone"]) == 1


def test_a_run_without_a_key_prints_an_unverifiable_report(tmp_path, python_bin):
    code, report, printed = run(tmp_path, python_bin, HONEST, key=None)
    assert code == 0 and report is None
    assert any(f"{sealed.MARKER} unkeyed " in text for text in printed)


def test_frame_inspection_and_test_reads_are_measured(tmp_path, python_bin):
    source = FRAME_AWARE + "\n\ndef peek():\n    return open('tests/test_shapes.py').read()\n"
    test = TEST + "\n\ndef test_peek():\n    from pkg.shapes import peek\n    assert peek()\n"
    _, report, _ = run(tmp_path, python_bin, source, test=test)
    assert report["frame_calls"] >= 2 and report["frame_callers"] == ["pkg/shapes.py"]
    assert report["protected_opens"] == 2 and report["opened"] == ["tests/test_shapes.py"]


def test_a_frame_aware_cheat_passes_inline_and_fails_isolated(tmp_path, python_bin):
    code, _, _ = run(tmp_path / "inline", python_bin, FRAME_AWARE)
    assert code == 0
    code, report, _ = run(tmp_path / "isolated", python_bin, FRAME_AWARE,
                          isolate=["pkg/shapes.py::area"])
    assert code == 1
    counts = report["isolated"]["targets"]["pkg.shapes:area"]
    assert counts["isolated"] == 4 and counts["inline"] == 0


def test_isolated_calls_keep_types_exceptions_and_fall_back_on_other_data(tmp_path, python_bin):
    source = ("def area(w, h):\n    if w < 0:\n        raise ValueError('negative')\n"
              "    return (w * h, [w, h], {'w': w}, 1.5, True, None, b'x')\n")
    test = ("import pytest\nfrom pkg.shapes import area\n\n\ndef test_types():\n"
            "    assert area(2, 3) == (6, [2, 3], {'w': 2}, 1.5, True, None, b'x')\n"
            "    assert type(area(2, 3)[0]) is int\n\n\ndef test_raises():\n"
            "    with pytest.raises(ValueError, match='negative'):\n        area(-1, 1)\n\n\n"
            "def test_object():\n    class Side(int):\n        pass\n    assert area(Side(2), 3)[0] == 6\n")
    code, report, printed = run(tmp_path, python_bin, source, isolate=["pkg/shapes.py::area"],
                                test=test)
    assert code == 0, printed
    counts = report["isolated"]["targets"]["pkg.shapes:area"]
    # Per run: two plain calls and one raising call cross; the int subclass stays inline.
    assert counts == {"isolated": 6, "raised": 2, "inline": 2}


def test_codec_round_trips_plain_data_only():
    value = {"a": [1, (2.5, None)], "b": b"\x00", "c": True}
    assert codec().decode(codec().encode(value)) == value
    try:
        codec().encode({1: 2})
    except codec().Unencodable:
        pass
    else:
        raise AssertionError("a non-string key must not cross")


def codec():
    from probity_observer.done.pytest_plugins import probity_isolated_call
    return probity_isolated_call


def test_the_grader_counts_collected_ids_from_the_verified_report(tmp_path, python_bin):
    state, held = tree(tmp_path, HONEST)
    argv = sealed.pytest_argv(PREFIX, ["tests/test_shapes.py"]) + (
        "tests/test_shapes.py::test_area",)
    item = {"id": "fail-to-pass", "argv": list(argv), "ids": ["tests/test_shapes.py::test_area"]}
    code, found = verify_run._plugin_run(SubprocessRunner(python_bin), state, item, held, 120)
    assert code == 0
    assert sealed.collected(list(found["items"]), item["ids"]) == 1


def test_a_patch_that_reads_caller_frames_is_listed(tmp_path):
    start, root = tmp_path / "start", tmp_path / "root"
    for base, text in ((start, HONEST), (root, FRAME_AWARE)):
        (base / "pkg").mkdir(parents=True)
        (base / "pkg" / "shapes.py").write_text(text)
    found = verify_run.frame_attributes(root, start, {"protected_paths": []})
    assert {"path": "pkg/shapes.py", "line": 5, "name": "_getframe"} in found
    assert {item["name"] for item in found} >= {"_getframe", "f_code"}


def test_report_lines_are_parsed_and_tampering_is_refused():
    import hashlib
    import hmac
    data = '{"items":{}}'
    mac = hmac.new(KEY, data.encode(), hashlib.sha256).hexdigest()
    line = f"{sealed.MARKER} {mac} {data}"
    assert sealed.report(["noise", line], KEY) == {"items": {}}
    assert sealed.report([line.replace("{}}", '{"x":1}}')], KEY) is None


# In-process runs of the same plugins (``pytester``), so their own lines are measured.
REPEAT = "probity_observer.done.pytest_plugins.probity_repeat"
ISOLATED = "probity_observer.done.pytest_plugins.probity_isolated_call"


def inline(pytester, source, test, *args):
    pytester.makepyfile(**{"pkg/__init__": "", "pkg/shapes": source,
                           "tests/__init__": "", "tests/test_shapes": test})
    pytester.syspathinsert()
    return pytester.runpytest_inprocess("-p", REPEAT, "--probity-protected",
                                        "tests/test_shapes.py", *args, "tests/test_shapes.py")


def captured_report(capfd):
    lines = [line for line in capfd.readouterr().out.splitlines()
             if line.startswith(sealed.MARKER + " ")]
    return json.loads(lines[-1].split(" ", 2)[2])


def test_inline_repeat_counts_outcomes_and_measures_frames(pytester, capfd):
    source = FRAME_AWARE + "\n\ndef peek():\n    return open('tests/test_shapes.py').read()\n"
    test = TEST + "\n\ndef test_peek():\n    from pkg.shapes import peek\n    assert peek()\n"
    result = inline(pytester, source, test, "--probity-repeats", "3")
    report = captured_report(capfd)
    assert result.ret == 0
    assert report["repeats"] == 3
    assert report["items"]["tests/test_shapes.py::test_area"]["passed"] == 3
    assert report["frame_calls"] >= 3 and report["protected_opens"] == 3


def test_inline_isolated_call_runs_the_target_with_no_test_frame(pytester, capfd):
    result = inline(pytester, FRAME_AWARE, TEST, "-p", ISOLATED, "--probity-isolate",
                    "pkg/shapes.py::area", "--probity-isolate-limit", "1")
    report = captured_report(capfd)
    # The first call crosses and fails; later calls stay inline once the limit is reached.
    assert result.ret == 1
    counts = report["isolated"]["targets"]["pkg.shapes:area"]
    assert counts["isolated"] == 1 and counts["inline"] >= 1


def repeat_module():
    from probity_observer.done.pytest_plugins import probity_repeat
    return probity_repeat


def test_the_audit_hook_counts_frame_calls_and_protected_reads(tmp_path, monkeypatch):
    repeat = repeat_module()
    here = Path(__file__).resolve().parent
    (here_file := tmp_path / "t.py").write_text("")
    counts = {"frame_calls": 0, "protected_opens": 0, "frame_callers": set(), "opened": set()}
    monkeypatch.setattr(repeat, "COUNTS", counts)
    monkeypatch.setattr(repeat, "PROTECTED", {"t.py"})
    monkeypatch.setitem(repeat.STATE, "in_call", True)
    monkeypatch.setitem(repeat.STATE, "cwd", str(tmp_path.resolve()))
    repeat._audit("open", (str(here_file), "r", 0))
    repeat._audit("open", (str(tmp_path / "other.py"), "r", 0))
    assert counts["protected_opens"] == 1 and counts["opened"] == {"t.py"}
    monkeypatch.setitem(repeat.STATE, "cwd", str(here))
    repeat._audit("sys._getframe", (1,))
    assert counts["frame_calls"] == 1 and counts["frame_callers"] == {Path(__file__).name}
    monkeypatch.setitem(repeat.STATE, "busy", True)
    repeat._audit("sys._getframe", (1,))
    monkeypatch.setitem(repeat.STATE, "busy", False)
    monkeypatch.setitem(repeat.STATE, "in_call", False)
    repeat._audit("sys._getframe", (1,))
    assert counts["frame_calls"] == 1


def test_the_report_key_is_read_once_from_standard_input(monkeypatch):
    import io
    import os
    import sys
    repeat = repeat_module()
    monkeypatch.setattr(os, "isatty", lambda fd: True)
    assert repeat._read_key() == b""
    monkeypatch.setattr(os, "isatty", lambda fd: False)
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(b"secret\n")))
    assert repeat._read_key() == b"secret"
    monkeypatch.setattr(sys, "stdin", None)
    assert repeat._read_key() == b""


def test_isolated_call_helpers_fall_back_and_re_raise(tmp_path, monkeypatch):
    import types

    import pytest
    iso = codec()
    (tmp_path / "isolated_target.py").write_text(
        "class Thing:\n    pass\n\n\ndef thing():\n    return Thing()\n\n\n"
        "def boom():\n    raise KeyError('k')\n")
    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.chdir(tmp_path)
    assert iso._isolated("isolated_target", "thing", (), {}) is None
    assert iso._isolated("isolated_target", "thing", (object(),), {}) is None
    answer = iso._isolated("isolated_target", "boom", (), {})
    assert answer["raise"] == "KeyError" and answer["module"] == "builtins"
    with pytest.raises(KeyError):
        iso._raise(answer)
    with pytest.raises(iso.Unencodable):
        iso._raise({"raise": "Unencodable", "module": iso.__name__, "message": "x"})
    with pytest.raises(RuntimeError):
        iso._raise({"raise": "Missing", "module": "no_such_module_here", "message": "x"})
    with pytest.raises(ValueError):
        iso.decode({"set": []})
    iso._wrap(types.ModuleType("no_file"))


def test_only_a_python_m_pytest_prefix_is_rewritten():
    import pytest
    assert not sealed.is_python_pytest(("pytest", "-q"))
    assert not sealed.is_python_pytest(())
    assert sealed.is_python_pytest(("python3", "-I", "-m", "pytest"))
    with pytest.raises(ValueError):
        sealed.pytest_argv(("pytest", "-q"))
    assert not sealed.is_sealed_pytest(("python", "-m", "pytest"))
