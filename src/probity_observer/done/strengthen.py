"""Held-out tests a model writes against the mutants the contract still lets through.

When a seal gate still fails after the guard harvest, the compiler asks the model that made
the proposal for one test file per round (template ``prompts/contract_strengthen_v1.txt``),
showing it the task, the start-tree source of the touched functions, the public modules and
each surviving change, cheat-class and function mutant as a diff against the reference. At
most :data:`ROUNDS` rounds run, and a round that adds no kill ends them.

Every test function is validated on its own (:func:`static_problems`, then runs):

1. no private attribute, mock, exception-text check, ``repr`` or ``type(x) is`` comparison,
   and imports only from public modules;
2. it passes every one of three runs on the reference;
3. it fails every one of three runs on the start state, or passes every one;
4. it kills at least one mutant that survives the current commands.

Kept functions go to ``heldout/synth/`` and run as ``heldout-synth-<round>``, tier
``synthesized``. In ``synthesize_failing_spec`` mode (no trusted command fails on the start
state) the model is asked for tests that fail on the start state.
"""

from __future__ import annotations

import ast
import difflib
import re
import shlex
import shutil
import tempfile
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any, Sequence

from . import mutants, pytest_plugins
from .formats import sha256
from .mutants import Mutant
from .runner import Command, Runner

TEMPLATE = "contract_strengthen_v1.txt"
ROUNDS = 3
RUNS = 3
SYNTH_DIR = "probity_synth"
PREFIX = "heldout-synth-"
MOCKS = frozenset({"mock", "monkeypatch", "mocker", "MagicMock", "patch"})
MODES = {
    "strengthen": "",
    "synthesize_failing_spec": ("No existing test checks the task yet. Write tests that fail on "
                                "the repository as it is now and pass once the task is done."),
}


def template() -> str:
    return resources.files(__package__).joinpath(f"prompts/{TEMPLATE}").read_text("utf-8")


def public_modules(start: Path, is_test: Any) -> list[str]:
    """Dotted names of the start tree's non-test modules with no private part."""
    found = []
    for path in sorted(start.rglob("*.py")):
        name = path.relative_to(start).as_posix()
        parts = name[:-3].split("/")
        if parts[-1] == "__init__":
            parts = parts[:-1]
        if parts and not is_test(name) and not any(part.startswith("_") for part in parts) \
                and not set(name.split("/")) & {".git", "__pycache__"}:
            found.append(".".join(parts))
    return found


def start_sources(start: Path, reference: Path, targets: dict[str, Any]) -> str:
    """The start-tree text of every function the reference change touches, by qualname."""
    blocks = []
    for name, change in sorted(targets.items()):
        wanted = {item.qualname for item in mutants.touched(
            ast.parse((reference / name).read_text()), list(change.ranges), change.anchors)}
        if not (start / name).is_file():
            continue
        text = (start / name).read_text()
        for item in mutants.functions(ast.parse(text)):
            if item.qualname in wanted:
                blocks.append(f"# {name}: {item.qualname}\n"
                              + (ast.get_source_segment(text, item.node) or ""))
    return "\n\n".join(blocks) or "(none in the start tree)"


def mutant_diffs(found: Sequence[Mutant], reference: Path, indexes: Sequence[int]) -> str:
    diffs = []
    for index in indexes:
        mutant = found[index]
        for name, text in mutant.files():
            before = (reference / name).read_text() if (reference / name).is_file() else ""
            diffs.append("".join(difflib.unified_diff(
                before.splitlines(True), text.splitlines(True), f"a/{name}", f"b/{name}")))
    return "\n".join(diffs) or "(none)"


def render(task: str, mode: str, sources: str, modules: Sequence[str], diffs: str) -> str:
    return template().format(task=task, mode=MODES[mode], sources=sources,
                             modules="\n".join(modules) or "(none)", mutants=diffs)


def test_file(answer: str) -> str:
    """The test file in a model answer: its ```python block, or the whole answer."""
    match = re.search(r"```(?:python)?\n(.*?)```", answer, re.DOTALL)
    return match.group(1) if match else answer


def _module_problem(tree: ast.Module, modules: Sequence[str]) -> str | None:
    local = {name.split(".")[0] for name in modules}
    for node in ast.walk(tree):
        names: list[str] = []
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            names = [node.module] + [f"{node.module}.{alias.name}" for alias in node.names]
        for name in names:
            parts = name.split(".")
            if any(part in MOCKS for part in parts) or name.startswith("unittest.mock"):
                return "mock"
            if parts[0] in local and any(part.startswith("_") and not part.startswith("__")
                                         for part in parts):
                return "private_import"
    return None


def _raises_names(function: ast.AST) -> set[str]:
    names = set()
    for node in ast.walk(function):
        if isinstance(node, ast.withitem) and isinstance(node.optional_vars, ast.Name):
            names.add(node.optional_vars.id)
        if isinstance(node, ast.ExceptHandler) and node.name:
            names.add(node.name)
    return names


def static_problems(function: ast.FunctionDef) -> str | None:
    """The first rule a test function breaks, or ``None``."""
    if any(arg.arg in MOCKS for arg in function.args.args):
        return "mock"
    caught = _raises_names(function)
    for node in ast.walk(function):
        if isinstance(node, ast.Attribute):
            if node.attr.startswith("_") and not (node.attr.startswith("__")
                                                  and node.attr.endswith("__")):
                return "private_attribute"
            if isinstance(node.value, ast.Name) and node.value.id in caught \
                    and node.attr in ("value", "args", "match"):
                return "exception_text"
        if isinstance(node, ast.Name) and node.id in MOCKS:
            return "mock"
        if isinstance(node, ast.Call):
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
            if name == "raises" and any(keyword.arg == "match" for keyword in node.keywords):
                return "exception_text"
            if name in ("repr", "str") and any(isinstance(arg, ast.Name) and arg.id in caught
                                              for arg in node.args):
                return "exception_text"
            if name == "repr":
                return "repr"
        if isinstance(node, ast.Compare) and isinstance(node.left, ast.Call) \
                and getattr(node.left.func, "id", "") == "type" \
                and any(isinstance(op, (ast.Is, ast.Eq, ast.IsNot, ast.NotEq)) for op in node.ops):
            return "type_identity"
    return None


@dataclass
class Round:
    """One strengthening round: its digests, kept functions and rejections."""

    number: int
    mode: str
    record: dict[str, Any] = field(default_factory=dict)
    kept: list[str] = field(default_factory=list)
    file: str = ""
    fails_on_start: bool = False
    kills: set[int] = field(default_factory=set)


def _outcomes(runner: Runner, state: Path, heldout: Path | None, prefix: Sequence[str],
              name: str, timeout: float) -> dict[str, dict[str, Any]]:
    printed: list[str] = []
    runner.run(state, tuple(prefix) + ("-p", "probity_outcome", name), heldout, timeout,
               output=printed)
    return pytest_plugins.outcomes(printed)


def _with_file(base: Path, scratch: Path, label: str, name: str, text: str,
               mutant: Mutant | None = None) -> Path:
    state = scratch / label
    shutil.copytree(base, state, symlinks=True, ignore=shutil.ignore_patterns("__pycache__"))
    for path, source in (mutant.files() if mutant else ()):
        (state / path).write_text(source)
    (state / name).parent.mkdir(parents=True, exist_ok=True)
    (state / name).write_text(text)
    return state


def _repeated(runner: Runner, state: Path, heldout: Path | None, prefix: Sequence[str],
              name: str, timeout: float) -> list[dict[str, dict[str, Any]]]:
    return [_outcomes(runner, state, heldout, prefix, name, timeout) for _ in range(RUNS)]


def validate(runner: Runner, start: Path, reference: Path, heldout: Path | None,
             prefix: Sequence[str], source: str, modules: Sequence[str], found: Sequence[Mutant],
             alive: Sequence[int], number: int, timeout: float
             ) -> tuple[list[str], dict[str, str], dict[str, bool], dict[str, set[int]]]:
    """Kept function names, rejected ones with the rule they broke, which kept ones fail on
    the start state, and the alive mutants each kept one kills."""
    rejected: dict[str, str] = {}
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return [], {"<file>": "syntax_error"}, {}, {}
    if (problem := _module_problem(tree, modules)) is not None:
        return [], {"<file>": problem}, {}, {}
    tests = [node for node in tree.body
             if isinstance(node, ast.FunctionDef) and node.name.startswith("test")]
    candidates = []
    for function in tests:
        if (problem := static_problems(function)) is not None:
            rejected[function.name] = problem
        else:
            candidates.append(function.name)
    name = f"{SYNTH_DIR}/test_synth_{number}.py"
    node_of = {function: f"{name}::{function}" for function in candidates}
    with tempfile.TemporaryDirectory(prefix="probity-synth-") as scratch:
        on_reference = _repeated(runner, _with_file(reference, Path(scratch), "r", name, source),
                                 heldout, prefix, name, timeout)
        on_start = _repeated(runner, _with_file(start, Path(scratch), "s", name, source),
                             heldout, prefix, name, timeout)
        fails: dict[str, bool] = {}
        for function in list(candidates):
            node = node_of[function]
            if not all(run.get(node, {}).get("passed") for run in on_reference):
                rejected[function] = "fails_on_reference"
            elif all(node in run and not run[node]["passed"] for run in on_start):
                fails[function] = True
            elif all(run.get(node, {}).get("passed") for run in on_start):
                fails[function] = False
            else:
                rejected[function] = "unstable_on_start"
        candidates = [function for function in candidates if function in fails]
        kills: dict[str, set[int]] = {function: set() for function in candidates}
        for index in alive:
            state = _with_file(reference, Path(scratch), f"m{index}", name, source, found[index])
            result = _outcomes(runner, state, heldout, prefix, name, timeout)
            for function in candidates:
                if not result.get(node_of[function], {}).get("passed"):
                    kills[function].add(index)
            shutil.rmtree(state)
    kept = [function for function in candidates if kills[function]]
    rejected.update({function: "kills_no_mutant" for function in candidates if not kills[function]})
    return kept, rejected, {function: fails[function] for function in kept}, \
        {function: kills[function] for function in kept}


def kept_file(source: str, kept: Sequence[str]) -> str:
    """``source`` with only its module-level statements and the kept test functions."""
    tree = ast.parse(source)
    tree.body = [node for node in tree.body
                 if not (isinstance(node, ast.FunctionDef) and node.name.startswith("test"))
                 or node.name in kept]
    return ast.unparse(tree) + "\n"


def command(number: int, prefix: Sequence[str], fails_on_start: bool) -> Command:
    """``heldout-synth-<n>``: copy the sealed file into the workspace and run it."""
    name = f"{SYNTH_DIR}/test_synth_{number}.py"
    script = (f"mkdir -p {SYNTH_DIR} && cp ../heldout/synth/test_synth_{number}.py {SYNTH_DIR}/ "
              f"&& exec {shlex.join(tuple(prefix) + (name,))}")
    return Command(f"{PREFIX}{number}", ("sh", "-c", script), heldout=True,
                   prepatch="fail" if fails_on_start else "pass")


def is_synthesized(command_id: str) -> bool:
    return command_id.startswith(PREFIX)


def ask(model: Any, task: str, mode: str, sources: str, modules: Sequence[str],
        found: Sequence[Mutant], reference: Path, alive: Sequence[int], number: int
        ) -> tuple[str, dict[str, Any]]:
    """One model call for round ``number``; the answer and its sealed digests."""
    prompt = render(task, mode, sources, modules, mutant_diffs(found, reference, alive))
    answer = model.complete(prompt)
    return answer, {"round": number, "mode": mode, "model": model.name, "template": TEMPLATE,
                    "template_sha256": sha256(template().encode()),
                    "prompt_sha256": sha256(prompt.encode()),
                    "response_sha256": sha256(answer.encode()), "mutants_shown": len(alive)}
