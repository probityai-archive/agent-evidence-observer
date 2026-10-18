"""Acceptance commands for a real-repository task, from one zero-shot model call.

A task with no dataset acceptance (no FAIL_TO_PASS, no test field) gets its acceptance
commands and protected paths from one model call with the shipped template
``prompts/contract_v1.txt``. The answer is only a proposal: every path is checked against the
repository, every command then goes through the same three-run stability step and the mutant
adequacy measurement as a dataset task, and the compile record names the model, the template
digest and the response digest. The model is any OpenAI-compatible chat endpoint (for
example a vLLM server); the verdict itself never calls a model.
"""

from __future__ import annotations

import ast
import json
import urllib.request
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any, Protocol

from . import mutants, pytest_plugins
from .changes import Changes
from .contract import (DEFAULT_TEST_CMD, EXCLUDE, Protected, Task, command_test_files,
                       is_test_path, sealed_config, source_changes)
from .formats import DoneError, sha256
from .runner import Command

LISTING_LIMIT = 400
TEST_HEAD_LINES = 12
TEST_FILE_LIMIT = 20
SKIP_DIRS = {".git", "__pycache__", ".venv", "node_modules", ".tox", ".pytest_cache"}


def template() -> str:
    return resources.files(__package__).joinpath("prompts/contract_v1.txt").read_text("utf-8")


class Model(Protocol):
    name: str

    def complete(self, prompt: str) -> str: ...


@dataclass
class ChatModel:
    """One request to an OpenAI-compatible ``/v1/chat/completions`` endpoint.

    A reasoning model that spends ``max_tokens`` before it answers returns ``content: null``
    (``finish_reason: length``); that is a refused proposal, never a crash. The default
    budget leaves room for the reasoning (measured on gpt-oss-120b: 2 of 2 compiles at 2000
    had no content, every call at 8192 had it). ``tag`` is sent as ``X-Probity-Tag`` so a
    metering proxy books the call to its purpose.
    """

    url: str
    name: str
    max_tokens: int = 8192
    timeout: float = 300.0
    tag: str | None = None
    finish_reason: str | None = field(default=None, init=False)

    def complete(self, prompt: str) -> str:
        body = json.dumps({"model": self.name, "max_tokens": self.max_tokens, "temperature": 0,
                           "messages": [{"role": "user", "content": prompt}]}).encode()
        headers = {"Content-Type": "application/json"}
        if self.tag:
            headers["X-Probity-Tag"] = self.tag
        request = urllib.request.Request(self.url.rstrip("/") + "/v1/chat/completions", data=body,
                                         headers=headers)
        with urllib.request.urlopen(request, timeout=self.timeout) as reply:
            answer = json.loads(reply.read())
        try:
            choice = answer["choices"][0]
            content = choice["message"].get("content")
        except (KeyError, IndexError, TypeError, AttributeError) as error:
            raise DoneError("model reply has no choices[0].message") from error
        self.finish_reason = choice.get("finish_reason")
        if not isinstance(content, str) or not content.strip():
            raise DoneError(f"model answer has no content (finish_reason {self.finish_reason})")
        return content


@dataclass
class RecordedModel:
    """A recorded answer replayed byte for byte, so a contract is re-measured without a call.

    ``path`` is either a recorded call (JSON with the ``request`` and ``response`` bodies, as
    the recording relays keep them) or the bare answer text. A recorded call replays only for
    the prompt it was recorded with; a bare answer is replayed with ``prompt_matched: False``.
    """

    path: Path
    name: str = "recorded"

    def __post_init__(self) -> None:
        self.path = Path(self.path)
        data = self.path.read_bytes()
        self.from_sha256 = sha256(data)
        self.prompt: str | None = None
        try:
            call = json.loads(data)
        except ValueError:
            call = None
        if isinstance(call, dict) and "response" in call:
            response = call["response"]
            response = json.loads(response) if isinstance(response, str) else response
            content = response["choices"][0]["message"].get("content")
            if not isinstance(content, str):
                raise DoneError("recorded answer has no content")
            self.answer = content
            request = call.get("request")
            request = json.loads(request) if isinstance(request, str) else request
            if isinstance(request, dict):
                self.prompt = request["messages"][-1]["content"]
                self.name = request.get("model", self.name)
        else:
            self.answer = data.decode("utf-8")
        self.prompt_matched = False

    def complete(self, prompt: str) -> str:
        if self.prompt is not None:
            if prompt != self.prompt:
                raise DoneError("the answer was recorded for a different prompt")
            self.prompt_matched = True
        return self.answer


def _files(repo: Path) -> list[Path]:
    found = []
    for path in sorted(repo.rglob("*")):
        relative = path.relative_to(repo)
        if path.is_file() and not path.is_symlink() and not set(relative.parts) & SKIP_DIRS:
            found.append(path)
    return found


def render(repo: Path, task: str) -> str:
    """The prompt for ``task`` on ``repo``: the template filled with a listing and test heads."""
    files = _files(repo)
    listing = "\n".join(f"{path.relative_to(repo).as_posix()} {path.stat().st_size}"
                        for path in files[:LISTING_LIMIT])
    heads = []
    for path in [item for item in files if is_test_path(item.relative_to(repo).as_posix())][:TEST_FILE_LIMIT]:
        lines = path.read_text("utf-8", "replace").splitlines()[:TEST_HEAD_LINES]
        heads.append(f"--- {path.relative_to(repo).as_posix()}\n" + "\n".join(lines))
    return template().format(task=task, listing=listing or "(empty)",
                             listing_limit=LISTING_LIMIT, tests="\n".join(heads) or "(none found)")


def _json_object(text: str) -> dict[str, Any]:
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end < start:
        raise DoneError("model answer holds no JSON object")
    try:
        value = json.loads(text[start:end + 1])
    except json.JSONDecodeError as exc:
        raise DoneError(f"model answer is not JSON: {exc}") from exc
    if not isinstance(value, dict) or set(value) != {"acceptance", "protected_paths", "rationale"}:
        raise DoneError("model answer must have exactly acceptance, protected_paths, rationale")
    return value


def is_test_runner(argv: list[str]) -> bool:
    """``pytest``, ``python -m pytest`` or ``python -m unittest``, and nothing else."""
    first = argv[0].rsplit("/", 1)[-1]
    if first == "pytest":
        return True
    return (first in ("python", "python3") and len(argv) >= 3 and argv[1] == "-m"
            and argv[2] in ("pytest", "unittest"))


def _commands(items: Any) -> list[Command]:
    if not isinstance(items, list) or not 1 <= len(items) <= 8:
        raise DoneError("acceptance must list 1 to 8 commands")
    commands, seen = [], set()
    for item in items:
        if not isinstance(item, dict) or set(item) != {"id", "argv", "expect_on_start"}:
            raise DoneError("each acceptance command has id, argv and expect_on_start")
        argv = item["argv"]
        if (not isinstance(argv, list) or not argv or any(not isinstance(arg, str) for arg in argv)
                or not isinstance(item["id"], str) or item["id"] in seen
                or item["expect_on_start"] not in ("fail", "pass")):
            raise DoneError(f"acceptance command is malformed: {item!r}")
        if not is_test_runner(argv):
            raise DoneError(f"acceptance command is not a test runner: {argv!r}")
        seen.add(item["id"])
        commands.append(Command(item["id"], tuple(argv), prepatch=item["expect_on_start"]))
    return commands


# Options the sealed prefix already sets, or that change only how much pytest prints.
_PREFIX_FLAGS = frozenset({"-q", "-qq", "-v", "-vv", "-x", "-s", "--quiet", "--verbose"})


def _runner_args(argv: tuple[str, ...]) -> tuple[str, list[str]]:
    """``("pytest" | "unittest", the arguments after the runner)``."""
    if argv[0].rsplit("/", 1)[-1] == "pytest":
        return "pytest", list(argv[1:])
    return argv[2], list(argv[3:])


def unittest_node(repo: Path, name: str) -> str | None:
    """The pytest node id of a ``python -m unittest`` name (``a.b.C.t`` to ``a/b.py::C::t``)."""
    parts = name.split(".")
    for index in range(len(parts), 0, -1):
        path = "/".join(parts[:index]) + ".py"
        if (repo / path).is_file():
            return "::".join([path, *parts[index:]])
    return None


def sealed_command(repo: Path, command: Command, prefix: tuple[str, ...]) -> Command | None:
    """``command`` in the sealed pytest form on ``prefix``, or ``None`` when a unittest name
    resolves to no file. A command whose arguments are all test ids or paths seals them
    (``ids_from``); one with other options keeps them after the prefix and seals no ids."""
    runner, args = _runner_args(command.argv)
    kept: list[str] = []
    index = 0
    while index < len(args):
        if args[index] in _PREFIX_FLAGS:
            index += 1
            continue
        if args[index:index + 2] == ["-p", "no:cacheprovider"]:
            index += 2
            continue
        kept.append(args[index])
        index += 1
    if runner == "unittest":
        names = [arg for arg in kept if not arg.startswith("-")]
        nodes = [unittest_node(repo, name) for name in names]
        if not names or any(node is None for node in nodes):
            return None
        kept = [node for node in nodes if node is not None]
    ids = not any(arg.startswith("-") for arg in kept) and bool(kept)
    return Command(command.id, prefix + tuple(kept), prepatch=command.prepatch,
                   ids_from=len(prefix) if ids else None)


def isolation_targets(reference: Path, changes: dict[str, Changes]) -> list[str]:
    """``path::name`` of every module-level function the reference change touches."""
    found = []
    for name, change in changes.items():
        tree = ast.parse((reference / name).read_text())
        for item in mutants.touched(tree, list(change.ranges), change.anchors):
            if "." not in item.qualname:
                found.append(f"{name}::{item.qualname}")
    return sorted(found)


def seal_commands(repo: Path, commands: list[Command], held: Path, tests: list[str],
                  isolate: list[str]
                  ) -> tuple[list[Command], list[dict[str, Any]], tuple[str, ...]]:
    """Every proposed command in the sealed pytest form, and the ones that cannot be.

    The start tree's pytest configuration and the sealed plugins are copied under ``held``;
    each test runs twice (``probity_repeat``) and each touched module-level function runs
    with no test frame (``probity_isolated_call``). Also returns the prefix before the
    plugins, which guard tests are sealed on.
    """
    base = DEFAULT_TEST_CMD + sealed_config(repo, held)
    pytest_plugins.install(held / "config")
    prefix = pytest_plugins.pytest_argv(base, tests, isolate, pytest_plugins.REPEATS)
    sealed, dropped = [], []
    for command in commands:
        found = sealed_command(repo, command, prefix)
        if found is None:
            dropped.append({"id": command.id, "argv": list(command.argv),
                            "reason": "unittest_unresolved"})
        else:
            sealed.append(found)
    return sealed, dropped, base


def _protected(repo: Path, items: Any) -> list[Protected]:
    if not isinstance(items, list):
        raise DoneError("protected_paths must be a list")
    found = []
    for item in items:
        if not isinstance(item, dict) or set(item) != {"path", "kind"}:
            raise DoneError("each protected path has path and kind")
        name, kind = item["path"], item["kind"]
        target = repo / str(name)
        if (not isinstance(name, str) or name.startswith("/") or ".." in name.split("/")
                or kind not in ("file", "directory")
                or not (target.is_file() if kind == "file" else target.is_dir())):
            raise DoneError(f"protected path is not in the repository: {item!r}")
        found.append(Protected(name, kind, EXCLUDE if kind == "directory" else ()))
    return found


@dataclass(frozen=True)
class Proposal:
    task: Task
    record: dict[str, Any]


def changed_sources(start: Path, reference: Path) -> dict[str, Changes]:
    """The changed lines of each Python source file the reference solution changes."""
    names = [path.relative_to(reference).as_posix() for path in _files(reference)]
    return source_changes(start, reference, [
        name for name in names if name.endswith(".py") and not is_test_path(name)
        and (not (start / name).is_file()
             or (start / name).read_bytes() != (reference / name).read_bytes())])


def propose(repo: Path, task_id: str, description: str, model: Model,
            reference: Path | None = None, work: Path | None = None) -> Proposal:
    """One model call; the answer becomes an unsealed task with its provenance.

    Every proposed command is rewritten into the sealed pytest form, whose configuration and
    plugins go to ``work/heldout`` (``work`` is required). Without a ``reference`` (a
    known-good solution) the contract has no mutants to measure.
    """
    if work is None:
        raise DoneError("a repo task needs a work directory for its sealed configuration")
    prompt = render(repo, description)
    answer = model.complete(prompt)
    value = _json_object(answer)
    proposed = _commands(value["acceptance"])
    targets = changed_sources(repo, reference) if reference else {}
    tests = sorted({name for command in proposed for name in command_test_files(command, repo)})
    held = work / "heldout"
    held.mkdir(parents=True, exist_ok=True)
    isolate = isolation_targets(reference, targets) if reference else []
    commands, dropped, base = seal_commands(repo, proposed, held, tests, isolate)
    if not commands:
        raise DoneError("no proposed command has a sealed pytest form")
    task = Task(task_id=task_id, source="repo", description=description, start=repo,
                commands=commands, protected=_protected(repo, value["protected_paths"]),
                heldout=held, reference=reference, mutation_targets=targets,
                guard_prefix=base, isolate=tuple(isolate))
    record = {"model_calls": 1, "model": model.name,
              "template": "contract_v1.txt", "template_sha256": sha256(template().encode()),
              "prompt_sha256": sha256(prompt.encode()), "response_sha256": sha256(answer.encode()),
              "finish_reason": getattr(model, "finish_reason", None),
              "rationale": value["rationale"],
              "proposed": [{"id": command.id, "argv": list(command.argv)} for command in proposed],
              "dropped": dropped, "isolated_targets": isolate}
    if isinstance(model, RecordedModel):
        record["replay"] = {"from_sha256": model.from_sha256,
                            "prompt_matched": model.prompt_matched}
    task.notes = {"proposal": record}
    return Proposal(task, record)
