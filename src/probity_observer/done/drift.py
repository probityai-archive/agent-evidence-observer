"""The exact drift and loop latches: each fires on repeats a stranger can recount from records.

All of them are pure functions of the observation, the tree and the attempt chain, so the
``loop_detected`` and ``stalled`` reasons recompute from the signed loop record:

- **command, across edits that cannot matter** (:func:`repeated_command`): the agent runs the
  same command (executed path, working directory, argv and exit) ``K`` times with no mutation,
  between two of the runs, to a path the previous run read. A ``touch .probe`` or an edit to a
  file the command never opened does not reset the count; an edit to a file it read does;
- **command, within one attempt** (:func:`repeated_in_attempt`): the same command ``K_cmd``
  times in one attempt, whatever the edits between;
- **tree** (:func:`repeated_ast_tree`): the attempt's tree, with every Python file reduced to
  its AST (comments and layout gone; a file that does not parse is hashed with its comments
  stripped under ``SYNTAX_ERR:``), equal to an earlier attempt's tree anywhere in the chain;
- **progress** (:func:`progress`): the passing acceptance commands grow from the start
  state's passing set ``B0``; ``B_t = B_{t-1} | P_t`` only when ``P_t`` keeps all of ``B0``,
  and ``stall_after`` attempts in a row without growth is ``stalled``.

The raw tree digest stays on every attempt record as evidence.
"""

from __future__ import annotations

import ast
import hashlib
import io
import os
import tokenize
from pathlib import Path
from typing import Any

MUTATIONS = frozenset({"write", "create", "rename", "link", "unlink", "truncate", "chmod"})
CACHE_NAMES = frozenset({"__pycache__", ".pytest_cache"})
COMMAND_REPEATS = 3
COMMAND_REPEATS_IN_ATTEMPT = 4
STALL_AFTER = 3


def command_key(event: dict[str, Any]) -> tuple[Any, ...]:
    """What makes two runs the same command: the executed path, cwd, argv and exit.

    ``exe`` and ``cwd`` come from ``probity-observation/v3``; the same argv run from another
    directory, or resolving to another program, is another command.
    """
    return (event.get("exe"), event.get("cwd"), tuple(event["argv"]), event.get("exit"))


def _command_roots(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The agent's own commands: execs of its root process, and the first exec of each
    command (whose id is an ``origin``)."""
    roots = {event.get("origin") for event in events if event.get("origin")}
    return [event for event in events if event["type"] == "exec"
            and (not event.get("origin") or event["id"] in roots)]


def _reads(events: list[dict[str, Any]]) -> dict[str, set[str]]:
    """The paths each command read, by its id."""
    found: dict[str, set[str]] = {}
    for event in events:
        if event["type"] == "read" and event.get("origin") and event.get("path"):
            found.setdefault(event["origin"], set()).add(event["path"])
    return found


def _paths(event: dict[str, Any]) -> set[str]:
    return {name for name in (event.get("path"), event.get("target")) if name}


def repeated_command(events: list[dict[str, Any]],
                     repeats: int = COMMAND_REPEATS) -> dict[str, Any] | None:
    """The first command run ``repeats`` times with no relevant mutation between runs.

    A mutation is relevant to a command when it touches a path that the command's last run
    read and was not made by that run itself. A run of the same argv with another exit
    starts that command's count again.
    """
    reads = _reads(events)
    roots = {event["id"] for event in _command_roots(events)}
    counts: dict[tuple[Any, ...], int] = {}
    last_run: dict[tuple[Any, ...], str] = {}
    for event in events:
        if event["type"] in MUTATIONS:
            touched = _paths(event)
            for key, run in list(last_run.items()):
                if event.get("origin") != run and touched & reads.get(run, set()):
                    counts[key] = 0
            continue
        if event["type"] != "exec" or event["id"] not in roots:
            continue
        key = command_key(event)
        for other in [item for item in counts if item[:3] == key[:3] and item != key]:
            counts[other] = 0
        counts[key] = counts.get(key, 0) + 1
        last_run[key] = event["id"]
        if counts[key] >= repeats:
            return {"latch": "command", "argv": list(event["argv"]), "exit": event.get("exit"),
                    "repeats": repeats}
    return None


def repeated_in_attempt(events: list[dict[str, Any]],
                        repeats: int = COMMAND_REPEATS_IN_ATTEMPT) -> dict[str, Any] | None:
    """The first command run ``repeats`` times in one attempt, whatever happened between."""
    counts: dict[tuple[Any, ...], int] = {}
    for event in _command_roots(events):
        key = command_key(event)
        counts[key] = counts.get(key, 0) + 1
        if counts[key] >= repeats:
            return {"latch": "command_in_attempt", "argv": list(event["argv"]),
                    "exit": event.get("exit"), "repeats": repeats}
    return None


def command_latch(events: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Either command latch, the across-edits one first."""
    return repeated_command(events) or repeated_in_attempt(events)


def _strip_comments(source: bytes) -> bytes:
    """A file's text without comments and blank lines, for a file that does not parse."""
    try:
        tokens = [token for token in tokenize.tokenize(io.BytesIO(source).readline)
                  if token.type not in (tokenize.COMMENT, tokenize.NL)]
        return tokenize.untokenize(tokens) if isinstance(tokenize.untokenize(tokens), bytes) \
            else tokenize.untokenize(tokens).encode()
    except (tokenize.TokenError, SyntaxError, UnicodeDecodeError, IndentationError):
        lines = [line.split(b"#", 1)[0].rstrip() for line in source.splitlines()]
        return b"\n".join(line for line in lines if line.strip())


def file_ast_digest(source: bytes) -> str:
    """A Python file's digest up to comments and layout."""
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return "SYNTAX_ERR:" + hashlib.sha256(_strip_comments(source)).hexdigest()
    return hashlib.sha256(ast.dump(tree, include_attributes=False).encode()).hexdigest()


def ast_tree_sha256(root: Path) -> str:
    """The tree digest with each Python file replaced by its AST digest; caches left out."""
    lines = []
    root = Path(root)
    for directory, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(name for name in dirnames if name not in CACHE_NAMES)
        base = Path(directory)
        for name in sorted(filenames):
            path = base / name
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                digest = "l:" + hashlib.sha256(os.readlink(path).encode(
                    "utf-8", "surrogateescape")).hexdigest()
            elif not path.is_file():
                digest = "s:special"
            elif name.endswith(".py"):
                digest = "ast:" + file_ast_digest(path.read_bytes())
            else:
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
            lines.append(f"{digest}  {relative}\n")
    lines.sort(key=lambda line: line.split("  ", 1)[1].encode("utf-8", "surrogateescape"))
    return hashlib.sha256("".join(lines).encode("utf-8", "surrogateescape")).hexdigest()


def repeated_ast_tree(chain: list[dict[str, Any]]) -> dict[str, Any] | None:
    """The last attempt's AST tree digest, when an earlier attempt already had it."""
    if not chain:
        return None
    last = chain[-1]["ast_tree_sha256"]
    for earlier in chain[:-1]:
        if earlier["ast_tree_sha256"] == last:
            return {"latch": "ast_tree", "ast_tree_sha256": last,
                    "first_attempt": earlier["attempt"], "attempt": chain[-1]["attempt"]}
    return None


def progress(baseline: list[str], chain: list[dict[str, Any]]) -> tuple[list[str], int]:
    """The grown passing set and the number of attempts in a row, ending with the last one,
    that did not grow it."""
    base = set(baseline)
    grown = set(base)
    without = 0
    for record in chain:
        passed = set(record["passed_ids"])
        if passed >= base and not passed <= grown:
            grown |= passed
            without = 0
        else:
            without += 1
    return sorted(grown), without
