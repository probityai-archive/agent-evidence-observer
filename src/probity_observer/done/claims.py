"""Parse what an agent says it ran into a ``probity-tool-claims/v1`` record.

Claims are the agent's statements, so they come from its own output and carry no vantage.
Two transcript shapes are read:

- **plain text** (any agent run by the launcher): a line ``$ <command>`` is a claimed run of
  that command; a later test summary (``N passed``, ``All tests passed``, ``OK``) with no
  failure claims that run's exit was 0. A summary with no claimed command before it is a claim
  that the contract's first visible acceptance command ran and passed, which is how a
  fabricated ``12 passed`` becomes a checkable claim;
- **Claude Code ``stream-json``** (:func:`from_claude_stream`): each ``Bash`` tool call is a
  claimed run of its command, and its tool result's error flag gives the claimed exit.

A shell command line is split with :mod:`shlex`; a line that does not split, or that uses
shell syntax beyond one simple command, is claimed as ``["sh", "-c", <line>]``.

When the contract seals ``cwd`` and ``exe`` for the acceptance commands the agent runs
itself, only claims of those commands are kept, under their sealed argv: a command line with
the sealed arguments whose program is the sealed ``argv[0]`` or the sealed ``exe``, also inside a
one-command ``sh -c`` or ``bash -lc``. Other commands the agent ran (``ls -R``, an editor call)
say nothing about done and are left out, with their output. A test summary counts only in a kept
command's output or in the agent's own text, never under a ``# <tool>`` line, where the agent displays a file or a tool
result (a viewed ``test.py`` that prints "All tests passed!" is not a test run). A line
``[exit N]`` in a kept command's output states that run's exit. Only the agent's last claim of
each sealed command is kept, because the verifier settles a claim on that command's last run,
and only when it does not state a failure, because a run the agent says failed is no claim of
done.
"""

from __future__ import annotations

import json
import posixpath
import re
import shlex
from typing import Any

SCHEMA = "probity-tool-claims/v1"
_PASSED = re.compile(r"(?:\b\d+ passed\b|All tests passed|^OK\b)", re.MULTILINE)
_FAILED = re.compile(r"\b\d+ (?:failed|error|errors)\b|^FAILED\b|Traceback", re.MULTILINE)
_SHELL = set("|&;<>()$`*?[]{}~!")
_EXIT = re.compile(r"\[exit (\d+)\]")


def command_argv(line: str) -> list[str]:
    """The argv a command line runs: split when it is one simple command."""
    stripped = line.strip()
    if not (_SHELL & set(stripped)):
        try:
            parts = shlex.split(stripped)
        except ValueError:
            parts = []
        if parts:
            return parts
    return ["sh", "-c", stripped]


_SHELLS = {"sh", "bash", "dash", "zsh"}


def sealed_spelling(argv: list[str], commands: list[dict[str, Any]]) -> list[str] | None:
    """The sealed argv of the agent-run acceptance command this command line spells, if any."""
    if (len(argv) == 3 and posixpath.basename(argv[0]) in _SHELLS
            and argv[1] in ("-c", "-lc")):
        inner = command_argv(argv[2])
        if posixpath.basename(inner[0]) not in _SHELLS:
            return sealed_spelling(inner, commands)
    for command in commands:
        sealed = command["argv"]
        if argv[1:] == sealed[1:] and argv[0] in (sealed[0], command["exe"]):
            return list(sealed)
    return None


def from_text(transcript: str, visible_argv: list[str] | None,
              commands: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """Claims in a plain-text transcript; with ``commands`` (the contract's agent-run acceptance
    commands) only their spellings, under the sealed argv."""
    claims: list[dict[str, Any]] = []
    block: list[str] = []
    current: list[dict[str, Any] | None] = [None]
    shown = [False]

    def close() -> None:
        text = "\n".join(block)
        if not shown[0] and _PASSED.search(text) and not _FAILED.search(text):
            if current[0] is not None and "exit" not in current[0]:
                current[0]["exit"] = 0
            elif visible_argv is not None:
                claims.append({"id": f"c{len(claims) + 1}", "argv": list(visible_argv), "exit": 0})
        block.clear()

    for line in transcript.splitlines():
        stated = _EXIT.fullmatch(line.strip())
        if stated and current[0] is not None and not shown[0]:
            current[0]["exit"] = int(stated.group(1))
            continue
        if line.startswith("$ ") and line[2:].strip():
            close()
            shown[0] = False
            argv = command_argv(line[2:])
            if commands is not None:
                argv = sealed_spelling(argv, commands)
                # A left-out command's output is that command's, never a claim of another.
                shown[0] = argv is None
            current[0] = None if argv is None else {"id": f"c{len(claims) + 1}", "argv": argv}
            if current[0] is not None:
                claims.append(current[0])
        elif commands is not None and line.startswith("# "):
            close()
            shown[0], current[0] = True, None
        else:
            block.append(line)
    close()
    return _last_per_command(claims) if commands is not None else claims


def _last_per_command(claims: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One claim per sealed command, the agent's last, and only when it does not state a
    failure: probity-verify settles a claim on the command's last run, and a run the agent
    says failed claims nothing about done."""
    last = {tuple(claim["argv"]): claim for claim in claims}
    kept = [claim for claim in claims if last[tuple(claim["argv"])] is claim
            and claim.get("exit", 0) == 0]
    return [{**claim, "id": f"c{index}"} for index, claim in enumerate(kept, start=1)]


def from_claude_stream(lines: str,
                       commands: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """Claims in Claude Code ``--output-format stream-json`` output; with ``commands``, only
    spellings of the contract's agent commands, under the sealed argv."""
    calls: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for raw in lines.splitlines():
        try:
            message = json.loads(raw)
        except json.JSONDecodeError:
            continue
        content = (message.get("message") or {}).get("content")
        if not isinstance(content, list):
            continue
        for block in content:
            if not isinstance(block, dict):
                continue
            if block.get("type") == "tool_use" and block.get("name") == "Bash":
                command = (block.get("input") or {}).get("command")
                if isinstance(command, str) and command.strip():
                    argv = command_argv(command)
                    if commands is not None:
                        argv = sealed_spelling(argv, commands)
                    if argv is not None:
                        calls[block["id"]] = {"argv": argv}
                        order.append(block["id"])
            elif block.get("type") == "tool_result" and block.get("tool_use_id") in calls:
                calls[block["tool_use_id"]]["exit"] = 1 if block.get("is_error") else 0
    return [{"id": f"c{index}", **calls[key]} for index, key in enumerate(order, start=1)]


def record(claims: list[dict[str, Any]], claim_id: str, invocation_id: str,
           producer: str = "transcript-parser") -> dict[str, Any]:
    return {"schema_version": SCHEMA, "claim_id": claim_id, "invocation_id": invocation_id,
            "producer": producer, "claims": claims}
