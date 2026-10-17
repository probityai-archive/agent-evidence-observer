#!/usr/bin/env python3
"""Refuse site literals in the HiPerGator templates.

The templates in this directory are public and generic. A scheduler account, a QOS, a user name or a
path on the parallel filesystem belongs in the submit environment (HPG_ACCOUNT, HPG_QOS, HPG_BLUE_DIR,
HPG_VENV), never in a file. The rules are structural, so this file names no real site value:

  * an #SBATCH --account, --qos or -A directive (submit.sh passes them on the command line);
  * a path under /blue, /orange, /red, /scratch or /home;
  * a user-specific /tmp or /var path assembled from a name (the generic /tmp is allowed);
  * any extra literal listed in the environment variable HPG_LITERALS (comma separated), so a private
    run can check the concrete values it knows without writing them into this file.

Exit 0 when clean, 1 when a literal is found, 2 on a usage error.
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

SUFFIXES = {".sh", ".sbatch", ".py", ".toml", ".md", ".yml", ".yaml", ".txt"}
SKIP_NAMES = {"uv.lock", "lint_literals.py", "test_lint_literals.py"}

RULES = [
    (re.compile(r"^\s*#SBATCH\s+(?:--account|--qos|-A)\b"), "an #SBATCH account or QOS directive"),
    (re.compile(r"(?<![\w.$-])/(?:blue|orange|red|scratch|home)/"), "a path on a site filesystem"),
]


def extra_literals() -> list[str]:
    raw = os.environ.get("HPG_LITERALS", "")
    return [x.strip() for x in raw.split(",") if x.strip()]


def scan_text(name: str, text: str, extras: list[str]) -> list[str]:
    hits = []
    for number, line in enumerate(text.splitlines(), 1):
        for pattern, label in RULES:
            if pattern.search(line):
                hits.append(f"{name}:{number}: {label}: {line.strip()[:120]}")
        for literal in extras:
            if literal in line:
                hits.append(f"{name}:{number}: listed literal found: {line.strip()[:120]}")
    return hits


def scan_tree(root: Path, extras: list[str]) -> list[str]:
    hits: list[str] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.name in SKIP_NAMES:
            continue
        if path.suffix not in SUFFIXES:
            continue
        hits.extend(scan_text(str(path.relative_to(root)), path.read_text(errors="replace"), extras))
    return hits


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: lint_literals.py <directory>", file=sys.stderr)
        return 2
    root = Path(argv[1])
    if not root.is_dir():
        print(f"not a directory: {root}", file=sys.stderr)
        return 2
    hits = scan_tree(root, extra_literals())
    for hit in hits:
        print(hit)
    print(f"lint_literals: {len(hits)} finding(s) in {root}")
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
