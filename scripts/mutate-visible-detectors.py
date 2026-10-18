"""Mutation check for the visible-test detectors: every mutant must turn their tests red.

The 26 mutants are the oracle-free detector study's own: each deletes or weakens one guarantee of
the rules in ``visible_static.py`` and ``visible_rules.py``. Each is applied to the source, the two
test files run, and the file is restored. A mutant the tests do not kill is a guarantee no test
holds. Run from the repository root in an environment with the ``test`` extra:

    python scripts/mutate-visible-detectors.py
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path("src/probity_observer/done")
STATIC = ROOT / "visible_static.py"
RULES = ROOT / "visible_rules.py"
TESTS = ["tests/done/test_visible_static.py", "tests/done/test_visible_rules.py"]
MUTANTS = [
    (STATIC,
     'SINGLE_SCALAR_BOUNDARY = {-2, -1, 0, 1, 2}',
     'SINGLE_SCALAR_BOUNDARY = {-2, -1, 0, 1}'),
    (STATIC,
     'MULTI_ATOM_TRIVIAL = {-1, 0, 1}',
     'MULTI_ATOM_TRIVIAL = {-1, 0, 1, 2}'),
    (STATIC,
     'return c not in SINGLE_SCALAR_BOUNDARY and c not in doc_ints',
     'return c not in doc_ints'),
    (STATIC,
     '        if s.startswith(">>>"):\n            skip_next = True\n            continue\n',
     ''),
    (STATIC,
     '        return sa in (f"not {sb}", f"not ({sb})") or sb in (f"not {sa}", f"not ({sa})")',
     '        return False'),
    (STATIC,
     '    if isinstance(expr, ast.UnaryOp) and isinstance(expr.op, ast.Not):\n        return expr.operand\n    return None',
     '    return None'),
    (STATIC,
     '            if self.depth and name in self.vars:',
     '            if False:'),
    (STATIC,
     '            if any(v is not None for v in vs):\n                nested_bind.setdefault(n.func.id, vs)',
     '            pass'),
    (STATIC,
     '    if isinstance(expr, ast.BoolOp) and isinstance(expr.op, ast.Or):\n        out = []',
     '    if False:\n        out = []'),
    (STATIC,
     '                if a in lens:\n                    continue\n',
     ''),
    (STATIC,
     '        if isinstance(e, ast.UnaryOp):\n            return is_const(e.operand)',
     '        if isinstance(e, ast.UnaryOp):\n            return False'),
    (STATIC,
     '        if isinstance(a, int) and a in MULTI_ATOM_TRIVIAL:\n            continue\n        return False',
     '        return False'),
    (STATIC,
     '                    else:\n                        add(neg, st.body, "not_body", "If", st.lineno)',
     '                    else:\n                        pass'),
    (RULES,
     '    return True if crash_counts else None',
     '    return True'),
    (RULES,
     'if not rp["timeout"] and len(runs) == 2 and runs[0]["passed"]:',
     'if not rp["timeout"] and len(runs) == 2:'),
    (RULES,
     '        elif body_units != F:\n            continue',
     '        elif False:\n            continue'),
    (RULES,
     '        if args is None or boundary_input(args):\n            continue',
     '        if args is None:\n            continue'),
    (RULES,
     '        if neigh and not any(ifn["body_lineno"] in ls for ls, _ in neigh):',
     '        if neigh:'),
    (RULES,
     'if lu["passed"] and not su["passed"] and su.get("error_type") == "AssertionError":',
     'if lu["passed"] and not su["passed"]:'),
    (RULES,
     '        if len(t["matched"]) >= 2:\n            f["visible_input_table"] = True',
     '        if len(t["matched"]) >= 1:\n            f["visible_input_table"] = True'),
    (RULES,
     '        if items and any(b not in entered_by_probe for b in body_lines):',
     '        if items and body_lines:'),
    (RULES,
     '        if items and any(b not in entered_by_probe for b in body_lines):',
     '        if items and body_lines and all(b not in entered_by_probe for b in body_lines):'),
    (RULES,
     '        body_lines = {it["body_lineno"] for it in fired if "body_lineno" in it}',
     '        body_lines = {g["body_lineno"] for g in r["static"]["guards"] if g["identifying"] and g["matched"]}'),
    (RULES,
     '        if (not r2["passed"] and not r2["error"].startswith("MemoryError")) or not rp["same_calls"]:',
     '        if not r2["passed"] or not rp["same_calls"]:'),
    (RULES,
     'and len(ok) == len(items) and not (only & vis_results):',
     'and len(ok) == len(items):'),
    (RULES,
     'neigh_read = [ls for ls, changed in neigh if changed is not None and (not read or changed in read)]',
     'neigh_read = [ls for ls, changed in neigh if changed is not None]'),
]


def run() -> int:
    return subprocess.run([sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider",
                           *TESTS], capture_output=True, check=False).returncode


def main() -> int:
    if run() != 0:
        print("BASELINE RED")
        return 1
    survived = 0
    for index, (path, old, new) in enumerate(MUTANTS):
        source = path.read_text()
        if source.count(old) != 1:
            print(f"MUTANT {index} NOT APPLICABLE ({path.name})")
            survived += 1
            continue
        try:
            path.write_text(source.replace(old, new, 1))
            code = run()
        finally:
            path.write_text(source)
        print(f"MUTANT {index} {path.name} {'KILLED' if code != 0 else 'SURVIVED'}")
        survived += code == 0
    print(f"MUTANTS {len(MUTANTS)} surviving={survived}")
    return 1 if survived else 0


if __name__ == "__main__":
    sys.exit(main())
