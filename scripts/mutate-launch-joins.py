"""Mutation check for the sensor joins: every mutant must turn the tests red.

Each mutant replaces one exact piece of source in the launcher's join, origin
or coverage logic, runs the launcher's unit tests, and restores the file. A
mutant the tests do not kill means a guarantee no test holds. Run from the
repository root:

    python scripts/mutate-launch-joins.py
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

RECORD = Path("src/probity_observer/record_oe.py")
STRACE = Path("src/probity_observer/sensors/strace.py")
MUTANTS = [
    ("an S1 change is always covered", RECORD,
     '    if change.path in s2_paths:\n        return True\n',
     '    return True\n'),
    ("scanned entries under a moved tree are not covered", RECORD,
     '    if not change.scanned:\n        return False\n',
     '    return False\n'),
    ("a created directory covers its scanned entries", RECORD,
     'if event.kind in ("rename", "link") and (fields.get("target")',
     'if True or event.kind in ("rename", "link") and (fields.get("target")'),
    ("a tree moved in from outside does not cover its scanned entries", RECORD,
     'or fields.get("kind") == "create"):',
     'or False):'),
    ("rename and link targets are ignored", RECORD,
     'paths.update(value for value in (fields.get("path"), fields.get("target")) if value)',
     'paths.update(value for value in (fields.get("path"),) if value)'),
    ("a link from inside to outside is dropped", RECORD,
     'return {"path": path, "kind": "unlink" if event.kind == "rename" else "link"}',
     'return {"path": path, "kind": "unlink"} if event.kind == "rename" else None'),
    ("an inotify loss leaves coverage complete", RECORD,
     '    if report.lost:\n        observation["coverage"] = "unknown"\n    elif gaps:',
     '    if gaps:'),
    ("a lost tracer names no gap", RECORD,
     '    if not effects.root_exited:\n        gaps.append(',
     '    if False:\n        gaps.append('),
    ("an unresolved call names no gap", RECORD,
     '    for unknown in effects.unresolved:\n',
     '    for unknown in []:\n'),
    ("origins are not carried through renumbering", RECORD,
     '                record["origin"] = ids[source.origin]\n',
     '                pass\n'),
    ("an interactive shell is a command root", STRACE,
     '            if started.argv and _is_session_shell(started.argv):\n                continue\n',
     ''),
    ("an undecorated directory descriptor falls back to the cwd", STRACE,
     '                if base is None:\n                    raise Unresolved(dirfd)\n',
     '                if base is None:\n                    base = self.of(pid)\n'),
    ("a shared writable mmap is not a write", STRACE,
     'if len(args) >= 5 and "PROT_WRITE" in args[2] and "MAP_SHARED" in args[3]:',
     'if False:'),
    ("the exit status is dropped", STRACE,
     '            last_exec[owner].exit = status\n',
     '            pass\n'),
]
TESTS = ["-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", "tests/launch",
         "--deselect", "tests/launch/test_docker_launch.py"]


def main() -> int:
    baseline = subprocess.run([sys.executable, *TESTS], capture_output=True)
    if baseline.returncode != 0:
        print("baseline tests fail; fix them before mutating")
        return 2
    survivors = 0
    for label, path, original, mutant in MUTANTS:
        source = path.read_text()
        if source.count(original) != 1:
            print(f"MISSING {label}: the original text is not unique in {path}")
            survivors += 1
            continue
        try:
            path.write_text(source.replace(original, mutant))
            result = subprocess.run([sys.executable, *TESTS], capture_output=True)
        finally:
            path.write_text(source)
        killed = result.returncode != 0
        survivors += not killed
        print(f"{'KILLED' if killed else 'SURVIVED'} {label}")
    print(f"{len(MUTANTS) - survivors} of {len(MUTANTS)} mutants killed")
    return 1 if survivors else 0


if __name__ == "__main__":
    sys.exit(main())
