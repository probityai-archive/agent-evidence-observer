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
TREE = Path("src/probity_observer/sensors/treedigest.py")
INOTIFY = Path("src/probity_observer/sensors/inotify.py")
APPTAINER = Path("src/probity_observer/launch/backend_apptainer.py")
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
    ("an exec records argv[0] instead of the executed path", STRACE,
     '        exe = resolve.path(pid, string_arg(args[0]))\n',
     '        exe = string_arg(args[0])\n'),
    ("an exec records the launch directory instead of its own", STRACE,
     'cwd=resolve.of(pid),', 'cwd=resolve.start,'),
    ("an exec records every environment member", STRACE,
     '        if sep and key in LOADER_ENV:\n', '        if sep:\n'),
    ("a mutation outside the workspace leaves no observation entry", RECORD,
     '            rows.append((event.time, outside, event, True))\n',
     '            pass\n'),
    ("a .pth file is not a grader path", RECORD,
     ' or name.endswith(".pth")', ''),
    ("a site-packages directory is not a grader path", RECORD,
     '            or any(part in GRADER_DIRECTORIES for part in parts[:-1])):',
     '            ):'),
    ("an outside mutation carries no origin", RECORD,
     '            if source.origin is not None and source.origin in ids:\n',
     '            if source.origin is not None and source.origin in ids and not outside:\n'),
    ("a lost tracer on a shared uid is not the agent's", RECORD,
     'return "agent" if signalled or not context.tracer_uid_separated else "host"',
     'return "agent" if signalled else "host"'),
    ("a signal the tracer died on is ignored", RECORD,
     'item["status"] == "interrupted" and item["outside_tree"]', 'False'),
    ("a timed-out run's lost tracer is not the host's", RECORD,
     '    if context.timed_out:\n        return "host"\n', ''),
    ("an inotify overflow names no gap", RECORD,
     '    for window in report.overflows:\n', '    for window in []:\n'),
    ("an overflow during an agent burst is not the agent's", RECORD,
     '            return "agent"\n    return "unknown"', '            return "unknown"\n    return "unknown"'),
    ("unparsed lines on a shared uid are not the agent's", RECORD,
     '"sensor" if context.tracer_uid_separated else "agent"', '"sensor"'),
    ("an overflow window starts at the last read, not the last empty queue", INOTIFY,
     '        if len(buffer) < READ_SIZE:\n            self._empty_at = now\n',
     '        self._empty_at = now\n'),
    ("a failed call counts as an effect", STRACE,
     '        if _failed(call) and not (name in CONNECT and _in_progress(call.result)):\n            continue\n',
     ''),
    ("an in-progress connect is dropped", STRACE,
     ' and not (name in CONNECT and _in_progress(call.result))', ''),
    ("a cut-off final line is a trace error", STRACE,
     '            if number == last and _cut_off(', '            if False and _cut_off('),
    ("a delivered signal outside the tree is not an escape", STRACE,
     '        if record["status"] == "ok" and record["outside_tree"]',
     '        if False and record["status"] == "ok" and record["outside_tree"]'),
    ("a root-mapped fakeroot namespace counts as uid separation", APPTAINER,
     '        return mapped(self.uid_map, 0) and mapped(self.uid_map, AGENT_UID)\n',
     '        return bool(self.uid_map)\n'),
    ("a uid map line covers one uid past its count", APPTAINER,
     '        if inside <= uid < inside + count:\n', '        if inside <= uid <= inside + count:\n'),
    ("a symbolic link leaves the tree digest unchanged", TREE,
     '    for name, target in fields["symlinks"].items():\n',
     '    for name, target in {}.items():\n'),
    ("a special file leaves the tree digest unchanged", TREE,
     '    for name, kind in fields["special"].items():\n',
     '    for name, kind in {}.items():\n'),
    ("an execute bit leaves the tree digest unchanged", TREE,
     '("x:" if name in executable else "")',
     '("" if name in executable else "")'),
    ("a symbolic link to a directory is not listed", TREE,
     '            if entry.is_symlink():\n                tree.symlinks',
     '            if False:\n                tree.symlinks'),
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
