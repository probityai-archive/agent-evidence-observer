"""Run the installed root broker and enforce its declared evidence boundary."""

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

import probity_observer

source = Path(__file__).resolve().parents[1]
installed = Path(probity_observer.__file__).resolve()
if installed.is_relative_to(source):
    raise ValueError("consumer imported the source checkout")
command = str(Path(sys.executable).parent / "agent-evidence-observer")
with tempfile.TemporaryDirectory(prefix="observer-installed-") as output:
    root = Path(output)
    run = root / "sample-run"
    expected = [
        {"noDetectedGap": "true", "retryReplayed": "true", "status": "verified", "witnessScope": "PEER"},
        {"noDetectedGap": "true", "status": "verified", "witnessScope": "PEER"},
    ]
    results = []
    for action, value in zip(["demo", "verify"], expected, strict=True):
        done = subprocess.run([command, action, str(run)], cwd=root, capture_output=True, check=False)
        if done.returncode != 0 or done.stderr or json.loads(done.stdout) != value:
            raise ValueError(f"installed broker {action} failed: {done.returncode}, {done.stderr!r}")
        results.append(value)
    before = {str(p.relative_to(run)): hashlib.sha256(p.read_bytes()).hexdigest()
              for p in run.rglob("*") if p.is_file()}
    duplicate = subprocess.run([command, "demo", str(run)], cwd=root, capture_output=True, check=False)
    after = {str(p.relative_to(run)): hashlib.sha256(p.read_bytes()).hexdigest()
             for p in run.rglob("*") if p.is_file()}
    if duplicate.returncode == 0 or duplicate.stdout or before != after:
        raise ValueError("a repeated demo must refuse the nonempty destination without changing it")
    result = run / "workspace/result.txt"
    result.write_bytes(result.read_bytes() + b"altered\n")
    altered = subprocess.run([command, "verify", str(run)], cwd=root, capture_output=True, check=False)
    if altered.returncode == 0 or altered.stdout:
        raise ValueError("altered retained effects must not produce a verified result")
print(json.dumps({"installed_module": str(installed), "results": results,
                  "nonempty_destination_exit_code": duplicate.returncode,
                  "altered_effect_exit_code": altered.returncode}, sort_keys=True))
