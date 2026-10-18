#!/bin/bash
# Negative control: the same fake-strace launch on the code before the tracer image (07d8dab).
set -u
git checkout -q 07d8dab -- src
git diff --stat 07d8dab -- src | tail -1; echo "src at 07d8dab: $(git diff --quiet 07d8dab -- src && echo yes || echo no)"
uv sync --all-extras --frozen > /tmp/nx-sync.log 2>&1 || { echo SYNC_FAILED; exit 1; }
docker build -q -t probity-observer-fake-strace:control tests/nemoclaw/fake-strace-image > /dev/null
T=$(mktemp -d); mkdir $T/ws; echo before > $T/ws/a.txt
uv run --frozen python -c "import sys; sys.path.insert(0, '.'); from tests.nemoclaw.test_openshell_live import POLICY; print(POLICY, end='')" > $T/policy.yaml; head -1 $T/policy.yaml
uv run --frozen python - "$T" <<'PY'
import json, sys
from pathlib import Path
from probity_observer.launch import launch_agent
t = Path(sys.argv[1])
spec = launch_agent.LaunchSpec(backend="openshell", image="probity-observer-fake-strace:control",
    agent_argv=("python3", "-c", "import pathlib; pathlib.Path('a.txt').write_text('after\\n')"),
    workspace=t / "ws", claim_id="control", invocation_id="control-1", network_policy=t / "policy.yaml",
    timeout_seconds=300)
try:
    r = launch_agent.launch(spec, t / "run")
    rec = json.loads((r.run_dir / "receipt.json").read_bytes())
    print("CONTROL tracer:", rec["sensors"]["tracer"], "coverage:", rec["coverage"],
          "s2:", rec["sensors"]["s2_strace"].get("tracer"), "unattributed:", rec["sensors"]["join"]["unattributed"])
except Exception as e:
    print("CONTROL launch raised:", type(e).__name__, e)
    for f in sorted((t / "run").glob("*")):
        if f.name in ("tracer.jsonl", "trace.txt"):
            print("CONTROL", f.name, repr(f.read_text()[:300]))
PY
docker image rm -f probity-observer-fake-strace:control > /dev/null; rm -rf $T
git checkout -q HEAD -- src
