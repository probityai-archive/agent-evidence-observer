#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 NEW_RESULT_DIRECTORY" >&2
  exit 64
fi

profile="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
root="$(cd "$profile/../.." && pwd -P)"
results="$1"

if [[ -e "$results" ]]; then
  echo "result path already exists: $results" >&2
  exit 2
fi
mkdir -p "$results"

uv venv "$results/.venv" --python python3.12
python="$results/.venv/bin/python"
uv pip install --python "$python" --require-hashes -r "$profile/requirements.lock"
uv pip install --python "$python" --no-deps -e "$root"
uv pip check --python "$python" > "$results/pip-check.log" 2>&1

set +e
"$python" -m pytest "$root/tests/test_refund_handoff.py" -q > "$results/pytest.log" 2>&1
test_status=$?
set -e
printf '%s\n' "$test_status" > "$results/pytest.exit"
if [[ $test_status -ne 0 ]]; then
  echo "refund handoff tests failed; retained in $results" >&2
  exit "$test_status"
fi

"$python" "$profile/run_corpus.py" \
  --verifier "$results/.venv/bin/agent-evidence-read-refund-handoff" \
  --profile "$profile" \
  --output "$results/vector-results"

echo "refund handoff corpus passed; retained in $results"
