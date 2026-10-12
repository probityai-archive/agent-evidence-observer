#!/usr/bin/env bash
set -u -o pipefail

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

stage_code=0
run_stage() {
  local name="$1"
  shift
  {
    printf '%q ' "$@"
    printf '\n'
  } > "$results/$name.command"
  if "$@" > "$results/$name.stdout" 2> "$results/$name.stderr"; then
    stage_code=0
  else
    stage_code=$?
  fi
  printf '%s\n' "$stage_code" > "$results/$name.exit"
  return "$stage_code"
}

run_stage source-status git -C "$root" status --porcelain=v1 --untracked-files=all || \
  exit "$stage_code"
if [[ -s "$results/source-status.stdout" ]]; then
  printf '%s\n' "source worktree is not clean; refusing non-repeatable evidence" \
    > "$results/source-clean.stderr"
  printf '%s\n' 2 > "$results/source-clean.exit"
  exit 2
fi
printf '%s\n' 0 > "$results/source-clean.exit"

run_stage create-venv uv venv "$results/.venv" --python python3.12 || \
  exit "$stage_code"
python="$results/.venv/bin/python"

run_stage install-locked-dependencies \
  uv pip install --python "$python" --require-hashes -r "$profile/requirements.lock" || \
  exit "$stage_code"

mkdir -p "$results/dist"
run_stage build-wheel \
  uv build --wheel --python "$python" \
    --build-constraints "$profile/requirements.lock" --require-hashes \
    --out-dir "$results/dist" "$root" || \
  exit "$stage_code"

shopt -s nullglob
wheels=("$results"/dist/*.whl)
shopt -u nullglob
if [[ ${#wheels[@]} -ne 1 ]]; then
  printf 'expected one wheel, found %s\n' "${#wheels[@]}" > "$results/select-wheel.stderr"
  printf '%s\n' 2 > "$results/select-wheel.exit"
  exit 2
fi
wheel="${wheels[0]}"
printf '%s\n' "$wheel" > "$results/select-wheel.stdout"
printf '%s\n' 0 > "$results/select-wheel.exit"

run_stage install-wheel uv pip install --python "$python" --no-deps "$wheel" || \
  exit "$stage_code"
run_stage pip-check uv pip check --python "$python" || exit "$stage_code"

source_commit="$(git -C "$root" rev-parse HEAD)"
run_stage archive-source-at-commit \
  git -C "$root" archive --format=tar --output="$results/source-at-commit.tar" \
    "$source_commit" || \
  exit "$stage_code"

run_stage write-provenance \
  "$python" - "$root" "$profile" "$wheel" "$results/source-at-commit.tar" \
    "$results/provenance.json" <<'PY'
from __future__ import annotations

import hashlib
from pathlib import Path
import platform
import subprocess
import sys

from probity_observer.crypto import canonical


def sha256(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(65_536), b""):
            value.update(block)
    return value.hexdigest()


root = Path(sys.argv[1]).resolve()
profile = Path(sys.argv[2]).resolve()
wheel = Path(sys.argv[3]).resolve()
source_archive = Path(sys.argv[4]).resolve()
output = Path(sys.argv[5]).resolve()
git = lambda *args: subprocess.check_output(
    ["git", "-C", str(root), *args], text=True
).strip()
document = {
    "schema": "probity-refund-handoff-run-provenance-v0.1",
    "profile": "https://probityai.github.io/agent-evidence-observer/contract/refund-handoff/0.1",
    "source": {
        "commit": git("rev-parse", "HEAD"),
        "tree": git("rev-parse", "HEAD^{tree}"),
        "dirty": False,
        "archive_file": source_archive.name,
        "archive_sha256": sha256(source_archive),
    },
    "wheel": {
        "file": wheel.name,
        "sha256": sha256(wheel),
        "size": wheel.stat().st_size,
    },
    "environment": {
        "python": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "uv": subprocess.check_output(["uv", "--version"], text=True).strip(),
    },
    "locks": {
        "requirements_file": "requirements.lock",
        "requirements_sha256": sha256(profile / "requirements.lock"),
    },
}
output.write_bytes(canonical(document))
PY
if [[ $stage_code -ne 0 ]]; then
  exit "$stage_code"
fi

run_stage focused-tests \
  "$python" -m pytest "$root/tests/test_refund_handoff.py" -q || \
  exit "$stage_code"

run_stage corpus \
  "$python" "$profile/run_corpus.py" \
    --verifier "$results/.venv/bin/agent-evidence-read-refund-handoff" \
    --profile "$profile" \
    --output "$results/vector-results" \
    --provenance "$results/provenance.json" || \
  exit "$stage_code"

echo "refund handoff corpus passed; complete retained evidence is in $results"
