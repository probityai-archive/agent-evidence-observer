#!/usr/bin/env bash
set -u -o pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 NEW_RESULT_DIRECTORY" >&2
  exit 64
fi

profile="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
root="$(cd "$profile/../.." && pwd -P)"
requested_results="$1"
results_parent="$(dirname -- "$requested_results")"
results_name="$(basename -- "$requested_results")"

if [[ -z "$results_name" || "$results_name" == "." || "$results_name" == ".." || \
      ! -d "$results_parent" ]]; then
  echo "result path must name a new child of an existing directory" >&2
  exit 2
fi
results_parent="$(cd "$results_parent" && pwd -P)"
results="$results_parent/$results_name"
if [[ -e "$results" || -L "$results" ]]; then
  echo "result path already exists: $results" >&2
  exit 2
fi
mkdir "$results" || exit 2

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

run_stage source-shallow \
  git -C "$root" rev-parse --is-shallow-repository || \
  exit "$stage_code"
if [[ "$(<"$results/source-shallow.stdout")" != "false" ]]; then
  printf '%s\n' "source repository is shallow; full source custody is unavailable" \
    > "$results/source-depth.stderr"
  printf '%s\n' 2 > "$results/source-depth.exit"
  exit 2
fi
printf '%s\n' 0 > "$results/source-depth.exit"

run_stage select-source-commit git -C "$root" rev-parse HEAD || \
  exit "$stage_code"
source_commit="$(<"$results/select-source-commit.stdout")"
run_stage select-source-epoch \
  git -C "$root" show -s --format=%ct "$source_commit" || \
  exit "$stage_code"
source_date_epoch="$(<"$results/select-source-epoch.stdout")"
if [[ ! "$source_date_epoch" =~ ^[0-9]+$ ]]; then
  printf '%s\n' "source commit has no valid timestamp" \
    > "$results/source-epoch.stderr"
  printf '%s\n' 2 > "$results/source-epoch.exit"
  exit 2
fi
printf '%s\n' 0 > "$results/source-epoch.exit"

run_stage bundle-source-at-commit \
  git -C "$root" bundle create "$results/source.bundle" HEAD || \
  exit "$stage_code"
run_stage list-bundle-head \
  git bundle list-heads "$results/source.bundle" || \
  exit "$stage_code"
if [[ "$(<"$results/list-bundle-head.stdout")" != "$source_commit HEAD" ]]; then
  printf '%s\n' "source HEAD changed while source custody was created" \
    > "$results/source-selection.stderr"
  printf '%s\n' 2 > "$results/source-selection.exit"
  exit 2
fi
printf '%s\n' 0 > "$results/source-selection.exit"

run_stage archive-source-at-commit \
  git -C "$root" -c core.autocrlf=false -c core.eol=lf archive \
    --format=tar --output="$results/source-at-commit.tar" \
    "$source_commit" || \
  exit "$stage_code"
mkdir -p "$results/test-source"
run_stage extract-source-at-commit \
  tar -xpf "$results/source-at-commit.tar" -C "$results/test-source" || \
  exit "$stage_code"
snapshot_root="$results/test-source"
snapshot_profile="$snapshot_root/interop/refund-handoff-conformance-2026-10-12"

run_stage create-venv uv venv "$results/.venv" --python python3.12 || \
  exit "$stage_code"
python="$results/.venv/bin/python"
if [[ ! -x "$python" ]]; then
  python="$results/.venv/Scripts/python.exe"
fi

run_stage install-locked-dependencies \
  uv pip install --python "$python" --require-hashes \
    -r "$snapshot_profile/requirements.lock" || \
  exit "$stage_code"

mkdir -p "$results/dist"
run_stage build-wheel \
  env SOURCE_DATE_EPOCH="$source_date_epoch" uv build --wheel --python "$python" \
    --build-constraints "$snapshot_profile/requirements.lock" --require-hashes \
    --out-dir "$results/dist" "$snapshot_root" || \
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

run_stage wheel-requirement "$python" -I -B - "$wheel" <<'PY'
from pathlib import Path
import hashlib
import sys

wheel = Path(sys.argv[1]).resolve(strict=True)
digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
print(f"agent-evidence-observer @ {wheel.as_uri()}#sha256={digest}")
PY
if [[ $stage_code -ne 0 ]]; then
  exit "$stage_code"
fi
wheel_requirement="$(<"$results/wheel-requirement.stdout")"
run_stage install-wheel \
  uv pip install --python "$python" --no-deps "$wheel_requirement" || \
  exit "$stage_code"
run_stage pip-check uv pip check --python "$python" || exit "$stage_code"

console="$results/.venv/bin/agent-evidence-read-refund-handoff"
if [[ ! -x "$console" ]]; then
  console="$results/.venv/Scripts/agent-evidence-read-refund-handoff.exe"
fi
if [[ ! -x "$console" ]]; then
  printf '%s\n' "installed console entry point is unavailable" \
    > "$results/console-entrypoint-select.stderr"
  printf '%s\n' 2 > "$results/console-entrypoint-select.exit"
  exit 2
fi
printf '%s\n' "$console" > "$results/console-entrypoint-select.stdout"
printf '%s\n' 0 > "$results/console-entrypoint-select.exit"

run_stage console-entrypoint-help "$console" --help || exit "$stage_code"
run_stage console-entrypoint-baseline \
  "$console" \
    --bundle "$snapshot_profile/fixtures/vectors/01-observed-success.json" \
    --trust-snapshot "$snapshot_profile/fixtures/trust/baseline.json" || \
  exit "$stage_code"
run_stage console-entrypoint-baseline-check \
  "$python" -I -B - \
    "$snapshot_profile/fixtures/vector-manifest.json" \
    "$results/console-entrypoint-baseline.stdout" \
    "$results/console-entrypoint-baseline.stderr" <<'PY'
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

manifest = json.loads(Path(sys.argv[1]).read_bytes())
stdout = Path(sys.argv[2]).read_bytes()
stderr = Path(sys.argv[3]).read_bytes()
selected = [
    item for item in manifest["vectors"] if item["case"] == "01-observed-success"
]
if len(selected) != 1 or selected[0]["expected"]["exit"] != 0:
    raise SystemExit("baseline vector expectation is unavailable")
if stderr:
    raise SystemExit("console baseline wrote stderr")
actual = hashlib.sha256(stdout).hexdigest()
expected = selected[0]["expected"]["report_sha256"]
if actual != expected:
    raise SystemExit(f"console baseline digest differs: {actual}")
print(actual)
PY
if [[ $stage_code -ne 0 ]]; then
  exit "$stage_code"
fi

run_stage write-provenance \
  "$python" -I -B - "$source_commit" "$snapshot_profile" "$wheel" \
    "$results/source.bundle" "$results/source-at-commit.tar" \
    "$results/provenance.json" <<'PY'
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import platform
import shutil
import subprocess
import sys

def sha256(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(65_536), b""):
            value.update(block)
    return value.hexdigest()


source_commit = sys.argv[1]
profile = Path(sys.argv[2]).resolve()
wheel = Path(sys.argv[3]).resolve()
source_bundle = Path(sys.argv[4]).resolve()
source_archive = Path(sys.argv[5]).resolve()
output = Path(sys.argv[6]).resolve()
python_executable = Path(sys.executable).resolve(strict=True)
uv_executable_raw = shutil.which("uv")
if uv_executable_raw is None:
    raise SystemExit("uv executable is unavailable")
uv_executable = Path(uv_executable_raw).resolve(strict=True)
document = {
    "schema": "probity-refund-handoff-run-provenance-v0.1",
    "profile": "https://probityai.github.io/agent-evidence-observer/contract/refund-handoff/0.1",
    "source": {
        "commit": source_commit,
        "dirty": False,
        "bundle_file": source_bundle.name,
        "bundle_sha256": sha256(source_bundle),
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
        "python_sha256": sha256(python_executable),
        "platform": platform.platform(),
        "uv": subprocess.check_output(
            [str(uv_executable), "--version"], text=True
        ).strip(),
        "uv_sha256": sha256(uv_executable),
    },
    "locks": {
        "requirements_file": "requirements.lock",
        "requirements_sha256": sha256(profile / "requirements.lock"),
    },
}
output.write_bytes(
    json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii")
)
PY
if [[ $stage_code -ne 0 ]]; then
  exit "$stage_code"
fi

run_stage focused-tests \
  "$python" -I -B -m pytest "$snapshot_root/interop/refund-handoff-conformance-2026-10-12/tests/test_refund_handoff.py" -q || \
  exit "$stage_code"

mkdir -p "$results/evidence-source"
run_stage extract-evidence-source \
  tar -xpf "$results/source-at-commit.tar" -C "$results/evidence-source" || \
  exit "$stage_code"
evidence_profile="$results/evidence-source/interop/refund-handoff-conformance-2026-10-12"

run_stage corpus \
  "$python" -I -B "$evidence_profile/run_corpus.py" \
    --profile "$evidence_profile" \
    --output "$results/vector-results" \
    --provenance "$results/provenance.json" || \
  exit "$stage_code"

echo "refund handoff corpus passed; complete retained evidence is in $results"
