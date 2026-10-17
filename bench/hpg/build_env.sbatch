#!/bin/bash
# Build the locked serving environment from pyproject.toml and uv.lock. CPU only, no GPU needed.
# Submit with submit.sh, which supplies the account, QOS and log path from the environment.
#SBATCH --job-name=hpg-env-build
#SBATCH --partition=hpg-default
#SBATCH --cpus-per-task=4
#SBATCH --mem=16gb
#SBATCH --time=02:00:00
set -euo pipefail
: "${HPG_BLUE_DIR:?set HPG_BLUE_DIR to the work area on the parallel filesystem}"
: "${HPG_VENV:?set HPG_VENV to the path the environment is built at (a new path, never an existing venv)}"
SRC=${HPG_ENV_SRC:-${SLURM_SUBMIT_DIR:?}}
if [ ! -f "$SRC/uv.lock" ] || [ ! -f "$SRC/pyproject.toml" ]; then echo "FATAL: no pyproject.toml and uv.lock in $SRC"; exit 2; fi
[ ! -e "$HPG_VENV" ] || { echo "FATAL: $HPG_VENV already exists; build at a new path"; exit 2; }
export UV_CACHE_DIR=$HPG_BLUE_DIR/cache/uv UV_LINK_MODE=copy
export UV_PROJECT_ENVIRONMENT=$HPG_VENV
echo "BUILD src=$SRC venv=$HPG_VENV lock_sha256=$(sha256sum "$SRC/uv.lock" | cut -d' ' -f1) start=$(date -Is)"
# --frozen: install exactly what uv.lock records, never re-resolve.
uv sync --frozen --project "$SRC" --no-install-project
uv pip freeze --python "$HPG_VENV/bin/python" > "$HPG_VENV/freeze.txt"
cp "$SRC/uv.lock" "$HPG_VENV/uv.lock.used"
# Every exact pin in pyproject.toml must be what the environment holds, and the environment must be consistent.
"$HPG_VENV/bin/python" - "$SRC/pyproject.toml" <<'PY'
import importlib.metadata as m
import re
import sys
import tomllib

deps = tomllib.load(open(sys.argv[1], "rb"))["project"]["dependencies"]
for dep in deps:
    match = re.fullmatch(r"([A-Za-z0-9_.-]+)==([^\s;]+)", dep)
    if not match:
        continue
    name, want = match.groups()
    got = m.version(name)
    print(f"CHECK {name} {got}")
    assert got == want, (name, got, want)
PY
uv pip check --python "$HPG_VENV/bin/python"
echo "BUILD_OK end=$(date -Is) packages=$(wc -l < "$HPG_VENV/freeze.txt")"
