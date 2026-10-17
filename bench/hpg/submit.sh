#!/bin/bash
# Submit a template from this directory through the host-memory budget wrapper.
#   HPG_ACCOUNT=... HPG_QOS=... HPG_BLUE_DIR=... HPG_VENV=... ./submit.sh serve_gpt-oss-120b.sbatch [sbatch args]
# Account, QOS and the log path come from the environment, so the templates carry no site literals.
# HPG_SUBMIT names the submit command (default safe_submit, the budget-capped wrapper; plain sbatch otherwise).
set -euo pipefail
: "${HPG_ACCOUNT:?}" "${HPG_QOS:?}" "${HPG_BLUE_DIR:?}"
script=${1:?usage: submit.sh <template.sbatch> [sbatch args]}
shift
mkdir -p "$HPG_BLUE_DIR/logs"
cd "$(dirname "$(readlink -f "$script")")"
exec "${HPG_SUBMIT:-safe_submit}" --account="$HPG_ACCOUNT" --qos="$HPG_QOS" \
  --output="$HPG_BLUE_DIR/logs/%x-%j.out" --export=ALL "$@" "$(basename "$script")"
