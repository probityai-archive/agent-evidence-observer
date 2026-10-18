#!/bin/bash
set -u
uv sync --all-extras --frozen > /tmp/nx-sync.log 2>&1 || { echo SYNC_FAILED; cat /tmp/nx-sync.log; exit 1; }
uv run --frozen ruff check src tests; echo "ruff_exit=$?"
uv run --frozen python -m pytest -q -p no:cacheprovider tests/done tests/nemoclaw tests/witness ${EXTRA:-}; echo "pytest_exit=$?"
