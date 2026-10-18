#!/usr/bin/env bash
# Zero-shot contracts from a live model on real repository tasks.
#
#   contract_live.sh <observer-src-with-.venv> <live-dir> <out-dir> <model-base-url>
#
# Tasks: four more-itertools bug-fix commits that add a test, fixed before the second run:
# 0e6acdf, def2dab, 67fcf64, f51a53b (the first run used 0e6acdf alone). For each, the start
# state is the commit's parent with the commit's test change applied (the new test fails there),
# the reference is the commit, and the one-line goal is the commit's own subject line, written by
# its upstream author. The model sees the start repository and the goal and proposes the
# acceptance commands and protected paths (`probity-done contract --dataset repo`, one call).
#
# A recording relay (record_relay.py) sits between the CLI and the model endpoint and keeps each
# request and response body as sent, so the response digest in a compile record can be
# recomputed, and a refused proposal still has its bytes on record.
#
# --work is passed although the repo path does not use it: at 12f74bf the CLI builds
# Path(args.work) before it branches on the dataset, so the repo path without --work crashes
# with a TypeError (measured on the first run, 2026-10-17).
# FIXES (environment) overrides the task list, to run part of it on a second box.
set -uo pipefail
SRC=$(realpath "$1"); LIVE=$(realpath "$2"); OUT=$(realpath -m "$3"); URL=$4
PD="$SRC/.venv/bin/probity-done"; PY="$SRC/.venv/bin/python"
rm -rf "$OUT"; mkdir -p "$OUT"
git clone -q https://github.com/more-itertools/more-itertools "$OUT/clone"
"$PD" keygen "$OUT/harness.seed" > "$OUT/harness.pub"
PORT=18820
for FIX in ${FIXES:-0e6acdf def2dab 67fcf64 f51a53b}; do
  T="$OUT/$FIX"; mkdir -p "$T"
  GOAL=$(git -C "$OUT/clone" log -1 --format=%s "$FIX")
  git -C "$OUT/clone" worktree add -q --detach "$T/reference" "$FIX"
  git -C "$OUT/clone" worktree add -q --detach "$T/start" "$FIX^"
  git -C "$OUT/clone" diff "$FIX^" "$FIX" -- tests | git -C "$T/start" apply
  rm -f "$T/start/.git" "$T/reference/.git"
  git -C "$OUT/clone" diff "$FIX^" "$FIX" --stat > "$T/task-diffstat.txt"
  git -C "$OUT/clone" rev-parse "$FIX" > "$T/commit.txt"
  echo "$GOAL" > "$T/goal.txt"
  PORT=$((PORT + 1))
  python3 "$LIVE/record_relay.py" "$URL" "$PORT" "$T/model" &
  RELAY=$!
  sleep 1
  echo "== $FIX: $GOAL"
  "$PD" contract --dataset repo --repo "$T/start" --reference "$T/reference" \
    --task "$GOAL" --task-id "more-itertools-$FIX" --work "$T/work" \
    --model-url "http://127.0.0.1:$PORT" --model gpt-oss-120b \
    --out "$T/contract" --harness-key "$OUT/harness.seed" --runner subprocess --python "$PY" \
    --timeout 300 > "$T/contract.txt" 2>&1
  echo "CONTRACT_RC=$?" >> "$T/contract.txt"
  kill "$RELAY"; wait "$RELAY" 2>/dev/null
  cat "$T/contract.txt"
done
rm -rf "$OUT/clone" "$OUT/harness.seed"
exit 0
