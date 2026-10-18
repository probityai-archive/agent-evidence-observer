#!/usr/bin/env bash
# The live loop: gpt-oss-120b (HiPerGator vLLM, reached through a tunnel) runs as the agent under
# `probity-done run` on LiveCodeBench-hard tasks; each refused attempt's replan reason goes back
# to the agent in PROBITY_DONE_FEEDBACK and the next attempt is graded.
#
#   run_live.sh <observer-src-with-.venv> <live-dir> <out-dir> <model-url-on-box> [parallel]
#
# <model-url-on-box> is the OpenAI-compatible base URL as seen from the box (the tunnel lands on
# 127.0.0.1:<port>); containers reach it on the docker0 address through a forwarder this script
# starts. Every loop writes its records under <out-dir>/<task>-<split>/ as it goes, so a stopped
# run keeps every attempt it graded.
set -uo pipefail
SRC=$(realpath "$1"); LIVE=$(realpath "$2"); OUT=$(realpath -m "$3"); URL=$4; PAR=${5:-3}
PD="$SRC/.venv/bin/probity-done"; PY="$SRC/.venv/bin/python"
IMAGE=probity-observer-agent-test:local
PORT=${URL##*:}; PORT=${PORT%%/*}
GW=$(ip -4 -o addr show docker0 | awk '{print $4}' | cut -d/ -f1)
mkdir -p "$OUT/keys"

# Containers on the bridge reach the host's docker0 address, not its loopback.
python3 - "$GW" "$PORT" <<'EOF' &
import socket, sys, threading
gw, port = sys.argv[1], int(sys.argv[2])
server = socket.socket(); server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((gw, port)); server.listen(64)
def pipe(a, b):
    try:
        while (data := a.recv(65536)):
            b.sendall(data)
    except OSError:
        pass
    finally:
        try:
            b.shutdown(socket.SHUT_WR)
        except OSError:
            pass
while True:
    client, _ = server.accept()
    upstream = socket.create_connection(("127.0.0.1", port))
    for a, b in ((client, upstream), (upstream, client)):
        threading.Thread(target=pipe, args=(a, b), daemon=True).start()
EOF
FWD=$!
trap 'kill $FWD 2>/dev/null' EXIT
sleep 1

for role in harness host grader; do
  [ -f "$OUT/keys/$role.seed" ] || "$PD" keygen "$OUT/keys/$role.seed" > "$OUT/keys/$role.pub"
done
docker build -q -t "$IMAGE" "$SRC/tests/launch/image" > "$OUT/image.txt"
B64=$(base64 -w0 "$LIVE/agent.py")
AGENT_URL="http://$GW:$PORT"

one() {
  local rec=$1 name; name=$(basename "$rec" .json); local dir="$OUT/$name"
  [ -f "$dir/DONE" ] && { echo "$name: already done"; return 0; }
  rm -rf "$dir"; mkdir -p "$dir"
  local tid; tid=$("$PY" -c 'import json,sys;print(json.load(open(sys.argv[1]))["task_id"])' "$rec")
  echo "$name: contract $(date -u +%H:%M:%S)"
  "$PD" contract --dataset lcb --record "$rec" --work "$dir/work" --out "$dir/contract" \
    --harness-key "$OUT/keys/harness.seed" --runner subprocess --python "$PY" --timeout 120 \
    > "$dir/contract.txt" 2>&1
  echo "CONTRACT_RC=$?" >> "$dir/contract.txt"
  if ! grep -q '^CONTRACT_RC=0' "$dir/contract.txt"; then touch "$dir/DONE"; echo "$name: contract refused"; return 0; fi
  echo "$name: loop $(date -u +%H:%M:%S)"
  "$PD" run --contract "$dir/contract" --out "$dir/loop" --image "$IMAGE" --task-id "$tid" \
    --attempts 3 --timeout 1800 --network \
    --harness-key "$OUT/keys/harness.seed" --host-key "$OUT/keys/host.seed" \
    --grader-key "$OUT/keys/grader.seed" -- \
    python3 -c "import base64; exec(base64.b64decode('$B64'))" "$AGENT_URL" gpt-oss-120b 40 \
    > "$dir/run.txt" 2>&1
  echo "RUN_RC=$?" >> "$dir/run.txt"
  for attempt in "$dir"/loop/attempt-*; do
    [ -f "$attempt/done-receipt.dsse.json" ] || continue
    "$PD" verify --run "$attempt" --harness-pub "$(cat "$OUT/keys/harness.pub")" \
      --host-pub "$(cat "$OUT/keys/host.pub")" --grader-pub "$(cat "$OUT/keys/grader.pub")" \
      > "$attempt/verify.txt" 2>&1
    echo "VERIFY_RC=$?" >> "$attempt/verify.txt"
  done
  touch "$dir/DONE"; echo "$name: done $(date -u +%H:%M:%S) $(tail -1 "$dir/run.txt")"
}
export -f one; export OUT PD PY IMAGE B64 AGENT_URL
ls "$LIVE"/tasks/*.json | xargs -P "$PAR" -I{} bash -c 'one "$@"' _ {}
echo "LIVE EXIT=0"
