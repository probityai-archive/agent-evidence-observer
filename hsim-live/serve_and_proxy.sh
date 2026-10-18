#!/usr/bin/env bash
# Submit a gpt-oss-120b serve job on HiPerGator with a fresh bearer key, wait for its endpoint,
# open the tunnel through the hpg master, and run the key-adding proxy. Run under tmux:
#
#   tmux new-session -d -s live_serve 'bash serve_and_proxy.sh <state-dir>'
#
# The key is generated here and exists only in this shell and the proxy's environment.
set -uo pipefail
STATE=$1; mkdir -p "$STATE"; HERE=$(dirname "$(realpath "$0")")
K=$(python3 -c 'import secrets;print(secrets.token_urlsafe(24))')
echo "$K" | ssh hpg 'read -r K; cd /blue/bonniejdorr/shlokgilda/probity835/jobs; HPG_IS_CANARY_RUN=1 VLLM_API_KEY=$K ~/bin/safe_submit --job-name=p835live-serve-gpt-oss-120b serve_gpt-oss-120b.sbatch' \
  > "$STATE/submit.txt" 2>&1
JOB=$(grep -oE 'Submitted batch job [0-9]+' "$STATE/submit.txt" | awk '{print $4}')
[ -n "$JOB" ] || { echo "SUBMIT FAILED"; cat "$STATE/submit.txt"; exit 1; }
echo "$JOB" > "$STATE/job.txt"; echo "job $JOB"
until ssh hpg "cat /blue/bonniejdorr/shlokgilda/probity835/runs/gpt-oss-120b-$JOB/endpoint.json" > "$STATE/endpoint.json" 2>/dev/null; do
  sleep 60
done
NODE=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["node"])' "$STATE/endpoint.json")
PORT=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["port"])' "$STATE/endpoint.json")
echo "endpoint $NODE:$PORT"
ssh -N -L 8811:"$NODE":"$PORT" hpg &
sleep 5
VLLM_API_KEY=$K exec python3 "$HERE/bearer_proxy.py" 8812 http://127.0.0.1:8811 "$STATE/proxy.jsonl"
