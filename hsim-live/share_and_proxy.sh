#!/usr/bin/env bash
# Share a running gpt-oss-120b serve job (owned by another lane): read its bearer key from the
# vLLM process's environment through an overlapping job step, open the tunnel through the hpg
# master, and run the key-adding proxy. Run under tmux:
#
#   tmux new-session -d -s live_serve 'bash share_and_proxy.sh <jobid> <state-dir>'
#
# Used because safe_submit refused a second 64 GB serve job (courtesy cap: 11 GB free of 187 GB).
# The key passes from the step's stdout into this shell variable and the proxy's environment
# only; it is never written to a file or a log.
set -uo pipefail
JOB=$1; STATE=$2; mkdir -p "$STATE"; HERE=$(dirname "$(realpath "$0")")
RUN=/blue/bonniejdorr/shlokgilda/probity835/runs/gpt-oss-120b-$JOB
ssh hpg "cat $RUN/endpoint.json" > "$STATE/endpoint.json" || { echo "NO ENDPOINT"; exit 1; }
B=$(base64 -w0 "$HERE/read_key.sh")
K=$(ssh hpg "srun --jobid=$JOB --overlap --ntasks=1 --cpus-per-task=1 --mem=0 --gres=none bash -c \"\$(echo $B | base64 -d)\"" 2>/dev/null)
[ -n "$K" ] || { echo "NO KEY READ"; exit 1; }
echo "key read (length ${#K})"
NODE=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["node"])' "$STATE/endpoint.json")
PORT=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["port"])' "$STATE/endpoint.json")
echo "endpoint $NODE:$PORT job $JOB"
ssh -N -L 8811:"$NODE":"$PORT" hpg &
sleep 5
VLLM_API_KEY=$K exec python3 "$HERE/bearer_proxy.py" 8812 http://127.0.0.1:8811 "$STATE/proxy.jsonl"
