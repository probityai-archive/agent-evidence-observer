# Runs inside an overlapping step of the serve job: print the vLLM server's bearer key.
for p in $(pgrep -u "$USER" -f "vllm"); do
  tr '\0' '\n' < /proc/$p/environ 2>/dev/null | sed -n 's/^VLLM_API_KEY=//p'
done | head -1
