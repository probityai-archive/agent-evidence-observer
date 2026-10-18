"""Forward HTTP requests to the HiPerGator vLLM tunnel, adding the bearer key.

    VLLM_API_KEY=<key> python3 bearer_proxy.py <listen-port> <upstream-base-url> <log>

The key lives only in this process's environment; neither the agent, the observer records nor
the gate box ever see it. Each request is logged as one JSON line (time, path, status, bytes in
and out, seconds), never with its body or headers.
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

KEY = os.environ.pop("VLLM_API_KEY")
PORT, UPSTREAM, LOG = int(sys.argv[1]), sys.argv[2].rstrip("/"), sys.argv[3]


class Handler(BaseHTTPRequestHandler):
    def _forward(self) -> None:
        start = time.time()
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None
        request = urllib.request.Request(UPSTREAM + self.path, data=body, method=self.command,
                                         headers={"Content-Type": "application/json",
                                                  "Authorization": f"Bearer {KEY}"})
        try:
            with urllib.request.urlopen(request, timeout=1800) as reply:
                status, data = reply.status, reply.read()
        except urllib.error.HTTPError as error:
            status, data = error.code, error.read()
        except Exception as error:  # upstream unreachable: answer 502 with the error text
            status, data = 502, json.dumps({"error": repr(error)}).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
        with open(LOG, "a") as log:
            log.write(json.dumps({"t": round(start, 3), "path": self.path, "status": status,
                                  "in": length, "out": len(data),
                                  "s": round(time.time() - start, 3)}) + "\n")

    do_GET = do_POST = _forward

    def log_message(self, *args: object) -> None:
        pass


ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
