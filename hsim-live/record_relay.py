"""Relay POSTs to an OpenAI-compatible endpoint and keep each request and response body.

    python3 record_relay.py <upstream-base-url> <listen-port> <record-dir>

Writes <record-dir>/call-<n>.request.json and call-<n>.response.json byte for byte, so a
digest computed by the caller over the model's answer can be recomputed from the record.
"""

import itertools
import pathlib
import sys
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

UPSTREAM, PORT, DIR = sys.argv[1].rstrip("/"), int(sys.argv[2]), pathlib.Path(sys.argv[3])
DIR.mkdir(parents=True, exist_ok=True)
COUNT = itertools.count(1)


class Relay(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        request = urllib.request.Request(UPSTREAM + self.path, data=body,
                                         headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=900) as reply:
            data = reply.read()
        n = next(COUNT)
        (DIR / f"call-{n}.request.json").write_bytes(body)
        (DIR / f"call-{n}.response.json").write_bytes(data)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args: object) -> None:
        pass


HTTPServer(("127.0.0.1", PORT), Relay).serve_forever()
