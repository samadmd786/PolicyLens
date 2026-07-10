#!/usr/bin/env python3
"""LOCAL DEV ONLY — serve the frontend and run the handler on one origin.

This is a convenience for walking the frontend test checklist before deploying.
It is NOT the production stack: the real deployment is Amplify (static frontend)
plus a Lambda Function URL. Do not use this to host the app.

It serves everything in frontend/ and answers POST /analyze by calling
backend.handler.analyze directly. If AWS creds are present (e.g.
AWS_PROFILE=policylens) it uses real Bedrock; otherwise the handler degrades to
Layer 1 findings, which is fine for testing the UI.

Usage:
    AWS_PROFILE=policylens .venv/bin/python scripts/dev_server.py
    # then open http://localhost:8000
"""

from __future__ import annotations

import json
import sys
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
FRONTEND = REPO_ROOT / "frontend"

from backend.handler import analyze  # noqa: E402

PORT = 8000


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(FRONTEND), **kwargs)

    def log_message(self, *args):  # keep the console quiet
        pass

    def do_POST(self):
        if self.path.rstrip("/") != "/analyze":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8") if length else ""
        try:
            body = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            body = {}
        policy_input = body.get("policy", raw)
        result = analyze(policy_input)  # real Bedrock if creds exist, else degraded
        payload = json.dumps(result).encode("utf-8")
        self.send_response(200 if result.get("ok") else 400)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(payload)


def main() -> int:
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"PolicyLens dev server on http://localhost:{PORT}  (Ctrl+C to stop)")
    print("Using real Bedrock if AWS creds are set; otherwise degraded mode.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
