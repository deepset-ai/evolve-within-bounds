# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0
"""The sandbox's long-running process: GET /health answers 200. Scans run separately, through `security-agent`."""

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Health(BaseHTTPRequestHandler):
    """Answers GET /health."""

    def do_GET(self) -> None:  # noqa: N802 - the standard library's name
        """200 on /health, 404 elsewhere."""
        ok = self.path.rstrip("/") in ("", "/health")
        body = json.dumps({"status": "ok", "platform": "security-agent"} if ok else {"status": "not_found"}).encode()
        self.send_response(200 if ok else 404)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        """Keep the sandbox's log quiet."""


def main() -> None:
    """Serve until the sandbox stops."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8661)
    args = parser.parse_args()
    ThreadingHTTPServer((args.host, args.port), Health).serve_forever()


if __name__ == "__main__":
    main()
