"""Tiny in-process fake OPA (threaded ``http.server``) for provider tests.

``policy(input) -> result`` supplies the Data API ``result`` value; ``raw`` overrides the whole exchange
(``(status, body_bytes, headers)``). ``calls`` records every request (path, headers, parsed body).
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


class FakeOPA:
    def __init__(self, policy: Callable[[dict[str, Any]], Any] | None = None) -> None:
        self.policy = policy or (lambda i: True)
        self.raw: Callable[[dict[str, Any]], tuple[int, bytes, dict[str, str]]] | None = None
        self.delay = 0.0
        self.calls: list[dict[str, Any]] = []
        self.on_call: Callable[[], None] | None = None
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a: Any) -> None:  # silence
                pass

            def do_POST(self) -> None:
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n) or b"{}")
                outer.calls.append({"path": self.path, "headers": dict(self.headers), "body": body})
                if outer.on_call:
                    outer.on_call()
                if outer.delay:
                    time.sleep(outer.delay)
                if outer.raw is not None:
                    status, data, headers = outer.raw(body)
                else:
                    status, headers = 200, {}
                    inp = body.get("input", body)
                    data = json.dumps({"result": outer.policy(inp)}).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                for k, v in headers.items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(data)

        self._srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._srv.daemon_threads = True
        self.port = self._srv.server_address[1]
        self._t = threading.Thread(target=self._srv.serve_forever, daemon=True)
        self._t.start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/v1/data/ales/authz"

    def stop(self) -> None:
        self._srv.shutdown()
        self._srv.server_close()
