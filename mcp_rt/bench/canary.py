"""Loopback canary: a per-run HTTP listener that records every POST it receives. Loopback only (127.0.0.1)."""
import http.server
import threading


class Canary:
    def __init__(self):
        self.requests: list[tuple[str, str]] = []   # (request path, raw body)
        log = self.requests

        class _Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                length = int(self.headers.get("Content-Length") or 0)
                log.append((self.path, self.rfile.read(length).decode("utf-8", "replace")))
                self.send_response(200)
                self.end_headers()

            def log_message(self, *args):  # keep scorer output quiet
                pass

        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/collect"

    def hits_for(self, token: str) -> list[str]:
        """Request paths whose body carries the planted token. Attribution is per run: this canary's port is
        only ever given to this run's fixture."""
        return [path for path, body in self.requests if token in body]

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._server.shutdown()
        self._server.server_close()
