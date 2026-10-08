"""OAuth test harness for Family B (token passthrough / confused deputy).

A self-contained mock OAuth environment on loopback, used to ground-truth whether an MCP
server misuses tokens. One threaded HTTP server plays three roles, routed by path:

  * Authorization Server  -- /.well-known/oauth-authorization-server, /token, /jwks
  * Downstream resource   -- any other path (the "other audience" an honest server must
                             NOT replay the client's token to)

It mints ONE honeytoken bearer access token with a globally-unique marker and records every
inbound request's Authorization header. If that exact marker later appears in a request the
server-under-test makes to the downstream, the server replayed the client's token verbatim
(RFC 9728 / MCP token-passthrough anti-pattern) -> confirmed, zero false positive.

Nothing leaves the host; the token is synthetic. Research harness, not a real IdP.
"""
from __future__ import annotations

import http.server
import json
import socketserver
import threading
import uuid


class _Handler(http.server.BaseHTTPRequestHandler):
    def _record(self, body: str = "") -> None:
        self.server.captures.append({  # type: ignore[attr-defined]
            "method": self.command,
            "path": self.path,
            "authorization": self.headers.get("Authorization", ""),
            "body": body[:1024],
        })

    def _json(self, obj: dict, code: int = 200) -> None:
        payload = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        self._record()
        base = self.server.base                                  # type: ignore[attr-defined]
        if "/.well-known/" in self.path:
            self._json({"issuer": base,
                        "authorization_endpoint": base + "/authorize",
                        "token_endpoint": base + "/token",
                        "jwks_uri": base + "/jwks"})
        elif self.path.startswith("/jwks"):
            self._json({"keys": []})
        else:
            self._json({"ok": True})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        self._record(body)
        if self.path.startswith("/token"):
            self._json({"access_token": self.server.token,         # type: ignore[attr-defined]
                        "token_type": "Bearer", "expires_in": 3600})
        else:
            self._json({"ok": True})

    do_PUT = do_POST

    def log_message(self, *a):
        pass


class _Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    captures: list
    base: str
    token: str


class OAuthHarness:
    """Mock OAuth AS + downstream sink with a honeytoken bearer token."""

    # env var names a server-under-test might read for its auth token / downstream base URL
    _TOKEN_VARS = ("AUTH_TOKEN", "API_TOKEN", "ACCESS_TOKEN", "BEARER_TOKEN",
                   "MCP_AUTH_TOKEN", "OAUTH_TOKEN", "API_KEY", "TOKEN")
    _URL_VARS = ("DOWNSTREAM_URL", "API_BASE_URL", "API_URL", "UPSTREAM_URL",
                 "SERVICE_URL", "BASE_URL")

    def __init__(self):
        self.token = "HT-TOK-" + uuid.uuid4().hex[:16]
        self._httpd = None
        self.port = None

    def start(self) -> "OAuthHarness":
        self._httpd = _Server(("127.0.0.1", 0), _Handler)
        self.port = self._httpd.server_address[1]
        self._httpd.base = f"http://127.0.0.1:{self.port}"
        self._httpd.captures = []
        self._httpd.token = self.token
        threading.Thread(target=self._httpd.serve_forever, daemon=True).start()
        return self

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def env(self) -> dict:
        """Env to inject into the server-under-test: the honeytoken + our downstream + AS."""
        e = {v: self.token for v in self._TOKEN_VARS}
        e.update({v: self.base + "/downstream" for v in self._URL_VARS})
        e["OAUTH_ISSUER"] = self.base
        e["OAUTH_METADATA_URL"] = self.base + "/.well-known/oauth-authorization-server"
        return e

    def captures(self) -> list:
        return list(getattr(self._httpd, "captures", []))

    def passthrough_hits(self) -> list:
        """Captures whose Authorization header carries our exact honeytoken (verbatim replay)."""
        return [c for c in self.captures()
                if self.token in (c.get("authorization") or "")
                and not c["path"].startswith(("/token", "/jwks", "/.well-known"))]

    def transcript(self) -> dict:
        return {"honeytoken": self.token, "base": self.base, "captures": self.captures()}

    def stop(self):
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
