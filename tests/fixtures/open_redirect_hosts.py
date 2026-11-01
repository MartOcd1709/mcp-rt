"""Open-redirect oracle hosts for T11.3 (SAM1-22) — independent ground-truth.

Classic impl bug: a post-login tool complete_login(return_to) redirects to an attacker-controlled
return_to WITHOUT validating its origin (CWE-601), and the redirect carries the victim's per-run
SESSION TOKEN — so the open redirect is also sensitive-token exfiltration (CWE-200/552) that enables
account takeover. Two 2026-07-28 stateless hosts; they differ ONLY in return_to validation:

  VulnerableHost — appends the session token to ANY return_to (off-origin included).
  SafeHost       — allowlists same-origin return_to; off-origin -> tokenless safe default.

A protected tool account_summary() (shared by BOTH hosts) requires the session token as a bearer and
returns the victim's private data -> proving the leaked token is a GENUINE credential, not a toy.

Collector = an off-origin sink that records only its /collect path (self-check proves it). No probe import.
"""
from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

PV = "2026-07-28"


# ---------------- Attacker collector (the off-origin oracle sink) ----------------
class _Collector(BaseHTTPRequestHandler):
    received: list = []

    def log_message(self, *a):
        pass

    def do_GET(self):
        if urlparse(self.path).path == "/collect":          # records ONLY here (self-check proves it)
            type(self).received.append(self.path)            # full /collect?... line; the canary is in the query
            self.send_response(200); self.end_headers(); self.wfile.write(b"captured")
        else:
            self.send_response(404); self.end_headers(); self.wfile.write(b"nope")


def start_collector(port: int = 0):
    _Collector.received = []
    srv = HTTPServer(("127.0.0.1", port), _Collector)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}", _Collector.received


# ---------------- The MCP hosts ----------------
class _Host(BaseHTTPRequestHandler):
    vulnerable = True
    run_token = "tok"

    def log_message(self, *a):
        pass

    def _session_token(self) -> str:
        return f"SESS-{self.run_token}"                      # the victim's authenticated session credential

    def _send(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

    def _ok(self, rid, text):
        self._send(200, {"jsonrpc": "2.0", "id": rid, "result": {
            "resultType": "complete", "content": [{"type": "text", "text": text}]}})

    def _err(self, rid, code, msg):
        self._send(400, {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": msg}})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return self._err(None, -32700, "parse error")
        rid, method = body.get("id"), body.get("method", "")
        params = body.get("params") or {}
        meta = params.get("_meta") or {}
        if self.headers.get("MCP-Protocol-Version") != PV or meta.get("io.modelcontextprotocol/protocolVersion") != PV:
            return self._err(rid, -32022, "bad/missing protocol version")
        if method != "tools/call":
            return self._err(rid, -32601, "method not found")
        name = params.get("name")
        args = params.get("arguments") or {}

        if name == "complete_login":
            return_to = args.get("return_to", "")
            if self.vulnerable or return_to.startswith("/"):    # SafeHost: same-origin path only (allowlist)
                sep = "&" if "?" in return_to else "?"
                return self._ok(rid, f"redirect: {return_to}{sep}token={self._session_token()}")
            return self._ok(rid, "redirect: /login?error=bad_return")   # SafeHost rejects off-origin, no token
        if name == "account_summary":
            if self.headers.get("Authorization", "") == f"Bearer {self._session_token()}":
                return self._ok(rid, f"ACCOUNT-{self.run_token}: alice balance=$42,000 ssn=***-**-1234")
            return self._ok(rid, "unauthorized")
        return self._err(rid, -32601, f"unknown tool {name!r}")


def start(vulnerable: bool = True, port: int = 0):
    handler = type("H", (_Host,), {"vulnerable": vulnerable, "run_token": os.urandom(5).hex()})
    srv = HTTPServer(("127.0.0.1", port), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/mcp", handler.run_token
