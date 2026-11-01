"""_meta identity-spoofing oracle hosts for T10.3 (SAM1-21) — independent ground-truth.

Per-request `_meta` carries self-reported, UNVERIFIED identity (basic/index §_meta: clientInfo/
clientCapabilities "are not verified by the protocol ... SHOULD NOT rely on them for security
decisions"). These two 2026-07-28 stateless hosts expose a privileged tool and differ only in WHAT
they trust for the privilege decision:

  VulnerableHost — grants admin on the SPOOFABLE _meta: clientInfo.name=="trusted-admin" OR
                   clientCapabilities.extensions has the admin ext. (SHOULD-NOT violation / trust error)
  SafeHost       — grants admin on the REAL Authorization principal only; ignores _meta for security.

A NON-privileged attacker (Authorization: Bearer attacker) that spoofs _meta gets the admin CANARY on
VulnerableHost and nothing privileged on SafeHost. Per-run token => unique canary. Hand-written from
the spec; no client/probe import.
"""
from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

PV = "2026-07-28"
_ADMINS = {"realadmin"}          # the only principals SafeHost treats as admin (real auth)


def _principal(headers) -> str:
    auth = headers.get("Authorization", "")
    return auth[7:].strip() if auth.lower().startswith("bearer ") else "anon"


class _Base(BaseHTTPRequestHandler):
    vulnerable = True
    run_token = "tok"

    def log_message(self, *a):
        pass

    def _send(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _err(self, rid, code, msg):
        self._send(400, {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": msg}})

    def admin_canary(self) -> str:
        return f"ADMIN-SECRET-{self.run_token}"

    def _is_admin(self, principal, meta) -> bool:
        if not self.vulnerable:
            return principal in _ADMINS                       # SafeHost: real Authorization principal only
        # VulnerableHost: trust the self-reported, unverified _meta (the bug)
        info = meta.get("io.modelcontextprotocol/clientInfo") or {}
        caps = meta.get("io.modelcontextprotocol/clientCapabilities") or {}
        exts = caps.get("extensions") or {}
        return info.get("name") == "trusted-admin" or "com.acme/admin" in exts

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
        if "io.modelcontextprotocol/clientCapabilities" not in meta:
            return self._err(rid, -32602, "missing _meta clientCapabilities")
        accept = self.headers.get("Accept", "")
        if "application/json" not in accept or "text/event-stream" not in accept:
            return self._err(rid, -32020, "Accept must offer both")
        if self.headers.get("Mcp-Method") != method:
            return self._err(rid, -32020, "Mcp-Method mismatch")

        if method == "tools/call" and params.get("name") == "read_dashboard":
            principal = _principal(self.headers)
            admin = self._is_admin(principal, meta)
            text = (f"dashboard: {self.admin_canary()}" if admin else "dashboard: public tiles only")
            return self._send(200, {"jsonrpc": "2.0", "id": rid, "result": {
                "resultType": "complete", "content": [{"type": "text", "text": text}]}})
        return self._err(rid, -32601, f"method/tool not found: {method}/{params.get('name')}")


class VulnerableHandler(_Base):
    vulnerable = True


class SafeHandler(_Base):
    vulnerable = False


def start(vulnerable: bool = True, port: int = 0):
    """Fresh host with a per-run token. Returns (server, url, run_token, thread)."""
    handler = VulnerableHandler if vulnerable else SafeHandler
    handler.run_token = os.urandom(5).hex()
    srv = HTTPServer(("127.0.0.1", port), handler)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/mcp", handler.run_token, th
