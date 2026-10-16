"""cacheScope cross-tenant poisoning oracle hosts for T10.1 (SAM1-21) — independent ground-truth.

Two 2026-07-28 stateless hosts whose `tools/list` is PER-TENANT (embeds the caller's principal: a
secret in a tool description = leak canary, and a tool NAME = poison marker). They differ only in the
`cacheScope` they stamp:
  VulnerableHost -> "public"  (spec: public = "does not contain user-specific data" — a lie here; any
                              conformant shared cache will serve tenant A's bytes to tenant B)
  SafeHost       -> "private" (cache MUST NOT cross authorization contexts) + a genuinely-shared public
                              catalog (prompts/list, no tenant data) for the benign control.

Per-run random token => the leaked secret is unique per run (the nonce role): A's secret reaching B
cannot be coincidence. Hand-written from the spec; does not import the client or the probe.
"""
from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

PV = "2026-07-28"


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

    def leak_secret(self, principal) -> str:
        return f"SECRET-{self.run_token}-{principal}"          # confidentiality canary (in a tool description)

    def poison_tool(self, principal) -> str:
        return f"POISON-{self.run_token}-{principal}"          # integrity marker (an attacker-controlled tool NAME)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return self._err(None, -32700, "parse error")
        rid, method = body.get("id"), body.get("method", "")
        meta = (body.get("params") or {}).get("_meta") or {}
        # 2026 header/_meta enforcement (same discipline as the T1/T2 fixtures)
        if self.headers.get("MCP-Protocol-Version") != PV or meta.get("io.modelcontextprotocol/protocolVersion") != PV:
            return self._err(rid, -32022, "bad/missing protocol version")
        if "io.modelcontextprotocol/clientCapabilities" not in meta:
            return self._err(rid, -32602, "missing _meta clientCapabilities")
        accept = self.headers.get("Accept", "")
        if "application/json" not in accept or "text/event-stream" not in accept:
            return self._err(rid, -32020, "Accept must offer both")
        if self.headers.get("Mcp-Method") != method:
            return self._err(rid, -32020, "Mcp-Method mismatch")

        principal = _principal(self.headers)
        if method == "tools/list":
            # PER-TENANT content: this list legitimately varies by authenticated principal.
            tools = [{"name": self.poison_tool(principal),
                      "description": f"owner={principal} {self.leak_secret(principal)}"}]
            scope = "public" if self.vulnerable else "private"   # the whole defect is this one choice
            return self._send(200, {"jsonrpc": "2.0", "id": rid, "result": {
                "resultType": "complete", "tools": tools, "ttlMs": 300000, "cacheScope": scope}})
        if method == "prompts/list":
            # genuinely shared, NO tenant data -> correctly public (benign control)
            return self._send(200, {"jsonrpc": "2.0", "id": rid, "result": {
                "resultType": "complete", "prompts": [{"name": "public_help", "description": "shared catalog"}],
                "ttlMs": 300000, "cacheScope": "public"}})
        return self._err(rid, -32601, f"method not found: {method}")


class VulnerableHandler(_Base):
    vulnerable = True


class SafeHandler(_Base):
    vulnerable = False


def start(vulnerable: bool = True, port: int = 0):
    """Start a fresh host with a per-run random token. Returns (server, url, run_token, thread)."""
    handler = VulnerableHandler if vulnerable else SafeHandler
    handler.run_token = os.urandom(5).hex()
    srv = HTTPServer(("127.0.0.1", port), handler)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/mcp", handler.run_token, th
