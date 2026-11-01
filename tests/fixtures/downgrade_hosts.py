"""Downgrade-to-deprecated oracle hosts for T10.5 (SAM1-21) — independent ground-truth.

Dual-era 2026-07-28 servers that ALSO accept the older `2025-06-18` protocolVersion (serving the legacy
version during the 12-month overlap is PERMITTED — so that alone is not the vuln). The defect is a
security control (profile redaction) applied on the MODERN path but NOT uniformly on the DEPRECATED
path, so a FORCED downgrade bypasses it.

  VulnerableHost — modern path redacts (public fields); legacy path SKIPS redaction -> returns the
                   per-run profile CANARY. (The SAME tool on the modern path is clean — contrast proves
                   the bypass is the downgrade, not a tool that always leaks.)
  SafeHost       — applies redaction on EVERY version; a downgrade bypasses nothing.

Hand-written from the versioning spec; no client/probe import. Per-run token => unique canary.
"""
from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

PV_MODERN = "2026-07-28"
PV_LEGACY = "2025-06-18"          # established older MCP protocol version (the deprecated/overlap era)
_SUPPORTED = {PV_MODERN, PV_LEGACY}


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
        hv = self.headers.get("MCP-Protocol-Version")
        mv = meta.get("io.modelcontextprotocol/protocolVersion")
        if hv not in _SUPPORTED:
            return self._err(rid, -32022, f"unsupported protocol version {hv!r}")   # dual-era: both are supported
        if hv != mv:
            return self._err(rid, -32020, "header/_meta protocolVersion mismatch")
        if "io.modelcontextprotocol/clientCapabilities" not in meta:
            return self._err(rid, -32602, "missing _meta clientCapabilities")
        accept = self.headers.get("Accept", "")
        if "application/json" not in accept or "text/event-stream" not in accept:
            return self._err(rid, -32020, "Accept must offer both")
        if self.headers.get("Mcp-Method") != method:
            return self._err(rid, -32020, "Mcp-Method mismatch")

        if method == "tools/call" and params.get("name") == "read_profile":
            # the security control = redaction. Applied on modern always; on legacy only by SafeHost.
            redact = (hv == PV_MODERN) or (not self.vulnerable)
            if redact:
                return self._ok(rid, "profile: public fields only")
            return self._ok(rid, f"profile: FULL name/email/ssn {self.run_token}=PROFILE-SECRET-{self.run_token}")
        return self._err(rid, -32601, f"method/tool not found: {method}/{params.get('name')}")


class VulnerableHandler(_Base):
    vulnerable = True


class SafeHandler(_Base):
    vulnerable = False


def start(vulnerable: bool = True, port: int = 0):
    handler = VulnerableHandler if vulnerable else SafeHandler
    handler.run_token = os.urandom(5).hex()
    srv = HTTPServer(("127.0.0.1", port), handler)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/mcp", handler.run_token, th
