"""ReDoS oracle hosts for T11.5 (SAM1-22) — independent ground-truth.

Two 2026-07-28 stateless hosts expose validate_username; the tool's inputSchema declares the regex
`pattern` the server applies. They differ ONLY in that pattern:

  VulnerableHost — pattern "^(a+)+$": nested quantifier -> catastrophic backtracking (CWE-1333).
  SafeHost       — pattern "^a+$":    linear, bounded.

The probe reads the pattern via list_tools and proves catastrophicity STATICALLY (deterministic
step-count); it never sends an adversarial input here. validate_username runs re.fullmatch on the
SHORT benign input the probe sends — proving the server really applies the pattern (no detonation).
No client/probe import.
"""
from __future__ import annotations

import json
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading

PV = "2026-07-28"
_VULN_PATTERN = "^(a+)+$"
_SAFE_PATTERN = "^a+$"


class _Base(BaseHTTPRequestHandler):
    vulnerable = True

    def log_message(self, *a):
        pass

    def _pattern(self) -> str:
        return _VULN_PATTERN if self.vulnerable else _SAFE_PATTERN

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
        if method == "tools/list":
            return self._send(200, {"jsonrpc": "2.0", "id": rid, "result": {"tools": [{
                "name": "validate_username", "description": "Validate a username against the server policy regex.",
                "inputSchema": {"type": "object",
                                "properties": {"username": {"type": "string", "pattern": self._pattern()}},
                                "required": ["username"]}}]}})
        if method == "tools/call" and params.get("name") == "validate_username":
            username = (params.get("arguments") or {}).get("username", "")
            # server applies its policy regex to the SHORT benign input the probe sends (no detonation)
            valid = re.fullmatch(self._pattern(), username) is not None
            return self._ok(rid, f"username {'valid' if valid else 'invalid'}")
        return self._err(rid, -32601, "method not found")


class VulnerableHandler(_Base):
    vulnerable = True


class SafeHandler(_Base):
    vulnerable = False


def start(vulnerable: bool = True, port: int = 0):
    handler = VulnerableHandler if vulnerable else SafeHandler
    srv = HTTPServer(("127.0.0.1", port), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/mcp"
