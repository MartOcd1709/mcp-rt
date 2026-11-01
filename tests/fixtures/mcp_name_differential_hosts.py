"""Mcp-Name header/body method-differential oracle hosts for T10.4 (SAM1-21) — independent ground-truth.

Streamable-HTTP transport: `Mcp-Name` (required for tools/call, resources/read, prompts/get) MUST equal
body `params.name`; on mismatch the server MUST return HeaderMismatchError (-32020). The differential:
a server that AUTHORIZES on one value and EXECUTES the other = request smuggling.

  VulnerableHost — authorizes on the Mcp-Name HEADER (allowlist {safe_echo}) but EXECUTES body
                   params.name, accepting the mismatch (the MUST-violation).
  SafeHost       — enforces header == body params.name; on mismatch returns -32020 and executes nothing.

Both DENY an honest admin_exec (not allowlisted) and both COMPLETE a benign agreeing safe_echo — so the
fire is specifically the DIFFERENTIAL, and neither host is accidentally allow-all. Per-run token =>
unique canary. Hand-written from the transport spec; no client/probe import.
"""
from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

PV = "2026-07-28"
_ALLOWLIST = {"safe_echo"}       # the only tool name permitted by the guard


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

    def _execute(self, name) -> str:
        if name == "safe_echo":
            return "echo: public tiles"
        if name == "admin_exec":
            return f"EXEC-ADMIN-{self.run_token}"            # privileged canary — only if admin_exec runs
        return f"unknown tool {name}"

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

        if method != "tools/call":
            return self._err(rid, -32601, f"method not found: {method}")
        header_name = self.headers.get("Mcp-Name")
        body_name = params.get("name")
        if header_name is None:
            return self._err(rid, -32020, "missing required Mcp-Name header")

        if not self.vulnerable:
            # SafeHost: the spec MUST — header must equal body; mismatch -> -32020, execute NOTHING
            if header_name != body_name:
                return self._err(rid, -32020, "Mcp-Name header does not match params.name (HeaderMismatch)")
            if body_name not in _ALLOWLIST:
                return self._ok(rid, f"denied: {body_name} not allowlisted")
            return self._ok(rid, self._execute(body_name))

        # VulnerableHost: authorize on the HEADER, execute the BODY (the differential)
        if header_name not in _ALLOWLIST:
            return self._ok(rid, f"denied: {header_name} not allowlisted")   # not allow-all: honest admin_exec denied
        return self._ok(rid, self._execute(body_name))                       # ...but a smuggled body runs


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
