"""Telemetry-leak oracle hosts for T12.1 (SAM1-23) — independent ground-truth.

OWASP MCP08 family ("Lack of Audit and Telemetry"). The CONFIRMED-able form is the INVERSE of
under-logging: sensitive data OVER-exposed into a telemetry surface a LOWER-PRIVILEGED party can read
(CWE-532, sensitive info in a log). Four modes of one 2026-07-28 host expose process(data) +
get_telemetry():

  leak       — process() writes `data` verbatim to telemetry; get_telemetry() is low-priv readable.
  redact     — process() masks the value in telemetry; get_telemetry() low-priv readable (no secret).
  auth_gated — process() writes `data` verbatim BUT get_telemetry() requires admin auth (the secret IS
               logged, but a low-priv reader cannot see it -> not a cross-privilege leak).

A per-run secret makes the canary unique. No client/probe import.
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

PV = "2026-07-28"
_ADMIN = "admin-token"


class _Base(BaseHTTPRequestHandler):
    mode = "leak"            # leak | redact | auth_gated

    def log_message(self, *a):
        pass

    def _telemetry(self) -> list:
        # per-handler-class store so each host instance keeps its own events
        if not hasattr(type(self), "_events"):
            type(self)._events = []
        return type(self)._events

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

        if name == "process":
            data = args.get("data", "")
            if self.mode == "redact":
                self._telemetry().append("event=process status=ok data=***REDACTED***")   # logs event, masks value
            else:
                self._telemetry().append(f"event=process status=ok data={data}")           # raw value in telemetry
            return self._ok(rid, "processed")
        if name == "get_telemetry":
            if self.mode == "auth_gated" and self.headers.get("Authorization", "") != f"Bearer {_ADMIN}":
                return self._ok(rid, "denied: telemetry requires admin")                    # low-priv cannot read
            return self._ok(rid, "\n".join(self._telemetry()) or "(no events)")
        return self._err(rid, -32601, f"unknown tool {name!r}")


def start(mode: str = "leak", port: int = 0):
    handler = type("H", (_Base,), {"mode": mode, "_events": []})
    srv = HTTPServer(("127.0.0.1", port), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/mcp"
