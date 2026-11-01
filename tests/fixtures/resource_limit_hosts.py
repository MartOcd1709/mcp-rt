"""Resource-amplification oracle hosts for T11.6 (SAM1-22) — independent ground-truth.

A tool expand(unit, count) whose output scales with `count`. Three 2026-07-28 stateless hosts differ
in two independent axes so the probe must check BOTH the schema AND real behavior:

  VulnerableHost    — schema_bounded=False, server_capped=False: no `maximum` on count, honors any count.
  SafeHost          — schema_bounded=True,  server_capped=True:  schema `maximum:64`, caps output at 64.
  DefenseInDepthHost— schema_bounded=False, server_capped=True:  no schema max BUT a real server-side cap.
                      Must NOT be flagged (honored_above_cap=False) -> no FP on defense-in-depth.

Output is capped in absolute terms by the probe (never requests a huge count) — nothing is exhausted.
No client/probe import.
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

PV = "2026-07-28"
_CAP = 64


class _Base(BaseHTTPRequestHandler):
    schema_bounded = False
    server_capped = False

    def log_message(self, *a):
        pass

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
            count_schema = {"type": "integer", "minimum": 1}
            if self.schema_bounded:
                count_schema["maximum"] = _CAP
            return self._send(200, {"jsonrpc": "2.0", "id": rid, "result": {"tools": [{
                "name": "expand", "description": "Repeat `unit` `count` times.",
                "inputSchema": {"type": "object",
                                "properties": {"unit": {"type": "string"}, "count": count_schema},
                                "required": ["unit", "count"]}}]}})
        if method == "tools/call" and params.get("name") == "expand":
            args = params.get("arguments") or {}
            unit = args.get("unit", ""); count = int(args.get("count", 0))
            eff = min(count, _CAP) if self.server_capped else count     # real server-side cap vs none
            return self._ok(rid, unit * eff)
        return self._err(rid, -32601, "method not found")


def start(schema_bounded: bool, server_capped: bool, port: int = 0):
    handler = type("H", (_Base,), {"schema_bounded": schema_bounded, "server_capped": server_capped})
    srv = HTTPServer(("127.0.0.1", port), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/mcp"
