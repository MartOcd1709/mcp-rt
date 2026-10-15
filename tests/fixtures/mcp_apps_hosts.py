"""MCP Apps UI-injection oracle hosts for T10.7 (SAM1-21) — independent ground-truth.

A tool stores an attacker-controlled `note`, and the `ui://dashboard` resource renders it into HTML the
host would show in its sandboxed iframe. The app can drive `ui/*` tool-calls, so content that escapes
into an executable position can act.

  VulnerableHost — renders the note UNESCAPED (string concat) -> injected markup is live.
  SafeHost       — renders it through stdlib html.escape() -> injected markup is inert text.

SafeHost's escaper is `html.escape` (stdlib). The oracle (the reference HTML evaluator in the probe) is
a SEPARATE HTMLParser-based structural check — deliberately NOT sharing escaping logic (anti-circularity).
tools/list also carries `_meta.ui` (csp/permissions) for the STRUCTURAL LEAD observations (unconfirmed).
Hand-written from the apps extension; no client/probe import. Per-run token => unique canary.
"""
from __future__ import annotations

import html
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

PV = "2026-07-28"


class _Host(BaseHTTPRequestHandler):
    vulnerable = True
    run_token = "tok"
    note = "welcome"

    def log_message(self, *a):
        pass

    def _json(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

    def _ok(self, rid, result):
        self._json(200, {"jsonrpc": "2.0", "id": rid, "result": result})

    def _render(self) -> str:
        note = type(self).note
        shown = note if self.vulnerable else html.escape(note)   # the ONLY difference: escape or not
        return f'<main class="app"><h1>Dashboard</h1><div class="note">{shown}</div></main>'

    def _ui_meta(self) -> dict:
        if self.vulnerable:
            return {"resourceUri": "ui://dashboard", "csp": "*", "permissions": ["camera", "microphone"]}
        return {"resourceUri": "ui://dashboard", "csp": "'self'", "permissions": []}

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return self._json(400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse"}})
        rid, method = body.get("id"), body.get("method", "")
        params = body.get("params") or {}
        meta = params.get("_meta") or {}
        if self.headers.get("MCP-Protocol-Version") != PV or meta.get("io.modelcontextprotocol/protocolVersion") != PV:
            return self._json(400, {"jsonrpc": "2.0", "id": rid, "error": {"code": -32022, "message": "version"}})

        if method == "tools/list":
            return self._ok(rid, {"resultType": "complete", "ttlMs": 0, "cacheScope": "private",
                                  "tools": [{"name": "set_note", "description": "set the dashboard note",
                                             "inputSchema": {"type": "object", "properties": {"note": {"type": "string"}}},
                                             "_meta": {"ui": self._ui_meta()}}]})
        if method == "tools/call" and params.get("name") == "set_note":
            type(self).note = (params.get("arguments") or {}).get("note", "")
            return self._ok(rid, {"resultType": "complete", "content": [{"type": "text", "text": "stored"}]})
        if method == "resources/read" and params.get("uri") == "ui://dashboard":
            return self._ok(rid, {"resultType": "complete", "ttlMs": 0, "cacheScope": "private",
                                  "contents": [{"uri": "ui://dashboard", "mimeType": "text/html", "text": self._render()}]})
        return self._json(400, {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "method"}})


def start(vulnerable: bool, port: int = 0):
    handler = type("H", (_Host,), {"vulnerable": vulnerable, "run_token": os.urandom(5).hex(), "note": "welcome"})
    srv = HTTPServer(("127.0.0.1", port), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/mcp", handler.run_token
