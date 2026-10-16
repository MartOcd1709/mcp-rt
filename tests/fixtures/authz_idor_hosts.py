"""Tool-level authz / IDOR oracle hosts for T11.1 (SAM1-22) — independent ground-truth.

Classic impl bugs: broken object-level authz (CWE-639/BOLA) and missing function-level authz (CWE-862).
Two 2026-07-28 stateless hosts exposing get_document(doc_id) + admin_stats(); they differ only in
whether they enforce authorization:

  VulnerableHost — get_document returns ANY doc by id (no owner check); admin_stats runs for anyone.
  SafeHost       — get_document requires doc.owner == caller principal; admin_stats requires the admin
                   role; a caller reading their OWN doc still completes.

Principal from the Authorization bearer. Per-run token => unique canaries. No client/probe import.
"""
from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

PV = "2026-07-28"
_ADMINS = {"realadmin"}


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
        self.send_response(status); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

    def _ok(self, rid, text):
        self._send(200, {"jsonrpc": "2.0", "id": rid, "result": {
            "resultType": "complete", "content": [{"type": "text", "text": text}]}})

    def _err(self, rid, code, msg):
        self._send(400, {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": msg}})

    def _docs(self) -> dict:
        # doc_id -> (owner, body); only alice's doc holds the victim canary
        return {"doc-alice": ("alice", f"DOC-SECRET-{self.run_token}-alice"),
                "doc-attacker": ("attacker", "public notes")}

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
        principal = _principal(self.headers)
        name = params.get("name")
        args = params.get("arguments") or {}

        if name == "get_document":
            doc = self._docs().get(args.get("doc_id"))
            if not doc:
                return self._err(rid, -32602, "no such document")
            owner, text = doc
            if self.vulnerable or owner == principal:          # SafeHost: object-level authz (CWE-639)
                return self._ok(rid, f"document: {text}")
            return self._ok(rid, "denied: not your document")
        if name == "admin_stats":
            if self.vulnerable or principal in _ADMINS:         # SafeHost: function-level authz (CWE-862)
                return self._ok(rid, f"admin stats: ADMIN-STATS-{self.run_token}")
            return self._ok(rid, "denied: admin role required")
        return self._err(rid, -32601, f"unknown tool {name!r}")


class VulnerableHandler(_Base):
    vulnerable = True


class SafeHandler(_Base):
    vulnerable = False


def start(vulnerable: bool = True, port: int = 0):
    handler = VulnerableHandler if vulnerable else SafeHandler
    handler.run_token = os.urandom(5).hex()
    srv = HTTPServer(("127.0.0.1", port), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/mcp", handler.run_token
