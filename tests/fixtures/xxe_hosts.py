"""XXE oracle hosts for T11.2 (SAM1-22) — independent ground-truth.

Classic impl bug: a tool parses attacker XML with external-entity resolution enabled (CWE-611),
which also yields SSRF via an http(s) SYSTEM entity (CWE-918). Two 2026-07-28 stateless hosts
expose import_profile(xml); they differ ONLY in whether the XML parser resolves external entities:

  VulnerableHost — xml.sax with feature_external_ges=True: file:// and http:// SYSTEM entities
                   are fetched and expanded into the tool's output.
  SafeHost       — feature_external_ges=False (the stdlib secure default; the posture defusedxml
                   enforces): external entities are never resolved; well-formed XML still parses.

A per-run secret is planted in a temp file so only a working XXE can read it. No client/probe import.
"""
from __future__ import annotations

import io
import json
import os
import tempfile
import threading
import xml.sax
from http.server import BaseHTTPRequestHandler, HTTPServer
from xml.sax.handler import feature_external_ges

PV = "2026-07-28"


class _Collector(xml.sax.ContentHandler):
    def __init__(self):
        super().__init__()
        self.buf: list[str] = []

    def characters(self, content):
        self.buf.append(content)


def _extract(xml_text: str, resolve_external: bool) -> str:
    """Parse XML, return its character data. resolve_external gates XXE (external general entities)."""
    parser = xml.sax.make_parser()
    parser.setFeature(feature_external_ges, resolve_external)
    handler = _Collector()
    parser.setContentHandler(handler)
    parser.parse(io.StringIO(xml_text))
    return "".join(handler.buf)


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
        if name != "import_profile":
            return self._err(rid, -32601, f"unknown tool {name!r}")
        try:
            extracted = _extract(args.get("xml") or "", self.vulnerable)   # SafeHost: external entities off
        except Exception as e:                                             # malformed XML -> error text, no crash
            return self._ok(rid, f"import error: {type(e).__name__}")
        return self._ok(rid, f"imported profile: {extracted}")


class VulnerableHandler(_Base):
    vulnerable = True


class SafeHandler(_Base):
    vulnerable = False


def start(vulnerable: bool = True, port: int = 0):
    handler = VulnerableHandler if vulnerable else SafeHandler
    handler.run_token = os.urandom(5).hex()
    tmpdir = tempfile.mkdtemp(prefix="xxe_oracle_")
    canary_file = os.path.join(tmpdir, "victim_secret.txt")
    with open(canary_file, "w") as f:
        f.write(f"XXE-FILE-{handler.run_token}")
    srv = HTTPServer(("127.0.0.1", port), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/mcp", handler.run_token, canary_file
