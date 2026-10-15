"""A 2026-07-28 STATELESS MCP server fixture — the ORACLE for T1 (SAM1-12).

Hand-written from the official 2026-07-28 schema.ts shapes, deliberately INDEPENDENT of the client
under test: it strictly enforces the spec's required headers and _meta, so a client that does NOT
speak the protocol correctly FAILS here (anti-circularity — the fixture is pinned to the spec, not to
the client's assumptions). Pure stdlib http.server; no mcp SDK, no new deps.

Stateless, so a "retry" is recognized by the presence of `inputResponses` in params (not by session).
Tools:
  * echo  — first call (no inputResponses) -> input_required (one elicitation); retry (must echo
            requestState + carry inputResponses) -> complete.
  * spin  — ALWAYS input_required (never completes) — exercises the client's MRTR round ceiling.
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

PV = "2026-07-28"
_REQUEST_STATE = "OPAQUE-STATE-abc123"   # opaque blob the client MUST echo back byte-for-byte
_NAME_SRC = {"tools/call": "name", "prompts/get": "name", "resources/read": "uri"}

_TOOLS = [
    {"name": "echo", "description": "echo back, after one confirmation round",
     "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}}},
    {"name": "spin", "description": "never completes (tests the MRTR bound)",
     "inputSchema": {"type": "object", "properties": {}}},
]


def _caching(result: dict) -> dict:
    """Attach required CacheableResult fields (schema.ts: ttlMs + cacheScope at result top level)."""
    result["ttlMs"] = 300000
    result["cacheScope"] = "public"
    return result


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence
        pass

    def _send(self, status: int, payload: dict):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _err(self, rpc_id, code: int, message: str, http: int = 400):
        self._send(http, {"jsonrpc": "2.0", "id": rpc_id, "error": {"code": code, "message": message}})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return self._err(None, -32700, "parse error")
        rpc_id = body.get("id")
        method = body.get("method", "")
        params = body.get("params") or {}
        meta = params.get("_meta") or {}

        # --- header enforcement (the oracle: a non-conformant client fails here) ---
        hv = self.headers.get("MCP-Protocol-Version")
        if hv != PV:
            return self._err(rpc_id, -32022, f"unsupported/missing MCP-Protocol-Version: {hv!r}")
        if meta.get("io.modelcontextprotocol/protocolVersion") != PV:
            return self._err(rpc_id, -32602, "missing params._meta protocolVersion")
        if hv != meta.get("io.modelcontextprotocol/protocolVersion"):
            return self._err(rpc_id, -32020, "header/_meta protocolVersion mismatch")
        if "io.modelcontextprotocol/clientCapabilities" not in meta:
            return self._err(rpc_id, -32602, "missing params._meta clientCapabilities")
        accept = self.headers.get("Accept", "")
        if "application/json" not in accept or "text/event-stream" not in accept:
            return self._err(rpc_id, -32020, f"Accept must offer both json and event-stream: {accept!r}")
        if self.headers.get("Mcp-Method") != method:
            return self._err(rpc_id, -32020, "Mcp-Method header must equal body method")
        if method in _NAME_SRC:
            want = str(params.get(_NAME_SRC[method]))
            if self.headers.get("Mcp-Name") != want:
                return self._err(rpc_id, -32020, f"Mcp-Name must equal params.{_NAME_SRC[method]}")

        # --- method handling ---
        if method == "server/discover":
            return self._send(200, {"jsonrpc": "2.0", "id": rpc_id, "result": _caching(
                {"resultType": "complete", "supportedVersions": [PV, "2025-06-18"],
                 "capabilities": {"tools": {}}})})
        if method == "tools/list":
            return self._send(200, {"jsonrpc": "2.0", "id": rpc_id, "result": _caching(
                {"resultType": "complete", "tools": _TOOLS})})
        if method == "tools/call":
            name = params.get("name")
            responses = params.get("inputResponses")
            if name == "spin":
                return self._send(200, {"jsonrpc": "2.0", "id": rpc_id, "result": {
                    "resultType": "input_required",
                    "inputRequests": {"again": {"method": "elicitation/create",
                                                "params": {"mode": "form", "message": "again?"}}},
                    "requestState": _REQUEST_STATE}})
            if name == "echo":
                if responses is None:                       # first leg -> ask for input
                    return self._send(200, {"jsonrpc": "2.0", "id": rpc_id, "result": {
                        "resultType": "input_required",
                        "inputRequests": {"confirm": {"method": "elicitation/create",
                                                      "params": {"mode": "form", "message": "confirm?"}}},
                        "requestState": _REQUEST_STATE}})
                # retry leg -> the client MUST have echoed requestState exactly and keyed inputResponses
                if params.get("requestState") != _REQUEST_STATE:
                    return self._err(rpc_id, -32602, "requestState not echoed exactly")
                if "confirm" not in responses:
                    return self._err(rpc_id, -32602, "inputResponses missing key 'confirm'")
                text = (params.get("arguments") or {}).get("text", "")
                return self._send(200, {"jsonrpc": "2.0", "id": rpc_id, "result": {
                    "resultType": "complete",
                    "content": [{"type": "text", "text": f"ok:{text}"}],
                    "_meta": {"io.modelcontextprotocol/serverInfo": {"name": "stateless-fixture", "version": "1.0"}}}})
            return self._err(rpc_id, -32602, f"unknown tool {name!r}")
        return self._err(rpc_id, -32601, f"method not found: {method}")


def start(port: int = 0) -> tuple[HTTPServer, str, threading.Thread]:
    """Start the fixture on an ephemeral port in a daemon thread. Returns (server, url, thread)."""
    srv = HTTPServer(("127.0.0.1", port), _Handler)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/mcp", th


if __name__ == "__main__":  # manual run
    s, url, _ = start()
    print("stateless 2026-07-28 fixture at", url)
    try:
        s.serve_forever()
    except KeyboardInterrupt:
        s.shutdown()
