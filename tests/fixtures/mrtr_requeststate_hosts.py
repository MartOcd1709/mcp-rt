"""MRTR requestState oracle fixtures for T2 (SAM1-13) — the independent ground-truth.

Two 2026-07-28 stateless hosts offering a one-time `redeem` tool whose MRTR `requestState` encodes an
authz-relevant grant. Hand-written from schema.ts; NOT built from the client's assumptions.

  VulnerableHost — requestState is a forgeable base64-JSON blob; the server performs NONE of the spec
    §Server-Requirements checks -> tamper / cross-user / replay all succeed.
  SafeHost — HMAC-protects the state (rejects tamper, spec #4 MUST), binds the authenticated principal
    (rejects cross-user, #5), and enforces single-use (rejects replay, #5 one-time MUST). A benign
    same-principal retry COMPLETES (control (d) passes here too — "resilient" is earned, not reject-all).

Ground truth: only principal "victim" maps to the CANARY secret; the probe injects a unique nonce the
host echoes. A manipulated retry that returns the CANARY (tamper/cross-user) or redeems a consumed
voucher twice (replay) is undeniable — not a model's opinion.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

PV = "2026-07-28"
CANARY = "CANARY-mrtr-7f3a9c2e5b11"          # secret that belongs to principal "victim" only
_HMAC_KEY = b"safehost-mrtr-signing-key-v1"   # SafeHost only
_SECRETS = {"victim": CANARY}                 # grant -> data; anything else is non-secret "public:<grant>"
_NAME_SRC = {"tools/call": "name", "prompts/get": "name", "resources/read": "uri"}


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _principal(headers) -> str:
    auth = headers.get("Authorization", "")
    return auth[7:].strip() if auth.lower().startswith("bearer ") else "anon"


class _Base(BaseHTTPRequestHandler):
    vulnerable = True          # overridden per subclass
    # per-process state (one host per test); single-threaded server => consistent
    _voucher_seq = 0
    _consumed: set = set()
    _redeem_count: dict = {}

    def log_message(self, *a):
        pass

    def _send(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _ok(self, rpc_id, result):
        self._send(200, {"jsonrpc": "2.0", "id": rpc_id, "result": result})

    def _err(self, rpc_id, code, message):
        self._send(400, {"jsonrpc": "2.0", "id": rpc_id, "error": {"code": code, "message": message}})

    # ---- requestState encode/verify ----
    def _mint_state(self, principal, grant, voucher) -> str:
        payload = json.dumps({"principal": principal, "grant": grant, "voucher": voucher}).encode()
        if self.vulnerable:
            return _b64e(payload)                                  # forgeable: no integrity tag
        tag = hmac.new(_HMAC_KEY, payload, hashlib.sha256).digest()
        return _b64e(payload) + "." + _b64e(tag)

    def _open_state(self, rpc_id, state):
        """Return the decoded state dict, or None after sending the appropriate rejection."""
        seg = state.split(".")
        try:
            data = json.loads(_b64d(seg[0]))
        except Exception:
            self._err(rpc_id, -32602, "unparseable requestState")
            return None
        if not self.vulnerable:
            # #4 MUST: integrity-protect and reject what fails verification
            if len(seg) != 2:
                self._err(rpc_id, -32020, "requestState missing integrity tag")
                return None
            expect = hmac.new(_HMAC_KEY, json.dumps(data).encode(), hashlib.sha256).digest()
            try:
                got = _b64d(seg[1])
            except Exception:
                got = b""
            if not hmac.compare_digest(expect, got):
                self._err(rpc_id, -32020, "requestState integrity verification failed (tamper)")
                return None
        return data

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return self._err(None, -32700, "parse error")
        rpc_id, method = body.get("id"), body.get("method", "")
        params = body.get("params") or {}
        meta = params.get("_meta") or {}

        # header/_meta enforcement (same oracle discipline as the T1 fixture)
        if self.headers.get("MCP-Protocol-Version") != PV or meta.get("io.modelcontextprotocol/protocolVersion") != PV:
            return self._err(rpc_id, -32022, "bad/missing protocol version")
        if "io.modelcontextprotocol/clientCapabilities" not in meta:
            return self._err(rpc_id, -32602, "missing _meta clientCapabilities")
        accept = self.headers.get("Accept", "")
        if "application/json" not in accept or "text/event-stream" not in accept:
            return self._err(rpc_id, -32020, "Accept must offer both")
        if self.headers.get("Mcp-Method") != method:
            return self._err(rpc_id, -32020, "Mcp-Method mismatch")
        if method in _NAME_SRC and self.headers.get("Mcp-Name") != str(params.get(_NAME_SRC[method])):
            return self._err(rpc_id, -32020, "Mcp-Name mismatch")

        principal = _principal(self.headers)
        if method == "tools/call" and params.get("name") == "redeem":
            return self._redeem(rpc_id, params, principal)
        return self._err(rpc_id, -32601, f"method/tool not found: {method}/{params.get('name')}")

    def _redeem(self, rpc_id, params, principal):
        nonce = (params.get("arguments") or {}).get("nonce", "")
        if params.get("inputResponses") is None:
            # begin leg: a grant is minted ONLY for your own principal (server decides, not the caller)
            cls = type(self)
            cls._voucher_seq += 1
            voucher = f"v{cls._voucher_seq}"
            state = self._mint_state(principal, principal, voucher)
            return self._ok(rpc_id, {"resultType": "input_required",
                                     "inputRequests": {"confirm": {"method": "elicitation/create",
                                                                   "params": {"mode": "form", "message": "confirm?"}}},
                                     "requestState": state})
        # resume leg
        state = params.get("requestState")
        if not state:
            return self._err(rpc_id, -32602, "missing requestState on retry")
        data = self._open_state(rpc_id, state)
        if data is None:
            return None  # rejection already sent (tamper/unparseable)
        voucher, grant = data.get("voucher"), data.get("grant")
        if not self.vulnerable:
            # #5: bind the authenticated principal (reject cross-user) and enforce single-use (reject replay)
            if data.get("principal") != principal:
                return self._err(rpc_id, -32602, "requestState principal != authenticated principal (cross-user)")
            if voucher in type(self)._consumed:
                return self._err(rpc_id, -32602, "requestState already consumed (replay)")
            type(self)._consumed.add(voucher)
        type(self)._redeem_count[voucher] = type(self)._redeem_count.get(voucher, 0) + 1
        data_out = _SECRETS.get(grant, f"public:{grant}")
        text = f"REDEEMED#{type(self)._redeem_count[voucher]} nonce={nonce} data={data_out}"
        return self._ok(rpc_id, {"resultType": "complete", "content": [{"type": "text", "text": text}]})


class VulnerableHandler(_Base):
    vulnerable = True


class SafeHandler(_Base):
    vulnerable = False


def start(vulnerable: bool = True, port: int = 0):
    """Start a fresh host (isolated per-class state) on an ephemeral port. Returns (server, url, thread)."""
    handler = VulnerableHandler if vulnerable else SafeHandler
    handler._voucher_seq = 0
    handler._consumed = set()
    handler._redeem_count = {}
    srv = HTTPServer(("127.0.0.1", port), handler)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/mcp", th
