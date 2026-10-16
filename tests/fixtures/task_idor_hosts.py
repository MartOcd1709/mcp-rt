"""Task IDOR oracle hosts for T10.2 (SAM1-21) — independent ground-truth.

Two 2026-07-28 stateless hosts implementing the Tasks extension (io.modelcontextprotocol/tasks, v2
schema): tools/call -> CreateTaskResult{resultType:"task", taskId, status, ...}; tasks/get ->
GetTaskResult{resultType:"complete"} with CompletedTask.result (top-level) or InputRequiredTask
.inputRequests; tasks/update{taskId, inputResponses}. Shapes pinned to the ext-tasks v2 schema.

The Tasks spec is SILENT on owner-binding / revocation re-check, so:
  VulnerableHost — tasks/get & tasks/update ignore the requester: no owner check, no revocation re-check.
  SafeHost       — taskId bound to the creating principal; tasks/get/update require requester == owner
                   AND re-check the principal is still authorized at delivery (real authz-state change
                   via revoke()). Benign owner-poll completes.

Hand-written from the schema; does not import the client or the probe. Per-run token => unique canary.
"""
from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

PV = "2026-07-28"


def _principal(headers) -> str:
    auth = headers.get("Authorization", "")
    return auth[7:].strip() if auth.lower().startswith("bearer ") else "anon"


class _Base(BaseHTTPRequestHandler):
    vulnerable = True
    run_token = "tok"
    _valid: set = set()          # currently-authorized principals (revoke() mutates this = real authz state)
    _tasks: dict = {}            # taskId -> {owner, status, result, inputRequests}
    _seq = 0

    def log_message(self, *a):
        pass

    def _send(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _ok(self, rid, result):
        self._send(200, {"jsonrpc": "2.0", "id": rid, "result": result})

    def _err(self, rid, code, msg):
        self._send(400, {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": msg}})

    def canary(self, owner) -> str:
        return f"CANARY-{self.run_token}-{owner}"

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

        principal = _principal(self.headers)
        cls = type(self)
        if method == "tools/call":
            return self._create(rid, params, principal)
        if method == "tasks/get":
            return self._get(rid, params, principal)
        if method == "tasks/update":
            return self._update(rid, params, principal)
        return self._err(rid, -32601, f"method not found: {method}")

    def _create(self, rid, params, principal):
        cls = type(self)
        cls._seq += 1
        tid = f"task-{cls._seq}"                              # sequential => guessable (amplifier)
        name = params.get("name")
        if name == "need_input":
            cls._tasks[tid] = {"owner": principal, "status": "input_required",
                               "inputRequests": {"confirm": {"method": "elicitation/create",
                                                             "params": {"mode": "form", "message": "confirm?"}}},
                               "result": None}
            status = "input_required"
        else:  # get_secret: completes immediately with the owner's canary
            cls._tasks[tid] = {"owner": principal, "status": "completed",
                               "result": {"output": self.canary(principal)}, "inputRequests": None}
            status = "completed"
        return self._ok(rid, {"resultType": "task", "taskId": tid, "status": status,
                              "createdAt": "2026-07-28T00:00:00Z", "lastUpdatedAt": "2026-07-28T00:00:00Z",
                              "ttlMs": 300000, "pollIntervalMs": 500})

    def _authz_ok(self, rid, task, principal) -> bool:
        """SafeHost gate: requester must OWN the task AND still be authorized (re-checked now)."""
        if self.vulnerable:
            return True                                      # no owner check, no revocation re-check
        if task["owner"] != principal:
            self._err(rid, -32602, "task owned by a different principal (IDOR)")
            return False
        if principal not in type(self)._valid:               # real authz-state re-check at delivery
            self._err(rid, -32602, "principal no longer authorized (revoked)")
            return False
        return True

    def _get(self, rid, params, principal):
        task = type(self)._tasks.get(params.get("taskId"))
        if not task:
            return self._err(rid, -32602, "no such task")
        if not self._authz_ok(rid, task, principal):
            return None
        out = {"resultType": "complete", "taskId": params.get("taskId"), "status": task["status"]}
        if task["status"] == "completed":
            out["result"] = task["result"]
        elif task["status"] == "input_required":
            out["inputRequests"] = task["inputRequests"]
        return self._ok(rid, out)

    def _update(self, rid, params, principal):
        task = type(self)._tasks.get(params.get("taskId"))
        if not task:
            return self._err(rid, -32602, "no such task")
        if not self._authz_ok(rid, task, principal):
            return None
        # apply inputResponses -> task completes, RECORDING what was injected (observable via tasks/get)
        task["status"] = "completed"
        task["result"] = {"output": self.canary(task["owner"]), "applied": params.get("inputResponses")}
        task["inputRequests"] = None
        return self._ok(rid, {"resultType": "complete"})


class VulnerableHandler(_Base):
    vulnerable = True


class SafeHandler(_Base):
    vulnerable = False


def start(vulnerable: bool = True, port: int = 0, principals=("alice", "mallory")):
    """Fresh host: own task store, authz registry, run token. Returns (server, url, run_token, revoke, thread)
    where revoke(principal) performs a REAL authz-state change (removes the principal)."""
    handler = VulnerableHandler if vulnerable else SafeHandler
    handler.run_token = os.urandom(5).hex()
    handler._valid = set(principals)
    handler._tasks = {}
    handler._seq = 0
    srv = HTTPServer(("127.0.0.1", port), handler)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()

    def revoke(principal):
        handler._valid.discard(principal)

    return srv, f"http://127.0.0.1:{srv.server_address[1]}/mcp", handler.run_token, revoke, th
