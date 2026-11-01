"""T10.2 / SAM1-21 — Tasks-extension IDOR probe (oracle-gated).

The Tasks extension is SILENT on owner-binding / revocation re-check (an authz GAP the spec leaves
open, NOT a MUST-violation — keep that wording in any finding text). A durable, obtainable `taskId`
with no required owner check is IDOR by default. Ground truth only: a sub-case FIRES iff the victim's
per-run-unique CANARY reaches the attacker (get-IDOR / result-after-revoke) or the attacker's marker
lands in the victim's task (update-injection). No model judgement.
"""
from __future__ import annotations

import json

from mcp_rt.mcp_client import StatelessHTTPClient

VICTIM, ATTACKER = "alice", "mallory"


def _canary(tok: str, owner: str) -> str:
    return f"CANARY-{tok}-{owner}"


def _call(url: str, method: str, params: dict, auth: str):
    """One JSON-RPC call as `auth`. Returns the result dict, or None if the server REJECTED (HTTP 400)."""
    try:
        return StatelessHTTPClient(url).begin(method, params, extra_headers={"Authorization": f"Bearer {auth}"})
    except Exception:  # noqa: BLE001 — a rejection is the resilient outcome, not a crash
        return None


def _create(url: str, auth: str, tool: str) -> str:
    res = _call(url, "tools/call", {"name": tool, "arguments": {}}, auth) or {}
    return res.get("taskId")


def probe_get_idor(url: str, tok: str) -> dict:
    tid = _create(url, VICTIM, "get_secret")                 # victim's completed task (holds victim's canary)
    stolen = _call(url, "tasks/get", {"taskId": tid}, ATTACKER)   # attacker fetches the victim's task
    fired = bool(stolen) and _canary(tok, VICTIM) in json.dumps(stolen)
    return {"case": "get_idor", "fired": fired, "evidence": (json.dumps(stolen) if stolen else "REJECTED")[:120]}


def probe_result_after_revoke(url: str, tok: str, revoke) -> dict:
    tid = _create(url, VICTIM, "get_secret")
    revoke(VICTIM)                                           # REAL authz-state change (principal removed)
    after = _call(url, "tasks/get", {"taskId": tid}, VICTIM)     # owner polls, but authorization is now revoked
    fired = bool(after) and _canary(tok, VICTIM) in json.dumps(after)
    return {"case": "result_after_revoke", "fired": fired, "evidence": (json.dumps(after) if after else "REJECTED")[:120]}


def probe_update_injection(url: str, tok: str) -> dict:
    tid = _create(url, VICTIM, "need_input")                 # victim's input_required task
    marker = f"ATKMARK-{tok}"
    _call(url, "tasks/update", {"taskId": tid, "inputResponses": {"confirm": {"marker": marker}}}, ATTACKER)
    victim_view = _call(url, "tasks/get", {"taskId": tid}, VICTIM)   # did the attacker's input land in the victim's task?
    fired = bool(victim_view) and marker in json.dumps(victim_view)
    return {"case": "update_injection", "fired": fired, "evidence": (json.dumps(victim_view) if victim_view else "none")[:120]}


def probe_benign(url: str, tok: str) -> dict:
    """Control: the owner polls their OWN (non-revoked) task — must COMPLETE with their own result."""
    tid = _create(url, VICTIM, "get_secret")
    own = _call(url, "tasks/get", {"taskId": tid}, VICTIM)
    completes = bool(own) and _canary(tok, VICTIM) in json.dumps(own) and own.get("status") == "completed"
    return {"case": "benign", "fired": False, "completes": completes}
