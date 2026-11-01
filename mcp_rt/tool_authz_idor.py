"""T11.1 / SAM1-22 — tool-level authz / IDOR probe (oracle-gated).

Classic impl bug: broken object-level authz (CWE-639/BOLA) + missing function-level authz (CWE-862).
A valid NON-privileged attacker (owns only their own object, no admin role) asks for someone else's
object or calls a privileged tool. Ground truth only: FIRES iff a per-run CANARY the attacker is NOT
entitled to (the victim's document / the admin-only secret) is returned to the attacker.
"""
from __future__ import annotations

from mcp_rt.mcp_client import StatelessHTTPClient, _result_text_2026

ATTACKER = "attacker"


def _call(url, name, args):
    return _result_text_2026(StatelessHTTPClient(url).begin(
        "tools/call", {"name": name, "arguments": args}, extra_headers={"Authorization": f"Bearer {ATTACKER}"}))


def probe_object_idor(url: str, tok: str) -> dict:
    text = _call(url, "get_document", {"doc_id": "doc-alice"})   # the victim's document
    fired = f"DOC-SECRET-{tok}-alice" in text
    return {"case": "object_idor", "fired": fired, "evidence": text[:120]}


def probe_function_authz(url: str, tok: str) -> dict:
    text = _call(url, "admin_stats", {})                         # privileged tool, attacker is not admin
    fired = f"ADMIN-STATS-{tok}" in text
    return {"case": "function_authz", "fired": fired, "evidence": text[:120]}


def probe_benign(url: str, tok: str) -> dict:
    text = _call(url, "get_document", {"doc_id": "doc-attacker"})  # the attacker's OWN document
    completes = "public notes" in text and f"DOC-SECRET-{tok}" not in text
    return {"case": "benign", "fired": False, "completes": completes, "evidence": text[:120]}
