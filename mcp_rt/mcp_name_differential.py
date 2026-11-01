"""T10.4 / SAM1-21 — Mcp-Name header/body method differential probe (oracle-gated).

Streamable-HTTP: the Mcp-Name header MUST equal body params.name; mismatch MUST -> -32020. A server
that authorizes on the HEADER but executes the BODY is smuggling. Ground truth only: FIRES iff the
privileged per-run admin_exec CANARY returns when the Mcp-Name header claimed the allowlisted safe_echo
— i.e. the mismatch provably crossed the trust boundary. MUST-violation (not a gap/SHOULD-NOT).
"""
from __future__ import annotations

from mcp_rt.mcp_client import StatelessHTTPClient, _result_text_2026


def _canary(tok: str) -> str:
    return f"EXEC-ADMIN-{tok}"


def _call(url: str, body_name: str, header_override: str | None = None):
    """tools/call with body params.name=body_name; Mcp-Name header overridden if header_override is set
    (the client otherwise sets it to body_name). Returns text, or None if the server REJECTED (-32020)."""
    eh = {"Mcp-Name": header_override} if header_override else None
    try:
        res = StatelessHTTPClient(url).begin("tools/call", {"name": body_name, "arguments": {}}, extra_headers=eh)
        return _result_text_2026(res)
    except Exception:  # noqa: BLE001 — a -32020 rejection is the resilient outcome
        return None


def probe_smuggle(url: str, tok: str) -> dict:
    # header says safe_echo (allowlisted); body says admin_exec (privileged, not allowlisted)
    text = _call(url, "admin_exec", header_override="safe_echo")
    fired = bool(text) and _canary(tok) in text
    return {"case": "header_body_smuggle", "fired": fired, "evidence": (text or "REJECTED")[:120]}


def probe_benign(url: str, tok: str) -> dict:
    # header == body == safe_echo -> authorized + executed -> public, completes (must hold on BOTH hosts)
    text = _call(url, "safe_echo")
    completes = bool(text) and "public tiles" in text and _canary(tok) not in text
    return {"case": "benign", "fired": False, "completes": completes, "evidence": (text or "REJECTED")[:120]}


def probe_honest_admin_denied(url: str, tok: str) -> dict:
    # header == body == admin_exec (honest, no smuggle) -> NOT allowlisted -> denied on BOTH hosts.
    # This is the control that makes (a) prove the DIFFERENTIAL, not mere reachability of admin_exec.
    text = _call(url, "admin_exec")
    denied = bool(text) and _canary(tok) not in text
    return {"case": "honest_admin_denied", "fired": _canary(tok) in (text or ""), "denied": denied,
            "evidence": (text or "REJECTED")[:120]}
