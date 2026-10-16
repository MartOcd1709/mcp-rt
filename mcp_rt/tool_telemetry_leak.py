"""T12.1 / SAM1-23 — telemetry leak probe (oracle-gated), OWASP MCP08 family.

Honest labeling (REQUIRED): a CONFIRMED here is CWE-532 — sensitive data written to a telemetry/log
surface a LOWER-PRIVILEGED party can read — surfaced UNDER the MCP08 family but NOT asserted as
"MCP08 confirmed". True MCP08 "Lack of Audit and Telemetry" (under-logging) is a SHOULD/gap posture
that cannot be canaried (can't prove a negative), so it is never reported CONFIRMED here.

Oracle: plant a per-run secret via process(data=TELEM-<tok>), then read the telemetry surface as a
LOW-privileged party; the canary appearing there = CONFIRMED leak. The oracle checks the READER's
privilege, not merely that logging happened (a secret logged to an admin-only surface is NOT flagged).
"""
from __future__ import annotations

from mcp_rt.mcp_client import StatelessHTTPClient, _result_text_2026

_ADMIN = "admin-token"


def canary(tok: str) -> str:
    return f"TELEM-{tok}"


def probe_telemetry_leak(url: str, tok: str, as_admin: bool = False) -> dict:
    c = StatelessHTTPClient(url)
    c.begin("tools/call", {"name": "process", "arguments": {"data": canary(tok)}})          # sensitive arg
    headers = {"Authorization": f"Bearer {_ADMIN}"} if as_admin else None                   # reader privilege
    telem = _result_text_2026(c.begin("tools/call", {"name": "get_telemetry", "arguments": {}},
                                      extra_headers=headers))
    fired = canary(tok) in telem
    return {"case": "telemetry_leak", "fired": fired,
            "cwe": "CWE-532", "owasp_family": "MCP08",
            "confirmed_label": "sensitive data written to a low-privilege-readable telemetry surface (CWE-532)",
            "mcp08_posture_note": ("MCP08 'Lack of Audit and Telemetry' (under-logging) is a SHOULD/gap "
                                   "posture, not canaried-CONFIRMED"),
            "evidence": telem[:120]}


def probe_benign(url: str, tok: str) -> dict:
    c = StatelessHTTPClient(url)
    c.begin("tools/call", {"name": "process", "arguments": {"data": "routine-event"}})      # non-sensitive
    telem = _result_text_2026(c.begin("tools/call", {"name": "get_telemetry", "arguments": {}}))
    return {"case": "benign", "fired": False,
            "completes": "event=process" in telem and canary(tok) not in telem,              # telemetry works, no secret
            "evidence": telem[:120]}
