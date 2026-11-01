"""T10.3 / SAM1-21 — per-request _meta identity-spoofing probe (oracle-gated).

A NON-privileged attacker (real Authorization principal with no admin rights) spoofs the self-reported,
unverified _meta identity to claim privilege. Spec (basic/index §_meta): clientInfo/clientCapabilities
"are not verified ... SHOULD NOT rely on them for security decisions." Ground truth only: FIRES iff the
privileged per-run CANARY comes back when the ONLY thing asserting privilege is the spoofed _meta.
Honest framing: (a) clientInfo = a SHOULD-NOT violation; (b) clientCapabilities = a trust error on
self-asserted caps (negotiation field, not a security boundary) — not a bare MUST.
"""
from __future__ import annotations

from mcp_rt.mcp_client import StatelessHTTPClient, _result_text_2026

ATTACKER = "attacker"          # a genuinely non-privileged real-auth principal


def _canary(tok: str) -> str:
    return f"ADMIN-SECRET-{tok}"


def _dashboard(url: str, *, client_info: dict, capabilities: dict) -> str:
    """Call read_dashboard as the non-privileged attacker, with the given (spoofed) _meta identity."""
    c = StatelessHTTPClient(url, client_info=client_info, capabilities=capabilities)
    res = c.begin("tools/call", {"name": "read_dashboard", "arguments": {}},
                  extra_headers={"Authorization": f"Bearer {ATTACKER}"})
    return _result_text_2026(res)


def probe_clientinfo_spoof(url: str, tok: str) -> dict:
    # only clientInfo claims privilege (caps empty) -> isolates clientInfo as the trigger
    text = _dashboard(url, client_info={"name": "trusted-admin", "version": "9"}, capabilities={})
    fired = _canary(tok) in text
    return {"case": "clientinfo_spoof", "fired": fired, "evidence": text[:120]}


def probe_caps_spoof(url: str, tok: str) -> dict:
    # only clientCapabilities claims privilege (clientInfo is a nobody) -> isolates caps as the trigger
    text = _dashboard(url, client_info={"name": "nobody", "version": "1"},
                      capabilities={"extensions": {"com.acme/admin": {}}})
    fired = _canary(tok) in text
    return {"case": "caps_spoof", "fired": fired, "evidence": text[:120]}


def probe_benign(url: str, tok: str) -> dict:
    # honest modest identity -> non-privileged result, must COMPLETE and NOT leak the admin canary
    text = _dashboard(url, client_info={"name": "honest-client", "version": "1"}, capabilities={})
    completes = "public tiles" in text and _canary(tok) not in text
    return {"case": "benign", "fired": False, "completes": completes, "evidence": text[:120]}
