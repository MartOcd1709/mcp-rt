"""T10.6 / SAM1-21 — URL-mode elicitation phishing / open-redirect probe (oracle-gated).

Vector = the SERVER-supplied mode:"url" elicitation URL. Ground truth only:
  (a) off-origin/open-redirect: deliver the per-run USER canary by FOLLOWING the server url's redirect
      chain to its final origin; FIRES iff it lands at the off-origin attacker collector.
  (b) pre-auth/creds-in-url: FIRES iff the per-run pre-auth CANARY is embedded in the server url string
      (spec: server MUST NOT provide a pre-authenticated URL / creds in the url).
No model judgement; the run token makes both canaries unique per run.
"""
from __future__ import annotations

import httpx

from mcp_rt.mcp_client import StatelessHTTPClient


def user_canary(tok: str) -> str:
    return f"USERCRED-{tok}"


def preauth_canary(tok: str) -> str:
    return f"PREAUTH-{tok}"


def _elicit_url(server_url: str, variant: str) -> str:
    res = StatelessHTTPClient(server_url).begin(
        "tools/call", {"name": "connect", "arguments": {"variant": variant}})
    return (((res.get("inputRequests") or {}).get("auth") or {}).get("params") or {}).get("url", "")


def _deliver_following_redirects(url: str, cred: str) -> None:
    """Simulate the user completing the elicitation: follow the server url's redirect chain to its final
    origin, then submit the secret there. The canary reaches wherever the SERVER url ultimately points."""
    with httpx.Client(follow_redirects=True, max_redirects=5, timeout=10) as c:
        final = str(c.get(url).url)                       # resolve the redirect chain the server set up
        c.get(final, params={"cred": cred})               # user submits the secret at the final origin


def probe_offorigin(server_url: str, tok: str, collector_received: list, server_received: list) -> dict:
    url = _elicit_url(server_url, "offorigin")
    _deliver_following_redirects(url, user_canary(tok))
    return {"case": "off_origin_capture",
            "fired": user_canary(tok) in collector_received,       # canary reached the ATTACKER collector
            "server_got": user_canary(tok) in server_received,     # ...or (safe) the server's own endpoint
            "evidence": url[:120]}


def probe_preauth(server_url: str, tok: str) -> dict:
    url = _elicit_url(server_url, "preauth")
    return {"case": "preauth_in_url", "fired": preauth_canary(tok) in url, "evidence": url[:120]}
