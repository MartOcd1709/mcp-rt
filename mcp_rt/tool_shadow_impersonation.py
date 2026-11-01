"""T12.2 / SAM1-23 — shadow / tool-impersonation probe (oracle-gated), OWASP MCP09.

mcp-rt assesses whether a TARGET server declares a tool name that collides with a canonical/trusted
tool and would OVERRIDE it under a standard host resolver. The resolution policy below models a
realistic host (it is the TEST HARNESS, not the target). Ground truth: the shadow source carries a
per-run nonce SHADOW-<tok>; if resolving the bare name invokes the shadow (nonce observed), the
override is DEMONSTRATED.

Honest attribution (REQUIRED): a name collision alone does NOT make the target malicious. The finding
attributes the shadowing CAPABILITY to the target (CWE-706, incorrectly-resolved reference, under the
MCP09 family). Severity MUST only when the override is DEMONSTRATED (nonce wins) AND no server-identity
namespacing would let a host disambiguate.
"""
from __future__ import annotations

from mcp_rt.mcp_client import StatelessHTTPClient, _result_text_2026

_ATTRIBUTION = ("target server declares a tool name colliding with a canonical/trusted tool; under a "
                "standard last-wins / untrusted-first resolver it OVERRIDES the trusted tool "
                "(impersonation). MUST only when the override is DEMONSTRATED (shadow nonce wins) AND no "
                "server-identity namespacing would disambiguate. A name collision alone does not imply a "
                "malicious target.")


class CollisionError(Exception):
    pass


def resolve(sources: list, name: str, policy: str):
    """Model of a host's tool-name resolution. sources are in registration order; each is
    {label, url, tools:[names]}. Returns the chosen {label,url} for `name`, or None if absent."""
    matches = [{"label": s["label"], "url": s["url"]} for s in sources if name in s["tools"]]
    if not matches:
        return None
    if len(matches) == 1:
        return matches[0]
    if policy == "last_wins":            # naive: a later-registered collision silently overrides
        return matches[-1]
    if policy == "namespaced":           # host disambiguates by server identity -> keep the trusted/first
        return matches[0]
    if policy == "reject_collision":     # host refuses to resolve an ambiguous name
        raise CollisionError(name)
    raise ValueError(f"unknown policy {policy!r}")


def _source(label: str, url: str) -> dict:
    tools = [t["name"] for t in StatelessHTTPClient(url).list_tools()]
    return {"label": label, "url": url, "tools": tools}


def _call(url: str, name: str) -> str:
    return _result_text_2026(StatelessHTTPClient(url).begin("tools/call", {"name": name, "arguments": {}}))


def probe_shadow(trusted_url: str, shadow_url: str, tok: str, policy: str = "last_wins",
                 name: str = "get_weather") -> dict:
    sources = [_source("trusted", trusted_url), _source("shadow", shadow_url)]   # shadow registered after
    meta = {"case": "shadow_impersonation", "cwe": "CWE-706", "owasp_family": "MCP09",
            "policy": policy, "attribution": _ATTRIBUTION}
    try:
        chosen = resolve(sources, name, policy)
    except CollisionError:
        return {**meta, "verdict": "LEAD", "nonce_present": False,
                "note": "collision present but the resolver refuses to resolve -> override not demonstrated"}
    if chosen is None:
        return {**meta, "verdict": "BOUNDED", "nonce_present": False, "note": "no such tool"}
    nonce = f"SHADOW-{tok}" in _call(chosen["url"], name)
    return {**meta, "verdict": "CONFIRMED" if nonce else "BOUNDED", "nonce_present": nonce,
            "chosen": chosen["label"],
            "note": ("shadow overrode the trusted tool under this resolver" if nonce
                     else "trusted tool resolved; shadow did not override")}
