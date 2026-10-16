"""T10.1 / SAM1-21 — cacheScope cross-tenant cache poisoning (oracle-gated).

A server that stamps a PER-AUTHORIZATION-CONTEXT result `cacheScope:"public"` lets any conformant
shared cache serve tenant A's bytes to tenant B. We prove it with a REFERENCE conformant shared cache
(itself self-tested — we trust the intermediary before we trust the finding) sitting between two
tenants with distinct bearer tokens. Ground truth only: a sub-case FIRES iff tenant A's per-run-unique
secret / poison marker reaches tenant B THROUGH the shared cache. No model judgement.
"""
from __future__ import annotations

import json

from mcp_rt.mcp_client import StatelessHTTPClient


def _pkey(params: dict) -> str:
    return json.dumps(params or {}, sort_keys=True)


class SharedCache:
    """A spec-conformant shared cache (the trusted oracle intermediary). `fetch(method, params, auth)`
    returns (result_dict, cacheScope). Conformance (caching §Cache Scope):
      * cacheScope "public"  -> keyed by (method, params); served to ANY caller (shared across tenants)
      * cacheScope "private" -> keyed by (method, params, auth); NEVER shared across authorization contexts
    """

    def __init__(self, fetch):
        self._fetch = fetch
        self._public: dict = {}
        self._private: dict = {}
        self.fetches = 0            # observable for the self-test (proves a miss actually re-fetched)

    def get(self, method: str, params: dict, auth: str) -> dict:
        pk = (method, _pkey(params))
        if pk in self._public:
            return self._public[pk]                       # shared across callers — the whole point of "public"
        prk = (method, _pkey(params), auth)
        if prk in self._private:
            return self._private[prk]
        self.fetches += 1
        result, scope = self._fetch(method, params, auth)
        if scope == "public":
            self._public[pk] = result
        else:
            self._private[prk] = result                   # bound to this authorization context
        return result


def _host_fetch(url: str):
    """fetch() backed by a real 2026 stateless host, per-tenant via the Authorization bearer."""
    def fetch(method, params, auth):
        c = StatelessHTTPClient(url)
        res = c.begin(method, params or {}, extra_headers={"Authorization": f"Bearer {auth}"})
        return res, res.get("cacheScope")
    return fetch


def _text(result: dict) -> str:
    return json.dumps(result)


def probe_leak(url: str, run_token: str, attacker="alice", victim="bob") -> dict:
    """Confidentiality: attacker's per-tenant SECRET reaches the victim through the shared cache."""
    cache = SharedCache(_host_fetch(url))
    cache.get("tools/list", {}, attacker)                  # attacker populates the cache first
    victim_view = _text(cache.get("tools/list", {}, victim))
    secret_of_attacker = f"SECRET-{run_token}-{attacker}"
    fired = secret_of_attacker in victim_view
    return {"case": "cross_tenant_leak", "fired": fired, "evidence": secret_of_attacker if fired else "not leaked"}


def probe_poison(url: str, run_token: str, attacker="alice", victim="bob") -> dict:
    """Integrity: attacker's per-tenant poison tool NAME reaches the victim through the shared cache."""
    cache = SharedCache(_host_fetch(url))
    cache.get("tools/list", {}, attacker)
    victim_view = _text(cache.get("tools/list", {}, victim))
    poison_of_attacker = f"POISON-{run_token}-{attacker}"
    fired = poison_of_attacker in victim_view
    return {"case": "cross_tenant_poison", "fired": fired, "evidence": poison_of_attacker if fired else "not poisoned"}


def probe_benign(url: str, run_token: str) -> dict:
    """Controls (resilient earned): (1) a per-tenant PRIVATE list — the victim gets its OWN data and
    COMPLETES, never the attacker's secret; (2) a genuinely-shared PUBLIC catalog served to both,
    correctly and without any tenant secret."""
    cache = SharedCache(_host_fetch(url))
    cache.get("tools/list", {}, "alice")
    bob_tools = _text(cache.get("tools/list", {}, "bob"))
    private_ok = (f"SECRET-{run_token}-bob" in bob_tools) and (f"SECRET-{run_token}-alice" not in bob_tools)
    cat = SharedCache(_host_fetch(url))
    cat.get("prompts/list", {}, "alice")
    bob_cat = _text(cat.get("prompts/list", {}, "bob"))
    public_ok = "public_help" in bob_cat and f"SECRET-{run_token}" not in bob_cat
    return {"case": "benign", "fired": False, "private_completes": private_ok, "public_shared_ok": public_ok}


def assess(url: str, run_token: str) -> list[dict]:
    return [probe_leak(url, run_token), probe_poison(url, run_token), probe_benign(url, run_token)]
