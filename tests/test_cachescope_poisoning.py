"""T10.1 / SAM1-21 zero-FP proof: cacheScope cross-tenant cache poisoning.

We trust the intermediary before the finding: test_reference_cache_* proves the SharedCache oracle is
itself spec-conformant (public shared across callers; private never crosses) BEFORE it is used to
judge a host. Then leak+poison FIRE on VulnerableHost (public on per-tenant data); SafeHost (private)
does not leak, and both benign controls complete. Fixtures/oracle independent of the client."""
import pytest

from mcp_rt.cachescope import SharedCache, probe_benign, probe_leak, probe_poison
from tests.fixtures import cachescope_hosts as H


@pytest.fixture()
def vuln():
    srv, url, tok, _ = H.start(vulnerable=True)
    try:
        yield url, tok
    finally:
        srv.shutdown()


@pytest.fixture()
def safe():
    srv, url, tok, _ = H.start(vulnerable=False)
    try:
        yield url, tok
    finally:
        srv.shutdown()


# ---- oracle integrity: the reference shared cache is itself conformant ----
def test_reference_cache_public_is_shared_across_callers():
    cache = SharedCache(lambda m, p, auth: ({"who": auth}, "public"))
    first = cache.get("tools/list", {}, "alice")          # populates
    second = cache.get("tools/list", {}, "bob")           # different caller
    assert second == {"who": "alice"} and cache.fetches == 1   # bob served alice's cached public entry

def test_reference_cache_private_never_crosses():
    cache = SharedCache(lambda m, p, auth: ({"who": auth}, "private"))
    cache.get("tools/list", {}, "alice")
    second = cache.get("tools/list", {}, "bob")
    assert second == {"who": "bob"} and cache.fetches == 2      # bob re-fetched; never got alice's


# ---- VulnerableHost: leak + poison FIRE through the shared cache ----
def test_vuln_cross_tenant_leak_fires(vuln):
    url, tok = vuln
    assert probe_leak(url, tok)["fired"] is True

def test_vuln_cross_tenant_poison_fires(vuln):
    url, tok = vuln
    assert probe_poison(url, tok)["fired"] is True


# ---- SafeHost: private -> no cross-tenant leak/poison, benign controls complete ----
def test_safe_no_leak(safe):
    url, tok = safe
    assert probe_leak(url, tok)["fired"] is False

def test_safe_no_poison(safe):
    url, tok = safe
    assert probe_poison(url, tok)["fired"] is False

def test_safe_benign_controls_complete(safe):
    url, tok = safe
    v = probe_benign(url, tok)
    assert v["private_completes"] and v["public_shared_ok"], v   # resilient earned, not reject-all
