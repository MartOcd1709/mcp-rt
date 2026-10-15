"""T10.5 / SAM1-21 zero-FP proof: forced downgrade-to-deprecated. On VulnerableHost the forced-legacy
path bypasses the redaction control -> profile CANARY, while the SAME tool on the modern path is CLEAN
(killer control: the leak is caused by the downgrade, not a tool that always leaks). SafeHost applies
redaction on every version (downgrade bypasses nothing); modern completes on both. Fixtures independent
of the client; each assertion independent."""
import pytest

from mcp_rt import downgrade as P
from tests.fixtures import downgrade_hosts as H


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


# ---- VulnerableHost: forced downgrade FIRES, and the SAME tool on modern is CLEAN (killer control) ----
def test_vuln_forced_downgrade_fires(vuln):
    url, tok = vuln
    assert P.probe_forced_downgrade(url, tok)["fired"] is True

def test_vuln_modern_same_tool_is_clean(vuln):
    url, tok = vuln
    v = P.probe_modern(url, tok)
    assert v["clean"] and v["completes"] and v["fired"] is False   # contrast proves the downgrade caused it


# ---- SafeHost: uniform redaction -> downgrade bypasses nothing; modern completes ----
def test_safe_forced_downgrade_no_bypass(safe):
    url, tok = safe
    assert P.probe_forced_downgrade(url, tok)["fired"] is False

def test_safe_modern_completes(safe):
    url, tok = safe
    v = P.probe_modern(url, tok)
    assert v["completes"] and v["clean"] and v["fired"] is False
