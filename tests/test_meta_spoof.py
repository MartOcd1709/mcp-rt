"""T10.3 / SAM1-21 zero-FP proof: per-request _meta identity spoofing. A non-privileged attacker spoofs
clientInfo (a) / clientCapabilities (b) to claim admin. VulnerableHost (trusts the unverified _meta)
FIRES; SafeHost (decides on the real Authorization principal, ignores _meta for security) does not, and
the benign honest request completes. Fixtures independent of the client; each sub-case independent."""
import pytest

from mcp_rt import meta_spoof as P
from tests.fixtures import meta_spoof_hosts as H


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


# ---- VulnerableHost: privilege granted off the spoofed _meta alone ----
def test_vuln_clientinfo_spoof_fires(vuln):
    url, tok = vuln
    assert P.probe_clientinfo_spoof(url, tok)["fired"] is True

def test_vuln_caps_spoof_fires(vuln):
    url, tok = vuln
    assert P.probe_caps_spoof(url, tok)["fired"] is True

def test_vuln_benign_does_not_fire(vuln):
    url, tok = vuln
    v = P.probe_benign(url, tok)
    assert v["fired"] is False and v["completes"]


# ---- SafeHost: decides on real Authorization, ignores _meta for security ----
def test_safe_clientinfo_spoof_rejected(safe):
    url, tok = safe
    assert P.probe_clientinfo_spoof(url, tok)["fired"] is False

def test_safe_caps_spoof_rejected(safe):
    url, tok = safe
    assert P.probe_caps_spoof(url, tok)["fired"] is False

def test_safe_benign_completes(safe):
    url, tok = safe
    v = P.probe_benign(url, tok)
    assert v["completes"] and v["fired"] is False
