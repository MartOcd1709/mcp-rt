"""T10.4 / SAM1-21 zero-FP proof: Mcp-Name header/body method differential (request smuggling).

VulnerableHost authorizes on the Mcp-Name header but executes the body -> the smuggle FIRES (admin_exec
canary returns when the header claimed safe_echo). SafeHost enforces header==body (-32020 on mismatch,
executes nothing). Controls make the finding airtight: benign (header==body==safe_echo) COMPLETES on
BOTH; honest admin_exec==admin_exec is DENIED on BOTH (not allowlisted) — so the fire is specifically
the differential, not mere reachability. Fixtures independent of the client."""
import pytest

from mcp_rt import mcp_name_differential as P
from tests.fixtures import mcp_name_differential_hosts as H


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


# ---- VulnerableHost: the differential FIRES; controls hold ----
def test_vuln_smuggle_fires(vuln):
    url, tok = vuln
    assert P.probe_smuggle(url, tok)["fired"] is True

def test_vuln_benign_completes(vuln):
    url, tok = vuln
    v = P.probe_benign(url, tok)
    assert v["completes"] and v["fired"] is False          # not allow-all: safe_echo still works

def test_vuln_honest_admin_denied(vuln):
    url, tok = vuln
    v = P.probe_honest_admin_denied(url, tok)
    assert v["denied"] and v["fired"] is False             # honest admin_exec denied -> (a) proves the differential


# ---- SafeHost: mismatch rejected (-32020); controls hold ----
def test_safe_smuggle_rejected(safe):
    url, tok = safe
    assert P.probe_smuggle(url, tok)["fired"] is False

def test_safe_benign_completes(safe):
    url, tok = safe
    v = P.probe_benign(url, tok)
    assert v["completes"] and v["fired"] is False

def test_safe_honest_admin_denied(safe):
    url, tok = safe
    v = P.probe_honest_admin_denied(url, tok)
    assert v["denied"] and v["fired"] is False
