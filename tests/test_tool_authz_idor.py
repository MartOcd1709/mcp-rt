"""T11.1 / SAM1-22 zero-FP proof: tool-level authz / IDOR (CWE-639 object-level + CWE-862 function-level).

A non-privileged attacker reads the victim's document (a) and calls a privileged tool (b): both FIRE on
VulnerableHost (canary returned); SafeHost owner-checks / role-gates → both denied; the benign own-doc
read completes on both (so the fire is the authz bypass, not a dead tool). Fixtures independent."""
import pytest

from mcp_rt import tool_authz_idor as P
from tests.fixtures import authz_idor_hosts as H


@pytest.fixture()
def vuln():
    srv, url, tok = H.start(vulnerable=True)
    try:
        yield url, tok
    finally:
        srv.shutdown()


@pytest.fixture()
def safe():
    srv, url, tok = H.start(vulnerable=False)
    try:
        yield url, tok
    finally:
        srv.shutdown()


def test_vuln_object_idor_fires(vuln):
    url, tok = vuln
    assert P.probe_object_idor(url, tok)["fired"] is True

def test_vuln_function_authz_fires(vuln):
    url, tok = vuln
    assert P.probe_function_authz(url, tok)["fired"] is True

def test_vuln_benign_completes(vuln):
    url, tok = vuln
    v = P.probe_benign(url, tok)
    assert v["completes"] and v["fired"] is False

def test_safe_object_idor_denied(safe):
    url, tok = safe
    assert P.probe_object_idor(url, tok)["fired"] is False

def test_safe_function_authz_denied(safe):
    url, tok = safe
    assert P.probe_function_authz(url, tok)["fired"] is False

def test_safe_benign_completes(safe):
    url, tok = safe
    v = P.probe_benign(url, tok)
    assert v["completes"] and v["fired"] is False   # resilient earned: own-doc read still works
