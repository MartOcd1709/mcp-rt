"""T10.2 / SAM1-21 zero-FP proof: Tasks-extension IDOR (get-IDOR / result-after-revoke / update-
injection) + benign owner-poll control. Each sub-case asserted independently per host. VulnerableHost
(no owner check, no revocation re-check) FIRES a/b/c; SafeHost (owner-bound + revocation re-checked at
delivery) rejects all three and the benign owner-poll COMPLETES. Fixtures independent of the client."""
import pytest

from mcp_rt import task_idor as P
from tests.fixtures import task_idor_hosts as H


@pytest.fixture()
def vuln():
    srv, url, tok, revoke, _ = H.start(vulnerable=True)
    try:
        yield url, tok, revoke
    finally:
        srv.shutdown()


@pytest.fixture()
def safe():
    srv, url, tok, revoke, _ = H.start(vulnerable=False)
    try:
        yield url, tok, revoke
    finally:
        srv.shutdown()


# ---- VulnerableHost: a/b/c FIRE (canary reaches attacker / marker lands in victim task) ----
def test_vuln_get_idor_fires(vuln):
    url, tok, _ = vuln
    assert P.probe_get_idor(url, tok)["fired"] is True

def test_vuln_result_after_revoke_fires(vuln):
    url, tok, revoke = vuln
    assert P.probe_result_after_revoke(url, tok, revoke)["fired"] is True

def test_vuln_update_injection_fires(vuln):
    url, tok, _ = vuln
    assert P.probe_update_injection(url, tok)["fired"] is True

def test_vuln_benign_does_not_fire(vuln):
    url, tok, _ = vuln
    v = P.probe_benign(url, tok)
    assert v["fired"] is False and v["completes"]


# ---- SafeHost: owner-bound + revocation re-checked -> a/b/c rejected; benign completes ----
def test_safe_get_idor_rejected(safe):
    url, tok, _ = safe
    assert P.probe_get_idor(url, tok)["fired"] is False

def test_safe_result_after_revoke_rejected(safe):
    url, tok, revoke = safe
    assert P.probe_result_after_revoke(url, tok, revoke)["fired"] is False

def test_safe_update_injection_rejected(safe):
    url, tok, _ = safe
    assert P.probe_update_injection(url, tok)["fired"] is False

def test_safe_benign_completes(safe):
    url, tok, _ = safe
    v = P.probe_benign(url, tok)
    assert v["completes"] and v["fired"] is False   # resilient earned: owner still gets their own result
