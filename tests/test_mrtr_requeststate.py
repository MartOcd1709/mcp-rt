"""T2 / SAM1-13 zero-FP proof: MRTR requestState tamper / replay / cross-user.

Each sub-case (a/b/c/d) is asserted INDEPENDENTLY per host so a failure localizes and the zero-FP
picture stays legible per mode. VulnerableHost FIRES on a/b/c (canary + nonce); SafeHost REJECTS a/b/c
and still COMPLETES the benign control (d) — so "resilient" is earned, not a reject-everything artifact.
The fixtures are the independent oracle (hand-written from schema.ts, no client import)."""
import pytest

from mcp_rt import mrtr_requeststate as P
from tests.fixtures import mrtr_requeststate_hosts as H


@pytest.fixture()
def vuln_url():
    srv, url, _ = H.start(vulnerable=True)
    try:
        yield url
    finally:
        srv.shutdown()


@pytest.fixture()
def safe_url():
    srv, url, _ = H.start(vulnerable=False)
    try:
        yield url
    finally:
        srv.shutdown()


# ---- VulnerableHost: each attack FIRES with canary + nonce (ground truth) ----
def test_vuln_tamper_fires(vuln_url):
    v = P.probe_tamper(vuln_url)
    assert v["fired"], v

def test_vuln_replay_fires(vuln_url):
    v = P.probe_replay(vuln_url)
    assert v["fired"], v

def test_vuln_cross_user_fires(vuln_url):
    v = P.probe_cross_user(vuln_url)
    assert v["fired"], v

def test_vuln_benign_does_not_fire(vuln_url):
    v = P.probe_benign(vuln_url)
    assert v["fired"] is False and v["completed"], v


# ---- SafeHost: each attack REJECTED (no FP); benign still COMPLETES (control earned) ----
def test_safe_tamper_rejected(safe_url):
    v = P.probe_tamper(safe_url)
    assert v["fired"] is False, v

def test_safe_replay_rejected(safe_url):
    v = P.probe_replay(safe_url)
    assert v["fired"] is False, v

def test_safe_cross_user_rejected(safe_url):
    v = P.probe_cross_user(safe_url)
    assert v["fired"] is False, v

def test_safe_benign_completes(safe_url):
    # the CIO's condition: a resilient host must still complete legitimate work, else "resilient" is a lie
    v = P.probe_benign(safe_url)
    assert v["completed"] and v["fired"] is False, v


# ---- aggregate verdict shape ----
def test_assess_vuln_flags_and_safe_clean(vuln_url, safe_url):
    vuln = {r["case"]: r for r in P.assess(vuln_url)}
    safe = {r["case"]: r for r in P.assess(safe_url)}
    assert any(vuln[c]["fired"] for c in ("tamper", "replay", "cross_user"))   # VULNERABLE
    assert not any(safe[c]["fired"] for c in ("tamper", "replay", "cross_user"))  # RESILIENT, zero-FP
    assert safe["benign"]["completed"]
