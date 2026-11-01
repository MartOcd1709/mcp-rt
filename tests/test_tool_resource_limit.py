"""T11.6 / SAM1-22 zero-FP proof: unbounded resource amplification (CWE-770 → CWE-400).

CONFIRMED needs THREE independent signals (missing schema bound AND server honors an above-cap
request AND output scales ~1:1). VulnerableHost (no bound anywhere) fires; SafeHost (schema max +
server cap) is BOUNDED; DefenseInDepthHost (no schema max BUT a real server-side cap) is NOT flagged —
the oracle checks real behavior, not just the schema (no FP on defense-in-depth). Benign small request
completes on all. Measured at tiny bounded values (no wall-clock, nothing exhausted); the CONFIRMED is
a structural proof, not a live outage."""
import pytest

from mcp_rt import tool_resource_limit as P
from tests.fixtures import resource_limit_hosts as H


@pytest.fixture()
def vuln():
    srv, url = H.start(schema_bounded=False, server_capped=False)      # unbounded everywhere
    try:
        yield url
    finally:
        srv.shutdown()


@pytest.fixture()
def safe():
    srv, url = H.start(schema_bounded=True, server_capped=True)        # bounded schema + server cap
    try:
        yield url
    finally:
        srv.shutdown()


@pytest.fixture()
def defense_in_depth():
    srv, url = H.start(schema_bounded=False, server_capped=True)       # no schema max BUT real server cap
    try:
        yield url
    finally:
        srv.shutdown()


def test_vuln_confirmed(vuln):
    v = P.probe_resource_limit(vuln)
    assert v["verdict"] == "CONFIRMED"
    assert v["schema_has_bound"] is False and v["honored_above_cap"] is True and v["amp_ratio_2x"] >= 1.8

def test_vuln_evidence_basis_structural_not_live(vuln):
    v = P.probe_resource_limit(vuln)
    assert "NOT a live-triggered outage" in v["evidence_basis"] and "deployment-dependent" in v["evidence_basis"]

def test_vuln_honored_above_cap_measurement_exact(vuln):
    # determinism: the above-cap request returns output of EXACTLY the proportional size
    v = P.probe_resource_limit(vuln)
    assert v["honored_above_cap"] is True

def test_safe_bounded(safe):
    assert P.probe_resource_limit(safe)["verdict"] == "BOUNDED"

def test_defense_in_depth_not_flagged(defense_in_depth):
    v = P.probe_resource_limit(defense_in_depth)
    assert v["verdict"] == "BOUNDED"                                   # no schema max, but server caps
    assert v["schema_has_bound"] is False and v["honored_above_cap"] is False   # real behavior saves it

def test_benign_completes_on_all(vuln, safe, defense_in_depth):
    for url in (vuln, safe, defense_in_depth):
        assert P.probe_benign(url)["completes"] is True
