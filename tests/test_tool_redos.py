"""T11.5 / SAM1-22 zero-FP proof: ReDoS / catastrophic backtracking (CWE-1333 -> CWE-400).

Oracle = a DETERMINISTIC, engine-independent step-counter (no wall-clock). Oracle-integrity FIRST:
exact-known-count self-checks on BOTH a known-catastrophic pattern and a known-linear one, so the
counter is trusted before any verdict. Then: VulnerableHost's schema pattern is CONFIRMED catastrophic
(step blowup super-polynomial), SafeHost's is BOUNDED, an out-of-class pattern is a LEAD (not
CONFIRMED), and a benign short input validates on both. The adversarial input is proven STATICALLY and
is NEVER sent to the server; the CONFIRMED is explicitly a static proof, NOT a live-triggered DoS."""
import pytest

from mcp_rt import tool_redos as P
from tests.fixtures import redos_hosts as H


@pytest.fixture()
def vuln():
    srv, url = H.start(vulnerable=True)
    try:
        yield url
    finally:
        srv.shutdown()


@pytest.fixture()
def safe():
    srv, url = H.start(vulnerable=False)
    try:
        yield url
    finally:
        srv.shutdown()


# ---- oracle integrity: trust the counter before any verdict (exact, deterministic, both classes) ----
def test_oracle_selfcheck_exact_counts():
    assert P.match_steps(P.parse("^(a+)+$"), "aaaa!")[1] == 81     # known-catastrophic, exact
    assert P.match_steps(P.parse("^a+$"), "aaaa!")[1] == 12        # known-linear, exact
    # determinism: identical on repeat
    assert P.match_steps(P.parse("^(a+)+$"), "aaaa!")[1] == 81


# ---- CONFIRMED: catastrophic schema pattern (static step-count blowup) ----
def test_vuln_host_confirmed(vuln):
    v = P.probe_redos(vuln)
    assert v["verdict"] == "CONFIRMED" and v["blowup"] >= 8 and v["steps_n2"] > v["steps_n1"]

def test_vuln_evidence_basis_is_static_not_live(vuln):
    v = P.probe_redos(vuln)
    assert "NOT a live DoS" in v["evidence_basis"] and "deployment-dependent" in v["evidence_basis"]


# ---- SafeHost pattern is bounded; out-of-class is a LEAD (honest scoping) ----
def test_safe_host_bounded(safe):
    assert P.probe_redos(safe)["verdict"] == "BOUNDED"

def test_out_of_class_pattern_is_lead():
    v = P.analyze_pattern("^[a-z]+@[a-z]+$")                       # char classes are outside the subset
    assert v["verdict"] == "LEAD"


# ---- benign short input validates on both (resilient earned; server applies the pattern) ----
def test_benign_input_completes_on_both(vuln, safe):
    for url in (vuln, safe):
        assert P.probe_benign(url)["completes"] is True
