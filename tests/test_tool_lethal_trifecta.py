"""T12.3 / SAM1-23 zero-FP proof: lethal-trifecta chain (private read + untrusted ingestion + egress).

CONFIRMED only when the PRIVATE canary walks out to the untrusted-named dest via one aggregate() call
(deterministic data-flow, no LLM). No-FP guards: benign feed (no exfil_to) → nothing exfils; fixed_dest
host ignores the untrusted dest → BOUNDED; feed_only host egresses but WITHOUT the private data (steal
hit present, canary absent) → BOUNDED, proving the oracle requires the PRIVATE data specifically, not
any egress; unchained host (three separate tools, no single-call chain) → LEAD. CONFIRMED wording is a
deterministic data-flow proof, explicitly NOT a live LLM injection."""
import pytest

from mcp_rt import tool_lethal_trifecta as P
from tests.fixtures import trifecta_hosts as H


@pytest.fixture()
def vuln():
    srv, url = H.start(mode="vuln", tok="tok")
    try:
        yield url
    finally:
        srv.shutdown()


@pytest.fixture()
def fixed_dest():
    srv, url = H.start(mode="fixed_dest", tok="tok")
    try:
        yield url
    finally:
        srv.shutdown()


@pytest.fixture()
def feed_only():
    srv, url = H.start(mode="feed_only", tok="tok")
    try:
        yield url
    finally:
        srv.shutdown()


@pytest.fixture()
def unchained():
    srv, url = H.start(mode="unchained", tok="tok")
    try:
        yield url
    finally:
        srv.shutdown()


def test_vuln_chain_confirmed(vuln):
    v = P.probe_trifecta(vuln, "tok", malicious_feed=True)
    assert v["verdict"] == "CONFIRMED" and v["exfiltrated"] is True

def test_vuln_benign_feed_bounded(vuln):
    v = P.probe_trifecta(vuln, "tok", malicious_feed=False)      # feed names no egress dest
    assert v["verdict"] == "BOUNDED" and v["exfiltrated"] is False

def test_fixed_dest_bounded(fixed_dest):
    v = P.probe_trifecta(fixed_dest, "tok", malicious_feed=True)  # host ignores the untrusted dest
    assert v["verdict"] == "BOUNDED" and v["exfiltrated"] is False

def test_feed_only_egress_bounded(feed_only):
    v = P.probe_trifecta(feed_only, "tok", malicious_feed=True)
    assert v["verdict"] == "BOUNDED" and v["exfiltrated"] is False
    assert v["steal_hit"] is True        # egress DID happen, but without the private canary -> no FP

def test_unchained_is_lead(unchained):
    assert P.probe_trifecta(unchained, "tok")["verdict"] == "LEAD"

def test_honest_confirmed_wording(vuln):
    v = P.probe_trifecta(vuln, "tok", malicious_feed=True)
    assert "deterministic data-flow proof" in v["confirmed_label"]
    assert "NOT demonstrated here" in v["context_note"] and "no LLM" in v["context_note"]
