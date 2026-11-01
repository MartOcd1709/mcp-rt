"""T10.6 / SAM1-21 zero-FP proof: URL-mode elicitation phishing / open-redirect.

Oracle integrity first: the attacker collector records a canary ONLY when delivered to its /collect path
(test_collector_only_records_its_endpoint). Then: (a) off-origin — VulnerableHost's open-redirect url
lands the USER canary at the collector (FIRES); SafeHost's same-origin url delivers it to the SERVER
instead (benign completes, server receives it — contrast proves the off-origin capture). (b) pre-auth —
VulnerableHost embeds the pre-auth canary in the url (FIRES); SafeHost doesn't. Collector + fixtures
independent of the client."""
import httpx
import pytest

from mcp_rt import url_elicitation as P
from tests.fixtures import url_elicit_hosts as H


@pytest.fixture()
def collector():
    srv, url, received = H.start_collector()
    try:
        yield url, received
    finally:
        srv.shutdown()


# ---- oracle integrity: the collector records ONLY deliveries to its /collect endpoint ----
def test_collector_only_records_its_endpoint(collector):
    url, received = collector
    httpx.get(f"{url}/collect", params={"cred": "X-on-collect"}, timeout=10)
    httpx.get(f"{url}/elsewhere", params={"cred": "Y-off-endpoint"}, timeout=10)
    assert "X-on-collect" in received and "Y-off-endpoint" not in received


# ---- (a) off-origin / open-redirect capture ----
def test_vuln_offorigin_fires(collector):
    curl, received = collector
    srv, mcp, tok, server_received = H.start(vulnerable=True, collector_url=curl)
    try:
        v = P.probe_offorigin(mcp, tok, received, server_received)
        assert v["fired"] is True                              # USER canary reached the attacker collector
    finally:
        srv.shutdown()

def test_safe_offorigin_delivers_to_server_not_attacker(collector):
    curl, received = collector
    srv, mcp, tok, server_received = H.start(vulnerable=False, collector_url=curl)
    try:
        v = P.probe_offorigin(mcp, tok, received, server_received)
        assert v["fired"] is False and v["server_got"] is True  # benign completes: server receives, attacker doesn't
    finally:
        srv.shutdown()


# ---- (b) pre-authenticated / credential-in-URL ----
def test_vuln_preauth_fires(collector):
    curl, _ = collector
    srv, mcp, tok, _ = H.start(vulnerable=True, collector_url=curl)
    try:
        assert P.probe_preauth(mcp, tok)["fired"] is True
    finally:
        srv.shutdown()

def test_safe_preauth_clean(collector):
    curl, _ = collector
    srv, mcp, tok, _ = H.start(vulnerable=False, collector_url=curl)
    try:
        assert P.probe_preauth(mcp, tok)["fired"] is False
    finally:
        srv.shutdown()
