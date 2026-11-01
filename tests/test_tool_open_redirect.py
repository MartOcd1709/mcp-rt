"""T11.3 / SAM1-22 zero-FP proof: open redirect (CWE-601) + session-token exfil (CWE-200/552).

VulnerableHost appends the session token to an off-origin return_to → the token lands at the
attacker's collector AND is replayable to account_summary (account takeover = the HIGH impact);
SafeHost allowlists same-origin → off-origin rejected, collector silent, no token to replay; benign
same-origin login completes on both. Oracle integrity first: the collector records ONLY its /collect
endpoint. Fire-check is pure substring / request-log with NO URL parser deciding it (anti-circularity)."""
import httpx
import pytest

from mcp_rt import tool_open_redirect as P
from tests.fixtures import open_redirect_hosts as H


@pytest.fixture()
def collector():
    srv, base, received = H.start_collector()
    try:
        yield base, received
    finally:
        srv.shutdown()


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


# ---- oracle integrity: the collector sink records only its own endpoint ----
def test_collector_oracle_self_check(collector):
    base, received = collector
    httpx.get(f"{base}/not-collect?token=SESS-xyz", timeout=5)      # wrong path -> records nothing
    assert received == []
    httpx.get(f"{base}/collect?token=SESS-xyz", timeout=5)          # its endpoint -> records
    assert any("SESS-xyz" in r for r in received)


# ---- CONFIRMED: off-origin open redirect leaks the session token ----
def test_vuln_open_redirect_leaks_token(vuln, collector):
    url, tok = vuln
    base, received = collector
    v = P.probe_open_redirect(url, tok, base, received)
    assert v["fired"] is True and v["collector_logged"] and v["in_redirect"]


def test_vuln_leaked_token_enables_account_takeover(vuln, collector):
    url, tok = vuln
    base, received = collector
    v = P.probe_open_redirect(url, tok, base, received)
    assert v["captured"]                                            # attacker now holds the session token
    a = P.probe_account_takeover(url, tok, v["captured"])
    assert a["ato"] is True                                         # replay -> victim's private account data


# ---- SafeHost denies both the leak and the takeover ----
def test_safe_open_redirect_denied(safe, collector):
    url, tok = safe
    base, received = collector
    v = P.probe_open_redirect(url, tok, base, received)
    assert v["fired"] is False and v["collector_logged"] is False


def test_safe_blocks_account_takeover(safe, collector):
    url, tok = safe
    base, received = collector
    v = P.probe_open_redirect(url, tok, base, received)             # nothing leaks on SafeHost
    a = P.probe_account_takeover(url, tok, v["captured"] or "garbage")
    assert a["ato"] is False                                        # attacker has no valid token


# ---- benign same-origin login completes on both (resilient earned) ----
def test_benign_same_origin_completes_on_both(vuln, safe):
    for url, tok in (vuln, safe):
        v = P.probe_benign(url, tok)
        assert v["completes"] and v["fired"] is False and v["off_origin_leak"] is False
