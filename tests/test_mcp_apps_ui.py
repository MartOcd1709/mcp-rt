"""T10.7 / SAM1-21 zero-FP proof: MCP Apps UI injection (CONFIRMED) + structural LEADs (UNCONFIRMED).

Oracle integrity first: the reference HTML evaluator (is the canary node in an executable position?) is
INDEPENDENT of the host's escaper (html.escape) and passes its own self-check with hand-written markup
(no html.escape). Then: VulnerableHost renders the injected note unescaped -> canary node is LIVE
(FIRES); SafeHost escapes it -> inert text (no fire); benign ordinary content renders inert on both.
Clickjacking/CSP/permission observations are emitted as clearly-labeled UNCONFIRMED leads."""
import pytest

from mcp_rt import mcp_apps_ui as P
from tests.fixtures import mcp_apps_hosts as H


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


# ---- oracle integrity: evaluator is correct AND independent of the escaper ----
def test_evaluator_self_check_independent_of_escaper():
    c = "ZZcanary"
    assert P.node_is_executable(f"<script>{c}</script>", c) is True          # live script -> executable
    assert P.node_is_executable(f"&lt;script&gt;{c}&lt;/script&gt;", c) is False  # escaped TEXT (hand-written) -> inert
    assert P.node_is_executable(f"<p>{c}</p>", c) is False                   # plain data -> inert
    # independence: the evaluator module must not import the host's escaper (html.escape via the fixture)
    import mcp_rt.mcp_apps_ui as m
    assert "html" not in getattr(m, "__dict__", {})  # no html module pulled into the evaluator's namespace


# ---- CONFIRMED: UI markup injection ----
def test_vuln_injection_fires(vuln):
    url, tok = vuln
    v = P.probe_injection(url, tok)
    assert v["confirmed"] and v["fired"] is True

def test_safe_injection_inert(safe):
    url, tok = safe
    v = P.probe_injection(url, tok)
    assert v["fired"] is False

def test_benign_renders_inert_on_both(vuln, safe):
    for url, tok in (vuln, safe):
        v = P.probe_benign(url, tok)
        assert v["fired"] is False and v["renders"]


# ---- LEADs: structural, always UNCONFIRMED ----
def test_leads_are_unconfirmed(vuln):
    url, _ = vuln
    leads = P.structural_leads(url)
    assert leads and all(l["confirmed"] is False for l in leads)
    kinds = {l["kind"] for l in leads}
    assert "clickjacking/ui-redress" in kinds and "permissive-csp" in kinds and "over-broad-permissions" in kinds
