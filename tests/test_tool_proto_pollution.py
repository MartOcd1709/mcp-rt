"""T11.4 / SAM1-22 zero-FP proof: JS prototype pollution (CWE-1321) → privilege escalation.

VulnerableHost's recursive merge pollutes Object.prototype: a FRESH server-owned object carries the
per-run canary AND a default user flips to admin (privesc); SafeHost skips __proto__/constructor/
prototype → fresh stays clean + default user not admin; benign patch completes on both. Baseline-
fresh-clean rules out a pre-polluted FP. JS host requires Node on PATH (skip otherwise, honestly)."""
import pytest

from mcp_rt import tool_proto_pollution as P
from tests.fixtures import proto_pollution_hosts as H

pytestmark = pytest.mark.skipif(not H.node_available(), reason="JS-host tests require Node on PATH")


@pytest.fixture()
def vuln():
    proc, url, tok = H.start(vulnerable=True)
    try:
        yield url, tok
    finally:
        proc.kill(); proc.wait()


@pytest.fixture()
def safe():
    proc, url, tok = H.start(vulnerable=False)
    try:
        yield url, tok
    finally:
        proc.kill(); proc.wait()


def test_vuln_prototype_pollution_fires(vuln):
    url, tok = vuln
    v = P.probe_prototype_pollution(url, tok)
    assert v["fired"] is True

def test_vuln_canary_on_fresh_object(vuln):
    url, tok = vuln
    assert P.probe_prototype_pollution(url, tok)["polluted"] is True     # canary read off a FRESH object

def test_vuln_reaches_privilege_sink(vuln):
    url, tok = vuln
    assert P.probe_prototype_pollution(url, tok)["privilege_escalated"] is True   # default user -> admin

def test_vuln_baseline_clean_rules_out_fp(vuln):
    url, tok = vuln
    assert P.probe_prototype_pollution(url, tok)["baseline_clean"] is True

def test_safe_prototype_pollution_denied(safe):
    url, tok = safe
    v = P.probe_prototype_pollution(url, tok)
    assert v["fired"] is False and v["polluted"] is False and v["privilege_escalated"] is False

def test_benign_completes_on_both(vuln, safe):
    for url, tok in (vuln, safe):
        v = P.probe_benign(url, tok)
        assert v["completes"] and v["fired"] is False
