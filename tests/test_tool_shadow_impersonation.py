"""T12.2 / SAM1-23 zero-FP proof: shadow / tool-impersonation (CWE-706, OWASP MCP09).

A shadow source declares the same tool name as a trusted one and, under a standard last-wins resolver,
OVERRIDES it (its per-run nonce is observed) = CONFIRMED. No-FP guards: a namespacing resolver keeps
the trusted tool (BOUNDED) — the mitigation; no collision at all (shadow uses a different name) →
trusted resolves (BOUNDED); a reject-on-collision resolver can't demonstrate an override → LEAD.
Honest attribution: the finding attributes the shadowing CAPABILITY to the target (CWE-706, MCP09),
never calls a name collision 'malicious', and marks MUST only when override is demonstrated."""
import pytest

from mcp_rt import tool_shadow_impersonation as P
from tests.fixtures import shadow_tool_hosts as H


@pytest.fixture()
def trusted():
    srv, url = H.start(role="trusted", tool_name="get_weather")
    try:
        yield url
    finally:
        srv.shutdown()


@pytest.fixture()
def shadow():
    srv, url = H.start(role="shadow", tok="tok", tool_name="get_weather")
    try:
        yield url
    finally:
        srv.shutdown()


@pytest.fixture()
def shadow_other_name():
    srv, url = H.start(role="shadow", tok="tok", tool_name="get_shadow_weather")   # no collision
    try:
        yield url
    finally:
        srv.shutdown()


def test_shadow_overrides_under_standard_resolver(trusted, shadow):
    v = P.probe_shadow(trusted, shadow, "tok", policy="last_wins")
    assert v["verdict"] == "CONFIRMED" and v["nonce_present"] is True and v["chosen"] == "shadow"

def test_namespacing_disambiguates_bounded(trusted, shadow):
    v = P.probe_shadow(trusted, shadow, "tok", policy="namespaced")   # host disambiguates by server
    assert v["verdict"] == "BOUNDED" and v["nonce_present"] is False and v["chosen"] == "trusted"

def test_no_collision_benign_bounded(trusted, shadow_other_name):
    v = P.probe_shadow(trusted, shadow_other_name, "tok", policy="last_wins")
    assert v["verdict"] == "BOUNDED" and v["nonce_present"] is False   # get_weather resolves to trusted only

def test_reject_collision_is_lead(trusted, shadow):
    v = P.probe_shadow(trusted, shadow, "tok", policy="reject_collision")
    assert v["verdict"] == "LEAD" and v["nonce_present"] is False      # override not demonstrated

def test_nonce_is_shadow_specific(trusted):
    # oracle integrity: invoking the trusted tool directly never yields the shadow nonce
    assert "SHADOW-tok" not in P._call(trusted, "get_weather")

def test_honest_attribution_labeling(trusted, shadow):
    v = P.probe_shadow(trusted, shadow, "tok", policy="last_wins")
    assert v["cwe"] == "CWE-706" and v["owasp_family"] == "MCP09"
    assert "does not imply a malicious target" in v["attribution"]
    assert "MUST only when" in v["attribution"]
