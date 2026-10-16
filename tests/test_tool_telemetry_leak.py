"""T12.1 / SAM1-23 zero-FP proof: telemetry leak (CWE-532, OWASP MCP08 family).

A low-privileged reader finds a planted secret in the telemetry surface = CONFIRMED (leak host).
No-FP guards: redaction (value masked) → BOUNDED; auth-gated telemetry (secret IS logged but a
low-priv reader can't see it) → BOUNDED, while an ADMIN read DOES see it — proving the oracle checks
the READER's privilege, not merely that logging happened. Benign data → telemetry works, no canary.
Honest labeling: the CONFIRMED is CWE-532, surfaced under MCP08, NOT asserted as 'MCP08 confirmed'."""
import pytest

from mcp_rt import tool_telemetry_leak as P
from tests.fixtures import telemetry_leak_hosts as H


@pytest.fixture()
def leak():
    srv, url = H.start(mode="leak")
    try:
        yield url
    finally:
        srv.shutdown()


@pytest.fixture()
def redact():
    srv, url = H.start(mode="redact")
    try:
        yield url
    finally:
        srv.shutdown()


@pytest.fixture()
def auth_gated():
    srv, url = H.start(mode="auth_gated")
    try:
        yield url
    finally:
        srv.shutdown()


def test_leak_fires(leak):
    assert P.probe_telemetry_leak(leak, "tok")["fired"] is True

def test_redaction_bounded(redact):
    assert P.probe_telemetry_leak(redact, "tok")["fired"] is False            # value masked in telemetry

def test_auth_gated_low_priv_bounded(auth_gated):
    assert P.probe_telemetry_leak(auth_gated, "tok", as_admin=False)["fired"] is False   # low-priv cannot read

def test_auth_gated_admin_sees_it(auth_gated):
    # the secret IS logged; only an entitled reader sees it -> proves the oracle checks reader privilege
    assert P.probe_telemetry_leak(auth_gated, "tok", as_admin=True)["fired"] is True

def test_benign_telemetry_works_no_canary(leak):
    b = P.probe_benign(leak, "tok")
    assert b["completes"] and b["fired"] is False

def test_honest_labeling_cwe532_not_mcp08_confirmed(leak):
    v = P.probe_telemetry_leak(leak, "tok")
    assert v["cwe"] == "CWE-532" and v["owasp_family"] == "MCP08"
    assert "CWE-532" in v["confirmed_label"] and "MCP08 confirmed" not in v["confirmed_label"]
    assert "SHOULD/gap" in v["mcp08_posture_note"]
