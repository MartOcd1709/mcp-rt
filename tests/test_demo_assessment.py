"""End-to-end demo zero-FP proof: the `mcp-rt demo` driver fires all 9 HTTP oracle classes on their
real vulnerable fixtures AND proves every safe-host control stays silent (the moat). No fabrication:
a class only counts CONFIRMED when its canary actually fired on the vuln host and did NOT on the safe
host. proto_pollution may skip if Node isn't installed (JS-host class) — it still must not false-positive."""
import pytest

from hunt import demo_assessment as D


@pytest.fixture(scope="module")
def outcomes():
    return D.run_demo()


def test_demo_zero_fp_and_all_fire(outcomes):
    assert len(outcomes) == 9
    for o in outcomes:
        # the moat invariant: a safe-host control must NEVER fire (zero false positives)
        assert o.silent_safe is True, f"{o.cls}: safe-host control fired — FALSE POSITIVE"
        if not o.skipped:
            assert o.fired_vuln is True, f"{o.cls}: did not fire on the vulnerable host"
    # 9 with Node present; proto_pollution may skip without Node, so >=8 CONFIRMED
    assert sum(o.confirmed for o in outcomes) >= 8


def test_demo_report_is_honest(outcomes):
    r = D.render_demo_report(outcomes)
    for needle in ("Zero false positives", "Proven findings", "Honest coverage ledger",
                   "LEAD-only", "SHOULD/gap", "COVERED"):
        assert needle in r, f"demo report missing honest-framing section: {needle!r}"


def test_classic_leg_fires_on_aggregate_vuln_server():
    # full library: the classic stdio probes must also fire on the aggregate vuln server
    classic = D.run_classic_leg()
    classes = {f.get("cls") for f in classic}
    assert "command_injection" in classes and len(classic) >= 8
