"""The engagement's OWASP scorecard: carried from phase 1, updated by later phases, never assumed to pass."""
from hunt.assess_complete import merge_compliance
from hunt.report import OWASP_MCP_TOP10


def _by_id(rows):
    return {r["id"]: r["status"] for r in rows}


def test_missing_phase1_starts_all_not_tested():
    got = _by_id(merge_compliance([], [], []))
    assert set(got) == set(OWASP_MCP_TOP10) and set(got.values()) == {"NOT TESTED"}


def test_canary_proof_fails_its_controls():
    got = _by_id(merge_compliance([], [{"cls": "elicitation_credential_harvest", "tool": "(server)"}], []))
    assert got["MCP06"] == "FAIL" and got["MCP01"] == "FAIL"
    assert got["MCP03"] == "NOT TESTED"


def test_lead_is_suspected_but_never_over_a_fail():
    base = [{"id": "MCP03", "title": "t", "status": "FAIL"}, {"id": "MCP02", "title": "t", "status": "PASS"}]
    got = _by_id(merge_compliance(base, [], [{"kind": "tool_poisoning"}, {"kind": "mcp_cap"}]))
    assert got == {"MCP03": "FAIL", "MCP02": "SUSPECTED"}


def test_sealed_run_tests_mcp02_only_when_the_seal_was_proven():
    base = [{"id": "MCP02", "title": "t", "status": "NOT TESTED"}]
    assert _by_id(merge_compliance(base, [], [], "ran (0 proven, 0 lead(s); seal proven, 0 egress attempt(s))")) == {"MCP02": "PASS"}
    assert _by_id(merge_compliance(base, [], [], "inconclusive: seal unproven (no netns)")) == {"MCP02": "NOT TESTED"}
    # a proven seal never upgrades a SUSPECTED or FAIL control to PASS
    sus = [{"id": "MCP02", "title": "t", "status": "SUSPECTED"}]
    assert _by_id(merge_compliance(sus, [], [], "ran (seal proven)")) == {"MCP02": "SUSPECTED"}
