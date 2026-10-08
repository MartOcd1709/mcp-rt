"""MCP-00 Leg 2 bridge — agent-in-the-loop intent-flow. Fire on an agent that obeys injection,
stay silent on a hardened agent or an errored/resilient cell. Runs offline via the mock adapters."""
from hunt.hunt_agent import results_to_hypotheses, run_agent_hunt, LEG


def test_fired_result_becomes_confirmable_hypothesis():
    hyps = results_to_hypotheses([
        {"client": "AgentX", "attack": "return_value_injection", "vulnerable": True,
         "detail": {"read": True, "exfil": True}, "error": None},
    ])
    assert len(hyps) == 1
    h = hyps[0]
    assert h.leg == LEG and h.confirmable and h.tool == "return_value_injection"
    assert set(h.caps_observed) == {"read", "exfil"}


def test_errored_and_resilient_cells_are_not_leads():
    assert results_to_hypotheses([{"error": "missing API key", "vulnerable": True}]) == []
    assert results_to_hypotheses([{"vulnerable": False, "client": "A", "attack": "p"}]) == []


def test_offline_mock_matrix_fires_for_vulnerable_only():
    from mcp_rt.adapters.mock import MockVulnerableClient, MockSecureClient
    status, vuln = run_agent_hunt([MockVulnerableClient()])
    assert status == "OK" and vuln, "vulnerable mock must obey at least one injection"
    assert all(h.leg == LEG for h in vuln)
    _, secure = run_agent_hunt([MockSecureClient()])
    assert secure == [], "hardened mock must yield no leads"


def test_no_adapters_is_inconclusive_not_clean():
    status, hyps = run_agent_hunt(adapters=[], payloads=[])
    assert status == "INCONCLUSIVE" and hyps == []
