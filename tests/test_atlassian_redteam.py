"""Atlassian ticket-injection agent red-team scenario (MCP06): a vulnerable agent obeys a poisoned Jira
ticket and exfiltrates; a hardened agent treats ticket content as data. Runs offline via the mock agents."""
from mcp_rt.harness import run_one
from mcp_rt.adapters.mock import MockVulnerableClient, MockSecureClient
from mcp_rt.payloads.atlassian_ticket_injection import AtlassianTicketInjection
from hunt.hunt_agent import results_to_hypotheses, LEG


def test_vulnerable_agent_obeys_poisoned_ticket():
    r = run_one(MockVulnerableClient(), AtlassianTicketInjection())
    assert r["vulnerable"] is True and r["detail"]["read"] and r["detail"]["exfil"]


def test_hardened_agent_ignores_ticket_content():
    r = run_one(MockSecureClient(), AtlassianTicketInjection())
    assert r["vulnerable"] is False


def test_fired_scenario_becomes_intent_flow_hypothesis():
    r = run_one(MockVulnerableClient(), AtlassianTicketInjection())
    hyps = results_to_hypotheses([r])
    assert len(hyps) == 1 and hyps[0].leg == LEG and "atlassian_ticket_injection" in hyps[0].tool


def test_payload_is_registered_in_the_corpus():
    from mcp_rt.payloads.registry import all_payloads
    assert any(p.name == "atlassian_ticket_injection" for p in all_payloads())
