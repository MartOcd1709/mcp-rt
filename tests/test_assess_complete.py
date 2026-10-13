"""The complete (advanced) assessment orchestrator: it drives every layer, keeps FINDINGS
(ground-truth) separate from LEADS (observed, not confirmed), records each component's ran|skipped
honestly, and never over-claims. Layers are stubbed so this is a fast, deterministic unit test of
the orchestration (the layers themselves have their own tests)."""
import hunt.assess_complete as ac


async def _fake_scan_vuln(cmd, env=None):
    return {"findings": [{"cls": "path_traversal", "tool": "read_doc", "detail": "/etc/passwd", "sev": "High"}],
            "verdict": "VULNERABLE", "mcp06": {"exposed": True, "reasons": ["search_files"]}}


async def _fake_scan_clean(cmd, env=None):
    return {"findings": [], "verdict": "CLEAN", "mcp06": {"exposed": False, "reasons": []}}


class _Hyp:
    tool = "fetch"
    observation = "opened a socket though declared read-only (undeclared capability)"


def test_findings_vs_leads_and_honest_components(monkeypatch):
    monkeypatch.setenv("MCPRT_AI_PROVIDER", "")                       # no model -> agent honestly skipped
    monkeypatch.setattr("hunt.report.run_full_scan", _fake_scan_vuln)
    monkeypatch.setattr("hunt.hunt_cap.strace_available", lambda: True)
    monkeypatch.setattr("hunt.hunt_cap.run_cap_hunt", lambda cmd, **kw: ("OK", [_Hyp()]))

    r = ac.run_complete("python x.py")
    assert r["verdict"] == "VULNERABLE"
    assert len(r["findings"]) == 1 and r["findings"][0]["source"] == "probe"
    assert len(r["leads"]) == 1 and r["leads"][0]["kind"] == "MCP-CAP"   # strace signal is a LEAD, not a finding
    assert r["components"]["direct_probe"].startswith("ran")
    assert r["components"]["mcp_cap"].startswith("ran")
    assert "skipped" in r["components"]["ai_agent"] and "model" in r["components"]["ai_agent"]


def test_ai_agent_findings_are_oracle_confirmed(monkeypatch):
    from mcp_rt.agent_loop import AgentResult
    from mcp_rt.oracle import OracleResult, Proof
    monkeypatch.setattr(ac, "ai_configured", lambda: True)
    monkeypatch.setattr("hunt.report.run_full_scan", _fake_scan_clean)   # direct probes find nothing
    monkeypatch.setattr("hunt.hunt_cap.strace_available", lambda: False)  # strace absent -> skipped
    monkeypatch.setattr("mcp_rt.mcp_client.MCPClient", lambda *a, **k: object())
    monkeypatch.setattr("mcp_rt.agent_loop.run_agent",
                        lambda target, **kw: AgentResult(target=target,
                            agent_claimed=[{"class": "ssti", "tool": "render"}], note="1 claim"))
    orc = OracleResult()
    orc.confirmed = [Proof("render", "ssti", True, "template evaluated 42", "42", "template")]
    monkeypatch.setattr("mcp_rt.oracle.confirm_claims", lambda client, claims: orc)

    r = ac.run_complete("python x.py")
    assert r["verdict"] == "VULNERABLE"                              # the oracle-confirmed agent finding
    assert any(f["source"] == "ai-agent" and f["cls"] == "ssti" for f in r["findings"])
    assert r["components"]["ai_agent"].startswith("ran") and "confirmed" in r["components"]["ai_agent"]
    assert r["components"]["mcp_cap"].startswith("skipped")          # honest: strace absent


def test_clean_when_a_layer_ran_and_nothing_fired(monkeypatch):
    monkeypatch.setenv("MCPRT_AI_PROVIDER", "")
    monkeypatch.setattr("hunt.report.run_full_scan", _fake_scan_clean)
    monkeypatch.setattr("hunt.hunt_cap.strace_available", lambda: False)
    r = ac.run_complete("python x.py")
    assert r["verdict"] == "CLEAN" and not r["findings"]


def test_advanced_flow_tier_persists_findings_and_leads(tmp_path, monkeypatch):
    from hunt.flow import run_flow
    from hunt.platform_db import Store
    monkeypatch.setattr("hunt.assess_complete.run_complete", lambda target, **kw: {
        "target": target, "verdict": "VULNERABLE",
        "findings": [{"cls": "ssrf", "tool": "fetch", "detail": "read /etc/passwd", "sev": "High", "source": "ai-agent"}],
        "leads": [{"kind": "MCP-CAP", "tool": "fetch", "observation": "undeclared socket"}],
        "chains": [], "components": {"ai_agent": "ran (1/1 confirmed)"}, "note": "1 finding, 1 lead"})
    store = Store(url=f"sqlite:///{tmp_path}/adv.db")
    org = store.org_for_token(store.ensure_default_org())
    fid = run_flow(store, org, "python x.py", tier="advanced")
    f = store.get_flow(fid)
    assert f["verdict"] == "VULNERABLE"
    steps = store.flow_steps(fid)
    assert any(s["text"].startswith("PROVEN") for s in steps)        # finding
    assert any(s["text"].startswith("LEAD") for s in steps)          # lead, shown but separate
    import json
    assert json.loads(f["summary"])["tier"] == "advanced"
