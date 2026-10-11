"""Executor: AI proposals validated against ground truth (zero-FP gate), with honest deferral.

A proposed probe is confirmed ONLY if a ground-truth finding proves it; agent-behavioral techniques
are deferred to the agent red-team (never falsely confirmed); direct techniques with no proof are
unconfirmed.
"""
from mcp_rt.adaptive_probe import ProbeCandidate
from hunt import executor as ex


def _c(tech, tool):
    return ProbeCandidate(technique=tech, target_tool=tool)


def test_confirmed_only_when_ground_truth_proves_it():
    cands = [_c("ssrf", "fetch"), _c("path_traversal", "read_file")]
    findings = [{"cls": "ssrf", "tool": "fetch", "sev": "High"}]   # only ssrf actually proven
    res = ex.validate(cands, findings)
    assert len(res.confirmed) == 1 and res.confirmed[0]["candidate"]["technique"] == "ssrf"
    assert [c.technique for c in res.unconfirmed] == ["path_traversal"]   # predicted, not proven


def test_agent_behavioral_is_deferred_not_confirmed():
    # tool_poisoning / prompt injection can't be confirmed by direct probing -> deferred, even if
    # a finding of that class exists (direct scan can't prove the agent behaviour).
    cands = [_c("tool_poisoning", "t"), _c("return_value_prompt_injection", "u")]
    res = ex.validate(cands, [{"cls": "tool_poisoning", "tool": "t"}])
    assert res.confirmed == [] and len(res.deferred) == 2


def test_prefers_same_tool_match():
    cands = [_c("command_injection", "run")]
    findings = [{"cls": "command_injection", "tool": "other"},
                {"cls": "command_injection", "tool": "run"}]
    res = ex.validate(cands, findings)
    assert res.confirmed[0]["finding"]["tool"] == "run"


def test_execute_uses_injected_scan():
    cands = [_c("ssrf", "fetch")]
    scan_fn = lambda target, backend: {"findings": [{"cls": "ssrf", "tool": "fetch"}]}
    res = ex.execute("npx x", cands, scan_fn=scan_fn)
    assert len(res.confirmed) == 1


def test_orchestrator_execute_populates_validation():
    from hunt import orchestrator as orch
    base = {"verdict": "VULNERABLE", "surface": {"tools": [{"name": "fetch"}]},
            "findings": [{"cls": "ssrf", "tool": "fetch", "sev": "High"}]}
    a = orch.assess("x", base_report=base, adaptive=True, execute=True)
    assert a.exec_result is not None
    d = a.as_dict()["adaptive_validation"]
    assert d is not None and "confirmed" in d
