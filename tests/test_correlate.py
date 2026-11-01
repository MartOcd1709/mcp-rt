"""Exploit correlation: confirmed findings -> proven multi-step chains.

A chain forms only when every capability its rule needs is present among already-confirmed findings,
so the chain is itself ground-truth (built from proofs), reported above point findings.
"""
from mcp_rt import correlate as co


def test_read_plus_egress_is_critical_exfil_chain():
    findings = [{"cls": "path_traversal", "tool": "read_file"},
                {"cls": "ssrf", "tool": "fetch"}]
    chains = co.correlate(findings)
    kinds = {c.kind for c in chains}
    assert "credential_exfiltration" in kinds
    assert all(c.severity == "Critical" for c in chains if c.kind == "credential_exfiltration")


def test_inject_plus_exec_is_rce_chain():
    findings = [{"cls": "tool_poisoning", "tool": "t"}, {"cls": "command_injection", "tool": "run"}]
    chains = co.correlate(findings)
    assert any(c.kind == "remote_code_execution" and c.severity == "Critical" for c in chains)


def test_single_finding_forms_no_chain():
    assert co.correlate([{"cls": "path_traversal", "tool": "read_file"}]) == []


def test_unknown_class_grants_no_capability():
    assert co._capability({"cls": "not_a_real_class"}) == ""
    assert co.correlate([{"cls": "x"}, {"cls": "y"}]) == []


def test_chains_sorted_critical_first():
    findings = [{"cls": "path_traversal"}, {"cls": "command_injection"}, {"cls": "ssrf"},
                {"cls": "tool_poisoning"}]
    chains = co.correlate(findings)
    sevs = [c.severity for c in chains]
    assert sevs == sorted(sevs, key=lambda s: {"Critical": 0, "High": 1}.get(s, 9))
