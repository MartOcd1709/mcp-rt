"""Coordinated assessment: discover -> generate -> (prove -> refine)* -> correlate -> report.

Uses a simulated-vulnerable client (no real server) so the coordination + ground-truth proof + the
Refiner's prove-then-broaden loop are all exercised offline.
"""
from mcp_rt import assessment as asm


class VulnClient:
    """Two tools share a SQLi weakness; the plan only flags one by param — the Refiner must sweep it
    to the sibling after SQLi is proven."""
    def list_tools(self):
        return [{"name": "search_notes", "description": "search notes",
                 "input_schema": {"properties": {"query": {"type": "string"}}, "required": ["query"]}},
                {"name": "lookup", "description": "look up a record",   # generic param -> not planned SQLi
                 "input_schema": {"properties": {"q": {"type": "string"}}, "required": ["q"]}}]

    def call_tool(self, name, args):
        v = str(next(iter(args.values()), "")) if args else ""
        if "'1'='1'" in v:          # both tools are SQL-injectable (boolean-based)
            return "('row a',) ('row b',)"
        return ""                    # false condition / benign -> empty


def test_assessment_proves_and_refines_to_a_sibling(monkeypatch):
    a = asm.run_assessment("vuln", client=VulnClient(), max_rounds=3)
    proven_tools = {p["tool"] for p in a.proven if p["vuln_class"] == "sql_injection"}
    assert a.verdict == "VULNERABLE"
    assert "search_notes" in proven_tools          # planned + proven in round 1
    assert "lookup" in proven_tools                # only reachable because the Refiner swept SQLi wider
    assert a.rounds >= 2                            # took a refine round to find the sibling


def test_clean_server_yields_no_findings():
    class Safe:
        def list_tools(self):
            return [{"name": "echo", "description": "echo",
                     "input_schema": {"properties": {"text": {"type": "string"}}, "required": ["text"]}}]
        def call_tool(self, name, args):
            return "ok"
    a = asm.run_assessment("safe", client=Safe(), max_rounds=2)
    assert a.verdict == "CLEAN" and a.proven == []
