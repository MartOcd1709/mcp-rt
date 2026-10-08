"""M1: report renders a leadership exec summary + an OWASP->SOC2/ISO/PCI compliance crosswalk,
for both a finding and a clean result."""
from hunt.report import COMPLIANCE_XWALK, OWASP_MCP_TOP10, render_markdown


def _compliance(failed_ids=()):
    return [{"id": cid, "title": OWASP_MCP_TOP10[cid],
             "status": ("FAIL" if cid in failed_ids else "PASS")} for cid in COMPLIANCE_XWALK]


def test_report_with_finding_has_execsummary_and_crosswalk():
    rep = {
        "target": "npx -y demo-mcp@1.0.0", "scanned_at": "2026-10-06T00:00:00", "verdict": "VULNERABLE",
        "counts": {"Critical": 1}, "token_passthrough_transcript": "",
        "findings": [{"cls": "command_injection", "tool": "run", "evidence": "sentinel fired",
                      "detail": "shell injection", "sev": "Critical", "cwe": "CWE-78",
                      "owasp": ["MCP05"], "title": "Command / Code Injection", "fix": "use argv array"}],
        "compliance": _compliance(failed_ids={"MCP05"}),
    }
    md = render_markdown(rep)
    assert "## Executive summary" in md
    assert "Verdict: VULNERABLE" in md and "highest-risk" in md.lower()
    assert "## Compliance crosswalk" in md
    assert "SOC 2" in md and "ISO 27001" in md and "PCI DSS" in md
    assert "6.5.1" in md            # the MCP05 PCI mapping actually rendered


def test_attack_surface_renders():
    rep = {
        "target": "npx -y demo@1", "scanned_at": "2026-10-07T00:00:00", "verdict": "CLEAN",
        "counts": {}, "findings": [], "compliance": _compliance(), "token_passthrough_transcript": "",
        "surface": {"transport": "stdio",
                    "tools": [{"name": "read_file", "params": ["path"]},
                              {"name": "list_dir", "params": []}],
                    "resources": ["file:///etc/config"]},
    }
    md = render_markdown(rep)
    assert "## Attack surface" in md
    assert "Transport:** stdio" in md and "Tools exposed:** 2" in md and "Resources exposed:** 1" in md
    assert "`read_file`" in md and "path" in md and "`list_dir`" in md


def test_coverage_matrix_renders():
    rep = {
        "target": "npx -y demo@1", "scanned_at": "2026-10-07T00:00:00", "verdict": "VULNERABLE",
        "counts": {"Critical": 1}, "token_passthrough_transcript": "", "compliance": _compliance(),
        "findings": [{"cls": "command_injection", "tool": "run", "evidence": "x", "detail": "y",
                      "sev": "Critical", "cwe": "CWE-78", "owasp": ["MCP05"],
                      "title": "Command / Code Injection", "fix": "argv"}],
        "coverage": [
            {"tool": "run", "cls": "command_injection", "verdict": "VULNERABLE"},
            {"tool": "run", "cls": "ssrf", "verdict": "CLEAN"},
            {"tool": "read_doc", "cls": "path_traversal", "verdict": "CLEAN"},
        ],
    }
    md = render_markdown(rep)
    assert "## Tool-by-tool coverage" in md
    assert "`run`" in md and "`read_doc`" in md
    assert "❌ vulnerable: command_injection" in md       # the vulnerable tool flagged
    assert "✅ clean" in md                                 # the all-clean tool marked clean


def test_clean_report_reads_as_attestation():
    rep = {"target": "npx -y safe-mcp@2.0.0", "scanned_at": "2026-10-06T00:00:00", "verdict": "CLEAN",
           "counts": {}, "findings": [], "compliance": _compliance(), "token_passthrough_transcript": ""}
    md = render_markdown(rep)
    assert "Verdict: CLEAN" in md and "attestation" in md.lower()
    assert "## Compliance crosswalk" in md and "not a certification" in md.lower()
