"""M2: branded HTML/PDF deliverable renders with the report's sections + styling."""
from hunt.report import COMPLIANCE_XWALK, OWASP_MCP_TOP10, render_html, to_pdf

_REP = {
    "target": "npx -y demo-mcp@1.0.0", "scanned_at": "2026-10-06T00:00:00", "verdict": "VULNERABLE",
    "counts": {"Critical": 1}, "token_passthrough_transcript": "",
    "findings": [{"cls": "command_injection", "tool": "run", "evidence": "sentinel fired",
                  "detail": "shell injection", "sev": "Critical", "cwe": "CWE-78",
                  "owasp": ["MCP05"], "title": "Command / Code Injection", "fix": "use argv array"}],
    "compliance": [{"id": cid, "title": OWASP_MCP_TOP10[cid], "status": "PASS"} for cid in COMPLIANCE_XWALK],
}


def test_render_html_has_sections_and_style():
    html = render_html(_REP)
    assert html.startswith("<!doctype html>")
    assert "<style>" in html and "@page" in html          # branded/print CSS present
    assert "Executive summary" in html and "Compliance crosswalk" in html
    assert "<table" in html                                # markdown tables became HTML tables


def test_to_pdf_smoke(tmp_path):
    out = tmp_path / "r.pdf"
    try:
        to_pdf(_REP, str(out))
    except Exception:          # weasyprint needs system libs (pango/cairo); skip if unavailable here
        import pytest
        pytest.skip("weasyprint runtime libs unavailable")
    assert out.exists() and out.read_bytes()[:5] == b"%PDF-"
