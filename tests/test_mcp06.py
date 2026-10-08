"""Basic-scan MCP06 (intent-flow) enabling-conditions flag — a surface signal, never a finding."""
from hunt.report import _mcp06_exposure


def test_resources_flag_exposure():
    r = _mcp06_exposure({"resources": ["file:///x"], "tools": []})
    assert r["exposed"] is True and "resource" in r["reasons"][0]


def test_external_content_tool_flags():
    r = _mcp06_exposure({"resources": [], "tools": [{"name": "fetch_url"}, {"name": "list_dir"}]})
    assert r["exposed"] is True and "fetch_url" in r["reasons"][0]


def test_minimal_surface_not_exposed():
    # a local exec/util server with no resources and no external-content tools -> not flagged
    r = _mcp06_exposure({"resources": [], "tools": [{"name": "run_cmd"}, {"name": "create_dir"}]})
    assert r["exposed"] is False and r["reasons"] == []
