"""M5: CI gate — config parsing, SARIF mapping, fail-on logic, and per-PR attestations (no network)."""
import json

from hunt.ci import _write_attestations, parse_mcp_config, should_fail, to_sarif
from mcp_rt import attest

_FINDINGS = [
    {"cls": "command_injection", "tool": "run", "sev": "Critical", "cwe": "CWE-78",
     "owasp": ["MCP05"], "title": "Command / Code Injection", "detail": "shell", "fix": "argv array",
     "server": "shell-srv", "file": ".mcp.json"},
    {"cls": "path_traversal", "tool": "read", "sev": "High", "cwe": "CWE-22", "owasp": ["MCP05"],
     "title": "Path Traversal", "detail": "escape", "fix": "confine", "server": "fs-srv", "file": ".mcp.json"},
]


def test_parse_mcp_config_extracts_stdio_only():
    cfg = {"mcpServers": {
        "fs": {"command": "npx", "args": ["-y", "@mcp/fs", "/tmp"], "env": {"X": "1"}},
        "remote": {"url": "https://x/mcp"},        # http-only -> no command -> skipped
    }}
    out = parse_mcp_config(cfg)
    assert len(out) == 1
    assert out[0]["name"] == "fs" and out[0]["argv"] == ["npx", "-y", "@mcp/fs", "/tmp"]
    assert out[0]["env"] == {"X": "1"}


def test_to_sarif_is_valid_shape():
    s = to_sarif(_FINDINGS)
    assert s["version"] == "2.1.0"
    run = s["runs"][0]
    assert run["tool"]["driver"]["name"] == "mcp-rt"
    assert len(run["tool"]["driver"]["rules"]) == 2      # one rule per class
    assert len(run["results"]) == 2
    r0 = run["results"][0]
    assert r0["ruleId"] == "command_injection" and r0["level"] == "error"   # Critical->error
    assert r0["properties"]["server"] == "shell-srv"
    # GitHub security-severity present for code-scanning sort
    assert run["tool"]["driver"]["rules"][0]["properties"]["security-severity"] == "9.5"


def test_should_fail_gate():
    assert should_fail(_FINDINGS, "critical") is True          # has a Critical
    assert should_fail(_FINDINGS, "high") is True
    assert should_fail(_FINDINGS, "none") is False
    assert should_fail([], "any") is False
    highs = [{"sev": "High"}]
    assert should_fail(highs, "critical") is False             # no Critical -> critical gate passes
    assert should_fail(highs, "high") is True


def test_ci_writes_verifiable_attestations(tmp_path):
    # Per-PR attestation output: a signed, verifiable attestation + badge per server, + registry.
    scans = [{"name": "fs-srv", "report": {"target": "npx -y @mcp/fs", "verdict": "CLEAN",
                                           "scanned_at": "2026-10-09T00:00:00", "findings": [],
                                           "coverage": [{"cls": "path_traversal", "verdict": "CLEAN"}]}}]
    n = _write_attestations(scans, str(tmp_path), key_path=None)
    assert n == 1
    att = tmp_path / "fs-srv.attestation.json"
    assert att.exists() and (tmp_path / "fs-srv.badge.svg").exists()
    assert (tmp_path / "index.html").exists()                  # registry built
    ok, _ = attest.verify(json.loads(att.read_text()))
    assert ok                                                   # the CI-signed attestation verifies
