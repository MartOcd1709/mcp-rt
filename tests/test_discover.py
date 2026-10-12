"""MCP host discovery: parse client configs into a server inventory, secret-safe.

Finds stdio + http servers across config shapes (mcpServers / mcp_servers / transport-wrapped /
vscode mcp.servers); reports env var NAMES only, never values.
"""
import json

from hunt import discover as dc


def test_parses_stdio_http_and_wrapped(tmp_path):
    home = tmp_path / "home"
    (home / ".gemini").mkdir(parents=True)
    (home / ".gemini/settings.json").write_text(json.dumps({
        "mcpServers": {"fs": {"command": "npx", "args": ["-y", "@mcp/fs", "/tmp"],
                              "env": {"TOKEN": "secret123"}},
                       "remote": {"url": "http://127.0.0.1:8085/sse"}}}))
    (home / ".cline/data/settings").mkdir(parents=True)
    (home / ".cline/data/settings/cline_mcp_settings.json").write_text(json.dumps({
        "mcpServers": {"wrapped": {"transport": {"command": "uvx", "args": ["some-mcp"]}}}}))
    servers = dc.discover_configs(home=home)
    by = {s.name: s for s in servers}
    assert by["fs"].transport == "stdio" and by["fs"].launch == "npx -y @mcp/fs /tmp"
    assert by["remote"].transport == "http" and by["remote"].launch.endswith("/sse")
    assert by["wrapped"].launch == "uvx some-mcp"


def test_env_values_are_never_exposed(tmp_path):
    home = tmp_path / "h"
    (home / ".gemini").mkdir(parents=True)
    (home / ".gemini/settings.json").write_text(json.dumps({
        "mcpServers": {"x": {"command": "npx", "args": ["s"], "env": {"API_KEY": "sk-leak-me"}}}}))
    servers = dc.discover_configs(home=home)
    s = servers[0]
    assert s.env_keys == ["API_KEY"]                       # name only
    assert "sk-leak-me" not in json.dumps(s.as_dict())     # value never present


def test_dedup_and_empty(tmp_path):
    assert dc.discover_configs(home=tmp_path / "empty") == []


def test_network_scan_requires_authorization():
    import pytest
    with pytest.raises(PermissionError):
        dc.discover_network("192.168.1.0/24", authorized_by="")      # active recon -> consent-gated


def test_probe_detects_sse_endpoint(monkeypatch):
    import socket
    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: _Dummy())
    import httpx
    monkeypatch.setattr(httpx, "get", lambda *a, **k:
                        type("R", (), {"headers": {"content-type": "text/event-stream"}, "text": ""})())
    s = dc.probe_mcp_endpoint("127.0.0.1", 8085)
    assert s and s.transport == "http" and "127.0.0.1:8085" in s.name


class _Dummy:
    def __enter__(self): return self
    def __exit__(self, *a): return False
