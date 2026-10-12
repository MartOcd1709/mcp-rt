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
    """SSE server: GET /sse returns text/event-stream -> matched 'open' by handshake, not substring."""
    _patch_http(monkeypatch, lambda method, url: (200, "text/event-stream", False, "")
                if method == "GET" and url.endswith("/sse") else (404, "text/html", False, ""))
    s = dc.probe_mcp_endpoint("127.0.0.1", 8085)
    assert s and s.transport == "http" and s.state == "open"
    assert s.name == "127.0.0.1:8085" and s.launch.endswith("/sse")


def test_probe_rejects_non_mcp_page_mentioning_mcp(monkeypatch):
    """Regression: a plain HTTP page whose body contains 'mcp'/'jsonrpc' must NOT be flagged.

    The old code matched a bare 'mcp' substring (even a 404 'Cannot GET /mcp' page) — a false positive.
    """
    body = '<html>this mentions mcp and jsonrpc but is not a server</html>'
    _patch_http(monkeypatch, lambda method, url: (200, "text/html", False, body))
    assert dc.probe_mcp_endpoint("127.0.0.1", 9000) is None


def test_probe_detects_protected_server(monkeypatch):
    """A 401 carrying WWW-Authenticate is a PROTECTED MCP server (RFC 9728), still reported."""
    _patch_http(monkeypatch, lambda method, url: (401, "application/json", True, ""))
    s = dc.probe_mcp_endpoint("127.0.0.1", 8443)
    assert s and s.state == "protected"


# --- test plumbing: fake socket + httpx.Client.stream so probe logic runs with no real network ---
def _patch_http(monkeypatch, responder):
    import socket
    import httpx
    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: _Dummy())

    class _Resp:
        def __init__(self, method, url):
            self.status_code, ct, self._www, self._body = responder(method, url)
            self.headers = {"content-type": ct}
            if self._www:
                self.headers["www-authenticate"] = 'Bearer resource_metadata="x"'

        def __enter__(self): return self
        def __exit__(self, *a): return False
        def iter_text(self): return iter([self._body] if self._body else [])

    class _Client:
        def __init__(self, *a, **k): pass
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def stream(self, method, url, **k): return _Resp(method, url)

    monkeypatch.setattr(httpx, "Client", _Client)


class _Dummy:
    def __enter__(self): return self
    def __exit__(self, *a): return False
