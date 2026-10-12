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


def test_redacts_secrets_in_command_lines():
    assert "sk-live-abcdef123456" not in dc._redact("npx server --api-key sk-live-abcdef123456")
    assert "ghp_" not in dc._redact("node s.js ghp_0123456789abcdef0123")
    assert "TOKEN=" in dc._redact("TOKEN=supersecretvalue node s.js")        # name kept
    assert "supersecretvalue" not in dc._redact("TOKEN=supersecretvalue node s.js")  # value gone


def test_process_discovery_finds_live_server_and_redacts(monkeypatch):
    import subprocess
    ps = ("ps\n/usr/bin/node /x/server-filesystem-mcp --token sk-abcdef123456\n"
          "uvx some-mcp-server --port 9\n/usr/bin/firefox\n")
    monkeypatch.setattr(subprocess, "run",
                        lambda *a, **k: type("R", (), {"stdout": ps})())
    import shutil
    monkeypatch.setattr(shutil, "which", lambda x: "/usr/bin/ps")
    found = dc.discover_processes()
    launches = " ".join(s.launch for s in found)
    assert any("server-filesystem-mcp" in s.name for s in found)
    assert "sk-abcdef123456" not in launches                 # token redacted
    assert "firefox" not in launches                         # non-MCP process ignored


def test_persist_discovery_upserts_assets(tmp_path):
    from hunt.findings_db import DB
    db = DB(tmp_path / "cmdb.db")
    servers = [dc.DiscoveredServer("fs", "/h/.cursor/mcp.json", "stdio", "npx -y @mcp/fs /tmp",
                                   env_keys=["API_KEY"]),
               dc.DiscoveredServer("127.0.0.1:3001", "network probe", "http",
                                   "http://127.0.0.1:3001/sse", state="open")]
    assert dc.persist_discovery(servers, db=db) == 2
    dc.persist_discovery(servers, db=db)                     # idempotent — no duplicate rows
    rows = db.conn.execute("SELECT name, source, meta FROM targets").fetchall()
    assert len(rows) == 2
    metas = " ".join(r["meta"] for r in rows)
    assert "stdio" in metas and "http" in metas and "API_KEY" in metas   # full asset detail stored
    db.close()


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
