"""Multi-client scan dispatch: config transforms + client selection.

The transforms are pure and tested without any CLI installed. Dispatch is tested by driving
a client whose binary is absent -> an honest "[agent: ...]" line, never the old
"not supported" ValueError that used to reject everything but claude-code.
"""
import pytest

from mcp_rt.scan import clients
from mcp_rt.scan.runner import scan
from mcp_rt.target import TargetSpec

_CFG = {"mcpServers": {"target": {"command": "npx", "args": ["-y", "some-mcp"],
                                  "env": {"MCPRT_PROXY": "http://127.0.0.1:9"}}}}


def test_cline_settings_uses_transport_wrapper():
    out = clients.cline_settings(_CFG)["mcpServers"]["target"]
    assert out == {"transport": {"type": "stdio", "command": "npx",
                                 "args": ["-y", "some-mcp"],
                                 "env": {"MCPRT_PROXY": "http://127.0.0.1:9"}}}
    assert "command" not in out            # legacy flat format would break Cline v3+


def test_codex_flags_are_dotted_toml():
    flags = clients.codex_flags(_CFG)
    assert "-c" in flags
    joined = " ".join(flags)
    assert 'mcp_servers.target.command="npx"' in joined
    assert 'mcp_servers.target.args=["-y", "some-mcp"]' in joined
    assert 'mcp_servers.target.env.MCPRT_PROXY="http://127.0.0.1:9"' in joined


def test_run_client_unknown_raises_listing_supported():
    with pytest.raises(ValueError) as e:
        clients.run_client("cursor", "p", _CFG, "/tmp", 1)
    assert "cursor" in str(e.value) and "claude-code" in str(e.value)


def test_dispatch_reaches_each_supported_client(tmp_path):
    # Binaries aren't installed in CI -> each runner should degrade to a FileNotFound marker,
    # proving the dispatch wired the client (not the old blanket rejection).
    for client in clients.SUPPORTED:
        t = clients.run_client(client, "hello", _CFG, str(tmp_path), 5)
        assert t and t[0].startswith("user:")
        assert any("binary not found" in ln or "assistant:" in ln or "[agent" in ln for ln in t)


def test_scan_rejects_unsupported_client_before_any_io():
    # The guard is first in scan(), so a bad client raises immediately — no planting/capture.
    with pytest.raises(ValueError) as e:
        scan(TargetSpec.from_stdio("echo hi"), client="notaclient")
    assert "notaclient" in str(e.value)
