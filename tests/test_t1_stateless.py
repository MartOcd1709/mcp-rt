"""T1 / SAM1-12 self-check: the client SPEAKS 2026-07-28 stateless end-to-end against the oracle
fixture, the MRTR round-trip advances and is bounded, list caching is read, negotiation picks the
right transport, and the old-spec stdio path still works. The fixture is pinned to schema.ts and
enforces the spec, so a non-conformant client fails (see test_oracle_rejects_*)."""
import sys
from pathlib import Path

import httpx
import pytest

from mcp_rt.mcp_client import (MCPClient, MRTRBounded, StatelessHTTPClient,
                               negotiate_transport)
from tests.fixtures import stateless_2026_server as fx

_FIX = Path(__file__).parent / "fixtures"


@pytest.fixture()
def server():
    srv, url, _ = fx.start()
    try:
        yield url
    finally:
        srv.shutdown()


def test_stateless_tool_call_with_mrtr(server):
    # echo requires one input_required -> complete round-trip; a correct result PROVES the client sent
    # the right headers + _meta AND advanced MRTR (the oracle rejects anything non-conformant).
    c = StatelessHTTPClient(server)
    assert c.call_tool("echo", {"text": "hi"}) == "ok:hi"


def test_list_tools_reads_caching(server):
    c = StatelessHTTPClient(server)
    names = {t["name"] for t in c.list_tools()}
    assert {"echo", "spin"} <= names
    assert c.cache_hints["tools/list"] == {"ttlMs": 300000, "cacheScope": "public"}


def test_mrtr_loop_is_bounded(server):
    # spin never completes; the client must give up within the ceiling, not hang.
    c = StatelessHTTPClient(server, max_mrtr=3)
    with pytest.raises(MRTRBounded):
        c.call_tool("spin")


def test_negotiation_prefers_2026_and_records_downgrade(server):
    n = negotiate_transport(server)
    assert n["transport"] == "stateless-2026"
    assert n["chosen_version"] == "2026-07-28"
    assert "2025-06-18" in n["supported"]
    assert n["downgrade_available"] is True   # offered but NOT forced (forcing = T10)


def test_oracle_rejects_missing_mcp_name(server):
    # anti-circularity: the fixture enforces the spec independently — a tools/call WITHOUT the required
    # Mcp-Name header is rejected. (If this passed, the fixture would be a pushover and green would be meaningless.)
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "echo", "arguments": {},
                       "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                                 "io.modelcontextprotocol/clientCapabilities": {}}}}
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
               "MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/call"}  # NO Mcp-Name
    r = httpx.post(server, json=body, headers=headers, timeout=10)
    assert r.status_code == 400 and r.json()["error"]["code"] == -32020


def test_old_spec_stdio_unchanged():
    # the existing session-based stdio path must still list tools on a benign old-spec fixture.
    c = MCPClient(f"{sys.executable} {_FIX / 'benign_server.py'}")
    assert any(t["name"] == "prepare_workspace" for t in c.list_tools())
