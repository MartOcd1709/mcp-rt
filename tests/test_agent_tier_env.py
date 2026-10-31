"""RoE env enabler: a generic string->string env override reaches the SEALED target (e.g. HOME, so a server
reads a seeded config file — the DesktopCommander Pass-2 confinement enabler). Sealed-only + additive; no
server-specific keys (a server is DATA)."""
import asyncio
import json
import sys
from pathlib import Path

import pytest

from mcp_rt.agent_tier.roe import RoEError, load_roe
from tests.seal_capability import SEAL_REASON, can_seal


# ---- structural (no seal) --------------------------------------------------------------------------
def _roe(tmp_path, **over):
    doc = {"roe_version": 1, "target": {"id": "x", "argv": ["echo", "hi"]},
           "classes": ["egress"], "authorized_by": "ved"}
    doc.update(over)
    p = tmp_path / "roe.json"
    p.write_text(json.dumps(doc))
    return p


def test_load_roe_parses_env(tmp_path):
    assert load_roe(_roe(tmp_path, env={"HOME": "/tmp/h"})).env == {"HOME": "/tmp/h"}


def test_load_roe_env_defaults_empty(tmp_path):
    assert load_roe(_roe(tmp_path)).env == {}


def test_load_roe_rejects_non_string_env(tmp_path):
    with pytest.raises(RoEError):
        load_roe(_roe(tmp_path, env={"HOME": 5}))


# ---- sealed behaviour (seal-gated) -----------------------------------------------------------------
_HOME_FIXTURE = '''import asyncio, os
import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server
srv = Server("envfix")


@srv.list_tools()
async def lt():
    return [types.Tool(name="read_home", description="Return HOME.",
            inputSchema={"type": "object", "properties": {}})]


@srv.call_tool()
async def ct(name, args):
    return [types.TextContent(type="text", text="HOME=" + os.environ.get("HOME", "unset"))]


async def main():
    async with stdio_server() as (r, w):
        await srv.run(r, w, srv.create_initialization_options())

asyncio.run(main())
'''


@pytest.mark.skipif(not can_seal(), reason=SEAL_REASON)
def test_roe_env_reaches_the_sealed_child(tmp_path):
    from mcp_rt.agent_tier.session import sealed_session
    script = tmp_path / "envfix.py"
    script.write_text(_HOME_FIXTURE)
    home = tmp_path / "confined-home"
    home.mkdir()

    async def _run():
        async with sealed_session([sys.executable, str(script)], env={"HOME": str(home)}) as h:
            assert h.sealed, h.error
            r = await h.session.call_tool("read_home", {})
            return "\n".join(getattr(c, "text", "") or "" for c in (r.content or []))

    out = asyncio.run(_run())
    assert f"HOME={home}" in out, out        # the RoE env override reached the sealed target
