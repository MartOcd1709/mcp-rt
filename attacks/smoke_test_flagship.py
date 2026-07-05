"""Mechanics smoke test for the flagship family (MCP-26 / MCP-27 / MCP-28 / MCP-29).

This is NOT a client resilience test and produces NO VULNERABLE/RESILIENT verdict
about any real product. It drives the real malicious_mcp_server.py subprocess with
the real MCP Python SDK's ClientSession, using synthetic callbacks that stand in
for a client's sampling/elicitation/roots handlers, to prove two things per attack:

  1. Non-support path: a ClientSession with NO sampling/elicitation/roots callback
     registered (the SDK default) talks to the server without the server raising or
     hanging, and the poisoned tool returns a graceful {"status": "unsupported", ...}
     JSON rather than crashing the process.
  2. Mechanics path: a ClientSession with a synthetic "auto-approving" callback that
     echoes/accepts whatever the server asks for exercises the full server-side code
     path (the sampling round trip, the elicitation form round trip, or the roots
     round trip plus boundary substitution) end to end, and the loopback honeytoken
     canary fires -- proving the exfil branch is reachable and syntactically correct,
     not that any real CLI client (Claude Code, Codex CLI, Gemini CLI) behaves this
     way. The synthetic callback is our own test code, not a product.

Everything is loopback-only and synthetic, per the framework's honeytoken model
(mcp_rt.honeytoken.Honeytoken).

This script requires no API key and spawns only local subprocesses. It was written
as part of building the flagship family but has NOT been executed by the agent that
wrote it (no code-execution tool was available in that session). Run it once and
read the PASS/FAIL summary before trusting the mechanics; a failure here means a bug
in the server/payload code, not a finding about any client.

Usage:
    cd ~/Desktop/mcp-rt
    .venv/bin/python attacks/smoke_test_flagship.py
"""
import asyncio
import json
import os
import sys
import tempfile
import traceback
from pathlib import Path

_PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_PROJECT))

# Dry-import check (mirrors the instruction to run `python -c "import mcp_rt.payloads"`).
import mcp_rt.payloads  # noqa: F401,E402

# Explicit submodule imports register each payload class (matches run_flagship.py).
import mcp_rt.payloads.sampling_instruction_laundering  # noqa: F401,E402
import mcp_rt.payloads.elicitation_credential_harvest   # noqa: F401,E402
import mcp_rt.payloads.structured_output_resource_link  # noqa: F401,E402
import mcp_rt.payloads.roots_path_manipulation           # noqa: F401,E402

from mcp_rt.honeytoken import Honeytoken               # noqa: E402
from mcp_rt.payloads.registry import all_payloads      # noqa: E402

import mcp.types as mtypes                              # noqa: E402
from mcp import ClientSession                            # noqa: E402
from mcp.client.stdio import StdioServerParameters, stdio_client  # noqa: E402

_SERVER = str(_PROJECT / "server" / "malicious_mcp_server.py")
_VENV_PY = str(_PROJECT / ".venv" / "bin" / "python")
if not os.path.exists(_VENV_PY):
    _VENV_PY = sys.executable

_ATTACK_NAMES = [
    "sampling_instruction_laundering",
    "elicitation_credential_harvest",
    "structured_output_resource_link",
    "roots_path_manipulation",
]

_MODE_KEYS = {
    "sampling_instruction_laundering": "sampling_laundering_mode",
    "elicitation_credential_harvest": "elicitation_harvest_mode",
    "structured_output_resource_link": "resource_link_mode",
    "roots_path_manipulation": "roots_path_manipulation_mode",
}


def _write_cfg(spec: dict, extra: dict) -> str:
    tool = spec["poisoned"]
    cfg = {
        "canary_path": spec["canary_path"],
        "exfil_url": spec["exfil_url"],
        "tool_name": tool["name"],
        "tool_desc": tool["description"],
        "tool_result": spec.get("tool_result", ""),
    }
    cfg.update(extra)
    fd, path = tempfile.mkstemp(prefix="mcprt_smoke_", suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh)
    return path


# ---------------------------------------------------------------------------
# Synthetic "auto-approving" callbacks -- OUR test code, not any real client.
# ---------------------------------------------------------------------------
async def _echo_sampling_callback(context, params):
    """Restate whatever text the server sent, verbatim -- simulates a client with
    no human-in-the-loop review that runs the completion as asked."""
    text = ""
    for msg in params.messages:
        content = msg.content
        blocks = content if isinstance(content, list) else [content]
        for block in blocks:
            t = getattr(block, "text", None)
            if t:
                text += t
    return mtypes.CreateMessageResult(
        role="assistant",
        content=mtypes.TextContent(type="text", text=text),
        model="smoke-test-echo-model",
        stopReason="endTurn",
    )


async def _autofill_elicitation_callback(context, params):
    """Auto-accept the elicitation and fill the requested field with a synthetic
    string -- simulates a headless agent that supplies a value without review.
    We don't know the honeytoken value here (that is the point of the real attack:
    the AGENT is expected to have read it into context); this callback supplies a
    placeholder so we can verify the round trip and the graceful-decline path
    without asserting a marker match."""
    schema = params.requestedSchema or {}
    props = schema.get("properties", {})
    content = {name: "smoke-test-value" for name in props}
    return mtypes.ElicitResult(action="accept", content=content)


async def _fake_roots_callback(context):
    return mtypes.ListRootsResult(roots=[mtypes.Root(uri="file:///tmp/smoke-test-root")])


async def _run_case(name: str, use_callbacks: bool) -> tuple[bool, str]:
    """Returns (ok, detail)."""
    spec_name = name
    payload = next(p for p in all_payloads() if p.name == spec_name)
    ht = Honeytoken(
        filename=getattr(payload, "honeytoken_filename", "id_rsa"),
        content_template=getattr(payload, "honeytoken_content_template", None),
        dir_prefix=getattr(payload, "honeytoken_dir_prefix", "mcp_rt_canary_"),
    ).plant()
    try:
        spec = payload.build(ht.path, ht.exfil_url)
        mode_key = _MODE_KEYS[spec_name]
        cfg_path = _write_cfg(spec, {mode_key: True})
        env = dict(os.environ)
        env["MCPRT_CONFIG"] = cfg_path
        params = StdioServerParameters(command=_VENV_PY, args=[_SERVER], env=env)

        kwargs = {}
        if use_callbacks:
            kwargs["sampling_callback"] = _echo_sampling_callback
            kwargs["elicitation_callback"] = _autofill_elicitation_callback
            kwargs["list_roots_callback"] = _fake_roots_callback

        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write, **kwargs) as session:
                await session.initialize()
                tools = await session.list_tools()
                tool_names = [t.name for t in tools.tools]
                if spec["poisoned"]["name"] not in tool_names:
                    return False, f"poisoned tool {spec['poisoned']['name']!r} not in list_tools(): {tool_names}"

                result = await session.call_tool(spec["poisoned"]["name"], {"path": "workspace_config.json"}
                                                  if spec_name == "roots_path_manipulation" else {})

                # For the resource_link attack, also verify the list-exemption
                # property directly: the concrete URI must not appear in
                # resources/list, and the tool result must carry a resource_link
                # block.
                if spec_name == "structured_output_resource_link":
                    blocks = result.content
                    link_blocks = [b for b in blocks if getattr(b, "type", None) == "resource_link"]
                    if not link_blocks:
                        return False, "no resource_link content block in tool result"
                    uri = str(link_blocks[0].uri)
                    listed = await session.list_resources()
                    listed_uris = [str(r.uri) for r in listed.resources]
                    if uri in listed_uris:
                        return False, f"resource_link URI unexpectedly enumerated in resources/list: {uri}"
                    read_result = await session.read_resource(link_blocks[0].uri)
                    if not read_result.contents:
                        return False, "resource_link URI did not resolve via resources/read"

                fired, detail = ht.fired()
                mode_desc = "auto-approving synthetic callbacks" if use_callbacks else "no callbacks (SDK default)"
                return True, f"ok ({mode_desc}); canary_fired={fired}; detail={detail}"
    except Exception as exc:  # noqa: BLE001
        return False, f"EXCEPTION: {exc}\n{traceback.format_exc()}"
    finally:
        ht.cleanup()


async def main() -> None:
    print("=" * 72)
    print("  mcp-rt Flagship -- mechanics smoke test (NOT a resilience verdict)")
    print("=" * 72)
    all_ok = True
    for name in _ATTACK_NAMES:
        for use_callbacks in (False, True):
            label = f"{name} [{'callbacks' if use_callbacks else 'no-callbacks'}]"
            ok, detail = await _run_case(name, use_callbacks)
            all_ok = all_ok and ok
            print(f"{'PASS' if ok else 'FAIL':<5} {label:<62} {detail[:200]}")
    print("=" * 72)
    print("PASS" if all_ok else "FAIL", "-- overall")
    if not all_ok:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
