"""Host driver for the sealed runtime unit. Starts a server inside the launcher, drives it over MCP stdio, and
assembles the verdict from what the recorder and the strace witness saw. The server runs only after the seal is proven.
"""
import asyncio
import base64
import json
import os
import random
import secrets
import sys
import tempfile
from pathlib import Path

import mcp.types as types
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from mcp_rt.runtime import observe

LAUNCHER = Path(__file__).with_name("sandbox.py")
CANARY = "http://127.0.0.1:9999/collect"
CALL_TIMEOUT = 10.0
GRACE = 2.0
LIMITS = [
    "seals IP egress only: unix-domain sockets to host daemons are not sealed in this unit",
    "payloads are inspected in plaintext; TLS payloads are opaque and can clear nothing",
    "IPv6 attempts are not captured by the IPv4 recorder and yield INCONCLUSIVE",
]


def _sample(spec, token, depth=0):
    """A benign value for one schema node. Every string carries the test token."""
    if not isinstance(spec, dict):
        return token
    if spec.get("enum"):
        return spec["enum"][0]
    kind = spec.get("type")
    if isinstance(kind, list):
        kind = next((k for k in kind if k != "null"), None)
    if kind is None and spec.get("anyOf"):
        return _sample(spec["anyOf"][0], token, depth)
    if kind in (None, "string"):
        return f"{token} sample"
    if kind in ("integer", "number"):
        return 1
    if kind == "boolean":
        return True
    if kind == "array":
        return [_sample(spec.get("items", {}), token, depth + 1)] if depth < 3 else []
    if kind == "object":
        props = spec.get("properties") or {}
        return {k: _sample(v, token, depth + 1) for k, v in props.items()} if depth < 3 else {}
    return token


async def _drive(params, token, timeout):
    out = {"instructions": None, "server_name": None, "tools": [], "calls": [], "elicitations": [], "error": None}

    async def elicit(context, request):
        # Every elicitation is answered with the token, so a server that asks for a secret gets ours.
        schema = getattr(request, "requestedSchema", None) or {}
        out["elicitations"].append(sorted((schema.get("properties") or {}).keys()))
        content = {k: _sample(v, token) for k, v in (schema.get("properties") or {}).items()}
        return types.ElicitResult(action="accept", content=content)
    try:
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write, elicitation_callback=elicit) as session:
                init = await asyncio.wait_for(session.initialize(), timeout)
                out["instructions"] = init.instructions
                out["server_name"] = init.serverInfo.name if init.serverInfo else None
                for tool in (await asyncio.wait_for(session.list_tools(), timeout)).tools:
                    schema = tool.inputSchema or {}
                    out["tools"].append({"name": tool.name, "description": tool.description or "",
                                         "inputSchema": schema})
                    args = {k: _sample(v, token) for k, v in (schema.get("properties") or {}).items()}
                    try:
                        res = await asyncio.wait_for(session.call_tool(tool.name, args), CALL_TIMEOUT)
                        text = " ".join(getattr(c, "text", "") or "" for c in res.content)[:200]
                        out["calls"].append({"tool": tool.name, "isError": bool(res.isError), "text": text})
                    except Exception as exc:  # a failing tool is a result, not a harness crash
                        out["calls"].append({"tool": tool.name, "error": repr(exc)[:200]})
                await asyncio.sleep(GRACE)
    except Exception as exc:
        out["error"] = repr(exc)[:300]
    return out


def _read_json(path):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return {}


def _read_events(path):
    try:
        return [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()]
    except OSError:
        return []


def _read_text(path):
    try:
        return Path(path).read_text()
    except OSError:
        return None


def _summary(ev, token):
    payload = base64.b64decode(ev["payload"])
    return {"proto": ev["proto"], "dst": ev["dst"], "port": ev["port"], "bytes": len(payload),
            "truncated": ev["truncated"], "inspectable": observe.inspectable(payload, ev["truncated"], ev["port"]),
            "token_hits": observe.token_hits(payload, token)}


def run_server(argv, *, token=None, timeout=120.0):
    """Run one server under the sealed launcher and return its verdict record."""
    token = token or "HT-" + secrets.token_hex(8)
    workdir = tempfile.mkdtemp(prefix="mcprt-rt-")
    names = {"report": "report.json", "events": "events.jsonl", "strace_server": "server.strace",
             "strace_probe": "probe.strace", "server_json": "server.json"}
    paths = {k: os.path.join(workdir, v) for k, v in names.items()}
    Path(paths["server_json"]).write_text(json.dumps(list(argv)))
    port = random.SystemRandom().randint(20000, 60000)
    host_ino = os.stat("/proc/self/ns/net").st_ino
    launcher = ["unshare", "-rn", "--", sys.executable, "-I", str(LAUNCHER),
                "--report", paths["report"], "--events", paths["events"], "--workdir", workdir,
                "--host-netns-ino", str(host_ino), "--port", str(port), "--server-json", paths["server_json"],
                "--strace-server", paths["strace_server"], "--strace-probe", paths["strace_probe"]]
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": workdir, "LANG": "C.UTF-8",
           "MCPRT_TEST_VALUE": token, "MCPRT_CANARY": CANARY}
    params = StdioServerParameters(command=launcher[0], args=launcher[1:], env=env, cwd=workdir)
    drive = asyncio.run(_drive(params, token, timeout))

    report = _read_json(paths["report"])
    server_events = [e for e in _read_events(paths["events"]) if e.get("phase") == "server"]
    strace_text = _read_text(paths["strace_server"]) if report.get("server_started") else None

    parts = [drive.get("server_name") or "", drive.get("instructions") or ""]
    for tool in drive["tools"]:
        parts += [tool["name"], tool["description"]]
        for spec in (tool["inputSchema"].get("properties") or {}).values():
            if isinstance(spec, dict):
                parts.append(spec.get("description") or "")
    refused = [c["tool"] for c in drive["calls"]
               if c.get("isError") or "error" in c or observe.REFUSAL.match(c.get("text") or "")]
    result = observe.verdict(sealed=bool(report.get("sealed")), server_started=bool(report.get("server_started")),
                             events=server_events, strace_text=strace_text, token=token,
                             claim_text=" \n ".join(parts), refused_calls=refused)
    return {"server": list(argv), "token": token, **result,
            "attempts": [_summary(ev, token) for ev in server_events],
            "proof": report.get("checks", {}), "proof_error": report.get("error"),
            "tools": [t["name"] for t in drive["tools"]], "calls": drive["calls"],
            "driver_error": drive["error"], "elicitations": drive["elicitations"], "refused": refused,
            "limits": LIMITS, "workdir": workdir}
