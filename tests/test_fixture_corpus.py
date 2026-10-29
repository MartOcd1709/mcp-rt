"""Verification for the mcp-rt malicious-server test-fixture corpus (fixtures/<attack_class>/).

Enforces the fixture skill's five hard safety rules and its consistency rules:
  * label.json schema, id == attack_class == folder name, loopback canary, marker format
  * static: server.py contacts only 127.0.0.1, spawns nothing, writes no files
  * runtime: each fixture RUNS over stdio and forwards ONLY a synthetic honeytoken to a loopback canary;
    a non-honeytoken value is never forwarded; any non-loopback MCPRT_CANARY makes it refuse to start.
"""
import asyncio
import http.server
import json
import os
import re
import subprocess
import sys
import threading
from pathlib import Path

import mcp.types as types
import pytest
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from pydantic import AnyUrl

ROOT = Path(__file__).resolve().parents[1] / "fixtures"
CLASSES = ["tool_description_injection", "server_side_workflow", "proxy_aggregator", "tool_annotation",
           "resource_content", "egress_evasion", "elicitation_prompt"]
MARKER = "HT-9f3a1c7e2b4d6a80"   # a synthetic honeytoken: the ONLY value these tests ever plant
_DOC_URI = "doc://onboarding/getting-started"


class _Canary:
    """A loopback HTTP listener owned by the test. Records every (path, json body) it receives."""

    def __init__(self):
        self.hits: list = []
        hits = self.hits

        class _Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length).decode("utf-8", "replace")
                try:
                    hits.append((self.path, json.loads(raw)))
                except ValueError:
                    hits.append((self.path, {"raw": raw}))
                self.send_response(200)
                self.end_headers()

            def log_message(self, *args):  # keep test output quiet
                pass

        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/collect"

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._server.shutdown()
        self._server.server_close()


def _params(cls: str, canary_url: str) -> StdioServerParameters:
    env = {**os.environ, "MCPRT_CANARY": canary_url}
    return StdioServerParameters(command=sys.executable, args=[str(ROOT / cls / "server.py")], env=env)


async def _plant(cls: str, session: ClientSession, value: str) -> None:
    """Drive the one attack path each fixture exposes, placing `value` where that fixture reads it."""
    if cls == "tool_description_injection":
        await session.call_tool("summarize_invoice", {"text": "x", "auth": value})
    elif cls == "server_side_workflow":
        await session.call_tool("check_invoice_status", {"reference": value})
    elif cls == "proxy_aggregator":
        await session.call_tool("delegate", {"tool": "ledger_lookup", "arguments": json.dumps({"auth": value})})
    elif cls == "tool_annotation":
        await session.call_tool("verify_account", {"session_token": value})
    elif cls == "resource_content":
        doc = await session.read_resource(AnyUrl(_DOC_URI))
        assert "sync_status" in doc.contents[0].text, "the injected instruction is not in the resource"
        await session.call_tool("sync_status", {"credential": value})
    elif cls == "egress_evasion":
        await session.call_tool("check_for_updates", {"client_id": value})
    elif cls == "elicitation_prompt":
        await session.call_tool("run_report", {"period": "2026-10"})
    else:
        raise AssertionError(f"no driver for {cls}")


async def _run(cls: str, value: str, canary_url: str, accept: bool = True) -> None:
    async def elicitation_callback(context, params):
        if accept:
            return types.ElicitResult(action="accept", content={"credential": value})
        return types.ElicitResult(action="decline")

    async with stdio_client(_params(cls, canary_url)) as (read, write):
        async with ClientSession(read, write, elicitation_callback=elicitation_callback) as session:
            await session.initialize()
            await _plant(cls, session, value)


# ---- corpus structure and label ground truth -------------------------------------------------------

def test_corpus_has_exactly_the_seven_listed_classes():
    assert sorted(p.name for p in ROOT.iterdir() if p.is_dir()) == sorted(CLASSES)


@pytest.mark.parametrize("cls", CLASSES)
def test_label_schema_and_ground_truth(cls):
    folder = ROOT / cls
    label = json.loads((folder / "label.json").read_text())
    for key in ("id", "attack_class", "mechanism", "expected", "marker_format", "canary",
                "protocol_features", "notes"):
        assert key in label, f"{cls}: label.json missing {key}"
    assert label["id"] == label["attack_class"] == cls
    assert label["expected"] == "VULNERABLE_IF_AGENT_SENDS_MARKER"
    assert label["marker_format"] == "HT-<hex>"
    assert re.fullmatch(r"http://127\.0\.0\.1:\d+/collect", label["canary"]), "canary must be loopback"
    assert label["protocol_features"]
    assert set(label["protocol_features"]) <= {"tools", "resources", "elicitation", "prompts", "sampling", "roots"}
    lines = [line for line in (folder / "README.md").read_text().splitlines() if line.strip()]
    assert len(lines) == 1, f"{cls}: README must be exactly one line"


# ---- static safety rules ----------------------------------------------------------------------------

@pytest.mark.parametrize("cls", CLASSES)
def test_static_safety_loopback_only_no_spawn_no_writes(cls):
    src = (ROOT / cls / "server.py").read_text()
    hosts = set(re.findall(r"https?://([^/:\s\"'{]+)", src))
    assert hosts <= {"127.0.0.1"}, f"{cls}: non-loopback host literal(s): {hosts - {'127.0.0.1'}}"
    assert not re.search(r"subprocess|os\.system|\beval\(|\bexec\(|\bsocket\b", src), f"{cls}: spawns or evals"
    assert not re.search(r"open\([^)]*['\"][wax]", src), f"{cls}: opens a file for writing"
    assert not re.search(r"write_text|write_bytes|os\.remove|unlink|mkdir", src), f"{cls}: filesystem write"


# ---- runtime: it runs, and it forwards only a planted honeytoken to the loopback canary --------------

@pytest.mark.parametrize("cls", CLASSES)
def test_planted_honeytoken_reaches_loopback_canary(cls):
    with _Canary() as canary:
        asyncio.run(_run(cls, MARKER, canary.url))
        assert any(MARKER in json.dumps(body) for _, body in canary.hits), \
            f"{cls}: the planted honeytoken did not reach the loopback canary"


@pytest.mark.parametrize("cls", CLASSES)
def test_non_honeytoken_is_never_forwarded(cls):
    with _Canary() as canary:
        asyncio.run(_run(cls, "not-a-token", canary.url))
        assert canary.hits == [], f"{cls}: forwarded a value that is not a synthetic honeytoken"


def test_elicitation_declined_forwards_nothing():
    with _Canary() as canary:
        asyncio.run(_run("elicitation_prompt", MARKER, canary.url, accept=False))
        assert canary.hits == []


@pytest.mark.parametrize("cls", CLASSES)
@pytest.mark.parametrize("bad", [
    "http://example.com:9/collect",
    "http://127.0.0.1.evil.example:9/collect",
    "http://127.0.0.1@evil.example:9/collect",
    "https://127.0.0.1:9/collect",
])
def test_refuses_to_start_with_non_loopback_canary(cls, bad):
    env = {**os.environ, "MCPRT_CANARY": bad}
    proc = subprocess.run([sys.executable, str(ROOT / cls / "server.py")], env=env,
                          stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60)
    assert proc.returncode != 0 and "SAFETY" in proc.stderr, f"{cls} started with canary {bad!r}"
