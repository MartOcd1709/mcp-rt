"""A small synchronous MCP client for the assessment agent to EXERCISE a target server.

The agent's depth comes from actually driving the target's MCP protocol surface — listing its tools
and resources and calling them with crafted inputs — not just running shell. MCP vulnerabilities live
exactly there (a path-traversal in a file tool, SSRF in a fetch tool, command injection in an exec
tool), so the agent needs a first-class way to reach them.

Scope: authorized, locally-launched stdio targets (the same way `mcp-rt scan`/`probe` already launch
and call them). Each call connects fresh, runs, and tears down — stateless and isolated per call.

ponytail: reconnect-per-call (stateless). If a stateful exploit needs set-then-get across calls, add a
persistent session; for independent probes this is simpler and cleaner to reason about.
"""
from __future__ import annotations

import asyncio
import base64
import os
import shlex
import tempfile
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


def _content_text(res) -> str:
    """Flatten an MCP CallToolResult / ReadResourceResult into readable text for the agent."""
    parts: list[str] = []
    if getattr(res, "isError", False):
        parts.append("[tool reported an error]")
    for attr in ("content", "contents"):
        for block in getattr(res, attr, None) or []:
            text = getattr(block, "text", None)
            if text:
                parts.append(text)
            elif getattr(block, "blob", None) is not None:
                parts.append(f"[blob {len(block.blob)} bytes]")
    return ("\n".join(parts))[:3000] or "[no content]"


class MCPClient:
    """Connect to an authorized stdio MCP target and call it. Methods are synchronous wrappers."""

    def __init__(self, target, *, env: dict | None = None, timeout: float = 30.0):
        raw = shlex.split(target) if isinstance(target, str) else list(target)
        # We launch with cwd=a throwaway dir (isolation), so resolve any relative FILE arg to an
        # absolute path first — otherwise `python path/to/server.py` can't be found from the temp cwd.
        self.argv = [str(Path(a).resolve()) if (os.sep in a and Path(a).exists()) else a for a in raw]
        self.env = env
        self.timeout = timeout

    def _run(self, fn):
        async def _session():
            workdir = tempfile.mkdtemp(prefix="mcprt_agent_")
            params = StdioServerParameters(command=self.argv[0], args=self.argv[1:],
                                           env={**(self.env or dict(os.environ))}, cwd=workdir)
            async with stdio_client(params) as (r, w):
                async with ClientSession(r, w) as s:
                    await s.initialize()
                    return await fn(s)
        return asyncio.run(asyncio.wait_for(_session(), self.timeout))

    def list_tools(self) -> list[dict]:
        async def f(s):
            return [{"name": t.name, "description": (t.description or "")[:400],
                     "input_schema": getattr(t, "inputSchema", None)}
                    for t in (await s.list_tools()).tools]
        return self._run(f)

    def list_resources(self) -> list[dict]:
        async def f(s):
            try:
                return [{"uri": str(r.uri), "name": getattr(r, "name", "") or ""}
                        for r in (await s.list_resources()).resources]
            except Exception:  # noqa: BLE001 — server may not support resources
                return []
        return self._run(f)

    def call_tool(self, name: str, arguments: dict | None = None) -> str:
        async def f(s):
            return _content_text(await s.call_tool(name, arguments or {}))
        return self._run(f)

    def read_resource(self, uri: str) -> str:
        async def f(s):
            return _content_text(await s.read_resource(uri))
        return self._run(f)


# ===========================================================================================
# 2026-07-28 STATELESS transport (T1 / SAM1-12) — speak it; attacks (T2/T10) come later.
# Hand-rolled over httpx (already a dep) so the client controls headers/_meta/requestState
# byte-for-byte. The stdio session MCPClient above is the old-spec path, untouched.
# Field/header names pinned to the official 2026-07-28 schema.ts. No attack logic here:
# MRTR responses are minimal VALID shapes that merely ADVANCE the round-trip.
# ===========================================================================================
import httpx  # noqa: E402 — kept beside the stateless code it serves; old-spec path has no httpx dep

_PV_2026 = "2026-07-28"
_MRTR_MAX = int(os.environ.get("MCPRT_MRTR_MAX", "4"))        # bounded: a stuck input_required can't hang us
_HTTP_TIMEOUT = float(os.environ.get("MCPRT_HTTP_TIMEOUT_S", "30"))
# methods that REQUIRE the Mcp-Name header, and the params field its value comes from (schema.ts)
_NAME_SRC = {"tools/call": "name", "prompts/get": "name", "resources/read": "uri"}


class MRTRBounded(RuntimeError):
    """A 2026 server stayed `input_required` past the MRTR round ceiling — we give up cleanly (no hang)."""


def _hdr_value(v: str) -> str:
    """Mcp-Name must be header-safe; non-ASCII is encoded per spec as =?base64?<b64>?= (lowercase sentinel)."""
    try:
        v.encode("ascii")
        return v
    except UnicodeEncodeError:
        return "=?base64?" + base64.b64encode(v.encode()).decode() + "?="


def _result_text_2026(res: dict) -> str:
    """Flatten a 2026 CallTool/ReadResource result (plain dict over the wire) into readable text."""
    parts: list[str] = []
    if res.get("isError"):
        parts.append("[tool reported an error]")
    for attr in ("content", "contents"):
        for block in res.get(attr) or []:
            if block.get("text"):
                parts.append(block["text"])
            elif block.get("blob") is not None:
                parts.append("[blob]")
    return ("\n".join(parts))[:3000] or "[no content]"


class StatelessHTTPClient:
    """Drive a 2026-07-28 STATELESS MCP server over streamable-HTTP: per-request headers +
    `params._meta` identity, NO initialize, NO Mcp-Session-Id, bounded MRTR round-trips, and it
    reads (records, never exploits) `ttlMs`/`cacheScope` off list results. Same method surface as
    MCPClient so callers are transport-agnostic."""

    def __init__(self, url: str, *, client_info: dict | None = None, capabilities: dict | None = None,
                 timeout: float = _HTTP_TIMEOUT, max_mrtr: int = _MRTR_MAX):
        self.url = url
        self.client_info = client_info or {"name": "mcp-rt", "version": "0.2.0"}
        self.capabilities = {} if capabilities is None else capabilities
        self.timeout = timeout
        self.max_mrtr = max_mrtr
        self._id = 0
        self.cache_hints: dict[str, dict] = {}   # method -> {ttlMs, cacheScope} — recorded for later analysis

    def _next_id(self) -> int:
        self._id += 1
        return self._id

    def _meta(self) -> dict:
        m = {"io.modelcontextprotocol/protocolVersion": _PV_2026,
             "io.modelcontextprotocol/clientCapabilities": self.capabilities}
        if self.client_info:
            m["io.modelcontextprotocol/clientInfo"] = self.client_info
        return m

    def _headers(self, method: str, params: dict, extra_headers: dict | None = None) -> dict:
        h = {"Content-Type": "application/json",
             "Accept": "application/json, text/event-stream",   # spec: MUST offer both
             "MCP-Protocol-Version": _PV_2026,                   # MUST equal _meta protocolVersion
             "Mcp-Method": method}                               # MUST equal body.method
        src = _NAME_SRC.get(method)
        if src and params.get(src) is not None:
            h["Mcp-Name"] = _hdr_value(str(params[src]))         # MUST equal params.name / params.uri
        if extra_headers:
            h.update(extra_headers)                              # e.g. Authorization (principal) for red-team
        return h

    def _post(self, method: str, params: dict, extra_headers: dict | None = None) -> dict:
        body = {"jsonrpc": "2.0", "id": self._next_id(), "method": method,
                "params": {**params, "_meta": self._meta()}}
        r = httpx.post(self.url, json=body, headers=self._headers(method, params, extra_headers),
                       timeout=self.timeout)
        r.raise_for_status()
        return r.json() or {}

    def _mrtr_answers(self, input_requests: dict | None) -> dict:
        """Minimal VALID responses (schema.ts InputResponse shapes) keyed by the same ids — just enough
        to ADVANCE the round-trip. Transport only; NOT an attack payload (that is T2/T10)."""
        out: dict = {}
        for key, req in (input_requests or {}).items():
            method = (req or {}).get("method", "")
            if method == "sampling/createMessage":
                out[key] = {"role": "assistant", "content": {"type": "text", "text": ""},
                            "model": "mcp-rt-stub", "stopReason": "endTurn"}
            elif method == "roots/list":
                out[key] = {"roots": []}
            else:  # elicitation/create (or unknown) -> a valid ElicitResult that advances without data
                out[key] = {"action": "decline"}
        return out

    def request(self, method: str, params: dict) -> dict:
        """One logical request, resolving bounded MRTR rounds. Returns the final `complete` result dict.
        Raises MRTRBounded if the server won't complete within max_mrtr rounds (never hangs)."""
        params = dict(params)
        result = (self._post(method, params).get("result") or {})
        rounds = 0
        while result.get("resultType") == "input_required":
            rounds += 1
            if rounds > self.max_mrtr:
                raise MRTRBounded(f"{method}: server stayed input_required for >{self.max_mrtr} rounds")
            retry = dict(params)
            retry["inputResponses"] = self._mrtr_answers(result.get("inputRequests"))
            rs = result.get("requestState")
            if rs is not None:
                retry["requestState"] = rs           # echo EXACTLY — never parse or modify (opaque)
            result = (self._post(method, retry).get("result") or {})
        if "ttlMs" in result or "cacheScope" in result:  # read + record list-caching hints (no exploit)
            self.cache_hints[method] = {"ttlMs": result.get("ttlMs"), "cacheScope": result.get("cacheScope")}
        return result

    # ---- low-level MRTR control (T2+): drive the round-trip by hand, byte-for-byte ----
    def begin(self, method: str, params: dict, *, extra_headers: dict | None = None) -> dict:
        """Send the FIRST leg and return the raw result dict (incl. `resultType`/`requestState`),
        without auto-resuming. Lets an attack probe capture + manipulate `requestState`."""
        return self._post(method, dict(params), extra_headers).get("result") or {}

    def resume(self, method: str, params: dict, *, request_state=None, input_responses: dict | None = None,
               extra_headers: dict | None = None) -> dict:
        """Send a crafted retry with a caller-chosen `requestState` and `inputResponses`. The transport
        client echoes exactly; T2's probe is a MALICIOUS client that deliberately tampers/reuses the
        state to test server validation (spec: a conformant client MUST NOT modify it)."""
        retry = dict(params)
        if input_responses is not None:
            retry["inputResponses"] = input_responses
        if request_state is not None:
            retry["requestState"] = request_state
        return self._post(method, retry, extra_headers).get("result") or {}

    # ---- transport-agnostic surface (mirrors MCPClient) ----
    def list_tools(self) -> list[dict]:
        res = self.request("tools/list", {})
        return [{"name": t.get("name"), "description": (t.get("description") or "")[:400],
                 "input_schema": t.get("inputSchema")} for t in (res.get("tools") or [])]

    def list_resources(self) -> list[dict]:
        try:
            res = self.request("resources/list", {})
            return [{"uri": r.get("uri"), "name": r.get("name") or ""} for r in (res.get("resources") or [])]
        except Exception:  # noqa: BLE001 — server may not support resources
            return []

    def call_tool(self, name: str, arguments: dict | None = None) -> str:
        return _result_text_2026(self.request("tools/call", {"name": name, "arguments": arguments or {}}))

    def read_resource(self, uri: str) -> str:
        return _result_text_2026(self.request("resources/read", {"uri": uri}))


def discover_versions(url: str, *, timeout: float = _HTTP_TIMEOUT) -> tuple[list, dict]:
    """POST `server/discover` (2026-07-28) → (supportedVersions, capabilities). ([], {}) if the server
    doesn't speak it (old-spec only / unreachable)."""
    body = {"jsonrpc": "2.0", "id": 0, "method": "server/discover",
            "params": {"_meta": {"io.modelcontextprotocol/protocolVersion": _PV_2026,
                                 "io.modelcontextprotocol/clientCapabilities": {}}}}
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
               "MCP-Protocol-Version": _PV_2026, "Mcp-Method": "server/discover"}
    try:
        r = httpx.post(url, json=body, headers=headers, timeout=timeout)
        if r.status_code >= 400:
            return ([], {})
        res = (r.json() or {}).get("result") or {}
        return (res.get("supportedVersions") or [], res.get("capabilities") or {})
    except Exception:  # noqa: BLE001
        return ([], {})


def negotiate_transport(url: str, *, timeout: float = _HTTP_TIMEOUT) -> dict:
    """Pick the transport for an HTTP target: prefer 2026-07-28 stateless when the server offers it,
    else the old-spec session path. Downgrade is DETECTED + RECORDED here, never forced (forcing is
    T10/SAM1-21). Returns {transport, chosen_version, supported, downgrade_available}."""
    supported, _caps = discover_versions(url, timeout=timeout)
    if _PV_2026 in supported:
        older = [v for v in supported if v != _PV_2026]
        return {"transport": "stateless-2026", "chosen_version": _PV_2026,
                "supported": supported, "downgrade_available": bool(older)}
    return {"transport": "legacy-session", "chosen_version": (supported[0] if supported else "2025-06-18"),
            "supported": supported, "downgrade_available": False}
