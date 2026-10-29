"""One fixture server, run as a stdio MCP server in its own event-loop thread, behind a synchronous facade.

The MCP session lives inside one coroutine (anyio cancel scopes must not cross tasks); the client adapter's calls
are queued to it. Every tool call is recorded, so the scorer can tell whether the planted token was ever supplied:
a lure that was never taken proves nothing about the fixture.
"""
import asyncio
import json
import os
import sys
import threading
from pathlib import Path

import mcp.types as types
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from pydantic import AnyUrl

CALL_TIMEOUT_S = 20.0
START_TIMEOUT_S = 60.0


class FixtureSession:
    def __init__(self, fixture_path: Path, canary_url: str, answer_elicitation):
        self._path = fixture_path
        self._canary_url = canary_url
        self._answer = answer_elicitation          # (message, requested_schema) -> (action, content or None)
        self.tools: list[dict] = []
        self.resources: list[str] = []
        self.calls: list[tuple[str, dict]] = []
        self._ready = threading.Event()
        self._error: Exception | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._queue: asyncio.Queue | None = None
        self._thread = threading.Thread(target=self._thread_main, daemon=True)

    # ---- lifecycle ----------------------------------------------------------------------------
    def __enter__(self):
        self._thread.start()
        if not self._ready.wait(START_TIMEOUT_S):
            raise RuntimeError(f"fixture {self._path.name} did not start within {START_TIMEOUT_S:.0f}s")
        if self._error is not None:
            raise self._error
        return self

    def __exit__(self, *exc):
        if self._loop is not None and self._queue is not None and self._thread.is_alive():
            self._loop.call_soon_threadsafe(self._queue.put_nowait, None)
        self._thread.join(30)

    def _thread_main(self):
        self._loop = asyncio.new_event_loop()
        try:
            self._loop.run_until_complete(self._serve())
        except Exception as exc:  # noqa: BLE001 — surfaced to the caller through __enter__
            self._error = exc
        finally:
            self._ready.set()
            self._loop.close()

    async def _serve(self):
        self._queue = asyncio.Queue()
        env = {**os.environ, "MCPRT_CANARY": self._canary_url}
        params = StdioServerParameters(command=sys.executable, args=[str(self._path / "server.py")], env=env)

        async def elicitation_callback(context, request):
            action, content = self._answer(request.message, request.requestedSchema)
            if content is not None:
                self.calls.append(("elicitation_reply", content))   # the reply is a supplied value, so it counts
            if content is None:
                return types.ElicitResult(action=action)
            return types.ElicitResult(action=action, content=content)

        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write, elicitation_callback=elicitation_callback) as session:
                await session.initialize()
                self.tools = [{"name": t.name, "description": t.description or "", "inputSchema": t.inputSchema or {}}
                              for t in (await session.list_tools()).tools]
                try:
                    self.resources = [str(r.uri) for r in (await session.list_resources()).resources]
                except Exception:  # noqa: BLE001 — many servers expose no resources endpoint
                    self.resources = []
                self._ready.set()
                while True:
                    item = await self._queue.get()
                    if item is None:
                        return
                    op, fut = item
                    try:
                        value = await asyncio.wait_for(op(session), CALL_TIMEOUT_S)
                        if not fut.done():
                            fut.set_result(value)
                    except Exception as exc:  # noqa: BLE001 — report the failure, keep the session alive
                        if not fut.done():
                            fut.set_exception(exc)

    # ---- synchronous facade for client adapters ----------------------------------------------
    def _submit(self, op):
        async def enqueue():
            fut = self._loop.create_future()
            await self._queue.put((op, fut))
            return await fut
        return asyncio.run_coroutine_threadsafe(enqueue(), self._loop).result(CALL_TIMEOUT_S + 10)

    def call(self, name: str, arguments: dict) -> str:
        self.calls.append((name, arguments))

        async def op(session):
            result = await session.call_tool(name, arguments)
            return "".join(getattr(c, "text", "") or "" for c in (result.content or []))
        try:
            return self._submit(op)
        except Exception as exc:  # noqa: BLE001 — a failed call is data for the client, not a harness crash
            return f"error: {type(exc).__name__}: {exc}"[:500]

    def read(self, uri: str) -> str:
        async def op(session):
            result = await session.read_resource(AnyUrl(uri))
            return "\n".join(getattr(c, "text", "") or "" for c in result.contents)
        try:
            return self._submit(op)
        except Exception as exc:  # noqa: BLE001
            return f"error: {type(exc).__name__}: {exc}"[:500]

    def token_supplied(self, token: str) -> bool:
        return any(token in json.dumps(arguments) for _, arguments in self.calls)
