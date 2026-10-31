"""A long-lived sealed MCP session for the agent tier.

Reuses the Unit-3 launcher (mcp_rt.runtime.runner.build_sealed_launcher): the stdio command is
`unshare -rn sandbox.py … --server-json <target argv>`, which proves the seal P1-P6 and only then execs the
target with stdio inherited. The host opens one ClientSession for the whole run, so target state persists
across actions and the seal is proven once. If the seal cannot be proven the launcher exits before execing
the target, the session's initialize() fails, and `.sealed` is False — the orchestrator then marks every
objective INCONCLUSIVE and never probes (fail-closed).

Per-action egress attribution: the recorder appends server-phase events to a shared file; new_events() returns
the ones written since the previous call. Actions run sequentially, so each window is that action's egress.
Whole-session integrity (recorder vs strace witness, no IPv6) is checked once at teardown — if it is broken,
the orchestrator downgrades egress conclusions to INCONCLUSIVE (ABORT_UNOBSERVABLE)."""
from __future__ import annotations

import asyncio
import secrets
from contextlib import asynccontextmanager
from pathlib import Path

import mcp.types as types
from mcp import ClientSession
from mcp.client.stdio import stdio_client

from mcp_rt.runtime import observe
from mcp_rt.runtime.runner import _read_events, _read_json, _read_text, _sample, build_sealed_launcher


class SealedHandle:
    """What the orchestrator drives: the live session, the surface, per-action egress, and integrity."""

    def __init__(self, token, paths):
        self.token = token
        self.paths = paths
        self.session = None
        self.sealed = False
        self.proof = {}
        self.error = None
        self.elicitations = []
        self._tools = None
        self._offset = 0
        self.integrity = None   # set at teardown: None = sound, else an out-dict (sandbox_unobservable)

    async def list_tools(self):
        if self._tools is None:
            self._tools = list((await self.session.list_tools()).tools)
        return self._tools

    def new_events(self):
        """Server-phase recorder events written since the previous call (this action's egress window)."""
        rows = [e for e in _read_events(self.paths["events"]) if e.get("phase") == "server"]
        fresh = rows[self._offset:]
        self._offset = len(rows)
        return fresh

    def finalize(self):
        """Whole-session integrity check, once, at teardown. Sets .integrity to an out-dict if unsound."""
        report = _read_json(self.paths["report"])
        self.proof = report.get("checks", {})
        all_events = [e for e in _read_events(self.paths["events"]) if e.get("phase") == "server"]
        strace = _read_text(self.paths["strace_server"])
        self.integrity = observe.integrity_problem(
            sealed=bool(report.get("sealed", self.sealed)),
            server_started=self.session is not None, strace_text=strace, events=all_events)


@asynccontextmanager
async def sealed_session(target_argv, *, token=None, connect_timeout=30.0, env=None):
    """Open one sealed session against the target. Yields a SealedHandle (check .sealed before probing).
    `env` (generic string->string) overrides the sealed target's environment (e.g. HOME) — sealed-only."""
    import shutil
    import tempfile
    token = token or "HT-" + secrets.token_hex(8)
    workdir = tempfile.mkdtemp(prefix="mcprt-at-")
    # The launcher runs in workdir, so resolve any relative target-file path against the CURRENT cwd first,
    # or the target would not be found and would never start.
    argv = [str(Path(t).resolve()) if Path(t).exists() else t for t in target_argv]
    params, paths = build_sealed_launcher(argv, workdir, token, extra_env=env)
    handle = SealedHandle(token, paths)

    async def elicit(context, request):
        schema = getattr(request, "requestedSchema", None) or {}
        handle.elicitations.append(sorted((schema.get("properties") or {}).keys()))
        content = {k: _sample(v, token) for k, v in (schema.get("properties") or {}).items()}
        return types.ElicitResult(action="accept", content=content)

    try:
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write, elicitation_callback=elicit) as session:
                try:
                    await asyncio.wait_for(session.initialize(), connect_timeout)
                except Exception as exc:  # noqa: BLE001 — launcher exited before exec (seal failed), or target crash
                    # No usable session -> we cannot probe, whatever the proof said. Fail-closed: sealed=False.
                    report = _read_json(paths["report"])
                    handle.error = (f"sealed={report.get('sealed')} but no session: {repr(exc)[:160]}"
                                    if report.get("sealed") else f"seal not proven: {repr(exc)[:160]}")
                    handle.sealed = False
                    yield handle
                    return
                handle.session = session
                handle.sealed = bool(_read_json(paths["report"]).get("sealed", True))
                yield handle
    finally:
        try:
            handle.finalize()
        finally:
            shutil.rmtree(workdir, ignore_errors=True)
