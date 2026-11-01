"""Orchestration: load and validate the RoE, open one sealed session, let the planner choose closed-space
actions, execute each inside the seal, route every verdict through the spine, and keep an honest ledger.

Fail-closed: an unproven seal means every objective is INCONCLUSIVE and nothing is probed. Bounded by the
RoE budget (action/wall/stall caps) under code ceilings, a kill switch, and a planner-reject cap. Every
VULNERABLE is re-demonstrated once (G8). If whole-session integrity breaks, egress conclusions downgrade to
INCONCLUSIVE (ABORT_UNOBSERVABLE). The model picks where to look; an oracle decides what is true.
"""
from __future__ import annotations

import asyncio
import time
from pathlib import Path

from mcp_rt.agent_tier.actions import ActionRejected, validate_action
from mcp_rt.agent_tier.executor import ALL_CLASSES, execute
from mcp_rt.agent_tier.ledger import Ledger
from mcp_rt.agent_tier.planner import DeterministicPlanner
from mcp_rt.agent_tier.roe import load_roe, validate_for_run
from mcp_rt.agent_tier.session import sealed_session

MAX_REJECTS = 3   # consecutive planner rejections before ABORT_SCOPE (closed-space / out-of-scope outputs)


def assess(roe_path, *, planner=None, allow_live=False, now=None) -> dict:
    """Entry point. Validates the RoE (raises RoEError if unsound), then runs the sealed assessment offline.
    `planner` may be injected (tests, or a live planner in U4); default is the DeterministicPlanner."""
    roe = load_roe(roe_path)
    validate_for_run(roe, allow_live=allow_live, now=now)
    report = asyncio.run(_run(roe, planner))
    if roe.upstream_url_keys:
        # #28 upstream-redirect SSRF: a SEPARATE sealed pass — the oracle needs the recorder configured with
        # the sentinel/canary AT LAUNCH, so it cannot ride the main loop's already-open session. Sealed +
        # loopback-only (nothing leaves the netns), so it is offline-safe; routed through the spine like all.
        from mcp_rt.runtime.runner import assess_redirect_follow
        rr = assess_redirect_follow(roe.argv, upstream_keys=roe.upstream_url_keys, env=roe.env)
        report["redirect_ssrf"] = {"verdict": rr["verdict"], "method": rr["method"], "evidence": rr["evidence"],
                                   "upstream_keys": list(roe.upstream_url_keys), "attempts": rr.get("attempts", [])}
    return report


def _objectives(classes, tools):
    # tool-major: for each tool, try each in-scope class. egress class -> run_egress, else run_probe.
    return [("run_egress" if c == "egress" else "run_probe", c, t) for t in tools for c in classes]


async def _run(roe, planner) -> dict:
    classes = [c for c in roe.classes if c in ALL_CLASSES]
    ledger = Ledger()
    kill = Path(roe.kill_switch) if roe.kill_switch else None
    handle = None
    async with sealed_session(roe.argv, env=roe.env) as h:
        handle = h
        if not h.sealed:
            objs = _objectives(classes, roe.surface_tools or ["(target)"])
            ledger.objectives_total = len(objs)
            for _, c, t in objs:
                ledger.record([{"class": c, "tool": t, "method": "sandbox_unproven",
                                "verdict": "INCONCLUSIVE", "evidence": h.error or "seal not proven"}])
            ledger.stop("ABORT_UNOBSERVABLE")
        else:
            discovered = [t.name for t in await h.list_tools()]
            surface = roe.surface_tools or discovered
            objs = _objectives(classes, surface)
            ledger.objectives_total = len(objs)
            await _loop(roe, h, ledger, planner or DeterministicPlanner(objs), classes, surface, kill)
    if handle is not None and handle.integrity is not None:   # finalize() ran on exit; integrity now known
        ledger.downgrade_unobservable(handle.integrity["evidence"])
    return ledger.report()


async def _loop(roe, handle, ledger, planner, classes, surface, kill) -> None:
    b = roe.budget
    start = time.monotonic()
    stale = rejects = 0
    while True:
        if kill and kill.exists():
            return ledger.stop("KILLED")
        if ledger.actions_used >= b.max_actions:
            return ledger.stop("BUDGET_ACTIONS")
        if time.monotonic() - start >= b.max_wall_seconds:
            return ledger.stop("BUDGET_WALL")
        if stale >= b.patience:
            return ledger.stop("STALL")

        raw = planner.next_action({"tools": surface, "classes": classes,
                                   "remaining_actions": b.max_actions - ledger.actions_used})
        try:
            action = validate_action(raw, classes=classes, tools=surface)
        except ActionRejected as exc:
            ledger.scope_violations.append({"raw": raw, "reason": str(exc)})
            ledger.actions_used += 1
            rejects += 1
            if rejects >= MAX_REJECTS:
                return ledger.stop("ABORT_SCOPE")
            continue
        rejects = 0
        if action.kind == "stop":
            return ledger.stop("COMPLETE")

        ledger.actions_used += 1
        observations = await execute(action, handle)
        progressed = ledger.record(observations)
        for o in observations:   # G8: re-demonstrate every VULNERABLE once, fresh nonces
            if o["verdict"] == "VULNERABLE" and ledger.actions_used < b.max_actions:
                rep = await execute(action, handle)
                ok = any(r["verdict"] == "VULNERABLE" and r["class"] == o["class"] for r in rep)
                ledger.mark_reproduction(o["class"], o["tool"], ok,
                                         evidence=", ".join(r["method"] for r in rep))
                ledger.actions_used += 1
        stale = 0 if progressed else stale + 1
