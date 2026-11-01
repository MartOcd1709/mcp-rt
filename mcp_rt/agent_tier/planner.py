"""Planners choose WHERE to look. They emit raw action dicts (the closed-space shape); the orchestrator
validates every one before it runs, so no planner — deterministic or live — can escape the action space.

U1 ships the DeterministicPlanner (no model, no network): it walks a fixed objective list in order and then
stops. It is the offline driver that lets the whole tier be tested without a live model. A LivePlanner
(a real model over the same closed-space contract) is U4 and is gated behind the RoE live gate.
"""
from __future__ import annotations


class DeterministicPlanner:
    """Walks (kind, class, tool) objectives in order, emitting one closed-space action each step, then stop.
    Deterministic: the same objectives always produce the same action sequence (T9)."""

    name = "deterministic"

    def __init__(self, objectives):
        # objectives: list of ("run_probe", cls, tool) or ("run_egress", "", tool)
        self._queue = list(objectives)
        self._i = 0

    def next_action(self, context) -> dict:  # context unused: deterministic by design
        if self._i >= len(self._queue):
            return {"action": "stop", "reason": "objectives_exhausted"}
        kind, cls, tool = self._queue[self._i]
        self._i += 1
        if kind == "run_egress":
            return {"action": "run_egress", "tool": tool, "reason": "scheduled egress observation"}
        return {"action": "run_probe", "class": cls, "tool": tool,
                "reason": f"scheduled {cls} probe"}
