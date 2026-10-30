"""The closed action space. The planner may emit exactly one of:

    {"action": "run_probe", "class": "<class>", "tool": "<tool>", "reason": "..."}
    {"action": "run_egress", "tool": "<tool>", "reason": "..."}
    {"action": "stop", "reason": "<enum>"}

There is no payload field, no argument field, no shell, and no verdict field. The validator rejects anything
else — unknown action, unknown key, a class not in the RoE, a tool not in the surface, a stop reason not in
the enum. A rejected action never executes; it is logged and counted (T3/T8). This closed space is the
planner's prompt-injection containment: a hijacked planner can still only choose among these (T14)."""
from __future__ import annotations

from dataclasses import dataclass

STOP_REASONS = frozenset({"objectives_exhausted", "no_more_progress", "operator_request"})
_KEYS = {"run_probe": {"action", "class", "tool", "reason"},
         "run_egress": {"action", "tool", "reason"},
         "stop": {"action", "reason"}}


class ActionRejected(ValueError):
    """The planner emitted something outside the closed action space or the RoE scope."""


@dataclass(frozen=True)
class Action:
    kind: str                 # run_probe | run_egress | stop
    cls: str = ""
    tool: str = ""
    reason: str = ""


def validate_action(raw, *, classes, tools) -> Action:
    """Normalize and scope-check one planner output. `classes` = RoE classes; `tools` = surface tool names.
    Raises ActionRejected on any deviation (the caller logs + counts it)."""
    if not isinstance(raw, dict):
        raise ActionRejected(f"action must be an object, got {type(raw).__name__}")
    kind = raw.get("action")
    if kind not in _KEYS:
        raise ActionRejected(f"unknown action {kind!r}")
    extra = set(raw) - _KEYS[kind]
    if extra:
        raise ActionRejected(f"unknown key(s) for {kind}: {sorted(extra)}")
    reason = str(raw.get("reason", ""))[:200]
    if kind == "stop":
        if raw.get("reason") not in STOP_REASONS:
            raise ActionRejected(f"stop reason must be one of {sorted(STOP_REASONS)}")
        return Action("stop", reason=reason)
    tool = raw.get("tool")
    if tool not in tools:
        raise ActionRejected(f"tool {tool!r} is not in the authorized surface")
    if kind == "run_probe":
        cls = raw.get("class")
        if cls not in classes:
            raise ActionRejected(f"class {cls!r} is not in the RoE scope")
        return Action("run_probe", cls=str(cls), tool=str(tool), reason=reason)
    return Action("run_egress", tool=str(tool), reason=reason)   # run_egress
