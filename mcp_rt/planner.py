"""Planner — turn a discovered MCP surface into an EXHAUSTIVE, surface-derived test plan.

A human pentester first maps the server, then plans which point to hit and how, then works the plan
to completion. This module is the plan step. It is built so the plan is:

  * complete  — every tool × every attackable parameter × every plausible vuln class becomes a point,
                so nothing on the surface is silently skipped ("nothing missed");
  * not hardcoded — points are DERIVED from the target's own tools/params at plan time, not a fixed
                list; a tool we have never seen still gets planned from the shape of its inputs;
  * agentic-extensible — a planner model can ADD creative points the deterministic pass misses (union).

Each point carries a ready-to-fire adversarial probe (with the other required args filled benign), so
the vulnerability phase just works the list and reads each observation. Ground truth still decides
whether a point is a real finding — the plan only says "check here, like this".
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# Parameter-name signals: what an input NAME suggests about the class to test + the payload to send.
# (regex on the param name, vuln class, adversarial value). Order = most specific first.
_PARAM_SIGNALS: list[tuple[str, str, str]] = [
    (r"(path|file|filename|filepath|dir|directory|doc|document)", "path_traversal",
     "../../../../etc/passwd"),
    (r"(url|uri|endpoint|host|link|address|webhook|callback)", "ssrf",
     "http://169.254.169.254/latest/meta-data/"),
    (r"(cmd|command|exec|shell|script|args|argv)", "command_injection", "$(id)"),
    (r"(query|sql|statement|where|filter)", "sql_injection", "' OR '1'='1' --"),
    (r"(template|format|render|message|msg|pattern)", "ssti", "{{7*7}}"),
    (r"(code|eval|expr|expression|python|js)", "code_injection", "__import__('os').popen('id').read()"),
]
# Tool-NAME signals: fall back to what the tool is called when its params are generic.
_NAME_SIGNALS: list[tuple[str, str, str]] = [
    (r"(fetch|download|http|request|curl|web|url|browse|crawl|import)", "ssrf",
     "http://169.254.169.254/latest/meta-data/"),
    (r"(read|cat|open|load|get).*(file|doc|path|content)?", "path_traversal",
     "../../../../etc/passwd"),
    (r"(run|exec|cmd|shell|system|spawn|process)", "command_injection", "$(id)"),
    (r"(sql|query|db|database|note|record)", "sql_injection", "' OR '1'='1' --"),
    (r"(render|template|format|colorize|message)", "ssti", "{{7*7}}"),
    (r"(python|eval|code|compute|calc)", "code_injection", "__import__('os').popen('id').read()"),
]


@dataclass
class TestPoint:
    target: str                       # tool (or resource) name
    vuln_class: str                   # path_traversal / ssrf / command_injection / ...
    param: str = ""                   # the input parameter to attack ("" for name-based / resources)
    kind: str = "tool"                # "tool" | "resource"
    rationale: str = ""               # why this point is plausible (surface-derived)
    probe: dict = field(default_factory=dict)   # ready-to-fire arguments for the tool call
    source: str = "deterministic"     # "deterministic" | "planner-model"
    status: str = "planned"           # planned -> tested -> candidate | clear

    def as_dict(self) -> dict:
        return {"target": self.target, "vuln_class": self.vuln_class, "param": self.param,
                "kind": self.kind, "rationale": self.rationale, "probe": self.probe,
                "source": self.source, "status": self.status}


@dataclass
class Plan:
    target: str
    points: list = field(default_factory=list)

    def coverage(self) -> dict:
        tools = {p.target for p in self.points if p.kind == "tool"}
        classes = {p.vuln_class for p in self.points}
        return {"points": len(self.points), "tools_covered": len(tools),
                "classes_covered": sorted(classes),
                "by_source": {s: sum(1 for p in self.points if p.source == s)
                              for s in {pt.source for pt in self.points}}}

    def as_dict(self) -> dict:
        return {"target": self.target, "coverage": self.coverage(),
                "points": [p.as_dict() for p in self.points]}


def _benign_value(spec: dict):
    """A harmless default for a non-targeted required param, by JSON-schema type."""
    t = (spec or {}).get("type", "string")
    return {"string": "test", "integer": 1, "number": 1, "boolean": False,
            "array": [], "object": {}}.get(t, "test")


def _args_for(tool: dict, attack_param: str, payload: str) -> dict:
    """Build a full argument dict: the attack payload on `attack_param`, every other required param
    filled with a benign default so the call actually executes."""
    schema = tool.get("input_schema") or {}
    props = schema.get("properties") or {} if isinstance(schema, dict) else {}
    required = schema.get("required") or list(props.keys()) if isinstance(schema, dict) else []
    args = {name: _benign_value(props.get(name, {})) for name in required}
    if attack_param:
        args[attack_param] = payload
    elif props:                                   # name-based: put the payload on the first string param
        first = next((n for n, s in props.items() if (s or {}).get("type", "string") == "string"),
                     next(iter(props), ""))
        if first:
            args[first] = payload
    return args


def plan_tool(tool: dict) -> list:
    """Every attackable (param × class) point for one tool, derived from its own schema + name."""
    points, seen = [], set()
    name = tool.get("name", "")
    schema = tool.get("input_schema") or {}
    props = (schema.get("properties") or {}) if isinstance(schema, dict) else {}

    for param in props:                                           # param-name driven (most precise)
        for rx, cls, payload in _PARAM_SIGNALS:
            if re.search(rx, param, re.I) and (name, cls, param) not in seen:
                seen.add((name, cls, param))
                points.append(TestPoint(
                    target=name, vuln_class=cls, param=param, kind="tool",
                    rationale=f"param '{param}' suggests {cls}",
                    probe=_args_for(tool, param, payload)))

    for rx, cls, payload in _NAME_SIGNALS:                        # tool-name driven (fallback/augment)
        if re.search(rx, name, re.I) and not any(p.vuln_class == cls for p in points):
            points.append(TestPoint(
                target=name, vuln_class=cls, param="", kind="tool",
                rationale=f"tool name '{name}' suggests {cls}",
                probe=_args_for(tool, "", payload)))
    return points


def build_plan(target: str, surface: dict, *, model=None) -> Plan:
    """Build the full test plan from a discovered surface. `surface` is {"tools": [ {name, description,
    input_schema}, ...]}. A `model` (planner agent) may add creative points beyond the deterministic
    enumeration — the union keeps completeness while gaining reach."""
    tools = surface.get("tools") or []
    points: list = []
    for tool in tools:
        if isinstance(tool, dict):
            points += plan_tool(tool)
    if model is not None:
        try:
            points += _model_augment(target, tools, points, model)
        except Exception:  # noqa: BLE001 — the deterministic plan stands on its own
            pass
    return Plan(target=target, points=points)


def _model_augment(target: str, tools: list, existing: list, model) -> list:
    """Ask the planner model for ADDITIONAL creative test points the deterministic pass missed."""
    import json
    have = [{"target": p.target, "vuln_class": p.vuln_class, "param": p.param} for p in existing]
    prompt = (
        "You are planning an authorized MCP security assessment. Here are the target's tools and the "
        "test points already planned deterministically. Propose ADDITIONAL, non-duplicate test points "
        "(creative or chained attacks the simple enumeration missed). Reply ONLY with a JSON array of "
        '{"target","vuln_class","param","rationale","probe"} objects.\n'
        f"TOOLS: {json.dumps(tools)[:4000]}\nALREADY PLANNED: {json.dumps(have)[:2000]}")
    reply = model.chat([{"role": "user", "content": prompt}])
    s, e = reply.find("["), reply.rfind("]")
    raw = json.loads(reply[s:e + 1]) if s >= 0 and e > s else []
    out = []
    for d in raw if isinstance(raw, list) else []:
        if isinstance(d, dict) and d.get("target") and d.get("vuln_class"):
            out.append(TestPoint(target=str(d["target"]), vuln_class=str(d["vuln_class"]),
                                  param=str(d.get("param", "")), rationale=str(d.get("rationale", "")),
                                  probe=d.get("probe") or {}, source="planner-model"))
    return out
