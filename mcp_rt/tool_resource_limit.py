"""T11.6 / SAM1-22 — unbounded resource amplification / missing input bounds (CWE-770 -> CWE-400).

A tool whose output/allocation scales with an attacker-controlled parameter that has NO bound. The
oracle is deterministic and bounded (never exhausts anything, no wall-clock). CONFIRMED needs THREE
independent signals:
  1. missing schema bound   — inputSchema declares no `maximum` on the resource-controlling param
  2. honored-above-cap      — the server actually returns output proportional to an above-cap request
                              (checks REAL behavior; a server with no schema max but a server-side cap
                              is correctly NOT flagged — no FP on defense-in-depth)
  3. amp scales             — output grows ~1:1 with the param (rules out constant-size tools)

Measured at tiny bounded values (<= a few hundred bytes). Pure request-RATE throttling is NOT
deterministically provable (needs timing) -> that is a LEAD, never CONFIRMED here.

HONEST EVIDENCE BASIS: a CONFIRMED means "unbounded amplification proven STRUCTURALLY (missing bound +
above-cap honored + output scales)" — NOT a live-triggered outage (we measured at a tiny bounded
value, never exhausted); reachability is deployment-dependent.
"""
from __future__ import annotations

from mcp_rt.mcp_client import StatelessHTTPClient, _result_text_2026

EVIDENCE_BASIS = ("unbounded resource amplification proven structurally (missing input bound + server "
                  "honors an above-cap request + output scales ~1:1 with the attacker-controlled "
                  "parameter); NOT a live-triggered outage, measured at a tiny bounded value, never "
                  "exhausted; reachability is deployment-dependent")

_UNIT = "AB"
_ABOVE_CAP = 256          # above any benign cap, yet tiny output (512 bytes) -> safe to measure
_C = 16                   # small in-policy sizes for the amplification-scaling check


def _expand(c: StatelessHTTPClient, count: int) -> str:
    return _result_text_2026(c.begin("tools/call", {"name": "expand", "arguments": {"unit": _UNIT, "count": count}}))


def _count_schema(tools: list) -> dict:
    for t in tools:
        props = (t.get("input_schema") or {}).get("properties") or {}
        if "count" in props and isinstance(props["count"], dict):
            return props["count"]
    return {}


def probe_resource_limit(url: str) -> dict:
    c = StatelessHTTPClient(url)
    schema_has_bound = "maximum" in _count_schema(c.list_tools())
    out_above = _expand(c, _ABOVE_CAP)
    honored_above_cap = len(out_above) == len(_UNIT) * _ABOVE_CAP         # REAL behavior, not just the schema
    o1, o2 = _expand(c, _C), _expand(c, 2 * _C)
    amp = (len(o2) / len(o1)) if o1 else 0.0                             # rules out constant-size tools
    confirmed = (not schema_has_bound) and honored_above_cap and amp >= 1.8
    return {"verdict": "CONFIRMED" if confirmed else "BOUNDED",
            "schema_has_bound": schema_has_bound, "honored_above_cap": honored_above_cap,
            "amp_ratio_2x": round(amp, 2),
            "evidence_basis": EVIDENCE_BASIS if confirmed else "output does not grow unboundedly; bounded"}


def probe_benign(url: str, count: int = 4) -> dict:
    out = _expand(StatelessHTTPClient(url), count)                       # small in-policy request
    return {"completes": len(out) == len(_UNIT) * count, "evidence": out[:40]}
