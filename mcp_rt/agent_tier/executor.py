"""Execute one validated action inside the sealed session and return observations the judge can route.

run_probe(class, tool): call the floor probe for that class against that one tool. The floor owns the
payloads and the oracle; each ProbeResult already carries a confirmation_method (the honesty spine maps it).
run_egress(tool): exercise the tool with benign, token-bearing arguments (elicitation answered with the
token by the session), then classify this action's recorder events with mcp_rt.runtime.observe.

Nothing here asserts a verdict. An observation's verdict is whatever verdict_for(method) returns.
"""
from __future__ import annotations

import asyncio

from hunt.probes import (probe_arg_injection, probe_command_injection, probe_context_oversharing,
                         probe_deserialization, probe_lure_text, probe_path_traversal, probe_rug_pull,
                         probe_session_argument, probe_sql_injection, probe_ssrf, probe_ssti,
                         probe_tool_poisoning, probe_xxe, verdict_for)
from mcp_rt.runtime import observe
from mcp_rt.runtime.runner import _sample

# class name -> floor probe. "egress" is not here: it is the Unit-3 observation, handled by run_egress.
PROBE_BY_CLASS = {
    "ssrf": probe_ssrf, "command_injection": probe_command_injection, "path_traversal": probe_path_traversal,
    "sql_injection": probe_sql_injection, "ssti": probe_ssti, "deserialization": probe_deserialization,
    "context_oversharing": probe_context_oversharing, "arg_injection": probe_arg_injection,
    "tool_poisoning": probe_tool_poisoning, "lure_text": probe_lure_text,
    "session_argument": probe_session_argument, "rug_pull": probe_rug_pull, "xxe": probe_xxe,
}
PROBE_CLASSES = frozenset(PROBE_BY_CLASS)
ALL_CLASSES = PROBE_CLASSES | {"egress"}
# A floor oracle whose confirmation needs reach or setup the seal removes: probe_ssrf uses a host-side sink
# the sealed target cannot reach (its 127.0.0.1 is the sandbox loopback), and probe_context_oversharing needs
# scan_target's planted env canary. Under the seal these cannot CONFIRM and must never be reported CLEAN —
# they are INCONCLUSIVE (probe_seal_incompatible). Outbound reach is still covered by the egress class via the
# recorder. Adapting these to run under the seal is U2 (R6).
SEAL_INCOMPATIBLE = frozenset({"ssrf", "context_oversharing"})
# Partially seal-affected: the class CAN confirm under the seal (xxe's file-read oracle reads our planted
# nonce over the shared fs), but one dimension cannot — xxe's out-of-band arm fetches an attacker URL whose
# sink the seal makes unreachable, and run_egress (benign args) never triggers the external entity. So a
# NEGATIVE xxe under the seal cannot rule out out-of-band XXE and must be INCONCLUSIVE, never a silent CLEAN.
# (Proven: fixtures/xxe_oob is cleared by neither xxe nor egress as-is.) VULNERABLE/NOT_APPLICABLE stand.
SEAL_PARTIAL = frozenset({"xxe"})
CALL_TIMEOUT = 10.0
EGRESS_GRACE = 1.5


def _obs(cls, tool, method, evidence):
    return {"class": cls, "tool": tool, "method": method, "verdict": verdict_for(method), "evidence": evidence}


def _claim_text(tool) -> str:
    parts = [tool.name, tool.description or ""]
    for spec in ((tool.inputSchema or {}).get("properties") or {}).values():
        if isinstance(spec, dict):
            parts.append(spec.get("description") or "")
    return " \n ".join(parts)


async def execute(action, handle) -> list[dict]:
    """Run one Action. Returns observation dicts {class, tool, method, verdict, evidence}. A failure is an
    observation with method 'error' (INCONCLUSIVE), never a raised exception that aborts the run."""
    tools = await handle.list_tools()
    tool = next((t for t in tools if t.name == action.tool), None)
    if tool is None:
        return [_obs(action.cls or "egress", action.tool, "error", "tool vanished from the surface mid-run")]

    if action.kind == "run_probe":
        if action.cls in SEAL_INCOMPATIBLE:
            return [_obs(action.cls, action.tool, "probe_seal_incompatible",
                         "this class's floor oracle needs reach/setup the seal removes; "
                         "outbound reach is covered by run_egress (R6, U2 adapts the probe)")]
        probe = PROBE_BY_CLASS[action.cls]
        try:
            results = await probe(handle.session, [tool])
        except Exception as exc:  # noqa: BLE001 — a probe failure is INCONCLUSIVE, not a crash
            return [_obs(action.cls, action.tool, "error", f"probe raised: {type(exc).__name__}: {exc}"[:160])]
        if not results:
            return [_obs(action.cls, action.tool, "not_applicable", "probe found nothing to test on this tool")]
        obs = []
        for r in results:
            if action.cls in SEAL_PARTIAL and r.confirmation_method == "oracle_negative":
                obs.append(_obs(action.cls, r.tool, "sandbox_unobservable",
                                "no file-read XXE; the external-entity out-of-band fetch is unobservable "
                                "under the seal (sink unreachable) -> INCONCLUSIVE, not clean"))
            else:
                obs.append(_obs(action.cls, r.tool, r.confirmation_method, (r.evidence or r.rationale or "")[:200]))
        return obs

    # run_egress: exercise the tool with benign token-bearing args, then classify this action's events.
    handle.new_events()   # drain any prior window so we attribute only this action's egress
    args = {k: _sample(v, handle.token) for k, v in ((tool.inputSchema or {}).get("properties") or {}).items()}
    refused, call_text = [], ""
    try:
        res = await asyncio.wait_for(handle.session.call_tool(tool.name, args), CALL_TIMEOUT)
        call_text = " ".join(getattr(c, "text", "") or "" for c in (res.content or []))[:200]
        if bool(getattr(res, "isError", False)) or observe.REFUSAL.match(call_text):
            refused.append(tool.name)
    except Exception as exc:  # noqa: BLE001 — a failed call is still an observation
        return [_obs("egress", action.tool, "error", f"tool call raised: {type(exc).__name__}: {exc}"[:160])]
    await asyncio.sleep(EGRESS_GRACE)   # let the recorder flush this action's attempts
    events = handle.new_events()
    result = observe.classify_egress(events, handle.token, _claim_text(tool), refused_calls=refused)
    return [_obs("egress", action.tool, result["method"], result["evidence"])]
