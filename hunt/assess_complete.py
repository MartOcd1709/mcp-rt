"""Complete assessment — the full-depth, AI-driven, MCP-00-covering engagement (the product's core).

A Flow's ADVANCED tier runs this. It orchestrates every engine layer end-to-end, each a visible
phase with an honest ran|skipped status (it NEVER over-claims a component that could not run), and
it holds the zero-FP line:

  * FINDINGS  = ground-truth: deterministic probes that fired + AI-agent claims re-demonstrated by
                the oracle. These decide the verdict.
  * LEADS     = observed-but-not-ground-truthed (MCP-CAP strace signals, unconfirmed agent leads).
                Reported SEPARATELY, never counted as findings, never inflating the verdict.

Layers:
  1. Direct ground-truth probes — 13 classes + supply-chain (MCP04) + context-oversharing (MCP10),
     plus the MCP06 intent-flow surface flag.                                   [deterministic]
  2. MCP-CAP — undeclared-capability / consent-gap hunt (the novel MCP-00 class, strace sensor).
  3. AI autonomous agent — the ReAct hunt driven by a real model, EVERY claim re-demonstrated by
     the oracle before it counts (this is the AI involvement; zero-FP preserved).
  4. Correlate confirmed findings into demonstrated attack chains.

The BASIC tier stays the fast deterministic coordinated loop (assessment.run_assessment); this is
why Advanced is deeper and takes longer — it actually drives the AI and the MCP-00 hunt.
"""
from __future__ import annotations

import os
import shlex


def ai_configured() -> bool:
    """True iff a real (non-mock) model backend is configured — same gate as agent_loop."""
    return bool(os.getenv("MCPRT_AI_PROVIDER") == "openai"
                and (os.getenv("MCPRT_AI_BASE_URL") or os.getenv("OPENAI_BASE_URL"))
                and (os.getenv("MCPRT_AI_API_KEY") or os.getenv("OPENAI_API_KEY")))


def _emit(progress, msg: str) -> None:
    if progress:
        try:
            progress(msg)
        except Exception:  # noqa: BLE001
            pass


def run_complete(target: str, *, progress=None, do_cap: bool = True, do_agent: bool = True) -> dict:
    """Run the full-depth assessment and return a unified result. Pure orchestration over existing,
    independently-tested layers — adds no detection logic and keeps the oracle as the only verdict."""
    import asyncio

    cmd = shlex.split(target)
    components: dict[str, str] = {}
    findings: list[dict] = []     # ground-truth (decide the verdict)
    leads: list[dict] = []        # observed, not yet ground-truthed (never counted as findings)
    seen: set = set()

    def add_finding(cls, tool, detail, sev="Medium", source="probe"):
        key = (cls, tool)
        if key in seen:
            return
        seen.add(key)
        findings.append({"cls": cls, "tool": tool, "detail": detail, "sev": sev, "source": source})

    # ---- 1. direct ground-truth probes ------------------------------------------------------
    _emit(progress, "phase 1/4 · direct ground-truth probes (13 classes + supply-chain + context-oversharing)…")
    try:
        from hunt.report import run_full_scan
        rep = asyncio.run(run_full_scan(cmd))
        for f in rep.get("findings", []):
            add_finding(f.get("cls", ""), f.get("tool", ""),
                        f.get("detail") or f.get("evidence", ""), f.get("sev", "Medium"), "probe")
        components["direct_probe"] = f"ran ({len(rep.get('findings', []))} finding(s))"
        mcp06 = rep.get("mcp06", {}) or {}
        if mcp06.get("exposed"):
            _emit(progress, "  MCP06 intent-flow surface exposed: "
                  + ", ".join(mcp06.get("reasons", []))[:120]
                  + " (enabling condition — not a finding)")
    except Exception as e:  # noqa: BLE001 — a server that won't start is recorded, not fatal
        components["direct_probe"] = f"skipped: {type(e).__name__}: {str(e)[:80]}"
        _emit(progress, f"  direct probes could not run: {str(e)[:100]}")

    # ---- 2. MCP-CAP — undeclared-capability hunt (novel MCP-00 class) ------------------------
    if do_cap:
        _emit(progress, "phase 2/4 · MCP-CAP — undeclared-capability hunt (MCP-00, strace sensor)…")
        try:
            from hunt.hunt_cap import run_cap_hunt, strace_available
            if strace_available():
                status, hyps = run_cap_hunt(cmd)
                for h in hyps:
                    leads.append({"kind": "MCP-CAP", "tool": getattr(h, "tool", ""),
                                  "observation": getattr(h, "observation", "")})
                components["mcp_cap"] = f"ran ({status}, {len(hyps)} lead(s))"
                _emit(progress, f"  MCP-CAP: {status}, {len(hyps)} undeclared-capability lead(s)")
            else:
                components["mcp_cap"] = "skipped: strace not installed"
                _emit(progress, "  MCP-CAP skipped: strace not installed (install strace to enable)")
        except Exception as e:  # noqa: BLE001
            components["mcp_cap"] = f"skipped: {type(e).__name__}: {str(e)[:80]}"
    else:
        components["mcp_cap"] = "not requested"

    # ---- 3. AI autonomous agent (ReAct) + ground-truth oracle confirmation -------------------
    if do_agent and ai_configured():
        _emit(progress, "phase 3/4 · AI autonomous agent (ReAct) hunting; every claim re-demonstrated by the oracle…")
        try:
            from mcp_rt import oracle
            from mcp_rt.agent_loop import run_agent
            from mcp_rt.mcp_client import MCPClient
            client = MCPClient(target)
            res = run_agent(target, progress=lambda m: _emit(progress, f"  agent: {m}"), mcp_client=client)
            orc = oracle.confirm_claims(client, res.agent_claimed)
            for p in orc.confirmed:
                add_finding(p.vuln_class, p.tool, p.signal, "High", "ai-agent")
            components["ai_agent"] = f"ran ({len(orc.confirmed)}/{len(res.agent_claimed)} claims confirmed)"
            _emit(progress, f"  agent: {len(res.agent_claimed)} claim(s), {len(orc.confirmed)} oracle-confirmed")
        except Exception as e:  # noqa: BLE001
            components["ai_agent"] = f"error: {type(e).__name__}: {str(e)[:80]}"
            _emit(progress, f"  agent error: {str(e)[:100]}")
    elif do_agent:
        components["ai_agent"] = "skipped: no model configured (set MCPRT_AI_PROVIDER/BASE_URL/API_KEY)"
        _emit(progress, "phase 3/4 · AI agent SKIPPED — no model configured (set MCPRT_AI_* to enable the AI hunt)")
    else:
        components["ai_agent"] = "not requested"

    # ---- T7: explain-the-exploit chain — ADDITIVE root-cause per CONFIRMED finding -----------
    # Never changes a verdict; the oracle stays the only source of truth. Findings here are all
    # ground-truth (leads live separately), so the confirmed-only rule holds.
    try:
        from mcp_rt.oracle import Proof
        from hunt.sink_locator import explain_chain, source_path_from_target
        src = source_path_from_target(target)
        for f in findings:
            chain = explain_chain(Proof(tool=f["tool"], vuln_class=f["cls"], confirmed=True,
                                        signal=f.get("detail", "")), source_path=src)
            if chain:
                f["root_cause"] = chain
    except Exception:  # noqa: BLE001 — enrichment is additive; its failure must never affect the verdict
        pass

    # ---- 4. correlate confirmed findings into attack chains ----------------------------------
    _emit(progress, "phase 4/4 · correlating confirmed findings into demonstrated attack chains…")
    try:
        from mcp_rt.correlate import correlate
        chains = [c.as_dict() for c in correlate(findings)]
    except Exception:  # noqa: BLE001
        chains = []

    ran_any = any(v.startswith("ran") for v in components.values())
    verdict = "VULNERABLE" if findings else ("CLEAN" if ran_any else "INCONCLUSIVE")
    note = (f"{len(findings)} ground-truth finding(s), {len(leads)} lead(s) (MCP-00/strace — need "
            f"confirmation), {len(chains)} chain(s) · "
            + " · ".join(f"{k}:{v}" for k, v in components.items()))
    _emit(progress, note)
    return {"target": target, "verdict": verdict, "findings": findings, "leads": leads,
            "chains": chains, "components": components, "note": note}
