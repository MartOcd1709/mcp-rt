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


def run_complete(target: str, *, progress=None, do_cap: bool = True, do_agent: bool = True,
                 env_keys: tuple = ()) -> dict:
    """Run the full-depth assessment and return a unified result. Pure orchestration over existing,
    independently-tested layers — adds no detection logic and keeps the oracle as the only verdict."""
    import asyncio

    cmd = shlex.split(target)
    components: dict[str, str] = {}
    findings: list[dict] = []     # ground-truth (decide the verdict)
    leads: list[dict] = []        # observed, not yet ground-truthed (never counted as findings)
    seen: set = set()
    surface: dict = {}            # tool manifest (with per-tool digests): drift detection across assessments
    phase1: dict = {}             # the direct-probe report: OWASP scorecard, tool-by-tool coverage, supply chain
    canary: dict | None = None    # the sealed canary run as evidence: planted, actions, egress, file access, verdict
    canary_cov: list[dict] = []   # what the canary run tested, per (tool, class)

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
        surface = rep.get("surface") or {}
        phase1 = rep
        for f in rep.get("findings", []):
            add_finding(f.get("cls", ""), f.get("tool", ""),
                        f.get("detail") or f.get("evidence", ""), f.get("sev", "Medium"), "probe")
        for sl in rep.get("suspected", []):   # static leads (tool poisoning, lure text, ...): never dropped
            leads.append({"kind": sl.get("cls", ""), "tool": sl.get("tool", ""),
                          "observation": " — ".join(x for x in (sl.get("evidence"), sl.get("detail")) if x)})
        components["direct_probe"] = (f"ran ({len(rep.get('findings', []))} finding(s), "
                                      f"{len(rep.get('suspected', []))} static lead(s))")
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

    # ---- 2b. MCP-00 PROOF: one sealed canary run (planted credentials, elicitation + sampling honeypots) -------
    if do_cap:
        _emit(progress, "phase 2b · MCP-00 canary proof: deep sealed run (planted credentials in HOME, project and "
                        "environment; every tool, variant, resource and prompt; mid-session re-list; watch window)…")
        try:
            from hunt.mcp00_proof import coverage_of, from_sealed
            from mcp_rt.runtime.runner import run_server
            rec = run_server(cmd, timeout=float(os.environ.get("MCPRT_SEALED_TIMEOUT_S", "90")), declared_env=env_keys)
            proof = from_sealed(rec)
            canary_cov = coverage_of(rec, proof)
            canary = canary_record(rec, proof["status"])
            for f in proof["findings"]:
                add_finding(f["cls"], f["tool"], f["detail"], f["sev"], f["source"])
            leads.extend(proof["leads"])
            components["mcp00_proof"] = proof["status"]
            _emit(progress, f"  MCP-00 proof: {proof['status']}")
            for f in proof["findings"]:
                _emit(progress, f"  PROVEN · {f['detail'][:160]}")
        except Exception as e:  # noqa: BLE001 — a seal that cannot run is INCONCLUSIVE, never a silent CLEAN
            components["mcp00_proof"] = f"inconclusive: {type(e).__name__}: {str(e)[:80]}"
            _emit(progress, f"  MCP-00 proof could not run: {str(e)[:100]}")

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
            "chains": chains, "components": components, "note": note, "surface": surface,
            "compliance": merge_compliance(phase1.get("compliance") or [], findings, leads,
                                           components.get("mcp00_proof", "")),
            "coverage": (phase1.get("coverage") or []) + canary_cov, "mcp06": phase1.get("mcp06") or {},
            "canary": canary,
            "supply_posture": phase1.get("supply_posture")}


def canary_record(rec: dict, status: str, max_events: int = 100) -> dict:
    """The sealed canary run as a durable evidence record (what was planted, every action, every egress attempt with
    its sha256 and captured bytes, every planted-secret open, every tamper write), bounded in size."""
    keep_a = ("i", "kind", "name", "round", "args", "t0", "t1", "ok", "note")
    return {
        "token": rec.get("token"), "sealed": rec.get("sealed"), "server_started": rec.get("server_started"),
        "status": status, "method": rec.get("method"), "evidence": rec.get("evidence"), "proof": rec.get("proof"),
        "duration_s": rec.get("duration_s"), "watch_s": rec.get("watch_s"), "not_reached": rec.get("not_reached"),
        "planted": [{k: x.get(k) for k in ("label", "kind", "where", "description")} for x in rec.get("planted") or []],
        "actions": [{k: a.get(k) for k in keep_a} for a in rec.get("actions") or []],
        "egress": (rec.get("egress") or [])[:max_events], "egress_total": len(rec.get("egress") or []),
        "file_access": rec.get("file_access") or [], "tamper": rec.get("tamper") or [],
        "redefinitions": rec.get("redefinitions") or [], "list_changed": rec.get("list_changed"),
        "samplings": rec.get("samplings") or [], "elicitations": rec.get("elicitation_log") or [],
        "limits": rec.get("limits") or [], "config_env": rec.get("config_env") or [],
    }


def merge_compliance(compliance: list[dict], findings: list[dict], leads: list[dict], canary_status: str = "") -> list[dict]:
    """The OWASP MCP Top 10 scorecard for the WHOLE engagement. Phase 1 scores it from the direct probes; the later
    phases add evidence: a proven finding (any phase) fails its controls, a lead marks them SUSPECTED (never over a
    FAIL), and a sealed run whose seal was proven tested MCP02 (no planted secret left during real tool calls).
    Everything else stays NOT TESTED; nothing is assumed to pass. Phase 1 missing -> all ten start NOT TESTED."""
    from hunt.report import CLASS_META, OWASP_MCP_TOP10

    if not compliance:
        compliance = [{"id": k, "title": v, "status": "NOT TESTED"} for k, v in OWASP_MCP_TOP10.items()]
    status = {c["id"]: c["status"] for c in compliance}

    def controls(cls: str) -> list[str]:
        return [c for c in CLASS_META.get(cls, {}).get("owasp", []) if c in status]

    for f in findings:
        for c in controls(f.get("cls", "")):
            status[c] = "FAIL"
    for lead in leads:
        for c in controls(lead.get("kind", "")):
            if status[c] != "FAIL":
                status[c] = "SUSPECTED"
    if "seal proven" in canary_status:
        for c in controls("mcp_cap"):
            if status[c] == "NOT TESTED":
                status[c] = "PASS"
    return [{**c, "status": status[c["id"]]} for c in compliance]
