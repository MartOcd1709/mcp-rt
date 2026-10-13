"""Phase A — the Flow: a first-class, replayable MCP-assessment engagement.

A Flow drives the ground-truth engine end-to-end (`run_assessment`: discover → plan →
(prove → refine)* → correlate → report) and persists every step + the final oracle-confirmed
verdict, so an engagement can be replayed/audited and — in Phase B — watched live over SSE.
This is the backbone the flow API and UI bolt onto; it adds no new detection logic and keeps
the zero-FP guarantee intact (the oracle still decides every finding).
"""
from __future__ import annotations

import json

# Map an engine progress line to an honest (phase, role) so the trace reads like a real engagement.
_PHASE_HINTS = [
    ("discover", ("discover", "recon")),
    ("surface", ("discover", "recon")),
    ("generated", ("plan", "coordinator")),
    ("point", ("plan", "coordinator")),
    ("proving", ("prove", "validation")),
    ("proven", ("prove", "validation")),
    ("refiner", ("refine", "coordinator")),
    ("correlat", ("correlate", "coordinator")),
    ("persist", ("report", "coordinator")),
]


def _classify_step(msg: str) -> tuple[str, str, str]:
    m = msg.lower()
    for key, (phase, role) in _PHASE_HINTS:
        if key in m:
            kind = "verdict" if ("proven" in m or "chain" in m) else "progress"
            return phase, role, kind
    return "", "coordinator", "progress"


def run_flow(store, org_id: int, target: str, *, tier: str = "basic") -> int:
    """Create and run a flow to completion; return its id (CLI path)."""
    flow_id = store.create_flow(org_id, target, tier)
    run_flow_into(store, flow_id, target, tier=tier)
    return flow_id


def run_flow_into(store, flow_id: int, target: str, *, tier: str = "basic") -> None:
    """Run the engine into an EXISTING flow id. Split from run_flow so the web layer can create
    the flow, return its id immediately, then drive this in a background thread while an SSE
    endpoint tails the persisted trace. Persists the full step trace + final verdict. The engine
    is injected at call time (`mcp_rt.assessment.run_assessment`) so it stays testable."""
    from mcp_rt import assessment as _assessment

    store.set_flow_status(flow_id, "running")
    store.add_step(flow_id, f"flow started on {target} (tier={tier})", phase="discover", role="coordinator")

    def progress(msg: str) -> None:
        phase, role, kind = _classify_step(msg)
        store.add_step(flow_id, msg, phase=phase, role=role, kind=kind)

    try:
        a = _assessment.run_assessment(target, progress=progress)
    except Exception as exc:  # noqa: BLE001 — a failed engagement is a recorded outcome, not a crash
        store.add_step(flow_id, f"error: {type(exc).__name__}: {str(exc)[:200]}",
                       phase="report", role="coordinator", kind="verdict")
        store.finish_flow(flow_id, status="error", verdict="ERROR")
        return

    # Record each ground-truth-PROVEN finding as its own verdict step (the audit trail).
    for p in a.proven:
        store.add_step(flow_id,
                       f"PROVEN {p.get('vuln_class')} on {p.get('tool')}: {p.get('signal', '')}",
                       phase="prove", role="validation", kind="verdict")
    summary = {"findings": len(a.proven), "chains": len(a.chains), "rounds": a.rounds,
               "points_tested": a.points_tested, "tools": len(a.tools)}
    store.add_step(flow_id, a.note, phase="report", role="coordinator", kind="verdict")
    store.finish_flow(flow_id, status="done", verdict=a.verdict, summary=summary)


def render_flow(store, flow_id: int) -> str:
    """Human-readable replay of a flow (the CLI view; the UI consumes the same data in Phase B)."""
    f = store.get_flow(flow_id)
    if not f:
        return f"flow {flow_id} not found"
    lines = [f"Flow #{f['id']} · {f['target']} · tier={f['tier']} · "
             f"{f['status'].upper()} · verdict={f['verdict'] or '—'}"]
    for s in store.flow_steps(flow_id):
        tag = f"[{s['phase']}/{s['role']}]" if s["phase"] else "[·]"
        mark = "✓" if s["kind"] == "verdict" else " "
        lines.append(f"  {s['seq']:3} {mark} {tag:24} {s['text'][:100]}")
    try:
        summ = json.loads(f.get("summary") or "{}")
        if summ:
            lines.append(f"  summary: {summ}")
    except Exception:  # noqa: BLE001
        pass
    return "\n".join(lines)


def main(argv=None) -> int:
    import argparse

    from hunt.platform_db import Store

    p = argparse.ArgumentParser(prog="mcp-rt flow", description="Run and inspect assessment flows")
    sub = p.add_subparsers(dest="cmd")
    pr = sub.add_parser("run", help="run an end-to-end assessment flow on a target")
    pr.add_argument("--target-stdio", required=True, help="launch command for the MCP server")
    pr.add_argument("--tier", default="basic", choices=["basic", "advanced"])
    sub.add_parser("list", help="list recent flows")
    ps = sub.add_parser("show", help="replay a flow's step trace")
    ps.add_argument("flow_id", type=int)
    args = p.parse_args(argv)

    store = Store()
    org_id = store.org_for_token(store.ensure_default_org())  # dev: a default org/tenant
    if args.cmd == "run":
        fid = run_flow(store, org_id, args.target_stdio, tier=args.tier)
        print(render_flow(store, fid))
        return 0
    if args.cmd == "list":
        for f in store.list_flows(org_id):
            print(f"#{f['id']:<4} {f['status']:<8} {f['verdict']:<11} {f['target'][:60]}")
        return 0
    if args.cmd == "show":
        print(render_flow(store, args.flow_id))
        return 0
    p.print_help()
    return 1
