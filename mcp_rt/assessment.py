"""Coordinated multi-agent assessment — the full professional loop, our ground-truth twist.

Models the coordination pattern of mature autonomous pentest systems (orchestrator → specialist →
result → refiner → reporter), but every finding is PROVEN by re-demonstration, not asserted:

    DISCOVER  → the target's live surface (tools/resources)
    GENERATE  → planner derives an exhaustive, surface-based test plan            [Generator role]
    PROVE     → the oracle fires every point and confirms by re-demonstration     [Pentester+oracle]
    REFINE    → re-plan from what was PROVEN (sweep proven classes wider)          [Refiner role]
      (PROVE/REFINE repeat until no new points or the round budget)
    CORRELATE → chain proven findings into demonstrated attack paths              [capability model]
    REPORT    → consolidated result, persisted to the CMDB under the target id    [Reporter+Memorist]

Deterministic coordination with a ground-truth gate on every step. A planner MODEL can enrich the
plan (creative points), but nothing is reported unless the server demonstrated it.
"""
from __future__ import annotations

from dataclasses import dataclass, field

_SEV = {"command_injection": "Critical", "code_injection": "Critical", "deserialization": "Critical",
        "path_traversal": "High", "ssrf": "High", "sql_injection": "High", "ssti": "High",
        "arg_injection": "Medium"}


def _emit(progress, msg: str) -> None:
    if progress:
        try:
            progress(msg)
        except Exception:  # noqa: BLE001
            pass


@dataclass
class Assessment:
    target: str
    tools: list = field(default_factory=list)
    proven: list = field(default_factory=list)       # oracle.Proof dicts (ground-truth confirmed)
    chains: list = field(default_factory=list)        # correlate.Chain dicts
    rounds: int = 0
    points_tested: int = 0
    verdict: str = "CLEAN"
    note: str = ""

    def as_dict(self) -> dict:
        return {"target": self.target, "verdict": self.verdict, "tools": self.tools,
                "proven": self.proven, "chains": self.chains, "rounds": self.rounds,
                "points_tested": self.points_tested, "note": self.note}


def run_assessment(target: str, *, model=None, client=None, save: bool = False, progress=None,
                   max_rounds: int = 3, max_points: int = 300) -> Assessment:
    """Run the coordinated DISCOVER→GENERATE→(PROVE→REFINE)*→CORRELATE→REPORT loop and return a
    consolidated, ground-truth Assessment."""
    from mcp_rt import correlate as _correlate
    from mcp_rt import oracle as _oracle
    from mcp_rt import planner as _planner
    if client is None:
        from mcp_rt.mcp_client import MCPClient
        client = MCPClient(target)

    _emit(progress, "discovering surface…")
    tools = client.list_tools()
    _emit(progress, f"surface: {len(tools)} tool(s)")

    plan = _planner.build_plan(target, {"tools": tools}, model=model)
    _emit(progress, f"generated {len(plan.points)} test point(s)")

    proven, tested, rnd = [], set(), 0
    for rnd in range(1, max_rounds + 1):
        todo = [p for p in plan.points
                if (p.target, p.vuln_class, p.param) not in tested][:max_points]
        if not todo:
            break
        _emit(progress, f"round {rnd}: proving {len(todo)} point(s)…")
        res = _oracle.confirm_plan(client, todo)
        for p in todo:
            tested.add((p.target, p.vuln_class, p.param))
        proven += res.confirmed
        _emit(progress, f"round {rnd}: +{len(res.confirmed)} PROVEN (total {len(proven)})")
        new_points = [p for p in _planner.refine(plan, res.confirmed, tools)
                      if (p.target, p.vuln_class, p.param) not in tested]
        if not new_points:
            break
        plan.points += new_points
        _emit(progress, f"refiner added {len(new_points)} follow-on point(s)")

    findings = [{"cls": p.vuln_class, "tool": p.tool, "evidence": p.evidence,
                 "detail": p.signal, "sev": _SEV.get(p.vuln_class, "Medium")} for p in proven]
    chains = _correlate.correlate(findings)
    _emit(progress, f"correlated {len(chains)} attack chain(s)")

    a = Assessment(target=target, tools=[t.get("name") for t in tools if isinstance(t, dict)],
                   proven=[p.as_dict() for p in proven], chains=[c.as_dict() for c in chains],
                   rounds=rnd, points_tested=len(tested),
                   verdict="VULNERABLE" if proven else "CLEAN",
                   note=f"{len(proven)} vulnerabilit(y/ies) PROVEN across {len(tested)} point(s) in "
                        f"{rnd} round(s); {len(chains)} chain(s)")
    if save:
        _persist(a, findings, chains, progress)
    return a


def _persist(a: Assessment, findings: list, chains: list, progress=None) -> None:
    """Write the proven assessment to the CMDB under the target's primary id (Memorist/Reporter)."""
    try:
        from hunt.orchestrator import Assessment as _OA
        from hunt.orchestrator import persist
        oa = _OA(target=a.target, verdict=a.verdict, findings=findings, chains=chains)
        ids = persist(oa, source="assessment")
        _emit(progress, f"persisted to CMDB (target #{ids.get('target_id')}, "
                        f"{ids.get('findings')} findings, {ids.get('chains')} chains)")
    except Exception as exc:  # noqa: BLE001 — never fail the assessment over persistence
        _emit(progress, f"[warn] persist skipped: {type(exc).__name__}: {str(exc)[:120]}")


def main(argv=None) -> int:
    import argparse
    import json
    import sys
    p = argparse.ArgumentParser(
        prog="mcp-rt pentest",
        description="Coordinated multi-agent assessment: discover -> plan -> prove -> refine -> "
                    "correlate -> report (every finding ground-truth-proven)")
    p.add_argument("--target-stdio", required=True, metavar="CMD", help="authorized target MCP server")
    p.add_argument("--save", action="store_true", help="persist proven findings + chains to the CMDB")
    p.add_argument("--rounds", type=int, default=3, help="max prove/refine rounds (default 3)")
    p.add_argument("--quiet", action="store_true", help="suppress live progress on stderr")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)

    prog = None if args.quiet else (lambda m: print(f"  ▸ {m}", file=sys.stderr, flush=True))
    model = None
    try:
        from mcp_rt.agent_loop import get_chat_model
        m = get_chat_model()
        model = m if m.name != "mock" else None          # only use a real planner model, not the mock
    except Exception:  # noqa: BLE001
        model = None
    try:
        a = run_assessment(args.target_stdio, model=model, save=args.save, progress=prog,
                           max_rounds=args.rounds)
    except Exception as exc:  # noqa: BLE001 — degrade honestly
        print(f"INCONCLUSIVE — could not assess target: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(a.as_dict(), indent=2, default=str))
        return 0
    print(f"verdict: {a.verdict}  ·  {a.note}")
    for pr in a.proven:
        print(f"  [PROVEN {pr['vuln_class']:16}] {pr['tool']:16} :: {pr['signal'][:70]}")
    for c in a.chains:
        print(f"  [CHAIN {c['severity']}] {c['kind']}: {c['narrative'][:80]}")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
