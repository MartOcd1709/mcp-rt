"""Assessment orchestrator — the autonomous MCP security lifecycle in one pass.

Sequences the full engagement over a target MCP server and returns one consolidated assessment:

    RECON + SCAN/VA  →  (adaptive probes)  →  CORRELATE  →  REMEDIATE

  1. Scan / VA  — run the ground-truth detection suite (hunt.report.run_full_scan): the 13 classes
     + supply chain + OWASP crosswalk → confirmed findings (each already proof, zero-FP).
  2. Adaptive  — optionally propose extra detection probes tailored to the target's own tools
     (mcp_rt.adaptive_probe). PROPOSAL ONLY here; a candidate becomes a finding only after the
     sandboxed executor validates it with a canary (wired by the platform's docker backend).
  3. Correlate — chain the confirmed findings into proven multi-step attack paths
     (mcp_rt.correlate) — the real-world impact, reported above point findings.
  4. Remediate — a prioritized fix plan: per-finding guidance + per-chain "break any link".

Guardrails: authorized/local targets only (remote is consent-gated upstream); the adaptive step runs
only in the hardened sandbox. Output is a vulnerability assessment for responsible disclosure.
"""
from __future__ import annotations

import asyncio
import shlex
from dataclasses import dataclass, field

from mcp_rt import correlate as _correlate
from mcp_rt.adaptive_probe import generate_candidates


@dataclass
class Assessment:
    target: str
    verdict: str
    findings: list = field(default_factory=list)
    chains: list = field(default_factory=list)          # correlate.Chain
    candidates: list = field(default_factory=list)      # adaptive_probe.ProbeCandidate (proposed)
    remediation: list = field(default_factory=list)
    surface: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "target": self.target,
            "verdict": self.verdict,
            "findings": self.findings,
            "chains": [c.as_dict() for c in self.chains],
            "proposed_probes": [c.as_dict() for c in self.candidates],
            "remediation": self.remediation,
            "surface": {"tools": [t.get("name") if isinstance(t, dict) else t
                                  for t in (self.surface.get("tools") or [])]},
        }


def _remediation_plan(findings: list, chains: list) -> list:
    """Prioritized fixes: chains first (break any link), then findings by severity."""
    plan = []
    for c in chains:          # chains are the top priority — they are demonstrated compromise
        plan.append({"priority": "P0", "target": "chain", "kind": c.kind, "severity": c.severity,
                     "action": f"Break any single link in this path to stop it: {c.narrative}. "
                               f"Fixing any one step below neutralizes the chain."})
    sev_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    for f in sorted(findings, key=lambda x: sev_rank.get(x.get("sev", ""), 9)):
        plan.append({"priority": "P1" if f.get("sev") in ("Critical", "High") else "P2",
                     "target": "finding", "cls": f.get("cls"), "tool": f.get("tool", ""),
                     "severity": f.get("sev", ""),
                     "action": f.get("fix") or "Apply least-privilege + input validation for this class."})
    return plan


def assess(target: str, *, base_report: dict | None = None, adaptive: bool = False,
           model=None) -> Assessment:
    """Run the full lifecycle for `target` and return a consolidated Assessment.

    `base_report` (a run_full_scan dict) can be injected (tests / reuse a prior scan); otherwise it
    is produced here. `adaptive=True` proposes tailored probes (validated downstream in the sandbox).
    """
    if base_report is None:
        from hunt.report import run_full_scan
        base_report = asyncio.run(run_full_scan(shlex.split(target)))

    findings = base_report.get("findings", []) or []
    surface = base_report.get("surface", {}) or {}
    chains = _correlate.correlate(findings)

    candidates = []
    if adaptive:
        tools = [t.get("name") if isinstance(t, dict) else t for t in (surface.get("tools") or [])]
        candidates = generate_candidates([t for t in tools if t], model=model)

    # A proven chain is demonstrated compromise -> the assessment verdict is VULNERABLE.
    verdict = "VULNERABLE" if (chains or base_report.get("verdict") == "VULNERABLE") else \
        base_report.get("verdict", "CLEAN")

    return Assessment(target=target, verdict=verdict, findings=findings, chains=chains,
                      candidates=candidates, remediation=_remediation_plan(findings, chains),
                      surface=surface)


def main(argv=None) -> int:
    import argparse
    import json
    import sys
    p = argparse.ArgumentParser(prog="mcp-rt assess",
                                description="Full MCP security lifecycle: scan/VA -> correlate -> remediate")
    p.add_argument("--target-stdio", required=True, metavar="CMD",
                   help='authorized local server, e.g. "npx -y some-mcp-server"')
    p.add_argument("--adaptive", action="store_true",
                   help="also propose adaptive probes tailored to the target (validated in the sandbox)")
    p.add_argument("--json", action="store_true", help="emit the full assessment as JSON")
    args = p.parse_args(argv)
    try:
        a = assess(args.target_stdio, adaptive=args.adaptive)
    except Exception as e:  # noqa: BLE001 — degrade honestly rather than dump a traceback
        print(f"INCONCLUSIVE — could not assess target: {e}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(a.as_dict(), indent=2, default=str))
        return 0
    print(f"verdict: {a.verdict}")
    print(f"findings: {len(a.findings)}  ·  chains: {len(a.chains)}  ·  proposed probes: {len(a.candidates)}")
    for c in a.chains:
        print(f"  [CHAIN {c.severity}] {c.kind}: {c.narrative}")
    if a.remediation:
        print("remediation (top):")
        for r in a.remediation[:10]:
            print(f"  [{r['priority']}] {r.get('kind') or r.get('cls')}: {r['action'][:90]}")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
