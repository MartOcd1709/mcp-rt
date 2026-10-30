"""The ledger keeps what the agent proved separate from what it only suspects, cleared, or could not resolve.

Honest buckets, straight from the observations' verdicts (which came from the honesty spine):
  proven       VULNERABLE, and reproduced (G8) — an oracle fired twice with fresh nonces
  leads        SUSPECTED — a static/signature/claim lead, never promoted to a finding
  cleared      CLEAN — an oracle ran and nothing fired (real response, not a refusal)
  inconclusive INCONCLUSIVE / NOT_APPLICABLE / a VULNERABLE that did not reproduce / untested objectives

INCONCLUSIVE is never folded into cleared. Absence of a finding is never a verdict.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from hunt.probes import verdict_for

_RANK = {"VULNERABLE": 4, "SUSPECTED": 3, "CLEAN": 2, "INCONCLUSIVE": 1, "NOT_APPLICABLE": 0}


@dataclass
class Finding:
    cls: str
    tool: str
    method: str
    verdict: str
    evidence: str
    reproduced: bool | None = None   # None = not a VULNERABLE / not yet re-run


@dataclass
class Ledger:
    objectives_total: int = 0
    actions_used: int = 0
    scope_violations: list = field(default_factory=list)
    stop_reason: str = ""
    integrity_note: str = ""
    _by_key: dict = field(default_factory=dict)   # (cls, tool) -> Finding (best verdict kept)

    def record(self, observations) -> bool:
        """Record an action's observations. Returns True if any was a NEW (class,tool) — i.e. progress."""
        progressed = False
        for o in observations:
            key = (o["class"], o["tool"])
            if key not in self._by_key:
                progressed = True
            cur = self._by_key.get(key)
            if cur is None or _RANK[o["verdict"]] > _RANK[cur.verdict]:
                self._by_key[key] = Finding(o["class"], o["tool"], o["method"], o["verdict"], o["evidence"])
        return progressed

    def mark_reproduction(self, cls, tool, reproduced: bool, evidence: str = "") -> None:
        f = self._by_key.get((cls, tool))
        if f and f.verdict == "VULNERABLE":
            f.reproduced = reproduced
            if not reproduced:
                f.evidence = (f.evidence + " | NOT reproduced on re-run: " + evidence)[:300]

    def stop(self, reason: str) -> None:
        if not self.stop_reason:
            self.stop_reason = reason

    def downgrade_unobservable(self, note: str) -> None:
        """Whole-session integrity broke: egress conclusions can no longer be trusted (ABORT_UNOBSERVABLE)."""
        self.integrity_note = note
        for f in self._by_key.values():
            if f.cls == "egress" and f.verdict in ("VULNERABLE", "CLEAN"):
                f.method = "sandbox_unobservable"
                f.verdict = verdict_for(f.method)       # single source: never a literal verdict string
                f.evidence = f"integrity broke after the fact: {note}"[:300]

    def _effective(self, f: Finding) -> tuple[str, str]:
        """The method and verdict to report. A VULNERABLE that did not reproduce is downgraded to the
        not_reproduced method; the verdict ALWAYS comes from verdict_for, never a literal (G2)."""
        if f.verdict == "VULNERABLE" and f.reproduced is False:
            return "not_reproduced", verdict_for("not_reproduced")
        return f.method, verdict_for(f.method)

    def report(self) -> dict:
        proven, leads, cleared, inconclusive = [], [], [], []
        for f in self._by_key.values():
            method, v = self._effective(f)
            row = {"class": f.cls, "tool": f.tool, "method": method, "evidence": f.evidence,
                   "reproduced": f.reproduced}
            if v == "VULNERABLE":
                proven.append(row)
            elif v == "SUSPECTED":
                leads.append(row)
            elif v == "CLEAN":
                cleared.append(row)
            else:
                inconclusive.append(row)
        tested = len(self._by_key)
        return {
            "stop_reason": self.stop_reason,
            "integrity_note": self.integrity_note,
            "coverage": {"objectives": self.objectives_total, "actions_used": self.actions_used,
                         "tested": tested, "flagged": len(proven), "leads": len(leads),
                         "cleared": len(cleared), "inconclusive": len(inconclusive),
                         "scope_violations": len(self.scope_violations)},
            "proven": proven, "leads": leads, "cleared": cleared, "inconclusive": inconclusive,
            "scope_violations": self.scope_violations,
        }
