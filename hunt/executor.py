"""Executor — validate AI-proposed probes against GROUND TRUTH, in the sandbox.

Closes the autonomous loop: the model *proposes* where to look (adaptive_probe); the ground-truth
engine *decides* whether it's real. A proposed probe becomes a confirmed finding ONLY if the
ground-truth scan proves that technique on the target (canary/sentinel fired) — never because the
model "thinks so". This keeps the zero-false-positive guarantee even with an AI in the loop.

Honesty about scope:
  * Direct-confirmable techniques (injection / traversal / SSRF / … — the classes a running scan
    proves with a canary) are validated here against the sandboxed ground-truth scan.
  * Agent-behavioral techniques (tool poisoning, prompt/return-value injection, sampling, …) cannot
    be confirmed by direct probing — they need a real agent in the loop — so they are DEFERRED to
    the agent red-team tier, never silently dropped or falsely confirmed.

Runs only through the hardened sandbox backend (hunt.sandbox) — we are executing against an
untrusted server. Active per-technique probing with the model's own crafted inputs is the next
depth step (v2); v1 validates the model's targeting against the ground-truth engine.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# Techniques a running direct-probe scan can confirm with a ground-truth oracle (canary/sentinel).
DIRECT_CONFIRMABLE = {
    "command_injection", "path_traversal", "ssrf", "sql_injection", "deserialization",
    "ssti", "arg_injection", "supply_chain", "dns_rebinding",
}


@dataclass
class ExecResult:
    confirmed: list = field(default_factory=list)     # {candidate, finding} — ground-truth proven
    unconfirmed: list = field(default_factory=list)   # predicted but the scan did not prove it
    deferred: list = field(default_factory=list)      # agent-behavioral -> needs the agent red-team
    note: str = ""

    def as_dict(self) -> dict:
        return {"confirmed": self.confirmed,
                "unconfirmed": [c.as_dict() for c in self.unconfirmed],
                "deferred": [c.as_dict() for c in self.deferred],
                "note": self.note}


def validate(candidates: list, findings: list) -> ExecResult:
    """Pure: match proposed candidates to CONFIRMED ground-truth findings.

    A candidate is confirmed iff its technique is direct-confirmable AND the ground-truth scan
    produced a finding of that class (preferring a match on the same tool). Agent-behavioral
    techniques are deferred; direct techniques with no proving finding are unconfirmed.
    """
    res = ExecResult()
    for c in candidates:
        tech = getattr(c, "technique", "")
        if tech not in DIRECT_CONFIRMABLE:
            res.deferred.append(c)
            continue
        proving = next((f for f in findings
                        if (f.get("cls") == tech and f.get("tool", "") == c.target_tool)), None) \
            or next((f for f in findings if f.get("cls") == tech), None)
        if proving:
            res.confirmed.append({"candidate": c.as_dict(), "finding": proving})
        else:
            res.unconfirmed.append(c)
    res.note = (f"{len(res.confirmed)} confirmed ground-truth, {len(res.unconfirmed)} unconfirmed, "
                f"{len(res.deferred)} deferred to agent red-team")
    return res


def confirm_claims(claims: list, findings: list) -> dict:
    """Confirm an agent's CLAIMED findings against ground-truth findings.

    The autonomous agent *claims* vulnerabilities as it reasons; a claim becomes real ONLY if the
    ground-truth scan independently proves a finding of that class. The agent's say-so is never a
    verdict (preserves zero-FP even for a free-roaming agent)."""
    proven = {f.get("cls") for f in findings}
    confirmed, unconfirmed = [], []
    for c in claims:
        cls = c.get("class") or c.get("cls") or ""
        (confirmed if cls in proven else unconfirmed).append(c)
    return {"confirmed": confirmed, "unconfirmed": unconfirmed,
            "note": f"{len(confirmed)}/{len(claims)} agent claim(s) confirmed by ground truth"}


def execute(target: str, candidates: list, *, backend: str = "auto", scan_fn=None) -> ExecResult:
    """Run the ground-truth scan in the sandbox, then validate the candidates against it.

    `scan_fn(target, backend) -> report dict` is injectable (tests / reuse a prior scan); the
    default runs the hardened sandboxed scan (hunt.sandbox.run_isolated) — mandatory isolation since
    we execute against an untrusted server.
    """
    if scan_fn is None:
        from hunt.sandbox import run_isolated
        report = run_isolated(target, backend=backend)
    else:
        report = scan_fn(target, backend)
    return validate(candidates, report.get("findings", []) or [])
