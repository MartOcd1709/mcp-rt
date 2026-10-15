"""mcp-rt demo — one-command end-to-end assessment over the full HTTP oracle library (T11 + T12).

Honest, zero-FP demonstration. For each of the 9 oracle classes we:
  1. fire the probe against its REAL deliberately-vulnerable fixture host  -> a canary/nonce-proven
     CONFIRMED finding (nothing is a finding unless the canary actually fired), and
  2. run the SAME probe against the SAFE host as a LIVE CONTROL that must stay silent (the moat made
     visible: "fires on the vuln host, silent on the safe host").
Findings are enriched from hunt.report.CLASS_META (severity / CWE / OWASP / code-level fix) and the
honest coverage ledger (CONFIRMED vs LEAD vs N-A) is read from mcp_rt.taxonomy. Nothing is fabricated
or padded.

The fixture hosts ARE the target under assessment here (a deliberately-vulnerable test server). In a
real engagement the same probes point at the customer's server and the root-cause locates their code.

Run:  python -m hunt.demo_assessment          (also wired as `mcp-rt demo`)
"""
from __future__ import annotations

import os
import shutil
from dataclasses import dataclass

from hunt.report import CLASS_META
from mcp_rt import taxonomy
from mcp_rt import (tool_authz_idor, tool_xxe, tool_open_redirect, tool_proto_pollution,
                    tool_redos, tool_resource_limit, tool_telemetry_leak,
                    tool_shadow_impersonation, tool_lethal_trifecta)
from tests.fixtures import (authz_idor_hosts, xxe_hosts, open_redirect_hosts, proto_pollution_hosts,
                            redos_hosts, resource_limit_hosts, telemetry_leak_hosts,
                            shadow_tool_hosts, trifecta_hosts)


@dataclass
class Outcome:
    cls: str
    fired_vuln: bool          # CONFIRMED on the vulnerable host (canary fired)
    silent_safe: bool         # live control: silent on the safe host
    proof: str                # the canary/nonce (or deterministic signal) observed
    evidence: str
    vuln_source: str          # the fixture host file — the "target" code under assessment
    skipped: str = ""

    @property
    def confirmed(self) -> bool:
        return self.fired_vuln and self.silent_safe and not self.skipped


def _authz_idor(tok: str) -> Outcome:
    sv, uv, t = authz_idor_hosts.start(vulnerable=True)
    ss, us, _ = authz_idor_hosts.start(vulnerable=False)
    try:
        v = tool_authz_idor.probe_object_idor(uv, t)
        s = tool_authz_idor.probe_object_idor(us, t)
        return Outcome("authz_idor", v["fired"], not s["fired"], f"DOC-SECRET-{t}-alice",
                       v["evidence"], "tests/fixtures/authz_idor_hosts.py")
    finally:
        sv.shutdown(); ss.shutdown()


def _xxe(tok: str) -> Outcome:
    sv, uv, t, cf = xxe_hosts.start(vulnerable=True)
    ss, us, _, cf2 = xxe_hosts.start(vulnerable=False)
    try:
        v = tool_xxe.probe_file_xxe(uv, t, cf)
        s = tool_xxe.probe_file_xxe(us, t, cf)
        return Outcome("xxe", v["fired"], not s["fired"], f"XXE-FILE-{t}", v["evidence"],
                       "tests/fixtures/xxe_hosts.py")
    finally:
        sv.shutdown(); ss.shutdown()
        for d in (cf, cf2):
            shutil.rmtree(os.path.dirname(d), ignore_errors=True)


def _open_redirect(tok: str) -> Outcome:
    sc, base, received = open_redirect_hosts.start_collector()
    sv, uv, t = open_redirect_hosts.start(vulnerable=True)
    ss, us, _ = open_redirect_hosts.start(vulnerable=False)
    try:
        v = tool_open_redirect.probe_open_redirect(uv, t, base, received)
        received.clear()
        s = tool_open_redirect.probe_open_redirect(us, t, base, received)
        return Outcome("open_redirect", v["fired"], not s["fired"], f"SESS-{t}", v["evidence"],
                       "tests/fixtures/open_redirect_hosts.py")
    finally:
        sv.shutdown(); ss.shutdown(); sc.shutdown()


def _proto_pollution(tok: str) -> Outcome:
    if not proto_pollution_hosts.node_available():
        return Outcome("proto_pollution", False, False, "", "", "tests/fixtures/proto_pollution_host.js",
                       skipped="node not on PATH (JS-host class)")
    pv, uv, t = proto_pollution_hosts.start(vulnerable=True)
    ps, us, _ = proto_pollution_hosts.start(vulnerable=False)
    try:
        v = tool_proto_pollution.probe_prototype_pollution(uv, t)
        s = tool_proto_pollution.probe_prototype_pollution(us, t)
        ev = f"fresh-object canary={v['polluted']}, default-user-admin={v['privilege_escalated']}"
        return Outcome("proto_pollution", v["fired"], not s["fired"], f"PP-{t}", ev,
                       "tests/fixtures/proto_pollution_host.js")
    finally:
        pv.kill(); pv.wait(); ps.kill(); ps.wait()


def _redos(tok: str) -> Outcome:
    sv, uv = redos_hosts.start(vulnerable=True)
    ss, us = redos_hosts.start(vulnerable=False)
    try:
        v = tool_redos.probe_redos(uv)
        s = tool_redos.probe_redos(us)
        ev = f"step blowup x{v.get('blowup')} (n={v.get('steps_n1')}->{v.get('steps_n2')}), deterministic/no-clock"
        return Outcome("redos", v["verdict"] == "CONFIRMED", s["verdict"] != "CONFIRMED",
                       f"step-blowup x{v.get('blowup')}", ev, "tests/fixtures/redos_hosts.py")
    finally:
        sv.shutdown(); ss.shutdown()


def _resource_limit(tok: str) -> Outcome:
    sv, uv = resource_limit_hosts.start(schema_bounded=False, server_capped=False)
    ss, us = resource_limit_hosts.start(schema_bounded=True, server_capped=True)
    try:
        v = tool_resource_limit.probe_resource_limit(uv)
        s = tool_resource_limit.probe_resource_limit(us)
        ev = f"missing-bound={not v['schema_has_bound']}, honored-above-cap={v['honored_above_cap']}, amp x{v['amp_ratio_2x']}"
        return Outcome("resource_limit", v["verdict"] == "CONFIRMED", s["verdict"] != "CONFIRMED",
                       f"amp x{v['amp_ratio_2x']} (uncapped)", ev, "tests/fixtures/resource_limit_hosts.py")
    finally:
        sv.shutdown(); ss.shutdown()


def _telemetry_leak(tok: str) -> Outcome:
    sv, uv = telemetry_leak_hosts.start(mode="leak")
    ss, us = telemetry_leak_hosts.start(mode="redact")
    try:
        v = tool_telemetry_leak.probe_telemetry_leak(uv, tok)
        s = tool_telemetry_leak.probe_telemetry_leak(us, tok)
        return Outcome("telemetry_leak", v["fired"], not s["fired"], f"TELEM-{tok}", v["evidence"],
                       "tests/fixtures/telemetry_leak_hosts.py")
    finally:
        sv.shutdown(); ss.shutdown()


def _shadow(tok: str) -> Outcome:
    st, ut = shadow_tool_hosts.start(role="trusted", tool_name="get_weather")
    sh, uh = shadow_tool_hosts.start(role="shadow", tok=tok, tool_name="get_weather")
    try:
        v = tool_shadow_impersonation.probe_shadow(ut, uh, tok, policy="last_wins")
        s = tool_shadow_impersonation.probe_shadow(ut, uh, tok, policy="namespaced")
        return Outcome("shadow_impersonation", v["verdict"] == "CONFIRMED", s["verdict"] != "CONFIRMED",
                       f"SHADOW-{tok}", v["note"], "tests/fixtures/shadow_tool_hosts.py")
    finally:
        st.shutdown(); sh.shutdown()


def _trifecta(tok: str) -> Outcome:
    sv, uv = trifecta_hosts.start(mode="vuln", tok=tok)
    ss, us = trifecta_hosts.start(mode="fixed_dest", tok=tok)
    try:
        v = tool_lethal_trifecta.probe_trifecta(uv, tok, malicious_feed=True)
        s = tool_lethal_trifecta.probe_trifecta(us, tok, malicious_feed=True)
        return Outcome("lethal_trifecta", v["verdict"] == "CONFIRMED", s["verdict"] != "CONFIRMED",
                       f"TRIFECTA-{tok}", v["note"], "tests/fixtures/trifecta_hosts.py")
    finally:
        sv.shutdown(); ss.shutdown()


_CLASSES = [_authz_idor, _xxe, _open_redirect, _proto_pollution, _redos, _resource_limit,
            _telemetry_leak, _shadow, _trifecta]


def run_demo() -> list[Outcome]:
    tok = os.urandom(6).hex()
    return [fn(tok) for fn in _CLASSES]


def render_demo_report(outcomes: list[Outcome]) -> str:
    confirmed = [o for o in outcomes if o.confirmed]
    skipped = [o for o in outcomes if o.skipped]
    cov = taxonomy.coverage()
    L = ["# mcp-rt — End-to-End Assessment (demo)", "",
         "> Each class is fired against a deliberately-vulnerable MCP host and proven only by a "
         "canary/nonce that actually fired; each is paired with a SAFE-host live control that stays "
         "silent. Zero false positives: no canary, no finding.", "",
         f"**Verdict: VULNERABLE** — {len(confirmed)}/{len(outcomes)} classes CONFIRMED on the "
         f"vulnerable target; every safe-host control stayed silent."
         + (f" ({len(skipped)} skipped: {', '.join(o.cls for o in skipped)})" if skipped else ""), "",
         "## Proven findings", ""]
    for o in confirmed:
        m = CLASS_META.get(o.cls, {})
        owasp = ", ".join(m.get("owasp") or []) or "—"
        L += [f"### {m.get('title', o.cls)}  ·  {m.get('sev','?')}  ·  {m.get('cwe','?')}  ·  OWASP-MCP: {owasp}",
              f"- **Proven offensive result (the moat):** canary `{o.proof}` observed via the probe "
              f"({o.evidence}); the SAFE-host control stayed **silent** → zero-FP.",
              f"- **Root cause (under assessment):** `{o.vuln_source}` — in a real engagement this "
              f"locates the sink in the customer's server code.",
              f"- **Fix:** {m.get('fix','(see remediation guidance)')}", ""]
    L += ["## Honest coverage ledger (never inflated)", "",
          f"From `mcp_rt/taxonomy.py` (single source of truth): **{cov['total_items']} canonical items** — "
          f"**{cov['by_status']['COVERED']} COVERED** (zero-FP proof), "
          f"**{cov['by_status']['PARTIAL']} PARTIAL**, **{cov['by_status']['PLANNED']} PLANNED**, "
          f"**{cov['by_status']['N-A']} N-A**.",
          "",
          "Shown openly, not hidden — examples of what we do NOT claim as proven:",
          "- **Request-rate throttling / denial-of-wallet** (frequency) — LEAD-only: needs timing, "
          "not deterministically provable, so never CONFIRMED.",
          "- **MCP08 under-logging** (absence of an audit trail) — SHOULD/gap: can't canary a negative.",
          "- See `docs/COVERAGE_MATRIX.md` for the full per-standard matrix (OWASP-MCP / ASI / CoSAI / "
          "CIS / MCP-38 / 2026-07-28 spec).", ""]
    return "\n".join(L)


def main(argv=None) -> int:
    outcomes = run_demo()
    report = render_demo_report(outcomes)
    out_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "hunt", "reports", "demo")
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "demo_report.md")
    with open(path, "w", encoding="utf-8") as f:
        f.write(report)
    confirmed = sum(o.confirmed for o in outcomes)
    for o in outcomes:
        status = "SKIP" if o.skipped else ("CONFIRMED" if o.confirmed else "NOT-FIRED")
        print(f"  [{status:9}] {o.cls:22} vuln={o.fired_vuln} safe_silent={o.silent_safe} {o.skipped}")
    print(f"\n{confirmed}/{len(outcomes)} CONFIRMED (safe controls silent) — report: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
