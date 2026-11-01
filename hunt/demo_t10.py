"""T10 — 2026-07-28 spec-surface classes for `mcp-rt demo` — OFFLINE, additive to the floor.

The 7 stateless-spec classes, each via its existing probe + vuln/safe host-pair: CONFIRMED only when a
real per-run canary fires on the VULNERABLE host and the safe/control stays silent. mcp_apps_ui's
markup-injection is CONFIRMED; its clickjacking / UI-redress / permissive-CSP / over-broad-permission
sub-vectors are structural LEADs (confirmed=False) shown honestly as leads and NEVER promoted.

Offline/deterministic: loopback-only (httpx client + stdlib http.server fixtures), no model/keys/egress.
Each fixture mints its own per-run token inside start(); we use THAT returned token, never a global one.
"""
from __future__ import annotations

from dataclasses import dataclass

from mcp_rt import (cachescope, downgrade, mcp_apps_ui, mcp_name_differential, meta_spoof,
                    task_idor, url_elicitation)
from tests.fixtures import (cachescope_hosts, downgrade_hosts, mcp_apps_hosts,
                            mcp_name_differential_hosts, meta_spoof_hosts, task_idor_hosts,
                            url_elicit_hosts)


# Report enrichment kept LOCAL (not in hunt/report.py CLASS_META): the T10 taxonomy rows use
# module-path our_class values, so bare-name CLASS_META keys would trip the CLASS_META<->taxonomy
# selfcheck guard. This dict gives the T10 section full sev/CWE/OWASP/fix enrichment with zero touch
# to CLASS_META or the taxonomy. Keys = the T10Outcome.cls below.
T10_META = {
    "cachescope": dict(sev="High", cwe="CWE-524", owasp=["MCP02", "MCP10"],
        title="cacheScope Cross-Tenant Cache Poisoning (T10.1)",
        fix="Honor cacheScope=private for per-principal results; key the cache by principal (not just the "
            "request); never serve one tenant's cached result to another."),
    "task_idor": dict(sev="High", cwe="CWE-639", owasp=["MCP02", "MCP07"],
        title="Tasks Handle IDOR / Result-After-Revoke / Update-Injection (T10.2)",
        fix="Bind every task handle to its owner and re-check ownership on get/result/update; reject "
            "results after revoke; validate inputResponses against the original request."),
    "meta_spoof": dict(sev="High", cwe="CWE-290", owasp=["MCP07", "MCP01"],
        title="_meta Self-Reported Identity / Capability Spoof (T10.3)",
        fix="Never authorize on _meta clientInfo/clientCapabilities (self-reported, unverified); decide on "
            "the real authenticated identity (token); treat _meta as hints, not credentials."),
    "mcp_name_differential": dict(sev="High", cwe="CWE-436", owasp=["MCP05", "MCP07"],
        title="Mcp-Name Header/Body Method Differential (T10.4)",
        fix="Require Mcp-Method/Mcp-Name headers to equal the body method/name (reject -32020 on mismatch); "
            "authorize on the SAME value you execute — never header-for-authz, body-for-exec."),
    "downgrade": dict(sev="High", cwe="CWE-757", owasp=["MCP07"],
        title="Forced Protocol Downgrade / Control Bypass (T10.5)",
        fix="Reject deprecated/legacy protocol versions that bypass modern controls; enforce the same guard "
            "on every supported version; don't let a client force a weaker path."),
    "url_elicitation": dict(sev="High", cwe="CWE-601", owasp=["MCP06", "MCP01"],
        title="URL-Mode Elicitation Phishing / Open-Redirect (T10.6)",
        fix="Elicitation URLs must be same-origin and opaque; never embed a pre-authenticated token/cred in "
            "the URL; do not follow off-origin redirects for credential delivery."),
    "mcp_apps_ui": dict(sev="High", cwe="CWE-79", owasp=["MCP06"],
        title="MCP Apps UI Markup Injection (T10.7)",
        fix="Escape/sanitize all tool-supplied content before rendering in the UI surface; enforce a strict "
            "CSP; sandbox the iframe; treat MCP-Apps content as untrusted."),
}


@dataclass
class T10Outcome:
    cls: str
    kind: str                 # "CONFIRMED" | "LEAD"
    fired_vuln: bool
    silent_safe: bool
    proof: str
    evidence: str
    source: str
    skipped: str = ""

    @property
    def confirmed(self) -> bool:
        return self.kind == "CONFIRMED" and self.fired_vuln and self.silent_safe and not self.skipped


def _cachescope() -> T10Outcome:
    sv, uv, tv, _ = cachescope_hosts.start(vulnerable=True)
    ss, us, ts, _ = cachescope_hosts.start(vulnerable=False)
    try:
        vl, vp = cachescope.probe_leak(uv, tv), cachescope.probe_poison(uv, tv)
        sl, sp = cachescope.probe_leak(us, ts), cachescope.probe_poison(us, ts)
        return T10Outcome("cachescope", "CONFIRMED", vl["fired"] or vp["fired"],
                          not (sl["fired"] or sp["fired"]),
                          f"cross-tenant cacheScope leak+poison (SECRET-{tv} / POISON-{tv})",
                          f"vuln: leak={vl['fired']} poison={vp['fired']} | safe: private cache, silent",
                          "mcp_rt/cachescope.py")
    finally:
        sv.shutdown(); ss.shutdown()


def _task_idor() -> T10Outcome:
    sv, uv, tv, rv, _ = task_idor_hosts.start(vulnerable=True)
    ss, us, ts, rs, _ = task_idor_hosts.start(vulnerable=False)
    try:
        v = [task_idor.probe_get_idor(uv, tv)["fired"], task_idor.probe_result_after_revoke(uv, tv, rv)["fired"],
             task_idor.probe_update_injection(uv, tv)["fired"]]
        s = [task_idor.probe_get_idor(us, ts)["fired"], task_idor.probe_result_after_revoke(us, ts, rs)["fired"],
             task_idor.probe_update_injection(us, ts)["fired"]]
        return T10Outcome("task_idor", "CONFIRMED", any(v), not any(s),
                          f"Tasks handle IDOR / result-after-revoke / update-injection (CANARY-{tv})",
                          f"vuln: [get-idor,revoke,update]={v} | safe: owner-binds + re-checks, silent",
                          "mcp_rt/task_idor.py")
    finally:
        sv.shutdown(); ss.shutdown()


def _meta_spoof() -> T10Outcome:
    sv, uv, tv, _ = meta_spoof_hosts.start(vulnerable=True)
    ss, us, ts, _ = meta_spoof_hosts.start(vulnerable=False)
    try:
        v = [meta_spoof.probe_clientinfo_spoof(uv, tv)["fired"], meta_spoof.probe_caps_spoof(uv, tv)["fired"]]
        s = [meta_spoof.probe_clientinfo_spoof(us, ts)["fired"], meta_spoof.probe_caps_spoof(us, ts)["fired"]]
        return T10Outcome("meta_spoof", "CONFIRMED", any(v), not any(s),
                          f"_meta self-reported clientInfo/caps spoof grants admin (ADMIN-SECRET-{tv})",
                          f"vuln: [clientinfo,caps]={v} | safe: decides on real auth, silent",
                          "mcp_rt/meta_spoof.py")
    finally:
        sv.shutdown(); ss.shutdown()


def _mcp_name() -> T10Outcome:
    sv, uv, tv, _ = mcp_name_differential_hosts.start(vulnerable=True)
    ss, us, ts, _ = mcp_name_differential_hosts.start(vulnerable=False)
    try:
        v = mcp_name_differential.probe_smuggle(uv, tv)
        denied = mcp_name_differential.probe_honest_admin_denied(uv, tv)   # same-host control: honest admin IS gated
        s = mcp_name_differential.probe_smuggle(us, ts)
        return T10Outcome("mcp_name_differential", "CONFIRMED", v["fired"], not s["fired"],
                          f"Mcp-Name header/body method differential smuggles exec (EXEC-ADMIN-{tv})",
                          f"vuln: smuggle fired={v['fired']}, honest-admin denied={denied.get('denied')} | safe: -32020",
                          "mcp_rt/mcp_name_differential.py")
    finally:
        sv.shutdown(); ss.shutdown()


def _downgrade() -> T10Outcome:
    sv, uv, tv, _ = downgrade_hosts.start(vulnerable=True)
    ss, us, ts, _ = downgrade_hosts.start(vulnerable=False)
    try:
        v = downgrade.probe_forced_downgrade(uv, tv)
        modern = downgrade.probe_modern(uv, tv)                 # same-host control: modern path is clean
        s = downgrade.probe_forced_downgrade(us, ts)
        return T10Outcome("downgrade", "CONFIRMED", v["fired"], not s["fired"],
                          f"forced legacy downgrade bypasses the modern guard (PROFILE-SECRET-{tv})",
                          f"vuln: forced-downgrade fired={v['fired']}, modern-same-host clean={modern.get('clean')} | safe: uniform",
                          "mcp_rt/downgrade.py")
    finally:
        sv.shutdown(); ss.shutdown()


def _url_elicitation() -> T10Outcome:
    sc, base, received = url_elicit_hosts.start_collector()
    sv, uv, tv, srv_recv_v = url_elicit_hosts.start(vulnerable=True, collector_url=base)
    ss, us, ts, srv_recv_s = url_elicit_hosts.start(vulnerable=False, collector_url=base)
    try:
        vo = url_elicitation.probe_offorigin(uv, tv, received, srv_recv_v)
        vp = url_elicitation.probe_preauth(uv, tv)
        received.clear()                                        # reset the attacker collector between runs
        so = url_elicitation.probe_offorigin(us, ts, received, srv_recv_s)
        sp = url_elicitation.probe_preauth(us, ts)
        return T10Outcome("url_elicitation", "CONFIRMED", vo["fired"] or vp["fired"],
                          not (so["fired"] or sp["fired"]),
                          f"URL-mode elicitation off-origin capture / pre-auth-in-URL (USERCRED-{tv} / PREAUTH-{tv})",
                          f"vuln: offorigin={vo['fired']} preauth={vp['fired']} | safe: same-origin to server, silent",
                          "mcp_rt/url_elicitation.py")
    finally:
        sv.shutdown(); ss.shutdown(); sc.shutdown()


def _mcp_apps() -> list[T10Outcome]:
    sv, uv, tv = mcp_apps_hosts.start(vulnerable=True)
    ss, us, ts = mcp_apps_hosts.start(vulnerable=False)
    try:
        vi = mcp_apps_ui.probe_injection(uv, tv)
        si = mcp_apps_ui.probe_injection(us, ts)
        confirmed = T10Outcome("mcp_apps_ui", "CONFIRMED", vi["fired"], not si["fired"],
                               f"MCP Apps UI markup injection renders in an executable context (UIEXEC-{tv})",
                               f"vuln: injection fired={vi['fired']} | safe: escaped/inert, silent",
                               "mcp_rt/mcp_apps_ui.py")
        leads = mcp_apps_ui.structural_leads(uv)                # every item confirmed=False — never promoted
        kinds = ", ".join(sorted({l.get("kind", "lead") for l in leads})) or "none"
        lead = T10Outcome("mcp_apps_ui", "LEAD", bool(leads), True,
                          f"{len(leads)} structural UI lead(s): {kinds}",
                          "clickjacking/UI-redress, permissive-CSP, over-broad-permissions — structural, no deterministic sink",
                          "mcp_rt/mcp_apps_ui.py")
        return [confirmed, lead]
    finally:
        sv.shutdown(); ss.shutdown()


def run_t10() -> list[T10Outcome]:
    """The 7 T10 spec-surface classes: 6 CONFIRMED host-pairs + mcp_apps_ui (injection CONFIRMED + a
    structural LEAD). Additive to the floor; never promotes a lead to CONFIRMED."""
    out = [_cachescope(), _task_idor(), _meta_spoof(), _mcp_name(), _downgrade(), _url_elicitation()]
    out.extend(_mcp_apps())
    return out
