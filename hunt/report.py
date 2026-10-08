"""Unified VAPT + compliance report for one MCP server — the product deliverable.

Runs every detection class against a target in a single pass, then emits a complete report:
an executive summary, per-finding detail (severity, CWE, evidence, reproduction,
remediation), and an OWASP MCP Top 10 compliance posture (pass/fail/not-tested per control).
Outputs Markdown (humans) + JSON (CI/SARIF-adjacent), preserved under hunt/reports/, and
records each finding to the ledger. This is the artifact a maintainer or enterprise receives.

    python -m hunt.report --target-stdio "npx some-mcp-server"
    python -m hunt.report --target-stdio "..." --exit-code     # CI gate: 1 if any finding

Guardrail: local, open-source servers only (see the mcp-hunt skill).
"""
from __future__ import annotations

import argparse
import asyncio
import datetime
import json
import os
import re
import sys
from pathlib import Path

from hunt.family_b import probe_token_passthrough
from hunt.probes import VULNERABLE, ScanError, scan_target
from hunt.supply_chain import installed_dir, analyze_path, _bare_name

# --- class metadata: severity, CWE, OWASP MCP Top 10 mapping, remediation ----------------
CLASS_META = {
    "command_injection": dict(sev="Critical", cwe="CWE-78", owasp=["MCP05"],
        title="Command / Code Injection",
        fix="Never build shell strings from input; spawn with an argv array (no shell=True); "
            "do not eval/exec untrusted code; prefer parameterised, non-shell APIs."),
    "sql_injection": dict(sev="High", cwe="CWE-89", owasp=["MCP05"],
        title="SQL Injection",
        fix="Use parameterised queries / bound parameters exclusively; never concatenate input into SQL."),
    "deserialization": dict(sev="Critical", cwe="CWE-502", owasp=["MCP05"],
        title="Insecure Deserialization",
        fix="Never deserialize untrusted input with code-executing loaders: use yaml.safe_load (not "
            "yaml.load/Loader), avoid pickle/marshal/jsonpickle on external data, and never eval/exec "
            "deserialized content; prefer plain JSON with a schema."),
    "ssrf": dict(sev="High", cwe="CWE-918", owasp=["MCP05", "MCP02"],
        title="Server-Side Request Forgery",
        fix="Block loopback, link-local (169.254.169.254) and private ranges; enforce an egress "
            "allowlist; resolve and validate the host before fetching; do not follow redirects blindly."),
    "path_traversal": dict(sev="High", cwe="CWE-22", owasp=["MCP05", "MCP02"],
        title="Path Traversal / Arbitrary File Access",
        fix="realpath the target and verify it stays within an allowed root; reject '..', absolute "
            "paths and escaping symlinks; apply the same check to write/edit/move operations."),
    "tool_poisoning": dict(sev="High", cwe="CWE-74", owasp=["MCP03"],
        title="Tool-Metadata Concealment (Tool Poisoning)",
        fix="Reject invisible/non-printable Unicode (TAG block U+E0000-E007F, zero-width, bidi, "
            "variation selectors) in tool names/descriptions/schemas; show the model's exact input in the approval view."),
    "token_passthrough": dict(sev="High", cwe="CWE-287", owasp=["MCP01", "MCP07"],
        title="Token Passthrough / Confused Deputy",
        fix="Never forward the client's bearer token downstream; use the server's own credential or "
            "RFC 8693 token exchange; validate token audience and issuer."),
    "ssti": dict(sev="High", cwe="CWE-1336", owasp=["MCP05"],
        title="Server-Side Template Injection",
        fix="Never render untrusted input as template source; use a logic-less/sandboxed template "
            "engine and pass user data as bound parameters, not into the template itself."),
    "rug_pull": dict(sev="Medium", cwe="CWE-494", owasp=["MCP03"],
        title="Dynamic Tool Redefinition (Rug Pull)",
        fix="Pin and verify tool definitions (hash/signature); surface any post-approval change to "
            "the user for re-consent; reject silent tool-definition mutation."),
    "arg_injection": dict(sev="High", cwe="CWE-88", owasp=["MCP05"],
        title="Argument Injection / CLI Flag Smuggling",
        fix="Pass user input only after '--' (end-of-options), reject leading-dash values, and "
            "validate against an explicit allowlist of expected values; never let input become an "
            "argv flag to a wrapped binary."),
    "dns_rebinding": dict(sev="High", cwe="CWE-346", owasp=["MCP07"],
        title="DNS Rebinding / Missing Origin Validation",
        fix="Enable DNS-rebinding protection: validate the Origin (and Host) header against an "
            "allowlist and reject foreign origins; bind local servers to 127.0.0.1 and require a "
            "per-session token."),
    "context_oversharing": dict(sev="High", cwe="CWE-200", owasp=["MCP10"],
        title="Context Oversharing / Environment Leak",
        fix="Never return raw environment, config, or secrets to the model: allowlist exactly the "
            "fields a tool needs, redact credentials, and keep server secrets out of any tool result "
            "or resource the model can read."),
    "supply_chain": dict(sev="High", cwe="CWE-829", owasp=["MCP04"],
        title="Supply Chain / Install-Time Code Execution",
        fix="Remove or vet install/postinstall lifecycle scripts, pin every dependency to an exact "
            "version with a committed lockfile, verify package provenance, and audit the dependency "
            "tree for known CVEs."),
}

OWASP_MCP_TOP10 = {
    "MCP01": "Token Mismanagement and Secret Exposure",
    "MCP02": "Privilege Escalation via Scope Creep",
    "MCP03": "Tool Poisoning",
    "MCP04": "Supply Chain Attacks and Dependency Tampering",
    "MCP05": "Command Injection and Execution",
    "MCP06": "Intent Flow Subversion (Prompt Injection via Context)",
    "MCP07": "Insufficient Authentication and Authorization",
    "MCP08": "Lack of Audit and Telemetry",
    "MCP09": "Shadow MCP Servers",
    "MCP10": "Context Injection and Over Sharing",
}
# Controls this engine actively tests (others are out of active scope -> NOT TESTED, stated honestly).
TESTED_CONTROLS = {c for m in CLASS_META.values() for c in m["owasp"]}
# Classes that need NO working tool call — they read tool metadata or the static package, so they stay
# trustworthy even when the server is auth-gated. Everything else is execution-dependent.
_NO_CRED_SAFE_CLASSES = {"tool_poisoning", "supply_chain"}
_SEV_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}

# Crosswalk from the OWASP MCP controls we test to the standard audit frameworks, so the report
# doubles as audit evidence. High-level control-family references (not a certification claim).
COMPLIANCE_XWALK = {
    "MCP01": dict(soc2="CC6.1, CC6.3", iso27001="A.5.17, A.8.24", pci="3.5, 8.3.1"),   # secrets/tokens
    "MCP02": dict(soc2="CC6.1, CC6.3", iso27001="A.5.15, A.8.3",  pci="7.2"),           # privilege/scope
    "MCP03": dict(soc2="CC7.1, CC8.1", iso27001="A.8.28",          pci="6.5"),           # tool integrity
    "MCP05": dict(soc2="CC8.1, CC7.1", iso27001="A.8.28, A.8.29",  pci="6.5.1"),         # injection/exec
    "MCP07": dict(soc2="CC6.1, CC6.6", iso27001="A.8.5, A.5.15",   pci="8.2, 8.3"),      # auth/authz
}


# Tools that pull ATTACKER-influenceable external content into the model (intent-flow / MCP06 surface).
_INTENT_FLOW_TOOL = re.compile(r"fetch|http|\bweb\b|url|scrape|crawl|browse|search|download|request", re.I)


def _mcp06_exposure(surface: dict) -> dict:
    """Basic-scan flag for OWASP MCP06 (intent-flow / prompt-injection-via-context, the MCP-00 class):
    the server-side ENABLING CONDITIONS, not a confirmed finding. Confirmation needs the Advanced
    Agent Red-Team (a real agent in the loop)."""
    reasons = []
    if surface.get("resources"):
        reasons.append(f"exposes {len(surface['resources'])} resource(s) whose content is routed to the "
                       "model (direct MCP-00 / context-injection vector)")
    ext = [t["name"] for t in (surface.get("tools") or []) if _INTENT_FLOW_TOOL.search(t["name"])]
    if ext:
        reasons.append("tool(s) pull external/fetched content into the model (return-value-injection "
                       f"surface): {', '.join(ext[:6])}" + (" …" if len(ext) > 6 else ""))
    return {"exposed": bool(reasons), "reasons": reasons}


async def run_full_scan(argv: list[str], env: dict | None = None) -> dict:
    """Run every detection class against one target; return a structured report dict."""
    surface: dict = {}
    probe_results = await scan_target(argv, env, surface=surface)   # also inventories the surface
    tok = await probe_token_passthrough(argv, env)               # Family B

    findings = []
    for r in probe_results:
        if r.verdict == VULNERABLE:
            findings.append({"cls": r.probe, "tool": r.tool,
                             "evidence": r.evidence or "", "detail": r.rationale})
    if tok.verdict == VULNERABLE:
        tool = tok.passthrough[0]["path"] if tok.passthrough else "downstream"
        findings.append({"cls": "token_passthrough", "tool": tool,
                         "evidence": json.dumps(tok.passthrough)[:300], "detail": tok.rationale})

    # MCP04 supply chain: analyze the installed package (static install-risk + OSV known-vuln deps).
    # Resolved only for npm/npx targets; a uvx/PyPI target has no node_modules -> not run for this scan.
    sc_dir = await asyncio.to_thread(installed_dir, _bare_name(_target_name(" ".join(argv))))
    supply_posture = []
    if sc_dir:
        for f in await asyncio.to_thread(analyze_path, sc_dir):
            if f.get("ground_truth"):                            # install hook / known-CVE dep = a real finding
                findings.append({"cls": "supply_chain", "tool": "(package)",
                                 "evidence": f.get("evidence", "")[:300], "detail": f.get("rationale", "")})
            else:                                                # unpinned etc. = posture, never a finding
                supply_posture.append({"severity": f.get("severity", ""),
                                       "evidence": f.get("evidence", ""), "detail": f.get("rationale", "")})

    for f in findings:                                           # enrich with metadata
        f.update(CLASS_META.get(f["cls"], dict(sev="Medium", cwe="", owasp=[], title=f["cls"], fix="")))
    findings.sort(key=lambda f: _SEV_RANK.get(f["sev"], 9))

    failed = {c for f in findings for c in f["owasp"]}
    tested = set(TESTED_CONTROLS)
    if not sc_dir:                       # supply chain didn't run for this target -> MCP04 not tested here
        tested.discard("MCP04")
    compliance = []
    for cid, title in OWASP_MCP_TOP10.items():
        status = ("FAIL" if cid in failed else "PASS") if cid in tested else "NOT TESTED"
        compliance.append({"id": cid, "title": title, "status": status})

    # Tool-by-tool coverage: every (tool, class) exercised + its verdict — proves what was tested,
    # not just what failed (the "tool-by-tool coverage" an MCP engagement is expected to leave behind).
    coverage = [{"tool": r.tool, "cls": r.probe, "verdict": r.verdict} for r in probe_results]
    if tok.passthrough is not None or tok.verdict in (VULNERABLE, "CLEAN"):
        coverage.append({"tool": (tok.passthrough[0]["path"] if tok.passthrough else "(downstream)"),
                         "cls": "token_passthrough", "verdict": tok.verdict})
    if sc_dir:                            # record that supply chain was actually exercised for this target
        coverage.append({"tool": "(package)", "cls": "supply_chain",
                         "verdict": "VULNERABLE" if any(f["cls"] == "supply_chain" for f in findings) else "CLEAN"})

    surface.setdefault("tools", [])
    surface.setdefault("resources", [])
    surface["transport"] = "stdio"            # run_full_scan is the local stdio path (remote.py is HTTP/SSE)

    # Graceful no-creds honesty: if the server rejects tool calls for lack of credentials, the
    # execution-dependent classes were NOT really tested — never score them PASS/CLEAN. Only the classes
    # that need no working tool call (tool metadata, static package) remain trustworthy.
    auth_gated = bool(surface.get("auth_gated"))
    if auth_gated:
        safe = {c for cls in _NO_CRED_SAFE_CLASSES for c in CLASS_META.get(cls, {}).get("owasp", [])}
        for c in compliance:
            if c["status"] == "PASS" and c["id"] not in safe:
                c["status"] = "NOT TESTED"      # couldn't exercise without credentials
        for cov in coverage:
            if cov["verdict"] == "CLEAN" and cov["cls"] not in _NO_CRED_SAFE_CLASSES:
                cov["verdict"] = "REQUIRES_CREDENTIALS"

    return {
        "auth_gated": auth_gated,
        "target": " ".join(argv),
        "scanned_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "verdict": "VULNERABLE" if findings else "CLEAN",
        "counts": {s: sum(1 for f in findings if f["sev"] == s)
                   for s in ("Critical", "High", "Medium", "Low") if any(f["sev"] == s for f in findings)},
        "findings": findings,
        "surface": surface,
        "coverage": coverage,
        "mcp06": _mcp06_exposure(surface),
        "compliance": compliance,
        "supply_posture": supply_posture,
        "token_passthrough_transcript": tok.transcript,
    }


def render_markdown(rep: dict) -> str:
    L = [f"# MCP VAPT Report — `{rep['target']}`", "",
         f"**Scanned:** {rep['scanned_at']}  ·  **Verdict:** {rep['verdict']}  ·  "
         f"**Findings:** {len(rep['findings'])}", ""]

    # --- Executive summary: leadership-facing, plain English (A1) -----------------------------
    counts = rep.get("counts", {})
    sev_line = ", ".join(f"{n} {s}" for s, n in counts.items()) or "no findings"
    L += ["## Executive summary", ""]
    if rep["findings"]:
        top = rep["findings"][0]   # findings are pre-sorted by severity
        L += [f"This MCP server was tested against {len(CLASS_META)} ground-truth attack classes and the "
              f"OWASP MCP Top 10. **Verdict: {rep['verdict']}** — {len(rep['findings'])} finding(s) "
              f"({sev_line}), each confirmed by a planted honeytoken / sentinel / canary, not a heuristic. "
              f"The highest-risk issue is **{top['title']} ({top['sev']}, {top['cwe']})** on tool "
              f"`{top['tool']}`. Per-finding remediation is below; a re-test is recommended once fixes land.", ""]
    else:
        L += [f"This MCP server was tested against {len(CLASS_META)} ground-truth attack classes and the "
              "OWASP MCP Top 10. **Verdict: CLEAN** — no vulnerability was confirmed by ground-truth "
              "probing. This report stands as a point-in-time security attestation across the tested "
              "controls (see the compliance crosswalk below).", ""]

    # --- Attack surface: map what exists before assessing it (every assessment starts here) ----
    surf = rep.get("surface") or {}
    if surf.get("tools") is not None or surf.get("transport"):
        tools = surf.get("tools") or []
        res = surf.get("resources") or []
        L += ["## Attack surface", "",
              f"- **Transport:** {surf.get('transport', 'stdio')}",
              f"- **Tools exposed:** {len(tools)}",
              f"- **Resources exposed:** {len(res)}", ""]
        if tools:
            L += ["| Tool | Parameters |", "|---|---|"]
            for t in tools:
                L.append(f"| `{t['name']}` | {', '.join(t.get('params') or []) or '—'} |")
            L += [""]
        if res:
            L += ["Resources: " + ", ".join(f"`{r}`" for r in res[:12]) + ("" if len(res) <= 12 else " …"), ""]

    if rep["findings"]:
        L += ["### Findings at a glance", "",
              "| # | Severity | Finding | Tool | CWE | OWASP |",
              "|---|---|---|---|---|---|"]
        for i, f in enumerate(rep["findings"], 1):
            L.append(f"| {i} | {f['sev']} | {f['title']} | `{f['tool']}` | {f['cwe']} | {', '.join(f['owasp'])} |")
        L += ["", "## Findings", ""]
        for i, f in enumerate(rep["findings"], 1):
            L += [f"### {i}. {f['title']} — {f['sev']} ({f['cwe']})",
                  f"- **Affected tool:** `{f['tool']}`",
                  f"- **OWASP MCP:** {', '.join(OWASP_MCP_TOP10[c] + f' ({c})' for c in f['owasp'])}",
                  f"- **Evidence (ground truth):** {f['evidence'] or f['detail']}",
                  f"- **Detail:** {f['detail']}",
                  f"- **Remediation:** {f['fix']}", ""]
    L += ["## OWASP MCP Top 10 — compliance posture", "",
          "| Control | Status |", "|---|---|"]
    for c in rep["compliance"]:
        mark = {"PASS": "✅ PASS", "FAIL": "❌ FAIL", "NOT TESTED": "— not tested"}[c["status"]]
        L.append(f"| {c['id']} {c['title']} | {mark} |")

    # --- Compliance crosswalk: tested controls -> audit frameworks (A2) ------------------------
    L += ["", "## Compliance crosswalk", "",
          "The actively-tested OWASP MCP controls mapped to standard audit frameworks (control-family "
          "references for evidence support — not a certification claim):", "",
          "| OWASP MCP control | SOC 2 | ISO 27001 | PCI DSS |", "|---|---|---|---|"]
    for cid in [c["id"] for c in rep["compliance"] if c["id"] in COMPLIANCE_XWALK]:
        x = COMPLIANCE_XWALK[cid]
        L.append(f"| {cid} {OWASP_MCP_TOP10[cid]} | {x['soc2']} | {x['iso27001']} | {x['pci']} |")

    # --- Tool-by-tool coverage: what was tested, not only what failed ---------------------------
    cov = rep.get("coverage") or []
    if cov:
        by_tool = {}
        for c in cov:
            by_tool.setdefault(c["tool"], []).append((c["cls"], c["verdict"]))
        L += ["", "## Tool-by-tool coverage", "",
              "Every tool exercised against each applicable class — evidence of what was tested, not "
              "only what failed.", "",
              "| Tool | Classes exercised | Result |", "|---|---|---|"]
        for tool, entries in by_tool.items():
            classes = ", ".join(sorted({cls for cls, _ in entries}))
            vulns = sorted({cls for cls, v in entries if v == VULNERABLE})
            result = ("❌ vulnerable: " + ", ".join(vulns)) if vulns else "✅ clean"
            L.append(f"| `{tool}` | {classes} | {result} |")

    # --- Intent-flow exposure (MCP06) — Basic-scan enabling-conditions flag, not a finding ---------
    m6 = rep.get("mcp06") or {}
    if m6:
        L += ["", "## Intent-flow exposure (OWASP MCP06) — enabling conditions", ""]
        if m6.get("exposed"):
            L += ["This Basic scan flags the server-side **surface** that intent-flow / prompt-injection-"
                  "via-context attacks (the MCP-00 class) target. **This is not a confirmed finding** — "
                  "confirming it requires the **Advanced Agent Red-Team** (a real agent in the loop):", ""]
            L += [f"- {r}" for r in m6["reasons"]]
            L += [""]
        else:
            L += ["Minimal intent-flow surface: the server exposes no model-facing resources and no "
                  "external-content tools that an attacker could use for context injection.", ""]

    L += ["> Verdicts are ground-truth (planted honeytoken / sentinel / canary), not heuristic. "
          "“Not tested” controls are outside this engine's active probe scope, stated honestly. "
          "Compliance references support an audit; they are not an attestation of certification.", ""]
    return "\n".join(L)


_REPORT_CSS = """
@page { size: A4; margin: 18mm 16mm; }
* { box-sizing: border-box; }
body { font: 13px/1.55 -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
       color: #1b2733; margin: 0; }
.doc { max-width: 820px; margin: 0 auto; padding: 8px 2px; }
h1 { font-size: 23px; letter-spacing: -.01em; margin: 0 0 4px; }
h1, h2 { color: #0f172a; } h2 { font-size: 17px; border-bottom: 2px solid #0ea5a4; padding-bottom: 4px;
       margin: 26px 0 10px; } h3 { font-size: 14px; margin: 16px 0 6px; }
a { color: #0ea5a4; } code { background: #eef2f4; padding: 1px 5px; border-radius: 4px;
       font: 12px/1.4 'JetBrains Mono', ui-monospace, Menlo, monospace; }
table { width: 100%; border-collapse: collapse; margin: 8px 0 4px; font-size: 12px; }
th, td { border: 1px solid #d5dde3; padding: 6px 9px; text-align: left; vertical-align: top; }
th { background: #0f172a; color: #e8eef3; font-weight: 600; }
tr:nth-child(even) td { background: #f6f9fa; }
blockquote { margin: 14px 0 0; padding: 9px 13px; background: #f0fafa; border-left: 3px solid #0ea5a4;
       color: #35505c; font-size: 12px; }
strong { color: #0f172a; }
footer { margin-top: 20px; padding-top: 10px; border-top: 1px solid #d5dde3; color: #6b7a87; font-size: 11px; }
"""


def render_html(rep: dict) -> str:
    """Branded, print-friendly HTML deliverable (the client-facing artifact). markdown -> HTML + CSS."""
    import markdown as _md
    body = _md.markdown(render_markdown(rep), extensions=["tables", "sane_lists"])
    tgt = rep["target"].replace("<", "&lt;")
    return (f"<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            f"<meta name='viewport' content='width=device-width, initial-scale=1'>"
            f"<title>MCP VAPT Report — {tgt}</title><style>{_REPORT_CSS}</style></head>"
            f"<body><div class='doc'>{body}"
            f"<footer>mcp-rt · ground-truth MCP security · every verdict proven by a planted "
            f"honeytoken / sentinel / canary. Responsible disclosure before any public listing.</footer>"
            f"</div></body></html>")


def to_pdf(rep: dict, path: str) -> str:
    """Render the branded HTML to a PDF deliverable via weasyprint."""
    from weasyprint import HTML
    HTML(string=render_html(rep)).write_pdf(path)
    return path


def preserve(rep: dict) -> str:
    base = Path(__file__).resolve().parent / "reports"
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in rep["target"])[:50] or "target"
    d = base / f"{stamp}_{safe}"
    d.mkdir(parents=True, exist_ok=True)
    (d / "report.md").write_text(render_markdown(rep))
    (d / "report.json").write_text(json.dumps(rep, indent=2, default=str))
    return str(d)


def _target_name(target: str) -> str:
    """Derive the real package/server name from a run command (not an npx flag or a path arg)."""
    import shlex
    skip = {"npx", "-y", "uvx", "--offline", "python", "python3", "node", "-m"}
    for tok in shlex.split(target):
        if tok in skip or tok.startswith("-"):
            continue
        if tok.startswith(("/", "./", "../")):   # a filesystem path arg (scoped @names keep their /)
            continue
        return tok
    return target


def record(rep: dict, report_dir: str) -> None:
    # Never record a self-test fixture as a real target (keeps the ledger honest).
    if any(x in rep["target"] for x in ("probe_fixtures", "family_b_fixtures", "remote_fixtures",
                                        "vuln_server.py", "safe_server.py")):
        return
    from hunt.findings_db import DB
    db = DB()
    tid = db.add_target(name=_target_name(rep["target"]), install_cmd=rep["target"], source="report")
    for f in rep["findings"]:
        db.add_scan(tid, mode=f"report:{f['cls']}", verdict=VULNERABLE, agent="n/a",
                    evidence=report_dir, notes=f"{f['title']} ({f['cwe']}) on {f['tool']}: {f['detail']}"[:500])
    if not rep["findings"]:
        db.add_scan(tid, mode="report", verdict="CLEAN", agent="n/a", evidence=report_dir,
                    notes="no findings across all tested classes")
    # Populate the relationship backbone: the surface (tools/resources), granular findings, and a
    # knowledge-graph node per confirmed finding — the labelled data the in-house model trains on.
    db.seed_classes()
    surf = rep.get("surface") or {}
    for t in surf.get("tools", []):
        db.upsert_tool(tid, t.get("name", ""), kind="tool", declared=",".join(t.get("params", []) or []))
    for r in surf.get("resources", []):
        if r:
            db.upsert_tool(tid, str(r), kind="resource")
    for f in rep["findings"]:
        fid = db.add_finding(tid, class_id=f["cls"], tool=f.get("tool", ""), verdict="VULNERABLE",
                             severity=f.get("sev", ""), evidence=f.get("detail", "")[:500],
                             rationale=f.get("title", ""))
        db.add_attack_pattern(class_id=f["cls"], finding_id=fid, technique=f.get("title", ""),
                              payload=f.get("detail", "")[:500], outcome="confirmed", cwe=f.get("cwe", ""))
    db.close()


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="hunt.report", description="unified VAPT + compliance report")
    p.add_argument("--target-stdio", required=True, metavar="CMD")
    p.add_argument("--exit-code", action="store_true", help="exit 1 if any finding (CI gate)")
    p.add_argument("--html", action="store_true", help="also write a branded HTML report deliverable")
    p.add_argument("--pdf", action="store_true", help="also write a branded PDF report deliverable (client-facing)")
    args = p.parse_args(argv)
    import shlex
    try:
        rep = asyncio.run(run_full_scan(shlex.split(args.target_stdio)))
    except ScanError as e:   # degrade gracefully instead of dumping a traceback
        print(f"INCONCLUSIVE — could not probe target: {e}", file=sys.stderr)
        return 2
    report_dir = preserve(rep)
    record(rep, report_dir)
    print(render_markdown(rep))
    print(f"\n[report preserved: {report_dir}]")
    if args.html:
        from pathlib import Path as _P
        (_P(report_dir) / "report.html").write_text(render_html(rep))
        print(f"[html deliverable: {report_dir}/report.html]")
    if args.pdf:
        try:
            to_pdf(rep, f"{report_dir}/report.pdf")
            print(f"[pdf deliverable: {report_dir}/report.pdf]")
        except Exception as e:  # noqa: BLE001 — weasyprint needs system libs; degrade to HTML honestly
            from pathlib import Path as _P
            (_P(report_dir) / "report.html").write_text(render_html(rep))
            print(f"[pdf unavailable ({type(e).__name__}); wrote HTML instead: {report_dir}/report.html]",
                  file=sys.stderr)
    return 1 if (args.exit_code and rep["findings"]) else 0


if __name__ == "__main__":
    sys.exit(main())
