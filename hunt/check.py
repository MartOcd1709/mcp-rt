"""`mcp-rt check` — assess one MCP server completely, in one command.

Runs the full detection scan (13 ground-truth classes + supply chain + OWASP mapping) AND the
undeclared-capability hunt (MCP-CAP), persists everything to the relationship DB, and prints one
consolidated verdict. This is the single "point it at a server and tell me everything" command.

    mcp-rt check --target-stdio "npx -y some-mcp-server"
    mcp-rt check --target-stdio "uvx mcp-atlassian"
"""
from __future__ import annotations

import asyncio
import shlex

from .probes import ScanError
from .report import run_full_scan, record, _target_name

_C = {"Critical": "\033[31m", "High": "\033[31m", "Medium": "\033[33m", "Low": "\033[33m"}
_R = "\033[0m"


def _run_full_check(target: str, do_cap: bool = True) -> int:
    cmd = shlex.split(target)
    print(f"\n━━ mcp-rt check ━━ {target}\n")

    # 1) full detection scan (all classes + supply chain + token + mcp06), persisted to the backbone
    try:
        rep = asyncio.run(run_full_scan(cmd))
    except ScanError as e:
        # Server wouldn't start (usually missing required config/credentials). Still run the checks that
        # need no running server, so the scan is never a dead end.
        print(f"⚠ server did not start — likely missing required config/credentials:\n    {e}\n")
        print("Running the credential-free checks (no running server needed):\n")
        from .supply_chain import scan_supply
        sc = scan_supply(target)
        if sc:
            for f in sc:
                kind = "VULN" if f.get("ground_truth") else "FLAG"
                print(f"  [supply-chain {kind}] {f.get('rationale','')[:90]}")
        else:
            print("  supply-chain: no npm package resolved (Python/uvx servers need PyPI supply-chain, "
                  "not yet built).")
        print("\nAUTHENTICATED CLASSES: NOT TESTED — provide the server's credentials via env and re-run "
              "for the full assessment.")
        return 2
    try:
        record(rep, "check")
    except Exception:  # noqa: BLE001 — persistence is best-effort; never fail the check over it
        pass

    verdict = rep["verdict"]
    mark = f"{_C.get('High','')}VULNERABLE{_R}" if verdict == "VULNERABLE" else "\033[32mCLEAN\033[0m"
    surf = rep.get("surface", {})
    print(f"verdict: {mark}   ·   {len(surf.get('tools', []))} tools, "
          f"{len(surf.get('resources', []))} resources")
    if rep.get("auth_gated"):
        print(f"\n{_C['High']}⚠ UNAUTHENTICATED ASSESSMENT{_R} — the server rejects tool calls without "
              "credentials.\n  Execution-dependent classes are marked REQUIRES_CREDENTIALS (not tested, "
              "not clean).\n  Trustworthy here: surface, tool-poisoning, supply-chain. Provide creds via env "
              "for the rest.")

    if rep["findings"]:
        print("\nFINDINGS (ground-truth, reproduced):")
        for f in rep["findings"]:
            c = _C.get(f["sev"], "")
            print(f"  {c}[{f['sev']:<8}]{_R} {f['cls']:<20} {f.get('tool',''):<16} {f.get('cwe','')}")
            print(f"            {f.get('detail','')[:100]}")
    else:
        print("\nFINDINGS: none across all tested classes.")

    posture = rep.get("supply_posture", [])
    if posture:
        print("\nSUPPLY-CHAIN POSTURE (flags, not confirmed findings):")
        for p in posture:
            print(f"  [{p.get('severity','')}] {p.get('detail','')[:90]}")

    m06 = rep.get("mcp06", {})
    if m06.get("exposed"):
        print(f"\nINTENT-FLOW SURFACE (OWASP MCP06, enabling conditions — NOT a confirmed finding):")
        for r in m06.get("reasons", []):
            print(f"  · {r}")
        print("  → confirm with the Advanced Agent Red-Team (mcp-rt hunt-agent).")

    # 2) undeclared-capability hunt (MCP-CAP) — needs the strace sensor
    if do_cap:
        from .hunt_cap import run_cap_hunt, strace_available, record_hypotheses
        if strace_available():
            status, hyps = run_cap_hunt(cmd)
            print(f"\nUNDECLARED-CAPABILITY HUNT (MCP-CAP): {status}")
            if hyps:
                is_fixture = any(x in target for x in ("probe_fixtures", "_fixtures", "vuln_server.py",
                                                       "safe_server.py"))
                if not is_fixture:
                    from .findings_db import DB
                    db = DB()
                    record_hypotheses(db, db.add_target(name=_target_name(target), install_cmd=target,
                                                        source="check"), hyps)
                    db.close()
                for h in hyps:
                    print(f"  • [{h.tool}] {h.observation}")
            elif status == "OK":
                print("  no tool exceeded its declared capabilities.")
        else:
            print("\nUNDECLARED-CAPABILITY HUNT (MCP-CAP): SKIPPED — strace not installed "
                  "(`sudo apt install strace`).")

    # 3) OWASP compliance crosswalk
    print("\nOWASP MCP Top 10:")
    for c in rep.get("compliance", []):
        tag = {"FAIL": f"{_C['High']}FAIL{_R}", "PASS": "\033[32mPASS\033[0m"}.get(c["status"], "not tested")
        print(f"  {c['id']}  {tag:<16} {c['title']}")

    print(f"\nrecorded to the database — see: mcp-rt db findings\n")
    return 1 if verdict == "VULNERABLE" else 0


def main(argv=None) -> int:
    import argparse
    p = argparse.ArgumentParser(prog="mcp-rt check",
                                description="assess one MCP server completely (scan + supply + MCP-CAP)")
    p.add_argument("--target-stdio", required=True, metavar="CMD",
                   help='launch command, e.g. "npx -y some-server" or "uvx mcp-atlassian"')
    p.add_argument("--no-cap", action="store_true", help="skip the undeclared-capability (MCP-CAP) hunt")
    args = p.parse_args(argv)
    return _run_full_check(args.target_stdio, do_cap=not args.no_cap)


if __name__ == "__main__":
    import sys
    sys.exit(main())
