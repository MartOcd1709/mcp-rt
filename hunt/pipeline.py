"""`mcp-rt hunt-all` — the end-to-end MCP security lifecycle in one command.

    DISCOVER → (per server) SCAN/VA → adaptive EXPLOIT (ground-truth-gated) → CORRELATE
             → persist(CMDB) → REPORT

Deterministic rails, agentic reach: every finding is engine-PROVEN before it is reported (the moat).
The autonomous agent (`mcp-rt agent`) is the depth/coverage tier that layers on top of this backbone —
it finds and tests what the fixed detection classes miss, but its claims still pass the same
ground-truth gate before they count. This command is the reliable, demoable spine.

HITL gates — irreversible / outward-facing actions only, nothing else:
  - subnet discovery (--network) requires --authorized-by (active recon on other hosts).
  - scanning a NON-LOCAL http server requires --authorized-by (you are touching someone else's host).
Local stdio servers and loopback http are your own → assessed autonomously, no gate.
"""
from __future__ import annotations

from urllib.parse import urlparse

from hunt import discover as _discover
from hunt import orchestrator as _orch

_LOOPBACK = {"127.0.0.1", "localhost", "::1"}


def _is_loopback(url: str) -> bool:
    try:
        return (urlparse(url).hostname or "") in _LOOPBACK
    except ValueError:
        return False


def hunt_all(*, roots=None, localhost: bool = True, network: str | None = None,
             authorized_by: str = "", adaptive: bool = False, execute: bool = False,
             save: bool = True):
    """Discover every reachable MCP server, then run the full assessment lifecycle on each.

    Returns (results, skipped): results is a list of (DiscoveredServer, Assessment); skipped is a list
    of (DiscoveredServer, reason) — e.g. a non-local http target held back by the HITL gate.
    """
    servers = _discover.discover(roots=roots)
    if localhost:
        servers += _discover.discover_localhost()
    if network:
        servers += _discover.discover_network(network, authorized_by=authorized_by)  # raises w/o authz

    seen, uniq = set(), []
    for s in servers:
        k = (s.name, s.launch)
        if k not in seen:
            seen.add(k)
            uniq.append(s)

    results, skipped = [], []
    for s in uniq:
        try:
            if s.transport == "stdio" and s.launch:                       # our own local server
                a = _orch.assess(s.launch, adaptive=adaptive, execute=execute, save=save)
            elif s.transport == "http" and s.launch:
                if _is_loopback(s.launch):
                    authz = "localhost (own machine)"
                elif authorized_by.strip():
                    authz = authorized_by.strip()
                else:
                    skipped.append((s, "non-local http target needs --authorized-by (HITL gate)"))
                    continue
                from hunt.remote import scan_remote
                rep = scan_remote(s.launch, {}, authz)
                rep.setdefault("surface", {"tools": rep.get("tools", [])})  # adaptive needs surface.tools
                a = _orch.assess(s.launch, base_report=rep, adaptive=adaptive,
                                 execute=execute, save=save)
            else:
                skipped.append((s, "no launch target"))
                continue
            results.append((s, a))
        except Exception as e:  # noqa: BLE001 — one unreachable/broken server never aborts the fleet
            skipped.append((s, f"error: {e}"))
    return results, skipped


def main(argv=None) -> int:
    import argparse
    import json
    import sys
    from pathlib import Path
    p = argparse.ArgumentParser(
        prog="mcp-rt hunt-all",
        description="End-to-end: discover → scan/VA → exploit → correlate → report (CMDB-tracked)")
    p.add_argument("--root", action="append", default=None,
                   help="project dir to also scan for configs (repeatable)")
    p.add_argument("--no-localhost", action="store_true", help="skip loopback HTTP/SSE probing")
    p.add_argument("--network", metavar="CIDR", help="also sweep a subnet (ACTIVE RECON)")
    p.add_argument("--authorized-by", default="",
                   help="REQUIRED for --network and for scanning any non-local http target")
    p.add_argument("--adaptive", action="store_true",
                   help="AI-generated probes tailored to each target (still ground-truth-gated)")
    p.add_argument("--execute", action="store_true",
                   help="with --adaptive: validate proposals against the ground-truth scan")
    p.add_argument("--no-save", action="store_true", help="do not persist to the CMDB ledger")
    p.add_argument("--no-report", action="store_true", help="skip writing the Desktop assessment report")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)

    try:
        results, skipped = hunt_all(
            roots=args.root, localhost=not args.no_localhost, network=args.network,
            authorized_by=args.authorized_by, adaptive=args.adaptive,
            execute=args.execute, save=not args.no_save)
    except PermissionError as e:
        print(f"refused: {e}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps({"assessed": [{"server": s.as_dict(), "assessment": a.as_dict()}
                                        for s, a in results],
                          "skipped": [{"server": s.as_dict(), "why": w} for s, w in skipped]},
                         indent=2, default=str))
        return 0

    if not results and not skipped:
        print("no MCP servers discovered.", file=sys.stderr)
        return 0
    vuln = sum(1 for _, a in results if a.verdict == "VULNERABLE")
    print(f"assessed {len(results)} MCP server(s) — {vuln} VULNERABLE:\n")
    for s, a in results:
        print(f"  [{a.verdict:12}] {s.name:24} findings={len(a.findings)} chains={len(a.chains)}")
        for c in a.chains:
            print(f"        └─ CHAIN {c.severity}: {c.kind}")
    for s, w in skipped:
        print(f"  [skipped     ] {s.name:24} {w}")

    if not args.no_save and not args.no_report:
        from hunt.assess_report import write_report
        out = write_report(str(Path.home() / "Desktop" / "mcp-rt_assessment_report.md"))
        print(f"\nreport: {out}")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
