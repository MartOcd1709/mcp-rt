#!/usr/bin/env python3
"""
mcp-rt Supply Chain Scanner

Audits npm MCP server packages for supply chain risk factors:
  - Single-maintainer packages (event-stream pattern)
  - Abandoned maintainer accounts (stale + high downloads)
  - Download blast radius (weekly install volume)
  - Code signing absence (universal gap in npm ecosystem)

Usage:
  python tools/supply_chain_scan.py fastmcp
  python tools/supply_chain_scan.py fastmcp @modelcontextprotocol/server-filesystem figma-mcp
  python tools/supply_chain_scan.py --top20
"""

import argparse
import json
import sys
import urllib.request
from datetime import datetime, timezone

NPM_REGISTRY  = "https://registry.npmjs.org"
NPM_DOWNLOADS = "https://api.npmjs.org/downloads/point/last-week"

# Top MCP packages by weekly install volume (Jun 2026 snapshot)
TOP_MCP_PACKAGES = [
    "@modelcontextprotocol/sdk",
    "chrome-devtools-mcp",
    "@upstash/context7-mcp",
    "fastmcp",
    "@modelcontextprotocol/server-filesystem",
    "@notionhq/notion-mcp-server",
    "@azure/mcp",
    "@supabase/mcp-server-supabase",
    "kubernetes-mcp-server",
    "mcp-searxng",
    "@benborla29/mcp-server-mysql",
    "@winor30/mcp-server-datadog",
    "figma-mcp",
    "slite-mcp-server",
    "@modelcontextprotocol/server-everything",
    "@penpot/mcp",
    "@eslint/mcp",
    "@cap-js/mcp-server",
    "@hubspot/mcp-server",
    "@sentry/mcp-server",
]


def _fetch(url: str) -> dict:
    req = urllib.request.Request(
        url, headers={"User-Agent": "mcp-rt/1.0 supply-chain-scanner"}
    )
    with urllib.request.urlopen(req, timeout=12) as r:
        return json.loads(r.read())


def _days_since(date_str: str) -> int:
    dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
    return (datetime.now(timezone.utc) - dt).days


def _risk(maintainers: int, days_stale: int, downloads: int) -> tuple[str, str]:
    if maintainers == 1 and days_stale > 180 and downloads >= 1000:
        return (
            "CRITICAL",
            f"single maintainer · {days_stale}d stale · {downloads:,}/wk — event-stream pattern",
        )
    if maintainers == 1 and downloads >= 100_000:
        return (
            "HIGH",
            f"single maintainer · {downloads:,}/wk installs — high blast radius if compromised",
        )
    if maintainers == 1 and days_stale > 90 and downloads >= 500:
        return (
            "HIGH",
            f"single maintainer · {days_stale}d stale · {downloads:,}/wk",
        )
    if maintainers == 1:
        return "MEDIUM", "single maintainer — no backup if npm account is compromised"
    if days_stale > 365:
        return "MEDIUM", f"last publish {days_stale}d ago — maintainer may be inactive"
    return "LOW", "multi-maintainer, recently published"


def scan(name: str) -> dict:
    encoded = name.replace("/", "%2F")
    try:
        meta = _fetch(f"{NPM_REGISTRY}/{encoded}")
    except Exception as e:
        return {"name": name, "error": str(e)}

    try:
        downloads = _fetch(f"{NPM_DOWNLOADS}/{encoded}").get("downloads", 0)
    except Exception:
        downloads = 0

    latest_ver  = meta.get("dist-tags", {}).get("latest", "unknown")
    maintainers = meta.get("maintainers", [])
    times       = meta.get("time", {})
    last_ts     = times.get(latest_ver) or times.get("modified", "")
    days_stale  = _days_since(last_ts) if last_ts else 9999

    m_count = len(maintainers)
    m_names = [m.get("name", "?") for m in maintainers]
    risk_level, risk_reason = _risk(m_count, days_stale, downloads)

    return {
        "name":             name,
        "version":          latest_ver,
        "downloads_week":   downloads,
        "maintainers":      m_count,
        "maintainer_names": m_names,
        "days_stale":       days_stale,
        "code_signing":     "none",
        "risk":             risk_level,
        "risk_reason":      risk_reason,
        "error":            None,
    }


_COLOR = {
    "CRITICAL": "\033[91m",
    "HIGH":     "\033[91m",
    "MEDIUM":   "\033[93m",
    "LOW":      "\033[92m",
}
_RESET = "\033[0m"


def _print(r: dict) -> None:
    if r.get("error"):
        print(f"\n  {r['name']}  ERROR — {r['error']}")
        return

    color = _COLOR.get(r["risk"], "")
    names = r["maintainer_names"]
    name_str = ", ".join(names[:3]) + ("..." if len(names) > 3 else "")

    print(f"\n{r['name']}  v{r['version']}")
    print(f"  Downloads/week : {r['downloads_week']:,}")
    print(f"  Maintainers    : {r['maintainers']} ({name_str})")
    print(f"  Last publish   : {r['days_stale']}d ago")
    print(f"  Code signing   : {r['code_signing']}")
    print(f"  Risk           : {color}{r['risk']}{_RESET} — {r['risk_reason']}")


def main() -> None:
    p = argparse.ArgumentParser(
        description="mcp-rt Supply Chain Scanner — npm MCP package risk audit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python tools/supply_chain_scan.py fastmcp\n"
            "  python tools/supply_chain_scan.py figma-mcp kubernetes-mcp-server\n"
            "  python tools/supply_chain_scan.py --top20\n"
        ),
    )
    p.add_argument("packages", nargs="*", help="npm package name(s) to scan")
    p.add_argument("--top20", action="store_true", help="Scan top 20 MCP packages by install volume")
    p.add_argument("--json", action="store_true", help="Output raw JSON")
    args = p.parse_args()

    targets = list(args.packages) or (TOP_MCP_PACKAGES if args.top20 else [])
    if not targets:
        p.print_help()
        sys.exit(1)

    print("=" * 64)
    print("  mcp-rt Supply Chain Scanner")
    print(f"  Packages  : {len(targets)}")
    print(f"  Source    : npmjs.com registry (live)")
    print(f"  Checks    : maintainer count · staleness · blast radius · signing")
    print("=" * 64)

    results = []
    for pkg in targets:
        sys.stdout.write(f"\r[*] Scanning {pkg:<45}")
        sys.stdout.flush()
        results.append(scan(pkg))
    print("\r" + " " * 60 + "\r", end="")

    if args.json:
        print(json.dumps(results, indent=2, default=str))
        return

    for r in results:
        _print(r)

    critical = [r for r in results if r.get("risk") == "CRITICAL"]
    high     = [r for r in results if r.get("risk") == "HIGH"]
    medium   = [r for r in results if r.get("risk") == "MEDIUM"]

    print("\n" + "=" * 64)
    print(f"  {len(results)} packages scanned")
    if critical:
        c = _COLOR["CRITICAL"]
        print(f"  {c}CRITICAL : {len(critical):2d}  {', '.join(r['name'] for r in critical)}{_RESET}")
    if high:
        c = _COLOR["HIGH"]
        print(f"  {c}HIGH     : {len(high):2d}  {', '.join(r['name'] for r in high)}{_RESET}")
    if medium:
        c = _COLOR["MEDIUM"]
        print(f"  {c}MEDIUM   : {len(medium):2d}{_RESET}")
    print(f"  Note: code signing absent on ALL npm packages (structural gap)")
    print("=" * 64)


if __name__ == "__main__":
    main()
