"""Fleet + supply-chain view (B3) — scan a whole set of MCP servers (a customer's config or an explicit
list) into ONE combined posture: per-server verdict + findings, a fleet rollup, and a supply-chain risk
flag per package (single-maintainer / stale / high-blast-radius = OWASP MCP04). The "assess my entire
MCP fleet" deliverable a per-engagement consultancy can't match at scale.

    mcp-rt fleet --config team/.mcp.json
    mcp-rt fleet --targets "npx -y a-mcp" "uvx b-mcp"
"""
from __future__ import annotations

import argparse
import asyncio
import datetime
import json
import shlex
import sys
import urllib.parse
import urllib.request
from collections import Counter

from hunt.ci import parse_mcp_config
from hunt.probes import ScanError
from hunt.report import _target_name, run_full_scan


def supply_risk(meta: dict) -> list[str]:
    """Pure: supply-chain risk flags (OWASP MCP04) from package metadata. Empty meta → no flags."""
    flags = []
    m = meta.get("maintainers")
    if m is not None and m <= 1:
        flags.append("single-maintainer")
    days = meta.get("stale_days")
    if days is not None and days > 365:
        flags.append(f"stale ({days}d)")
    dl = meta.get("weekly_downloads")
    if dl is not None and dl >= 100_000:
        flags.append(f"high-blast-radius ({dl}/wk)")
    return flags


def _npm_meta(pkg: str) -> dict:
    try:
        d = json.load(urllib.request.urlopen(
            "https://registry.npmjs.org/" + urllib.parse.quote(pkg, safe="@/"), timeout=10))
        latest = (d.get("dist-tags") or {}).get("latest", "")
        t = (d.get("time") or {}).get(latest, "")
        days = None
        if t:
            dt = datetime.datetime.fromisoformat(t.replace("Z", "+00:00"))
            days = (datetime.datetime.now(datetime.timezone.utc) - dt).days
        return {"maintainers": len(d.get("maintainers") or []), "stale_days": days}
    except Exception:  # noqa: BLE001 — supply-chain meta is best-effort, never blocks the scan
        return {}


def _pkg_from_cmd(argv: list[str]) -> tuple[str, str]:
    """(ecosystem, package) from a launch command, for the supply-chain lookup."""
    name = _target_name(" ".join(argv))
    base = name.rsplit("@", 1)[0] if "@" in name[1:] else name   # strip a trailing @version
    eco = "pypi" if argv and argv[0] in ("uvx", "uv") else "npm"
    return eco, base


def fleet_rollup(results: list[dict]) -> dict:
    """Pure: aggregate per-server results into a fleet posture."""
    tested = [r for r in results if r["verdict"] != "INCONCLUSIVE"]
    vuln = [r for r in tested if r["verdict"] == "VULNERABLE"]
    classes = Counter(c for r in vuln for c in r["findings"])
    supply = [r for r in results if r.get("supply_flags")]
    return {"total": len(results), "scanned": len(tested), "vulnerable": len(vuln),
            "inconclusive": len(results) - len(tested), "by_class": dict(classes),
            "servers_with_supply_risk": len(supply)}


def render_fleet_md(results: list[dict], roll: dict) -> str:
    L = [f"# MCP Fleet Security Report", "",
         f"**Servers:** {roll['total']}  ·  **Scanned:** {roll['scanned']}  ·  "
         f"**Vulnerable:** {roll['vulnerable']}  ·  **Inconclusive:** {roll['inconclusive']}  ·  "
         f"**Supply-chain risk:** {roll['servers_with_supply_risk']}", "",
         "## Fleet summary", "",
         f"- findings by class: {roll['by_class'] or '{}'}", "",
         "| Server | Verdict | Findings | Supply-chain risk |", "|---|---|---|---|"]
    for r in sorted(results, key=lambda r: (r["verdict"] != "VULNERABLE", r["name"])):
        L.append(f"| `{r['name']}` | {r['verdict']} | {', '.join(r['findings']) or '—'} "
                 f"| {', '.join(r.get('supply_flags') or []) or '—'} |")
    L += ["", "> Ground-truth verdicts (planted honeytoken/sentinel/canary). Supply-chain flags map to "
          "OWASP MCP04 (supply chain / dependency tampering) — a risk signal, not a code finding.", ""]
    return "\n".join(L)


async def _scan_fleet(targets: list[dict], timeout: int) -> list[dict]:
    out = []
    for t in targets:
        eco, pkg = _pkg_from_cmd(t["argv"])
        meta = _npm_meta(pkg) if eco == "npm" else {}
        try:
            rep = await asyncio.wait_for(run_full_scan(t["argv"], env=t.get("env") or None), timeout=timeout)
            verdict, findings = rep["verdict"], [f["cls"] for f in rep["findings"]]
        except (ScanError, asyncio.TimeoutError, Exception):  # noqa: BLE001
            verdict, findings = "INCONCLUSIVE", []
        name = _target_name(" ".join(t["argv"]))
        flags = supply_risk(meta)
        print(f"  {name}: {verdict}" + (f" ({', '.join(findings)})" if findings else "")
              + (f"  [supply: {', '.join(flags)}]" if flags else ""), file=sys.stderr)
        out.append({"name": name, "verdict": verdict, "findings": findings, "supply_flags": flags})
    return out


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="mcp-rt fleet", description="scan a whole MCP fleet into one report")
    p.add_argument("--config", nargs="*", help="MCP config file(s) to read servers from")
    p.add_argument("--targets", nargs="*", help="explicit launch commands")
    p.add_argument("--timeout", type=int, default=120)
    args = p.parse_args(argv)

    targets = []
    for cf in args.config or []:
        try:
            targets += parse_mcp_config(json.load(open(cf)))
        except Exception as e:  # noqa: BLE001
            print(f"  ! {cf}: unparseable ({e})", file=sys.stderr)
    for cmd in args.targets or []:
        targets.append({"name": cmd, "argv": shlex.split(cmd), "env": {}})
    if not targets:
        print("no servers given — use --config <mcp.json> or --targets \"<cmd>\"", file=sys.stderr)
        return 2

    print(f"fleet: scanning {len(targets)} server(s)\n", file=sys.stderr)
    results = asyncio.run(_scan_fleet(targets, args.timeout))
    roll = fleet_rollup(results)
    print(render_fleet_md(results, roll))
    return 1 if roll["vulnerable"] else 0


if __name__ == "__main__":
    sys.exit(main())
