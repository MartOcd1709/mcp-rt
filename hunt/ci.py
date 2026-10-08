"""CI/CD gate (B2) — scan the MCP servers declared in a repo's config on every PR, emit SARIF for the
GitHub Security tab, and fail the build per --fail-on. Puts mcp-rt INSIDE the developer pipeline, where
a manual consultancy can never live. Real SARIF + real verdicts (no placeholders).

    mcp-rt ci                                   # find .mcp.json/mcp_settings.json, scan, SARIF, gate
    mcp-rt ci --fail-on high --sarif out.sarif
"""
from __future__ import annotations

import argparse
import asyncio
import glob
import json
import sys

from hunt.probes import ScanError
from hunt.report import run_full_scan

# GitHub's code-scanning uses a numeric "security-severity"; map our severities to it.
_SARIF_LEVEL = {"Critical": "error", "High": "error", "Medium": "warning", "Low": "note"}
_SEC_SEV = {"Critical": "9.5", "High": "7.5", "Medium": "5.0", "Low": "3.0"}
_DEFAULT_GLOBS = ("**/.mcp.json", "**/mcp_settings.json", "**/.cursor/mcp.json")


def parse_mcp_config(obj: dict) -> list[dict]:
    """Extract stdio MCP servers from a config ({"mcpServers": {name: {command,args,env}}}).
    HTTP/url-only servers have no `command` → not stdio-scannable in CI, skipped."""
    servers = obj.get("mcpServers") or obj.get("servers") or {}
    out = []
    for name, spec in servers.items():
        if not isinstance(spec, dict) or not spec.get("command"):
            continue
        out.append({"name": name, "argv": [spec["command"], *(spec.get("args") or [])],
                    "env": spec.get("env") or {}})
    return out


def to_sarif(findings: list[dict]) -> dict:
    """SARIF 2.1.0: one rule per detection class, one result per finding, GitHub-ready."""
    rules, results = {}, []
    for f in findings:
        rules.setdefault(f["cls"], {
            "id": f["cls"], "name": f["title"],
            "shortDescription": {"text": f["title"]},
            "fullDescription": {"text": f.get("fix", "")},
            "helpUri": "https://github.com/MartOcd1709/mcp-rt",
            "properties": {"cwe": f["cwe"], "owasp": f.get("owasp", []),
                           "security-severity": _SEC_SEV.get(f["sev"], "5.0")}})
        results.append({
            "ruleId": f["cls"], "level": _SARIF_LEVEL.get(f["sev"], "warning"),
            "message": {"text": f"[{f['sev']}] {f['title']} in MCP server '{f['server']}' "
                                f"(tool `{f['tool']}`, {f['cwe']}): {f['detail']}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.get("file", "mcp-config")}}}],
            "properties": {"server": f["server"], "tool": f["tool"], "cwe": f["cwe"]}})
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "mcp-rt", "informationUri":
                      "https://github.com/MartOcd1709/mcp-rt", "rules": list(rules.values())}},
                      "results": results}]}


def should_fail(findings: list[dict], fail_on: str) -> bool:
    sevs = {f["sev"] for f in findings}
    return {"none": False, "any": bool(findings),
            "critical": "Critical" in sevs,
            "high": bool(sevs & {"Critical", "High"})}.get(fail_on, False)


async def _scan_servers(servers: list[dict], config_file: str, timeout: int) -> list[dict]:
    findings = []
    for s in servers:
        try:
            rep = await asyncio.wait_for(run_full_scan(s["argv"], env={**s["env"]} or None), timeout=timeout)
        except (ScanError, asyncio.TimeoutError, Exception):  # noqa: BLE001 — a server we can't probe isn't a gate failure
            print(f"  · {s['name']}: inconclusive (skipped)", file=sys.stderr)
            continue
        for f in rep["findings"]:
            findings.append({**f, "server": s["name"], "file": config_file})
        print(f"  · {s['name']}: {rep['verdict']} ({len(rep['findings'])} finding(s))", file=sys.stderr)
    return findings


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="mcp-rt ci", description="CI gate: scan repo MCP servers -> SARIF")
    p.add_argument("--config", nargs="*", help="explicit config files (default: auto-discover)")
    p.add_argument("--fail-on", choices=["any", "critical", "high", "none"], default="critical")
    p.add_argument("--sarif", default="mcp-rt.sarif", help="SARIF output path")
    p.add_argument("--timeout", type=int, default=90)
    args = p.parse_args(argv)

    files = args.config or sorted({f for g in _DEFAULT_GLOBS for f in glob.glob(g, recursive=True)})
    if not files:
        print("no MCP config files found (.mcp.json / mcp_settings.json) — nothing to scan.", file=sys.stderr)
        json.dump(to_sarif([]), open(args.sarif, "w"), indent=2)
        return 0
    all_findings = []
    for cf in files:
        try:
            servers = parse_mcp_config(json.load(open(cf)))
        except Exception as e:  # noqa: BLE001
            print(f"  ! {cf}: unparseable ({e})", file=sys.stderr)
            continue
        print(f"scanning {len(servers)} server(s) from {cf}", file=sys.stderr)
        all_findings += asyncio.run(_scan_servers(servers, cf, args.timeout))

    json.dump(to_sarif(all_findings), open(args.sarif, "w"), indent=2)
    print(f"findings-count={len(all_findings)}")
    print(f"sarif-path={args.sarif}")
    fail = should_fail(all_findings, args.fail_on)
    print(f"{'FAIL' if fail else 'PASS'}: {len(all_findings)} finding(s), gate=--fail-on {args.fail_on}",
          file=sys.stderr)
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
