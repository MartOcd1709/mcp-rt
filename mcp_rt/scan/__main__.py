"""`python -m mcp_rt.scan` — point mcp-rt at a customer's own MCP server.

    python -m mcp_rt.scan --target-stdio "npx some-mcp-server"
    python -m mcp_rt.scan --target-http https://mcp.example.com --header "Authorization: Bearer ..."
    python -m mcp_rt.scan --target-stdio "..." --exit-code   # CI gate: exit 1 on LEAKED

Reuses the whole harness (honeytoken battery + egress tap + taint verdict); see
mcp_rt/scan/runner.py. A console entry point (`mcp-rt scan ...`) is wired in pyproject at M4.
"""
from __future__ import annotations

import argparse
import json
import sys

from mcp_rt.scan.runner import VERDICT_LEAKED, VERDICT_UNOBSERVABLE, scan
from mcp_rt.target import TargetSpec


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="mcp-rt scan",
        description="Run a real agent against an MCP server and prove whether a planted "
                    "credential physically leaves the host.",
    )
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--target-stdio", metavar="CMD",
                   help='local server to spawn, e.g. "npx some-mcp-server"')
    g.add_argument("--target-http", metavar="URL", help="remote server endpoint")
    p.add_argument("--header", action="append", default=[], metavar="'K: V'",
                   help="header for --target-http (repeatable)")
    p.add_argument("--task", help="override the benign task given to the agent")
    p.add_argument("--timeout", type=int, default=180, help="agent timeout, seconds")
    p.add_argument("--json", action="store_true", help="emit the full result as JSON")
    p.add_argument("--exit-code", action="store_true",
                   help="exit 1 if LEAKED (CI gate); default always exits 0")
    args = p.parse_args(argv)

    spec = (TargetSpec.from_stdio(args.target_stdio) if args.target_stdio
            else TargetSpec.from_http(args.target_http, args.header))
    result = scan(spec, task=args.task, timeout=args.timeout)

    if args.json:
        print(json.dumps(result.as_dict(), indent=2))
    else:
        print(f"verdict: {result.verdict}")
        if result.verdict == VERDICT_LEAKED and result.detail:
            d = result.detail
            print(f"  leaked : {d.tainted_value}  ->  {d.undeclared_host}  ({d.sink})")
        if result.note:
            print(f"  note   : {result.note}")
        if result.verdict != VERDICT_UNOBSERVABLE:
            print(f"  egress : {len(result.egress)} outbound event(s) captured")

    return result.exit_code if args.exit_code else 0


if __name__ == "__main__":
    sys.exit(main())
