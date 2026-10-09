"""`mcp-rt` — unified command-line entry for the MCP security engine.

Installed via `pip install -e .` (see pyproject [project.scripts]), then:

    mcp-rt scan      --target-stdio "npx some-mcp-server"     # single credential-exfil scan
    mcp-rt probe     --target-stdio "..."                     # the 5 impl-bug probes
    mcp-rt token     --target-stdio "..."                     # token passthrough / confused deputy
    mcp-rt report    --target-stdio "..." [--exit-code] [--pdf]  # full VAPT + OWASP report (+PDF deliverable)
    mcp-rt attest    --target-stdio "..."                     # signed ground-truth attestation + badge (verify offline)
    mcp-rt diff      --target-stdio "..."                     # re-test: RESOLVED / NEW / UNCHANGED vs last scan
    mcp-rt benchmark --target-stdio "..."                     # grade + scorecard
    mcp-rt sweep     [--cap N] [--max-downloads N]            # discover + benchmark the long tail
    mcp-rt daily     [--cap N] [--plan] [--top-only]          # daily discovery + enrich (curated + fresh)
    mcp-rt monitor   --from-ledger N | --targets "..."        # continuous re-scan + ALERT on new findings
    mcp-rt ci        [--fail-on critical] [--sarif out.sarif] # CI gate: scan repo MCP configs -> SARIF
    mcp-rt fleet     --config team/.mcp.json | --targets "..." # whole-fleet report + supply-chain risk
    mcp-rt remote    --url https://.../mcp --authorized-by "..."   # AUTHORIZED hosted-server scan
    mcp-rt stats                                             # canonical stats.json (single source of truth)
    mcp-rt hunt      --target-stdio "..."                     # alias for report

One dispatcher over the hunt modules, so there is one product command, not a kit of scripts.
"""
from __future__ import annotations

import sys

_USAGE = __doc__.split("Installed", 1)[1] if "Installed" in __doc__ else __doc__

_COMMANDS = {
    "scan": ("mcp_rt.scan.__main__", "main"),
    "probe": ("hunt.probes", "main"),
    "token": ("hunt.family_b", "main"),
    "report": ("hunt.report", "main"),
    "attest": ("hunt.attestation", "main"),      # scan -> signed, offline-verifiable attestation (+badge)
    "registry": ("hunt.registry", "main"),       # build a static attestation registry from a folder
    "serve": ("hunt.webapp", "main"),            # scan service + dashboard (localhost or VPS)
    "org": ("hunt.orgadmin", "main"),            # platform tenant admin: create orgs, mint tokens
    "hunt": ("hunt.report", "main"),
    "diff": ("hunt.diff", "main"),
    "monitor": ("hunt.monitor", "main"),
    "ci": ("hunt.ci", "main"),
    "fleet": ("hunt.fleet", "main"),
    "benchmark": ("hunt.benchmark", "main"),
    "sweep": ("hunt.sweep", "main"),
    "daily": ("hunt.daily", "main"),
    "remote": ("hunt.remote", "main"),
    "scorecard": ("hunt.scorecard", "main"),
    "stats": ("hunt.stats", "main"),
    "hunt-cap": ("hunt.hunt_cap", "main"),       # MCP-00 Leg 1: undeclared-capability (strace sensor)
    "hunt-agent": ("hunt.hunt_agent", "main"),   # MCP-00 Leg 2: agent-in-the-loop (Advanced Red-Team)
    "supply": ("hunt.supply_chain", "main"),     # MCP04: supply-chain / install-time code execution
    "db": ("hunt.dbview", "main"),               # inspect the findings database without SQL
    "check": ("hunt.check", "main"),             # assess a server completely (scan + supply + MCP-CAP)
    "redteam-live": ("hunt.redteam_live", "main"),  # honeytoken-grounded live agent red-team (MCP06)
}


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help", "help"):
        print("mcp-rt — MCP security engine\nusage:" + _USAGE)
        return 0 if argv else 2
    cmd, rest = argv[0], argv[1:]
    target = _COMMANDS.get(cmd)
    if not target:
        print(f"mcp-rt: unknown command {cmd!r}\nusage:" + _USAGE)
        return 2
    import importlib
    mod = importlib.import_module(target[0])
    return getattr(mod, target[1])(rest)


if __name__ == "__main__":
    sys.exit(main())
