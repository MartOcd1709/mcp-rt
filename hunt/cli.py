"""`mcp-rt` — unified command-line entry for the MCP security engine.

Installed via `pip install -e .` (see pyproject [project.scripts]), then:

  ASSESS ONE SERVER
    mcp-rt check     --target-stdio "..."                     # ONE command: full scan + supply-chain + MCP-CAP, consolidated verdict
    mcp-rt flow      run --target-stdio "..." | list | show <id>  # end-to-end assessment as a tracked, replayable Flow (persisted step trace)
    mcp-rt report    --target-stdio "..." [--exit-code] [--pdf]  # full VAPT + OWASP report (+PDF deliverable); `hunt` is an alias
    mcp-rt scan      --target-stdio "npx some-mcp-server"     # single credential-exfil scan
    mcp-rt probe     --target-stdio "..."                     # the stdio impl-bug probes (SSRF, injection, traversal, ...)
    mcp-rt token     --target-stdio "..."                     # token passthrough / confused deputy
    mcp-rt benchmark --target-stdio "..."                     # grade + scorecard vs OWASP MCP Top 10
    mcp-rt diff      --target-stdio "..."                     # re-test: RESOLVED / NEW / UNCHANGED vs last scan
    mcp-rt attest    --target-stdio "..."                     # signed ground-truth attestation + badge (verify offline)

  HUNT THE UNDISCOVERED (novel-class legs)
    mcp-rt hunt-cap  --target-stdio "..." [--record]         # MCP-CAP: undeclared-capability / consent-gap (strace sensor)
    mcp-rt hunt-agent [--mock]                               # Advanced agent-in-the-loop red-team (intent-flow / MCP06)
    mcp-rt redteam-live [--issue --timeout]                  # honeytoken-grounded LIVE agent red-team (MCP06)
    mcp-rt supply    <path|launch-cmd>                       # MCP04: supply-chain / install-time code execution + OSV

  AUTONOMOUS
    mcp-rt agent     --target-stdio "..."                    # sandboxed ReAct assessment agent (ground-truth gated)
    mcp-rt pentest   --target-stdio "..."                    # coordinated multi-agent assessment (plan->prove->refine)
    mcp-rt assess    --target-stdio "..."                    # full lifecycle: scan/VA -> correlate -> remediate
    mcp-rt assess-report                                     # triaged assessment report (markdown) from the ledger

  DISCOVER & SCALE
    mcp-rt discover  [--subnet ...]                          # "nmap for MCP": enumerate servers on host (consent-gated subnet)
    mcp-rt hunt-all                                          # end-to-end: discover -> assess each -> correlate -> report
    mcp-rt sweep     [--cap N] [--max-downloads N]           # discover + benchmark the long tail
    mcp-rt daily     [--cap N] [--plan] [--top-only]         # daily discovery + enrich (curated + fresh)
    mcp-rt monitor   --from-ledger N | --targets "..."       # continuous re-scan + ALERT on new findings
    mcp-rt fleet     --config team/.mcp.json | --targets "..." # whole-fleet report + supply-chain risk

  INTEGRATE / SHIP / INSPECT
    mcp-rt ci        [--fail-on critical] [--sarif out.sarif] # CI gate: scan repo MCP configs -> SARIF
    mcp-rt remote    --url https://.../mcp --authorized-by "..."   # AUTHORIZED hosted-server scan (consent-gated)
    mcp-rt serve     [--host --port]                         # scan service + dashboard (localhost or VPS)
    mcp-rt scorecard                                         # public HTML scorecard from the ledger (disclosure-safe)
    mcp-rt registry  <folder>                               # build a static attestation registry
    mcp-rt stats                                             # canonical stats.json (single source of truth)
    mcp-rt db        [<table> [-n N]] [--backfill]           # inspect the findings DB without SQL
    mcp-rt org                                               # platform tenant admin: create orgs, mint tokens

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
    "assess": ("hunt.orchestrator", "main"),     # full lifecycle: scan/VA -> correlate -> remediate
    "assess-report": ("hunt.assess_report", "main"),  # triaged assessment report (markdown) from the ledger
    "agent": ("mcp_rt.agent_loop", "main"),      # autonomous sandboxed assessment agent (ReAct loop)
    "pentest": ("mcp_rt.assessment", "main"),    # coordinated multi-agent assessment (plan->prove->refine)
    "discover": ("hunt.discover", "main"),       # find MCP servers on this host (configs + packages)
    "hunt-all": ("hunt.pipeline", "main"),       # end-to-end: discover -> assess each -> correlate -> report
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
    "flow": ("hunt.flow", "main"),               # end-to-end assessment as a tracked, replayable Flow
    "redteam-live": ("hunt.redteam_live", "main"),  # honeytoken-grounded live agent red-team (MCP06)
}


def _install_graceful_sigterm() -> None:
    """Turn SIGTERM into KeyboardInterrupt so `async with stdio_client(...)` unwinds and
    terminates the spawned target server, instead of leaving it orphaned on a hard kill.
    No-op off the main thread / where signals are unsupported."""
    import signal
    try:
        signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    except (ValueError, OSError):
        pass


def main(argv=None) -> int:
    _install_graceful_sigterm()
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
