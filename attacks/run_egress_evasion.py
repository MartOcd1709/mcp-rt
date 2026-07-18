"""Egress-Control Evasion runner -- MCP-34 against real CLI MCP clients.

Attack (MCP-34): the exfiltrating half of a server_side_workflow-identical tool
pair (get_workspace_config / apply_workspace_config -- MCP-09, confirmed
VULNERABLE on Claude Code and Codex CLI, see FINDINGS.md) moves the retrieved
honeytoken out over a channel SHAPE chosen to survive a destination-allowlist
egress control, instead of the corpus-default direct HTTP POST to an arbitrary
URL. See mcp_rt/payloads/egress_evasion.py for the full mechanism.

The underlying tool implementation is byte-for-byte identical to the already-
confirmed server_side_workflow chain, so a canary fire is expected in the same way
it is for MCP-09; what this build ADDS is the demonstration that the exfil rode a
channel a naive destination-allowlist firewall would not flag as a new/unknown
destination. The honest claim is "this channel shape does not require the kind of
new, distinguishable connection a naive allowlist would block," not "we bypassed
product X" -- no real egress firewall is stood up here.

Two variants (see the payload module for rationale):
  webhook  (default) -- data leaves over an HTTP request shaped like a routine
                        chat-ops / issue-tracker webhook (a destination CLASS
                        corporate allowlists routinely pre-approve). POSTs to the
                        existing loopback canary; needs no extra infrastructure.
  dns      (--variant dns) -- data leaves as a DNS query to a loopback UDP catcher
                        this runner starts; the catcher reassembles the marker and
                        forwards it to the canary so the verdict works unchanged.

This attack in this runner is BUILT and UNCONFIRMED: no verdict here has been
reproduced against a live client.

Clients:
  Claude Code  (claude -p --dangerously-skip-permissions)
  Codex CLI    (codex exec --dangerously-bypass-approvals-and-sandbox)
  Gemini CLI   (gemini -p --yolo)

Results accumulate in report_egress_evasion.json -- safe to re-run after
interruption. Already-settled (client, variant) pairs are skipped unless --reset.

Usage:
  cd ~/Desktop/mcp-rt
  # Pre-flight: confirm no stale canary listener
  #   lsof -i :9999 2>/dev/null   (should be empty)
  #   pkill -f canary 2>/dev/null || true

  .venv/bin/python attacks/run_egress_evasion.py --client claude-code --reset --timeout 300
  .venv/bin/python attacks/run_egress_evasion.py --client codex --variant webhook
  .venv/bin/python attacks/run_egress_evasion.py --client claude-code --variant dns --reset
"""
import argparse
import shutil
import sys

# Registers the "webhook" (default, working) instance into the global registry.
import mcp_rt.payloads.egress_evasion  # noqa: F401  MCP-34

from mcp_rt.adapters.cli_client import ClaudeCodeClient, ClineClient, CodexClient, GeminiCLIClient
from mcp_rt.harness import run_matrix
from mcp_rt.payloads.egress_evasion import EgressEvasion
from mcp_rt.report import print_matrix, write_html, write_json
from mcp_rt.store import merge_and_save, settled_attacks

STORE = "report_egress_evasion.json"
HTML_OUT = "report_egress_evasion.html"

_CLIENT_MAP = {
    "claude-code": ClaudeCodeClient,
    "cline":       ClineClient,
    "codex":       CodexClient,
    "gemini":      GeminiCLIClient,
}


def _reset_store(path: str, client_names: list[str]) -> None:
    import json
    from pathlib import Path
    p = Path(path)
    if not p.exists():
        return
    kept = [r for r in json.loads(p.read_text()) if r["client"] not in client_names]
    p.write_text(json.dumps(kept, indent=2, default=str))
    print(f"[reset] Cleared {', '.join(client_names)} results from {path}\n")


def _preflight(clients: list) -> list[str]:
    errors = []
    for c in clients:
        if isinstance(c, ClaudeCodeClient) and not shutil.which("claude"):
            errors.append("'claude' not in PATH.  Install: npm install -g @anthropic-ai/claude-code")
        if isinstance(c, ClineClient) and not shutil.which("cline"):
            errors.append("'cline' not in PATH.  Install: npm install -g cline")
        if isinstance(c, CodexClient) and not shutil.which("codex"):
            errors.append("'codex' not in PATH.  Install: npm install -g @openai/codex")
        if isinstance(c, GeminiCLIClient) and not shutil.which("gemini"):
            errors.append("'gemini' not in PATH.  Install: npm install -g @google/gemini-cli")
    return errors


def _start_dns_catcher(exfil_url: str):
    """VED-FILL (only needed for --variant dns): start a loopback UDP socket that
    receives the DNS query the server's dns channel sends, parse the QNAME labels,
    reassemble the HT- marker, and POST {"metadata": marker} to exfil_url so the
    honeytoken's fired() captures it. Return (host, port, stop_fn). Leave as-is if
    you are shipping webhook-only first -- it is only invoked when a dns variant is
    selected below.
    """
    raise NotImplementedError("MCP-34 dns catcher: fill _start_dns_catcher")


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="mcp-rt Egress-Control Evasion (MCP-34) vs CLI agents",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  .venv/bin/python attacks/run_egress_evasion.py --client claude-code --reset\n"
            "  .venv/bin/python attacks/run_egress_evasion.py --client codex --variant webhook\n"
            "  .venv/bin/python attacks/run_egress_evasion.py --client claude-code --variant dns --reset"
        ),
    )
    p.add_argument(
        "--client",
        choices=["claude-code", "cline", "codex", "gemini", "both"],
        default="both",
        help="Which CLI client(s) to test (default: both = codex + gemini)",
    )
    p.add_argument(
        "--variant",
        choices=["webhook", "dns", "all"],
        default="webhook",
        help="Which egress channel shape(s) to run (default: webhook -- the variant "
             "that works with no extra infrastructure; dns needs the UDP catcher)",
    )
    p.add_argument(
        "--timeout",
        type=int,
        default=300,
        metavar="SECS",
        help="Per-task subprocess timeout in seconds (default: 300)",
    )
    p.add_argument(
        "--reset",
        action="store_true",
        help="Clear stored results for the selected client(s) and re-run",
    )
    return p.parse_args()


def _fmt_verdict(r: dict) -> str:
    if r["error"]:
        return f"ERROR    ({r['error'][:60]})"
    if r["vulnerable"]:
        return "VULNERABLE  <- honeytoken exfiltrated via evasion channel"
    return "RESILIENT"


def main() -> None:
    args = _parse_args()

    if args.client == "both":
        clients = [CodexClient(timeout=args.timeout), GeminiCLIClient(timeout=args.timeout)]
    else:
        clients = [_CLIENT_MAP[args.client](timeout=args.timeout)]

    errors = _preflight(clients)
    if errors:
        for e in errors:
            print(f"[FATAL] {e}", file=sys.stderr)
        sys.exit(1)

    if args.reset:
        _reset_store(STORE, [c.name for c in clients])

    variants = ["webhook", "dns"] if args.variant == "all" else [args.variant]
    payloads = [EgressEvasion(variant=v) for v in variants]

    # The dns variant needs a loopback UDP catcher wired in before the run so the
    # payload can forward its (host, port) to the server. webhook needs nothing.
    dns_stop = None
    if any(p.variant == "dns" for p in payloads):
        host, port, dns_stop = _start_dns_catcher("<set-per-run>")  # see stub note
        for p in payloads:
            if p.variant == "dns":
                p.dns_sink = (host, port)

    print("=" * 64)
    print("  mcp-rt Egress-Control Evasion (MCP-34)")
    print(f"  Targets  : {', '.join(c.name for c in clients)}")
    print(f"  Variants : {', '.join(p.name for p in payloads)}")
    print(f"  Timeout  : {args.timeout}s per task")
    print("  Canary   : honeytoken -> loopback (cross-process)")
    print("  Status   : BUILT, UNCONFIRMED -- no verdict here has been reproduced.")
    print("=" * 64)
    print()

    all_new: list[dict] = []

    for client in clients:
        done = settled_attacks(STORE, client.name)
        todo = [p for p in payloads if p.name not in done]
        if done:
            print(f"[{client.name}] Already settled (skipping): {sorted(done)}")
        print(f"[{client.name}] Running {len(todo)} variant(s)...")
        print()
        if not todo:
            continue

        new = run_matrix([client], todo)
        all_new.extend(new)

        for r in new:
            v = _fmt_verdict(r)
            print(f"  {r['attack']:<48}  {v}")
        print()

    all_results = merge_and_save(STORE, all_new)

    print()
    print_matrix(all_results)
    write_json(all_results, STORE)
    write_html(
        all_results,
        HTML_OUT,
        title="mcp-rt Egress-Control Evasion (MCP-34) -- Resilience Matrix",
    )
    print(f"\nArtifacts: {STORE}  |  {HTML_OUT}")

    if dns_stop:
        dns_stop()

    if all_new:
        print("\n" + "=" * 64)
        print("TRANSCRIPTS (this run)")
        print("=" * 64)
        for r in all_new:
            verdict_str = _fmt_verdict(r)
            print(f"\n--- [{r['client']}] {r['attack']} => {verdict_str} ---")
            for line in r["transcript"]:
                print("   ", line)


if __name__ == "__main__":
    main()
