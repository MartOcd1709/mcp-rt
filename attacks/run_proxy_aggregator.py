"""Proxy Aggregator Trust-Laundering runner -- MCP-30 against real CLI MCP clients.

Attack (MCP-30): a malicious "upstream" contributes a poisoned tool that is relayed
to the client under a trusted aggregator's server identity, alongside genuinely
benign tools from other upstreams. The client has no protocol-level signal to
distinguish which upstream supplied which tool. See
docs/ATTACK_SURFACE_ANALYSIS.md section 2(a) and
mcp_rt/payloads/proxy_aggregator_trust_laundering.py for the full mechanism and the
honest novelty framing (this generalizes an existing peer-reviewed architecture
pattern; no first-ever claim is made).

This attack in this runner is BUILT and REGISTERED but UNCONFIRMED: no verdict here
has been reproduced against a live client.

Two comparison arms (see mcp_rt/payloads/proxy_aggregator_trust_laundering.py for the
full rationale):
  fronted     (default) -- the poisoned tool sits behind the "workspace-aggregator"
                            identity, alongside 4 benign tools across 2 namespaces.
  standalone  (--standalone) -- the identical poisoned tool, presented on its own
                            narrow server identity with no aggregator dressing and no
                            benign siblings. Isolates whether fronting changes the
                            outcome, per ATTACK_SURFACE_ANALYSIS.md 2(a) comparison (i).

Running both arms back to back against the same client is the intended use of this
runner: a difference in verdict or in client-expressed skepticism between the two
runs is the measurable claim the analysis document asks for.

Clients:
  Claude Code  (claude -p --dangerously-skip-permissions)
  Codex CLI    (codex exec --dangerously-bypass-approvals-and-sandbox)
  Gemini CLI   (gemini -p --yolo)

Results accumulate in report_proxy_aggregator.json -- safe to re-run after
interruption. Already-settled (client, arm) pairs are skipped automatically unless
--reset is given.

Usage:
  cd ~/Desktop/mcp-rt
  # Pre-flight: confirm no stale canary listener
  #   lsof -i :9999 2>/dev/null   (should be empty)
  #   pkill -f canary 2>/dev/null || true

  .venv/bin/python attacks/run_proxy_aggregator.py --client claude-code --reset --timeout 300
  .venv/bin/python attacks/run_proxy_aggregator.py --client codex --arm both --reset
  .venv/bin/python attacks/run_proxy_aggregator.py --client gemini --arm standalone
  .venv/bin/python attacks/run_proxy_aggregator.py                    # codex + gemini, both arms, resume
"""
import argparse
import shutil
import sys

# Registers the fronted (default) instance into the global registry.
import mcp_rt.payloads.proxy_aggregator_trust_laundering  # noqa: F401  MCP-30

from mcp_rt.adapters.cli_client import ClaudeCodeClient, ClineClient, CodexClient, GeminiCLIClient
from mcp_rt.harness import run_matrix
from mcp_rt.payloads.proxy_aggregator_trust_laundering import ProxyAggregatorTrustLaundering
from mcp_rt.report import print_matrix, write_html, write_json
from mcp_rt.store import merge_and_save, settled_attacks

STORE = "report_proxy_aggregator.json"
HTML_OUT = "report_proxy_aggregator.html"

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


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="mcp-rt Proxy Aggregator Trust-Laundering (MCP-30) vs CLI agents",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  .venv/bin/python attacks/run_proxy_aggregator.py --client claude-code --reset\n"
            "  .venv/bin/python attacks/run_proxy_aggregator.py --client codex --arm both\n"
            "  .venv/bin/python attacks/run_proxy_aggregator.py --client gemini --arm standalone"
        ),
    )
    p.add_argument(
        "--client",
        choices=["claude-code", "cline", "codex", "gemini", "both"],
        default="both",
        help="Which CLI client(s) to test (default: both = codex + gemini)",
    )
    p.add_argument(
        "--arm",
        choices=["fronted", "standalone", "both"],
        default="both",
        help="Which comparison arm(s) to run (default: both -- recommended, since the "
             "measurable claim is a difference between them)",
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
        return "VULNERABLE  <- honeytoken exfiltrated to canary"
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

    arms = []
    if args.arm in ("fronted", "both"):
        arms.append(ProxyAggregatorTrustLaundering(fronted=True))
    if args.arm in ("standalone", "both"):
        arms.append(ProxyAggregatorTrustLaundering(fronted=False))

    print("=" * 64)
    print("  mcp-rt Proxy Aggregator Trust-Laundering (MCP-30)")
    print(f"  Targets  : {', '.join(c.name for c in clients)}")
    print(f"  Arms     : {', '.join(a.name for a in arms)}")
    print(f"  Timeout  : {args.timeout}s per task")
    print("  Canary   : honeytoken -> loopback HTTP (cross-process)")
    print("  Status   : BUILT, UNCONFIRMED -- no verdict here has been reproduced.")
    print("=" * 64)
    print()

    all_new: list[dict] = []

    for client in clients:
        done = settled_attacks(STORE, client.name)
        todo = [a for a in arms if a.name not in done]
        if done:
            print(f"[{client.name}] Already settled (skipping): {sorted(done)}")
        print(f"[{client.name}] Running {len(todo)} arm(s)...")
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
        title="mcp-rt Proxy Aggregator Trust-Laundering (MCP-30) -- Resilience Matrix",
    )
    print(f"\nArtifacts: {STORE}  |  {HTML_OUT}")

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
