"""Gen 2 targeted runner — 7 novel attacks x Claude Code + Codex CLI + Gemini CLI.

Attacks (run in order):
  MCP-19  cross_server_poisoning       — Server A return value hijacks Server B
  MCP-18  permission_prompt_social_eng — permission prompt UI can't reveal side effects
  MCP-17b mcp_resource_injection_v2    — natural JSON developer note in MCP resource
  MCP-17c mcp_resource_injection_v3    — split two-resource setup guide
  MCP-18  indirect_prompt_injection    — instruction lives in a file, not the server
  MCP-20  return_value_prompt_injection — injection in HTTP response body via web fetch
  MCP-21  mcp_json_supply_chain        — git clone auto-activates attacker server via .mcp.json

Clients:
  Claude Code  (claude -p --dangerously-skip-permissions)
  Codex CLI    (codex exec --dangerously-bypass-approvals-and-sandbox)
  Gemini CLI   (gemini -p --yolo)

Results accumulate in report_gen2.json — safe to re-run after interruption.
Already-settled attacks are skipped automatically.

Usage:
  cd ~/Desktop/mcp-rt
  # Pre-flight: confirm no stale canary
  #   lsof -i :9999 2>/dev/null  (should be empty)
  #   pkill -f canary 2>/dev/null || true

  .venv/bin/python run_gen2.py                     # both clients, sequential
  .venv/bin/python run_gen2.py --client codex      # Codex only
  .venv/bin/python run_gen2.py --client gemini     # Gemini CLI only
  .venv/bin/python run_gen2.py --reset             # clear stored results, re-run
  .venv/bin/python run_gen2.py --timeout 300       # 5-minute timeout per attack
"""
import argparse
import shutil
import sys

# Import ONLY the 6 Gen 2 payload modules.
# Each import registers its payload class(es) into the global registry.
# mcp_resource_injection registers three classes (v1, v2, v3); we filter to v2/v3 below.
import mcp_rt.payloads.cross_server_poisoning         # noqa: F401  MCP-19
import mcp_rt.payloads.permission_prompt_bypass       # noqa: F401  MCP-18 SE
import mcp_rt.payloads.mcp_resource_injection         # noqa: F401  MCP-17b + MCP-17c
import mcp_rt.payloads.indirect_prompt_injection      # noqa: F401  MCP-18 file
import mcp_rt.payloads.return_value_prompt_injection  # noqa: F401  MCP-20
import mcp_rt.payloads.mcp_json_supply_chain          # noqa: F401  MCP-21

from mcp_rt.adapters.cli_client import ClaudeCodeClient, ClineClient, CodexClient, GeminiCLIClient
from mcp_rt.harness import run_matrix
from mcp_rt.payloads.registry import all_payloads
from mcp_rt.report import print_matrix, write_html, write_json
from mcp_rt.store import merge_and_save, settled_attacks

STORE = "report_gen2.json"
HTML_OUT = "report_gen2.html"

# Ordered list of Gen 2 attack names (v1 of resource injection excluded).
GEN2_ATTACKS = [
    "cross_server_poisoning",
    "permission_prompt_social_eng",
    "mcp_resource_injection_v2",
    "mcp_resource_injection_v3",
    "indirect_prompt_injection",
    "return_value_prompt_injection",
    "mcp_json_supply_chain",
]
_GEN2_SET = set(GEN2_ATTACKS)

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
        if isinstance(c, ClineClient) and not os.environ.get("ANTHROPIC_API_KEY"):
            errors.append("ANTHROPIC_API_KEY not set.  export ANTHROPIC_API_KEY=sk-ant-...")
        if isinstance(c, CodexClient) and not shutil.which("codex"):
            errors.append("'codex' not in PATH.  Install: npm install -g @openai/codex")
        if isinstance(c, GeminiCLIClient) and not shutil.which("gemini"):
            errors.append("'gemini' not in PATH.  Install: npm install -g @google/gemini-cli")
    return errors


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="mcp-rt Gen 2 — 6 novel attacks x Codex CLI + Gemini CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  .venv/bin/python run_gen2.py\n"
            "  .venv/bin/python run_gen2.py --client codex --timeout 300\n"
            "  .venv/bin/python run_gen2.py --reset"
        ),
    )
    p.add_argument(
        "--client",
        choices=["claude-code", "cline", "codex", "gemini", "both"],
        default="both",
        help="Which CLI client(s) to test (default: both = codex + gemini; cline requires ANTHROPIC_API_KEY)",
    )
    p.add_argument(
        "--timeout",
        type=int,
        default=180,
        metavar="SECS",
        help="Per-task subprocess timeout in seconds (default: 180)",
    )
    p.add_argument(
        "--reset",
        action="store_true",
        help="Clear stored Gen 2 results for the selected client(s) and re-run",
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
        # "both" runs codex + gemini (original default); claude-code must be explicit
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

    # Filter registry to only the 6 Gen 2 attacks, preserving the canonical order.
    all_p = all_payloads()
    by_name = {p.name: p for p in all_p}
    payloads = [by_name[name] for name in GEN2_ATTACKS if name in by_name]

    if not payloads:
        print("[FATAL] No Gen 2 payloads found in registry — check imports.", file=sys.stderr)
        sys.exit(1)

    print("=" * 64)
    print("  mcp-rt Gen 2 — CLI Agent Red-Team")
    print(f"  Targets  : {', '.join(c.name for c in clients)}")
    print(f"  Attacks  : {len(payloads)} Gen-2 payloads")
    print(f"  Timeout  : {args.timeout}s per task")
    print("  Canary   : honeytoken -> loopback HTTP :9999 (cross-process)")
    print("  Web page : MCP-20 page server on :8888 (started by malicious_mcp_server)")
    print("=" * 64)
    print()

    all_new: list[dict] = []

    for client in clients:
        done = settled_attacks(STORE, client.name)
        todo = [p for p in payloads if p.name not in done]
        if done:
            print(f"[{client.name}] Already settled (skipping): {sorted(done)}")
        print(f"[{client.name}] Running {len(todo)} attack(s)...")
        print()
        if not todo:
            continue

        new = run_matrix([client], todo)
        all_new.extend(new)

        for r in new:
            v = _fmt_verdict(r)
            print(f"  {r['attack']:<38}  {v}")
        print()

    all_results = merge_and_save(STORE, all_new)

    print()
    print_matrix(all_results)
    write_json(all_results, STORE)
    write_html(
        all_results,
        HTML_OUT,
        title="mcp-rt Gen 2 — Codex + Gemini CLI Resilience Matrix",
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
