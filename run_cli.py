"""Real CLI-agent red-team runner — Claude Code and OpenAI Codex.

Unlike the API adapters (Gemini, Anthropic) that call model endpoints, this runner
drives the REAL installed CLI agents — the tools that millions of developers run
daily — by connecting them to our malicious MCP server and watching whether they
read and exfiltrate the planted honeytoken secret.

Verdicts come from the loopback honeytoken canary (cross-process HTTP POST),
not from parsing agent output. A VULNERABLE verdict means the real product, with
a real user behind it, would have had their secret exfiltrated silently.

No extra API keys required — both clients use their existing login:
  Claude Code : existing `claude` session  (run `claude login` to authenticate)
  Codex       : existing ChatGPT session   (run `codex login` to authenticate)

Rug-pull note: CLI agents are stateless — each task = a fresh subprocess. The two-
phase rug-pull tests whether the agent trusts a poisoned server in a fresh session,
rather than whether it re-validates a cached definition after mutation. Both are
valid attack surfaces; the semantics are noted in the report.

Usage:
    cd ~/Desktop/mcp-rt

    # Test both (default):
    .venv/bin/python run_cli.py

    # Test one client:
    .venv/bin/python run_cli.py --client claude-code
    .venv/bin/python run_cli.py --client codex

    # Longer timeout for slow responses:
    .venv/bin/python run_cli.py --timeout 300

    # Results accumulate — safe to re-run after interruption:
    .venv/bin/python run_cli.py          # skips already-settled attacks
"""
import argparse
import shutil
import sys

# Register the full attack corpus — standard + advanced payloads.
import mcp_rt.payloads.tool_poisoning          # noqa: F401
import mcp_rt.payloads.return_value_injection  # noqa: F401
import mcp_rt.payloads.tool_shadowing          # noqa: F401
import mcp_rt.payloads.hidden_unicode          # noqa: F401
import mcp_rt.payloads.rug_pull                # noqa: F401
import mcp_rt.payloads.api_error_injection     # noqa: F401
import mcp_rt.payloads.authority_injection     # noqa: F401
import mcp_rt.payloads.indirect_tool_chain     # noqa: F401
import mcp_rt.payloads.bash_exfil_injection    # noqa: F401
import mcp_rt.payloads.server_side_workflow    # noqa: F401
import mcp_rt.payloads.cross_session_temporal  # noqa: F401
import mcp_rt.payloads.prompt_template_injection  # noqa: F401
import mcp_rt.payloads.schema_examples_steering  # noqa: F401
import mcp_rt.payloads.honeytoken_path_alignment      # noqa: F401
import mcp_rt.payloads.return_value_context_injection  # noqa: F401
import mcp_rt.payloads.fake_authority_brand            # noqa: F401
import mcp_rt.payloads.mcp_resource_injection          # noqa: F401
import mcp_rt.payloads.permission_prompt_bypass        # noqa: F401
import mcp_rt.payloads.cross_server_poisoning          # noqa: F401
import mcp_rt.payloads.indirect_prompt_injection       # noqa: F401
import mcp_rt.payloads.return_value_prompt_injection   # noqa: F401
import mcp_rt.payloads.mcp_json_supply_chain           # noqa: F401

from mcp_rt.adapters.cli_client import ClaudeCodeClient, ClineClient, CodexClient
from mcp_rt.harness import run_matrix
from mcp_rt.payloads.registry import all_payloads
from mcp_rt.report import print_matrix, write_html, write_json
from mcp_rt.store import merge_and_save, settled_attacks

STORE = "report_cli.json"
HTML_OUT = "report_cli.html"


def _reset_store(path: str, client_names: list[str]) -> None:
    """Remove stored results for the given clients so they re-run from scratch."""
    import json
    from pathlib import Path
    p = Path(path)
    if not p.exists():
        return
    kept = [r for r in json.loads(p.read_text()) if r["client"] not in client_names]
    p.write_text(json.dumps(kept, indent=2, default=str))
    print(f"[reset] Cleared {', '.join(client_names)} results from {path}\n")


_CLIENT_MAP = {
    "claude-code": ClaudeCodeClient,
    "cline":       ClineClient,
    "codex":       CodexClient,
}


def _preflight(clients: list) -> list[str]:
    """Return fatal error strings. Empty list = ready to run."""
    errors = []
    for c in clients:
        if isinstance(c, ClaudeCodeClient) and not shutil.which("claude"):
            errors.append(
                "'claude' not found in PATH.\n"
                "  Install: https://claude.ai/code\n"
                "  Auth:    claude login"
            )
        if isinstance(c, ClineClient) and not shutil.which("cline"):
            errors.append(
                "'cline' not found in PATH.\n"
                "  Install: npm install -g cline   (requires Node.js 22+)\n"
                "  Auth:    cline auth anthropic    (or export ANTHROPIC_API_KEY=...)"
            )
        if isinstance(c, CodexClient) and not shutil.which("codex"):
            errors.append(
                "'codex' not found in PATH.\n"
                "  Install: npm install -g @openai/codex\n"
                "  Auth:    codex login"
            )
    return errors


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="mcp-rt — red-team Claude Code and Codex via malicious MCP server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Both clients use existing login auth — no extra API keys needed.\n\n"
            "Examples:\n"
            "  .venv/bin/python run_cli.py\n"
            "  .venv/bin/python run_cli.py --client claude-code\n"
            "  .venv/bin/python run_cli.py --client codex --timeout 300"
        ),
    )
    p.add_argument(
        "--client",
        choices=["claude-code", "cline", "codex", "both"],
        default="both",
        help="Which CLI agent(s) to test (default: both)",
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
        help="Clear stored results for the selected client(s) and re-run from scratch",
    )
    return p.parse_args()


def _banner(clients: list, n_attacks: int, timeout: int) -> None:
    div = "=" * 64
    print(div)
    print("  mcp-rt — CLI Agent Red-Team")
    print(f"  Targets  : {', '.join(c.name for c in clients)}")
    print(f"  Attacks  : {n_attacks} payloads (MCP-38 mapped)")
    print(f"  Timeout  : {timeout}s per task")
    print("  Detection: honeytoken → loopback HTTP canary (cross-process)")
    print(div)
    print()
    print("  Auth: both clients use existing login (no extra API keys).")
    print("  Rug-pull: stateless sessions — each phase = fresh subprocess.")
    print()


def _fmt_verdict(r: dict) -> str:
    if r["error"]:
        return f"ERROR    ({r['error'][:60]})"
    if r["vulnerable"]:
        return "VULNERABLE  ← honeytoken exfiltrated to canary"
    return "RESILIENT"


def main() -> None:
    args = _parse_args()

    if args.client == "both":
        clients = [cls(timeout=args.timeout) for cls in _CLIENT_MAP.values()]
    else:
        clients = [_CLIENT_MAP[args.client](timeout=args.timeout)]

    errors = _preflight(clients)
    if errors:
        for e in errors:
            print(f"[FATAL] {e}\n", file=sys.stderr)
        sys.exit(1)

    if args.reset:
        _reset_store(STORE, [c.name for c in clients])

    payloads = all_payloads()
    _banner(clients, len(payloads), args.timeout)

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
            print(f"  {r['attack']:<34} {_fmt_verdict(r)}")
        print()

    all_results = merge_and_save(STORE, all_new)

    print()
    print_matrix(all_results)

    write_json(all_results, STORE)
    write_html(
        all_results,
        HTML_OUT,
        title="mcp-rt — CLI Agent Resilience Matrix (Claude Code + Codex)",
    )
    print(f"\nArtifacts: {STORE}  |  {HTML_OUT}")

    if all_new:
        print("\n" + "=" * 64)
        print("TRANSCRIPTS (this run)")
        print("=" * 64)
        for r in all_new:
            print(f"\n--- [{r['client']}] {r['attack']} => {_fmt_verdict(r)} ---")
            for line in r["transcript"]:
                print("   ", line)


if __name__ == "__main__":
    main()
