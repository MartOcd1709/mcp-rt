"""Flagship runner -- the 2025 MCP feature-surface family (sampling, elicitation,
structured output / resource links, roots) against real CLI MCP clients.

Attacks (run in order):
  MCP-26  sampling_instruction_laundering  -- server-initiated sampling/createMessage
                                              launders a directive through the client's
                                              own model
  MCP-27  elicitation_credential_harvest   -- elicitation/create form-mode field
                                              indistinguishable from a credential request
  MCP-28  structured_output_resource_link  -- resource_link content block delivered
                                              from a tool call, exempt from resources/list
  MCP-29  roots_path_manipulation          -- server-initiated roots/list, then the
                                              declared boundary is disregarded server-side

Every attack in this runner is BUILT and REGISTERED but UNCONFIRMED: no verdict here
has been reproduced against a live client. See docs/FRONTIER_ATTACKS.md.

Clients:
  Claude Code  (claude -p --dangerously-skip-permissions)
  Codex CLI    (codex exec --dangerously-bypass-approvals-and-sandbox)
  Gemini CLI   (gemini -p --yolo)

Results accumulate in report_flagship.json -- safe to re-run after interruption.
Already-settled attacks are skipped automatically.

Usage:
  cd ~/Desktop/mcp-rt
  # Pre-flight: confirm no stale canary
  #   lsof -i :9999 2>/dev/null  (should be empty)
  #   pkill -f canary 2>/dev/null || true

  .venv/bin/python attacks/run_flagship.py --client claude-code --reset --timeout 300
  .venv/bin/python attacks/run_flagship.py --client codex --reset --timeout 300
  .venv/bin/python attacks/run_flagship.py --client gemini --reset --timeout 300
  .venv/bin/python attacks/run_flagship.py                        # codex + gemini, resume
"""
import argparse
import shutil
import sys

# Import ONLY the 4 flagship payload modules. Each import registers its payload
# class into the global registry.
import mcp_rt.payloads.sampling_instruction_laundering  # noqa: F401  MCP-26
import mcp_rt.payloads.elicitation_credential_harvest   # noqa: F401  MCP-27
import mcp_rt.payloads.structured_output_resource_link  # noqa: F401  MCP-28
import mcp_rt.payloads.roots_path_manipulation           # noqa: F401  MCP-29

from mcp_rt.adapters.cli_client import ClaudeCodeClient, ClineClient, CodexClient, GeminiCLIClient
from mcp_rt.adapters.sampling_host import NoSamplingHost, SafeSamplingHost, VulnerableSamplingHost
from mcp_rt.harness import run_matrix
from mcp_rt.payloads.registry import all_payloads
from mcp_rt.report import print_matrix, write_html, write_json
from mcp_rt.store import merge_and_save, settled_attacks

STORE = "report_flagship.json"
HTML_OUT = "report_flagship.html"

FLAGSHIP_ATTACKS = [
    "sampling_instruction_laundering",
    "elicitation_credential_harvest",
    "structured_output_resource_link",
    "roots_path_manipulation",
]
_FLAGSHIP_SET = set(FLAGSHIP_ATTACKS)

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
        description="mcp-rt Flagship -- 4 2025-feature-surface attacks vs CLI agents",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  .venv/bin/python attacks/run_flagship.py --client claude-code --reset --timeout 300\n"
            "  .venv/bin/python attacks/run_flagship.py --client codex --reset\n"
            "  .venv/bin/python attacks/run_flagship.py"
        ),
    )
    p.add_argument(
        "--client",
        choices=["claude-code", "cline", "codex", "gemini", "both", "sampling-host"],
        default="both",
        help="Which client(s) to test (default: both = codex + gemini). "
             "'sampling-host' = the offline MCP-00b archetype hosts (no keys/binaries): "
             "proves the sampling gap fires un-gated and holds with human-in-the-loop.",
    )
    p.add_argument(
        "--timeout",
        type=int,
        default=300,
        metavar="SECS",
        help="Per-task subprocess timeout in seconds (default: 300 -- sampling/elicitation "
             "round trips can run long)",
    )
    p.add_argument(
        "--reset",
        action="store_true",
        help="Clear stored flagship results for the selected client(s) and re-run",
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
    elif args.client == "sampling-host":
        # In-process MCP-00b archetypes: no binary, no key, no timeout.
        clients = [VulnerableSamplingHost(), SafeSamplingHost(), NoSamplingHost()]
    else:
        clients = [_CLIENT_MAP[args.client](timeout=args.timeout)]

    errors = _preflight(clients)
    if errors:
        for e in errors:
            print(f"[FATAL] {e}", file=sys.stderr)
        sys.exit(1)

    if args.reset:
        _reset_store(STORE, [c.name for c in clients])

    all_p = all_payloads()
    by_name = {p.name: p for p in all_p}
    # The sampling hosts only exercise the sampling flow; the other flagship payloads
    # issue no sampling request, so scope the run to MCP-00b for a clean matrix.
    attack_names = (["sampling_instruction_laundering"]
                    if args.client == "sampling-host" else FLAGSHIP_ATTACKS)
    payloads = [by_name[name] for name in attack_names if name in by_name]

    if not payloads:
        print("[FATAL] No flagship payloads found in registry -- check imports.", file=sys.stderr)
        sys.exit(1)

    print("=" * 64)
    print("  mcp-rt Flagship -- 2025 MCP Feature-Surface Family")
    print(f"  Targets  : {', '.join(c.name for c in clients)}")
    print(f"  Attacks  : {len(payloads)} flagship payloads (MCP-26 / 27 / 28 / 29)")
    print(f"  Timeout  : {args.timeout}s per task")
    print("  Canary   : honeytoken -> loopback HTTP (cross-process)")
    print("  Status   : BUILT, UNCONFIRMED -- no verdict here has been reproduced.")
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
        title="mcp-rt Flagship -- 2025 Feature-Surface Resilience Matrix",
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
