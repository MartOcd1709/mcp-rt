"""Escalated chain runner for Claude Code — self-contained orchestration.

This runner exercises the escalated chains designed in docs/CC_ATTACK_CHAINS.md by
running ordered sequences of the ALREADY-CONFIRMED primitive payloads and reporting a
per-stage honeytoken-canary verdict for each. It does not define new payloads and does
not modify the malicious server; it composes existing registered payloads only.

Two constraints from the harness shape what "chain" means here:

  1. Claude Code invoked as `claude -p` is stateless between invocations, so trust does
     not carry through the model's context window across stages. Cross-session escalation
     is realised only by the `cross_session_temporal` payload, which transfers state
     through a server-side state file and is exercised as a single two-session payload.

  2. Each payload run plants its own honeytoken with its own canary. A stage's verdict is
     therefore scoped to that stage's canary. Chains A, C and D fuse two primitives into a
     single server surface and require a new payload module owned by the Payload Engineer;
     this runner exercises their confirmed REDUCED forms (the single primitive that already
     fires) as baselines, alongside the fully composed Chain B.

Default target is the mock client pair, which lets chain wiring be validated with no API
keys and no cost. The operator runs the live reproduction explicitly with
`--client claude-code`.

Usage:
  cd ~/Desktop/mcp-rt
  .venv/bin/python attacks/run_cc_chains.py --mock                       # wiring validation
  .venv/bin/python attacks/run_cc_chains.py --client claude-code --reset # operator live run
"""
import argparse
import shutil
import sys

# Import the confirmed primitive modules so they self-register into the global registry.
import mcp_rt.payloads.server_side_workflow      # noqa: F401  Chain D reduced form
import mcp_rt.payloads.cross_session_temporal     # noqa: F401  Chain B (full)
import mcp_rt.payloads.fake_authority_brand       # noqa: F401  authority primitive
import mcp_rt.payloads.mcp_resource_injection     # noqa: F401  Chain A/C reduced form (v3)

from mcp_rt.adapters.cli_client import ClaudeCodeClient
from mcp_rt.adapters.mock import MockSecureClient, MockVulnerableClient
from mcp_rt.harness import run_one
from mcp_rt.payloads.registry import all_payloads
from mcp_rt.store import merge_and_save

STORE = "report_cc_chains.json"

# Each chain is an ordered list of (stage_label, payload_name). Payload names refer to
# already-registered confirmed primitives. Chains A/C/D list their confirmed reduced form;
# the fully fused variants are described in docs/CC_ATTACK_CHAINS.md and require a new
# payload module. Chain B lists the two-session primitive that composes across sessions.
CHAINS: dict[str, list[tuple[str, str]]] = {
    "B_buried_cross_session": [
        ("cross_session_state", "cross_session_temporal"),
    ],
    "A_authority_split_resource__reduced": [
        ("split_resource_v3", "mcp_resource_injection_v3"),
    ],
    "C_ramp_split_resource__reduced": [
        ("split_resource_v3", "mcp_resource_injection_v3"),
    ],
    "D_server_side_under_authority__reduced": [
        ("server_side_workflow", "server_side_workflow"),
    ],
}


def _fmt(r: dict) -> str:
    if r["error"]:
        return f"ERROR    ({r['error'][:60]})"
    if r["vulnerable"]:
        return "VULNERABLE  <- honeytoken marker reached canary"
    return "RESILIENT"


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Escalated chain runner for Claude Code",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--client",
        choices=["claude-code", "mock"],
        default="mock",
        help="Target client (default: mock = wiring validation, no cost)",
    )
    p.add_argument(
        "--mock",
        action="store_true",
        help="Alias for --client mock",
    )
    p.add_argument(
        "--timeout",
        type=int,
        default=180,
        help="Per-stage subprocess timeout in seconds (claude-code only)",
    )
    p.add_argument(
        "--reset",
        action="store_true",
        help="Clear stored results before running",
    )
    return p.parse_args()


def _clients(args: argparse.Namespace) -> list:
    if args.mock or args.client == "mock":
        return [MockVulnerableClient(), MockSecureClient()]
    if not shutil.which("claude"):
        print(
            "[FATAL] 'claude' not in PATH. Install: npm install -g @anthropic-ai/claude-code",
            file=sys.stderr,
        )
        sys.exit(1)
    return [ClaudeCodeClient(timeout=args.timeout)]


def main() -> None:
    args = _parse_args()
    clients = _clients(args)

    if args.reset:
        from pathlib import Path
        Path(STORE).unlink(missing_ok=True)
        print(f"[reset] Cleared {STORE}\n")

    by_name = {p.name: p for p in all_payloads()}

    print("=" * 64)
    print("  mcp-rt — Escalated Chains vs Claude Code")
    print(f"  Targets : {', '.join(c.name for c in clients)}")
    print(f"  Chains  : {len(CHAINS)} (design: docs/CC_ATTACK_CHAINS.md)")
    print("  Canary  : per-stage honeytoken -> loopback HTTP (cross-process)")
    print("=" * 64)
    print()

    all_new: list[dict] = []
    for client in clients:
        for chain_name, stages in CHAINS.items():
            print(f"[{client.name}] chain {chain_name}")
            for label, payload_name in stages:
                payload = by_name.get(payload_name)
                if payload is None:
                    print(f"    {label:<24} MISSING payload '{payload_name}'")
                    continue
                r = run_one(client, payload)
                r["chain"] = chain_name
                r["stage"] = label
                all_new.append(r)
                print(f"    {label:<24} {_fmt(r)}")
            print()

    merge_and_save(STORE, all_new)
    print(f"Artifacts: {STORE}")
    print(
        "\nNote: VULNERABLE here means a stage's own canary received the marker. "
        "Confirmation of a full chain requires operator reproduction with --reset."
    )


if __name__ == "__main__":
    main()
