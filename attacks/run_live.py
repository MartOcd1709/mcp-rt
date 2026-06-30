"""Live test — run the FREE Gemini adapter against the full attack corpus.

    export GEMINI_API_KEY=...        # free key: https://aistudio.google.com/apikey
    python3 run_live.py

Prints the resilience matrix plus each transcript so you can see exactly what the
real model did. Honeytoken-only + loopback canary => safe to run.
"""
import os
import sys

# register the full corpus
import mcp_rt.payloads.tool_poisoning         # noqa: F401
import mcp_rt.payloads.return_value_injection  # noqa: F401
import mcp_rt.payloads.tool_shadowing          # noqa: F401
import mcp_rt.payloads.hidden_unicode          # noqa: F401
import mcp_rt.payloads.rug_pull                # noqa: F401

from mcp_rt.harness import run_matrix
from mcp_rt.payloads.registry import all_payloads
from mcp_rt.report import print_matrix, write_html, write_json
from mcp_rt.store import merge_and_save, settled_attacks

STORE = "report_live.json"

if __name__ == "__main__":
    if not (os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")):
        sys.exit(
            "Set a free Gemini key first:\n"
            "  export GEMINI_API_KEY=...   (get one at https://aistudio.google.com/apikey)"
        )

    from mcp_rt.adapters.gemini_host import GeminiHostClient

    client = GeminiHostClient()
    # Accumulate: only run attacks that don't already have a verdict (saves quota).
    done = settled_attacks(STORE, client.name)
    todo = [p for p in all_payloads() if p.name not in done]
    if done:
        print(f"Already settled (skipping): {sorted(done)}")
    print(f"Running {len(todo)} attack(s) against real Gemini...\n")

    new_results = run_matrix([client], todo) if todo else []
    all_results = merge_and_save(STORE, new_results)

    print_matrix(all_results)
    write_html(all_results, "report_live.html", title="mcp-rt — Gemini Resilience Matrix")
    print("\nArtifacts: report_live.json (store), report_live.html")

    print("\n========== TRANSCRIPTS (this run) ==========")
    for r in new_results:
        status = f"ERROR: {r['error']}" if r["error"] else ("VULNERABLE" if r["vulnerable"] else "RESILIENT")
        print(f"\n--- {r['attack']}  =>  {status} ---")
        for line in r["transcript"]:
            print("   ", line)
