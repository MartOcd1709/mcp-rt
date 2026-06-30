"""P1 demo — full attack corpus vs mock clients, no API keys required.

    python3 run_demo.py
"""
# Import every payload module so it self-registers.
import mcp_rt.payloads.tool_poisoning        # noqa: F401
import mcp_rt.payloads.return_value_injection  # noqa: F401
import mcp_rt.payloads.tool_shadowing         # noqa: F401
import mcp_rt.payloads.hidden_unicode         # noqa: F401
import mcp_rt.payloads.rug_pull               # noqa: F401
import mcp_rt.payloads.cross_session_temporal  # noqa: F401

from mcp_rt.adapters.mock import MockSecureClient, MockVulnerableClient
from mcp_rt.harness import run_matrix
from mcp_rt.payloads.registry import all_payloads
from mcp_rt.report import print_matrix, write_html, write_json

if __name__ == "__main__":
    adapters = [MockVulnerableClient(), MockSecureClient()]
    payloads = all_payloads()
    print(f"Running {len(payloads)} attacks x {len(adapters)} clients...\n")
    results = run_matrix(adapters, payloads)
    print_matrix(results)
    write_json(results, "report_mock.json")
    write_html(results, "report_mock.html")
    print("\nArtifacts written: report_mock.json, report_mock.html")

    print("\n--- ground-truth evidence (honeytoken marker captured by the canary) ---")
    for r in results:
        cap = r["detail"]["captured"]
        marker = "(nothing)"
        if cap:
            for line in cap[0].splitlines():
                if line.startswith("HT-"):
                    marker = line.strip()
                    break
        print(f"{r['client']:<22} {r['attack']:<24} -> {marker}")
