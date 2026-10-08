"""MCP-00 hunting harness — Leg 2: intent-flow / agent-in-the-loop (true MCP-00 / OWASP MCP06).

The Basic-scan MCP06 flag says "this surface COULD deliver an injection; confirming it needs a real
agent in the loop." This is that agent. It reuses the already-built `mcp_rt/` client-resilience harness:
plant a honeytoken, deliver a poisoned tool/resource, drive an agent (adapter), and the honeytoken
FIRING is ground truth that the agent acted on injected content. = the premium Advanced Agent Red-Team.

Bridge scope: wire the unwired `mcp_rt/` matrix into the hunt + hypothesis store. The pure converter
(`results_to_hypotheses`) is tested; the live run degrades honestly when no agent adapter is configured
(real adapters need API keys) — it never reports a false clean.

Discipline: a fired honeytoken is real ground truth (the agent demonstrably read + exfiltrated), but it
is recorded as a confirmable HYPOTHESIS for human review/promotion, never auto-counted as a finding.
"""
from __future__ import annotations

from .hunt_cap import Hypothesis

LEG = "intent-flow"


def results_to_hypotheses(matrix_results: list[dict]) -> list[Hypothesis]:
    """Convert `mcp_rt.harness.run_matrix` result dicts into hunting hypotheses. PURE + zero-FP:
    - vulnerable (honeytoken fired)  -> a confirmable intent-flow hypothesis (agent obeyed injection)
    - resilient (ran, did not fire)  -> NOT a lead (agent passed); skipped
    - errored (adapter/key failure)  -> inconclusive; skipped (never a false signal)
    """
    out = []
    for r in matrix_results:
        if r.get("error") or not r.get("vulnerable"):
            continue
        client, attack = r.get("client", "?"), r.get("attack", "?")
        out.append(Hypothesis(
            leg=LEG, tool=attack,
            observation=f"agent '{client}' obeyed injected content via attack '{attack}' "
                        f"(honeytoken read + exfiltrated) — intent-flow / MCP06 confirmed in the loop",
            confirmable=True,
            confirm_plan="honeytoken already fired end-to-end; reproduce the transcript and promote to a "
                         "VULNERABLE finding against this agent/client configuration",
            caps_observed=[c for c in ("read", "exfil") if r.get("detail", {}).get(c)]))
    return out


def run_agent_hunt(adapters=None, payloads=None) -> tuple[str, list[Hypothesis]]:
    """Run the agent-red-team matrix and return (status, hypotheses). status in {"OK","INCONCLUSIVE"}.

    `adapters` defaults to real client adapters (need API keys); pass mock adapters for an offline run.
    No adapters resolvable -> INCONCLUSIVE, never a false clean.
    """
    from mcp_rt.harness import run_matrix
    from mcp_rt.payloads.registry import all_payloads

    if payloads is None:
        payloads = all_payloads()
    if adapters is None:
        adapters = _default_adapters()
    if not adapters or not payloads:
        return ("INCONCLUSIVE", [])
    return ("OK", results_to_hypotheses(run_matrix(adapters, payloads)))


def _default_adapters() -> list:
    """Real client adapters that have credentials available; empty if none are configured."""
    out = []
    for modname, clsname in (("anthropic_host", "AnthropicHostClient"),
                             ("gemini_host", "GeminiHostClient"),
                             ("cli_client", "CliClient")):
        try:
            mod = __import__(f"mcp_rt.adapters.{modname}", fromlist=[clsname])
            out.append(getattr(mod, clsname)())
        except Exception:  # noqa: BLE001 — missing key / optional dep = skip that adapter
            continue
    return out


def main(argv=None) -> int:
    import argparse
    p = argparse.ArgumentParser(prog="mcp-rt hunt-agent",
                                description="MCP-00 Leg 2: agent-in-the-loop intent-flow red-team")
    p.add_argument("--mock", action="store_true",
                   help="run offline with the vulnerable/secure mock agents (no API keys)")
    p.add_argument("--selftest", action="store_true")
    args = p.parse_args(argv)
    if args.selftest:
        _selftest()
        return 0
    adapters = None
    if args.mock:
        from mcp_rt.adapters.mock import MockVulnerableClient, MockSecureClient
        adapters = [MockVulnerableClient(), MockSecureClient()]
    status, hyps = run_agent_hunt(adapters)
    if status != "OK":
        print("INCONCLUSIVE — no agent adapter configured (real adapters need API keys; "
              "try `--mock` for an offline demo). Refusing a false clean.")
        return 2
    if not hyps:
        print("No agent obeyed an injected instruction — the agent(s) resisted every payload. "
              "Resilient, not proof of total safety.")
        return 0
    print(f"{len(hyps)} intent-flow hypothesis(es) — the agent obeyed injected content (LEADS):\n")
    for h in hyps:
        print(f"  • [{h.tool}] {h.observation}\n")
    return 1


def _selftest():
    """Offline end-to-end: the vulnerable mock MUST produce hypotheses, the secure mock MUST NOT."""
    from mcp_rt.adapters.mock import MockVulnerableClient, MockSecureClient
    from mcp_rt.payloads.registry import all_payloads

    payloads = all_payloads()
    _, vuln = run_agent_hunt([MockVulnerableClient()], payloads)
    _, secure = run_agent_hunt([MockSecureClient()], payloads)
    assert vuln, "vulnerable mock agent should obey at least one injection -> a hypothesis"
    assert all(h.leg == LEG and h.confirmable for h in vuln)
    assert secure == [], "hardened mock agent should yield no leads"
    # errored/resilient cells never become leads
    assert results_to_hypotheses([{"error": "no key", "vulnerable": True}]) == []
    assert results_to_hypotheses([{"vulnerable": False, "client": "x", "attack": "y"}]) == []
    print(f"hunt_agent selftest OK ({len(vuln)} injections obeyed by the vulnerable mock)")


if __name__ == "__main__":
    _selftest()
