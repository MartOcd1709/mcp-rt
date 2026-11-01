"""Exploit correlation — chain individually-confirmed findings into a proven attack path.

A single finding ("this tool has a path-traversal") is useful; a *chain* ("inject an instruction →
it reads a secret → it exfiltrates to an undeclared host") is the real-world impact. This module
composes CONFIRMED findings (ground-truth, already proven) into multi-step chains and scores them —
it never invents a vulnerability, only connects ones that were each separately proven.

Capability model: each finding grants a capability (INJECT / READ / EXEC / EGRESS / CRED). A chain is
an ordered path through those capabilities that matches a known impact pattern. Chains are reported at
the top of the severity list because they demonstrate end-to-end compromise, not a point weakness.

Reuses the `chains` / `chain_steps` tables already modeled in hunt/findings_db.py for persistence
(the orchestrator writes chains there); this module is the pure correlation logic.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# Which capability each detection class / technique grants once it is CONFIRMED.
CAPABILITY = {
    # INJECT — attacker-controlled instructions reach the agent/model
    "tool_poisoning": "INJECT", "return_value_injection": "INJECT", "api_error_injection": "INJECT",
    "indirect_prompt_injection": "INJECT", "prompt_template_injection": "INJECT",
    "return_value_prompt_injection": "INJECT", "return_value_context_injection": "INJECT",
    "sampling_instruction_laundering": "INJECT", "mcp_resource_injection": "INJECT",
    "cross_server_poisoning": "INJECT", "authority_injection": "INJECT",
    # READ — can reach secrets / out-of-scope data
    "path_traversal": "READ", "context_oversharing": "READ", "roots_path_manipulation": "READ",
    "honeytoken_path_alignment": "READ",
    # EXEC — reaches code/command execution
    "command_injection": "EXEC", "deserialization": "EXEC", "ssti": "EXEC", "arg_injection": "EXEC",
    # EGRESS — can send data off the host
    "ssrf": "EGRESS", "egress_evasion": "EGRESS", "bash_exfil_injection": "EGRESS",
    "network_position_delivery": "EGRESS", "server_side_workflow": "EGRESS",
    "workflow_scaffold_exfil": "EGRESS",
    # CRED — harvests credentials/tokens
    "token_passthrough": "CRED", "elicitation_credential_harvest": "CRED",
}

# Impact patterns: an ordered set of capabilities that together demonstrate a real attack.
# (name, required capabilities, severity, narrative template)
CHAIN_RULES = [
    ("credential_exfiltration", ("READ", "EGRESS"), "Critical",
     "a tool reads secret data and another sends it to an undeclared host — full credential exfiltration"),
    ("injected_exfiltration", ("INJECT", "EGRESS"), "Critical",
     "injected instructions drive the agent to exfiltrate data off the host"),
    ("remote_code_execution", ("INJECT", "EXEC"), "Critical",
     "injected/forwarded input reaches code or command execution"),
    ("credential_theft_chain", ("CRED", "EGRESS"), "Critical",
     "harvested credentials leave the host to an undeclared destination"),
    ("read_to_exec", ("READ", "EXEC"), "High",
     "data a tool can read influences a code/command path"),
]


@dataclass
class Chain:
    kind: str
    severity: str
    narrative: str
    steps: list = field(default_factory=list)      # the findings (dicts) forming the path

    def as_dict(self) -> dict:
        return {"kind": self.kind, "severity": self.severity, "narrative": self.narrative,
                "steps": [{"cls": s.get("cls") or s.get("technique"), "tool": s.get("tool", "")}
                          for s in self.steps]}


def _capability(finding: dict) -> str:
    key = finding.get("cls") or finding.get("technique") or ""
    return CAPABILITY.get(key, "")


def correlate(findings: list[dict]) -> list[Chain]:
    """Compose confirmed findings into proven attack chains, most-severe first.

    `findings` are ALREADY-CONFIRMED (ground-truth) findings; each should carry `cls` (or
    `technique`) and ideally `tool`. A chain forms only when every capability its rule requires is
    present among the confirmed findings — so a chain is itself ground-truth (built from proofs).
    """
    by_cap: dict[str, list[dict]] = {}
    for f in findings:
        cap = _capability(f)
        if cap:
            by_cap.setdefault(cap, []).append(f)

    chains: list[Chain] = []
    for kind, needed, sev, narrative in CHAIN_RULES:
        if all(cap in by_cap for cap in needed):
            steps = [by_cap[cap][0] for cap in needed]     # one representative finding per capability
            chains.append(Chain(kind=kind, severity=sev, narrative=narrative, steps=steps))

    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    chains.sort(key=lambda c: order.get(c.severity, 9))
    return chains
