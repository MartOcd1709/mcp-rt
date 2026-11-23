"""MCP-00 proof: turn ONE sealed canary run (mcp_rt/runtime, Detector Unit 3) into findings and leads.

The sealed run plants realistic fake credentials (cloud keys, SSH key, .env, MCP client configs, shell history) whose
values carry this run's token, answers every elicitation and sampling request with token-bearing values, routes every
outbound packet to a recorder inside a network namespace that cannot reach the world, and only starts the server after
the seal is proven. Mapping (the enterprise-precision rule):

  a PLANTED SECRET seen leaving (file / elicitation answer / sampled completion)  -> VULNERABLE (proven), with
                                                    the destination, which secret, and the captured bytes
  only the tool's own ARGUMENT echoed to a destination, egress with no network purpose, or a "no network" claim
  contradicted by egress                                                          -> LEAD (SUSPECTED)
  a sampling request (P00b), or an elicitation asking for a secret-like field (P00c)  -> LEAD with the request text
  the seal could not be proven / the server never started                         -> INCONCLUSIVE (never CLEAN)

Pure and deterministic: `from_sealed(record)` reads the record `mcp_rt.runtime.runner.run_server` returns.
"""
from __future__ import annotations

import re

# suffix appended to the run token in each planted secret -> what a reader should be told was stolen
SECRET_LABELS = {
    "AWS": "fake AWS credentials (~/.aws/credentials)",
    "SSH": "fake SSH private key (~/.ssh/id_rsa)",
    "GCP": "fake Google Cloud credentials (~/.config/gcloud)",
    "NETRC": "fake ~/.netrc login",
    "ENV": "fake .env secrets",
    "MCPCFG": "fake MCP client config token (~/.cursor/mcp.json)",
    "HIST": "fake token in shell history (~/.bash_history)",
    "KUBE": "fake Kubernetes credentials (~/.kube/config)",
    "ELICIT": "the value the user typed into the server's elicitation form",
    "SAMPLE": "the model's completion returned to the server's sampling request",
}
_CLASS_BY_SECRET = {"ELICIT": "elicitation_credential_harvest", "SAMPLE": "sampling_instruction_laundering"}
_SECRET_FIELD = re.compile(r"(?i)pass(word|code|phrase)?|secret|token|api[_-]?key|credential|otp|\bpin\b|ssn|private|"
                           r"mfa|2fa|auth")
_SEAL_PROBLEMS = {"sandbox_unproven", "sandbox_unobservable", "probe_seal_incompatible"}


def from_sealed(rec: dict) -> dict:
    """{findings: [...], leads: [...], status: str} for one sealed run record."""
    findings: list[dict] = []
    leads: list[dict] = []
    method = rec.get("method", "")
    if method in _SEAL_PROBLEMS or not rec.get("proof") and rec.get("proof_error"):
        why = rec.get("proof_error") or rec.get("evidence") or method
        return {"findings": [], "leads": [], "status": f"inconclusive: seal unproven ({str(why)[:120]})"}
    for leak in rec.get("leaks") or []:
        suffix = leak["secret"]
        findings.append({
            "cls": _CLASS_BY_SECRET.get(suffix, "mcp_cap"), "tool": leak.get("tool") or "(server)", "sev": "Critical",
            "source": "sealed canary",
            "detail": (f"PROVEN: {SECRET_LABELS.get(suffix, suffix)} left the server to {leak['dst']} "
                       f"(planted by this run, captured inside the seal). Captured bytes: {leak.get('excerpt', '')[:240]}"),
        })
    if not findings and method in ("sandbox_claim_mismatch", "sandbox_unexplained_egress", "oracle"):
        leads.append({"kind": "mcp_cap", "tool": "(server)",
                      "observation": f"sealed run: {rec.get('evidence', method)} (no planted secret left; a lead)"})
    for s in rec.get("samplings") or []:
        from hunt import poisoning
        kinds = sorted({h.kind for h in poisoning.scan(s.get("text", ""))})
        leads.append({"kind": "sampling_instruction_laundering", "tool": s.get("tool") or "(server)",
                      "observation": (f"server asked the client's model to complete: {s.get('text', '')[:200]!r}"
                                      + (f" · poisoning signals: {', '.join(kinds)}" if kinds else ""))})
    for fields in rec.get("elicitations") or []:
        secret_like = [f for f in fields if _SECRET_FIELD.search(f)]
        if secret_like:
            leads.append({"kind": "elicitation_credential_harvest", "tool": "(server)",
                          "observation": f"server asked the user for secret-like field(s): {', '.join(secret_like)}"})
    status = f"ran ({len(findings)} proven, {len(leads)} lead(s); seal proven, {len(rec.get('attempts') or [])} egress attempt(s))"
    return {"findings": findings, "leads": leads, "status": status}


def _selftest() -> None:
    proven = from_sealed({"method": "oracle", "proof": {"P1_own_netns": True}, "attempts": [{}],
                          "leaks": [{"secret": "AWS", "dst": "tcp 203.0.113.50:80", "excerpt": "POST /collect key=HT-1-AWS"}]})
    assert proven["findings"][0]["cls"] == "mcp_cap" and "PROVEN" in proven["findings"][0]["detail"], proven
    echo = from_sealed({"method": "oracle", "proof": {"P1_own_netns": True}, "leaks": [], "evidence": "arg echo"})
    assert not echo["findings"] and echo["leads"][0]["kind"] == "mcp_cap", echo      # argument echo is only a lead
    unsealed = from_sealed({"method": "sandbox_unproven", "proof_error": "unshare: Operation not permitted"})
    assert unsealed["status"].startswith("inconclusive") and not unsealed["findings"], unsealed
    phish = from_sealed({"method": "oracle", "proof": {"x": True}, "elicitations": [["password", "remember_me"]],
                         "leaks": [{"secret": "ELICIT", "dst": "tcp 203.0.113.51:80"}]})
    assert phish["findings"][0]["cls"] == "elicitation_credential_harvest"
    assert phish["leads"][0]["kind"] == "elicitation_credential_harvest"


if __name__ == "__main__":
    _selftest()
    print("mcp00_proof selftest OK")
