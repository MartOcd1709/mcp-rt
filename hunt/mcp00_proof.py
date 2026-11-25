"""MCP-00 proof: turn ONE sealed canary run (mcp_rt/runtime, Detector Unit 3) into findings, leads and coverage.

The deep sealed run plants realistic fake credentials (cloud keys, SSH key, .env, git remote, MCP client configs, shell
history) in the server's HOME and working directory, plus fake secrets in its ENVIRONMENT, all carrying this run's
token. It exercises every tool (with schema variants), every resource and prompt, re-reads the tool list mid-session,
calls every tool a second time, answers every elicitation and sampling request with token-bearing values, and watches
for delayed egress. Every outbound packet goes to a recorder inside a namespace that cannot reach the world, every
file open is traced, and every event is tied to the action that caused it. Mapping (the enterprise-precision rule):

  a PLANTED secret seen leaving (file, ambient env var, elicitation answer, sampled completion)
                                                    -> VULNERABLE (proven): which secret, where, during which action
  a write to shell startup / SSH trust / another MCP client's config / a credential file
                                                    -> VULNERABLE (tampering it performed)
  a SILENT mid-session tool redefinition that adds model-directed instructions -> VULNERABLE rug pull
  the server's OWN configured credential sent out, a planted secret opened but never sent (unexplained by its declared
  purpose), any other mid-session redefinition, argument echo / unexplained egress / contradicted "no network" claim,
  a sampling request, an elicitation asking for a secret-like field  -> LEAD (SUSPECTED)
  the seal could not be proven / the server never started -> INCONCLUSIVE (never CLEAN)

Pure and deterministic: `from_sealed(record)` reads the record `mcp_rt.runtime.runner.run_server` returns;
`coverage_of(record)` says what the run TESTED (per tool and class), so a later clean run can verify a fix.
"""
from __future__ import annotations

import re

# suffix appended to the run token in each planted secret -> what a reader should be told was stolen (fallback when a
# record predates the planted registry)
SECRET_LABELS = {
    "AWS": "fake AWS credentials (~/.aws/credentials)",
    "SSH": "fake SSH private key (~/.ssh/id_rsa)",
    "GCP": "fake Google Cloud credentials (~/.config/gcloud)",
    "NETRC": "fake ~/.netrc login",
    "ENV": "fake .env secrets",
    "MCPCFG": "fake MCP client config token (~/.cursor/mcp.json)",
    "HIST": "fake token in shell history (~/.bash_history)",
    "KUBE": "fake Kubernetes credentials (~/.kube/config)",
    "GIT": "fake Git remote credentials (.git/config)",
    "ELICIT": "the value the user typed into the server's elicitation form",
    "SAMPLE": "the model's completion returned to the server's sampling request",
}
_CLASS_BY_SECRET = {"ELICIT": "elicitation_credential_harvest", "SAMPLE": "sampling_instruction_laundering"}
_SECRET_FIELD = re.compile(r"(?i)pass(word|code|phrase)?|secret|token|api[_-]?key|credential|otp|\bpin\b|ssn|private|"
                           r"mfa|2fa|auth")
_SEAL_PROBLEMS = {"sandbox_unproven", "sandbox_unobservable", "probe_seal_incompatible"}
# Opening a credential store is EXPLAINED when the server's declared text names the matching service (boto3 reads
# ~/.aws by itself, a git tool reads .git/config). .env is the dotenv convention: always explained. Generic vocabulary.
_EXPLAINS = {
    "AWS": r"\b(?:aws|amazon|s3|boto3?|ec2|lambda|dynamodb|bedrock|cloudwatch)\b",
    "SSH": r"\b(?:ssh|git|sftp|scp|deploy(?:s|ment)?|remote (?:host|server))\b",
    "GCP": r"\b(?:gcp|google cloud|gcloud|bigquery|gcs|firebase|vertex)\b",
    "NETRC": r"\b(?:git|github|gitlab|netrc|ftp)\b",
    "KUBE": r"\b(?:kube\w*|k8s|kubernetes|cluster|helm)\b",
    "GIT": r"\b(?:git|github|gitlab|repo(?:sitory|sitories)?|commits?|branch(?:es)?)\b",
    "MCPCFG": r"\b(?:mcp (?:config|server|client)s?|cursor|claude desktop|client config)\b",
    "HIST": r"\b(?:history|shell|terminal|command line)\b",
    "ENV": r".",
}
_TOOLISH = ("tool", "resource", "prompt")


def _labels(rec: dict) -> dict:
    out = dict(SECRET_LABELS)
    for p in rec.get("planted") or []:
        out[p["label"]] = p["description"]
    return out


def _kinds(rec: dict) -> dict:
    return {p["label"]: p["kind"] for p in rec.get("planted") or []}


def _actor(rec: dict, idx) -> str:
    """The tool (or resource / prompt / startup) an event is tied to: the key an issue is tracked under."""
    acts = rec.get("actions") or []
    if idx is None or not (0 <= idx < len(acts)):
        return "(startup)" if rec.get("actions") else "(server)"
    a = acts[idx]
    return a["name"] if a["kind"] == "tool" else f"{a['kind']}:{a['name']}" if a["kind"] in _TOOLISH else "(startup)"


def from_sealed(rec: dict) -> dict:
    """{findings: [...], leads: [...], status: str} for one sealed run record."""
    findings: list[dict] = []
    leads: list[dict] = []
    method = rec.get("method", "")
    if method in _SEAL_PROBLEMS or not rec.get("proof") and rec.get("proof_error"):
        why = rec.get("proof_error") or rec.get("evidence") or method
        return {"findings": [], "leads": [], "status": f"inconclusive: seal unproven ({str(why)[:120]})"}
    desc, kinds = _labels(rec), _kinds(rec)
    leaked: set[str] = set()
    egress = rec.get("egress")
    if egress is None:                       # a record from before the deep run: leaks only, no attribution
        egress = [{"secrets": [lk["secret"]], "dst": lk["dst"], "port": None, "proto": "", "action": None,
                   "attribution": "", "excerpt": lk.get("excerpt", ""), "tool": lk.get("tool")}
                  for lk in rec.get("leaks") or []]
    for e in egress:
        dst = e["dst"] if e.get("port") is None else f"{e.get('proto', 'tcp')} {e['dst']}:{e['port']}"
        excerpt = e.get("excerpt")
        if excerpt is None:
            import base64
            excerpt = base64.b64decode(e.get("payload_b64") or "")[:240].decode("utf-8", "replace")
        tool = e.get("tool") or _actor(rec, e.get("action"))
        when = f" during {e['attribution']}" if e.get("attribution") else ""
        seal = f"; sha256 {e['sha256'][:16]}" if e.get("sha256") else ""
        for lab in e.get("secrets") or []:
            if (lab, dst, tool) in leaked:
                continue
            leaked.add((lab, dst, tool))
            if kinds.get(lab) == "own_env":
                leads.append({"kind": "mcp_cap", "tool": tool,
                              "observation": f"{desc.get(lab, lab)} was sent to {dst}{when}: possibly its own API, "
                                             "confirm the destination (a lead)"})
                continue
            findings.append({
                "cls": _CLASS_BY_SECRET.get(lab, "mcp_cap"), "tool": tool, "sev": "Critical", "source": "sealed canary",
                "detail": (f"PROVEN: {desc.get(lab, lab)} left the server to {dst}{when} (planted by this run, captured "
                           f"inside the seal{seal}). Captured bytes: {excerpt[:240]}"),
            })
    sent = {lab for (lab, _, _) in leaked}
    claim = rec.get("claim_text") or ""
    for a in rec.get("file_access") or []:
        lab = a["label"]
        if lab in sent or re.search(_EXPLAINS.get(lab, r"$^"), claim, re.I):
            continue
        leads.append({"kind": "mcp_cap", "tool": _actor(rec, a.get("action")),
                      "observation": (f"opened {a['description']} during {a['attribution']} but did not send it; nothing "
                                      "in its declared text explains needing it (credential access, a lead)")})
    for t in rec.get("tamper") or []:
        findings.append({"cls": "mcp_cap", "tool": _actor(rec, t.get("action")), "sev": "High", "source": "sealed canary",
                         "detail": (f"PROVEN: TAMPERED — wrote {t['where']} during {t['attribution']} (traced inside "
                                    "the seal): shell startup, SSH trust, a credential file or another MCP client's "
                                    "configuration is not this server's to change")})
    from hunt import poisoning
    for r in rec.get("redefinitions") or []:
        before = {h.kind for h in poisoning.scan(r.get("before") or "")}
        added = sorted({h.kind for h in poisoning.scan(r.get("after") or "")} - before)
        text = (f"tool {r['tool']} was {r['change']} mid-session after round {r['after_round']} "
                f"({'announced with tools/list_changed' if r.get('notified') else 'silently, no tools/list_changed'})"
                + (f": before {r['before'][:160]!r} → after {r['after'][:240]!r}" if r["change"] == "changed" else ""))
        if r["change"] == "changed" and not r.get("notified") and added:
            findings.append({"cls": "rug_pull", "tool": r["tool"], "sev": "High", "source": "sealed canary",
                             "detail": f"PROVEN: {text}; the new text adds model-directed instructions ({', '.join(added)})"})
        elif not (r["change"] in ("added", "removed") and r.get("notified")):
            leads.append({"kind": "rug_pull", "tool": r["tool"], "observation": text})
    if not findings and method in ("sandbox_claim_mismatch", "sandbox_unexplained_egress", "oracle"):
        leads.append({"kind": "mcp_cap", "tool": "(server)",
                      "observation": f"sealed run: {rec.get('evidence', method)} (no planted secret left; a lead)"})
    for s in rec.get("samplings") or []:
        kinds_ = sorted({h.kind for h in poisoning.scan(s.get("text", ""))})
        leads.append({"kind": "sampling_instruction_laundering", "tool": s.get("tool") or _actor(rec, s.get("action")),
                      "observation": (f"server asked the client's model to complete: {s.get('text', '')[:200]!r}"
                                      + (f" · poisoning signals: {', '.join(kinds_)}" if kinds_ else ""))})
    log = rec.get("elicitation_log") or [{"fields": f, "action": None} for f in rec.get("elicitations") or []]
    for el in log:
        secret_like = [f for f in el["fields"] if _SECRET_FIELD.search(f)]
        if secret_like:
            leads.append({"kind": "elicitation_credential_harvest", "tool": _actor(rec, el.get("action")),
                          "observation": f"server asked the user for secret-like field(s): {', '.join(secret_like)}"})
    acts = [a for a in rec.get("actions") or [] if a["kind"] in _TOOLISH]
    depth = (f"{len(acts)} action(s), {len(rec.get('planted') or [])} canaries, watched {rec.get('watch_s')}s · "
             if acts else "")
    status = (f"ran ({len(findings)} proven, {len(leads)} lead(s); seal proven, {depth}"
              f"{len(rec.get('attempts') or [])} egress attempt(s))")
    return {"findings": findings, "leads": leads, "status": status}


def coverage_of(rec: dict, result: dict | None = None) -> list[dict]:
    """What this sealed run TESTED: one row per (tool, class) it exercised, VULNERABLE where a finding came out of it,
    else CLEAN. Nothing for an unproven seal (an inconclusive run tests nothing). The issue lifecycle uses these rows:
    a later run that covers the same (tool, class) and stays CLEAN is what verifies a fix."""
    result = result or from_sealed(rec)
    if result["status"].startswith("inconclusive") or not rec.get("actions"):
        return []
    hit = {(f["tool"], f["cls"]) for f in result["findings"]}
    # a tool is CLEAN-eligible only if a call to it actually EXECUTED (ok). A tool whose every call was rejected by
    # validation was never exercised -> no CLEAN credit (it must not read as "tested clean"); a finding keeps its tool.
    tools = sorted({a["name"] for a in rec["actions"] if a["kind"] == "tool" and a.get("ok")}
                   | {t for (t, _) in hit if t not in ("(server)", "(startup)")})
    rows = []
    for t in ["(startup)", *tools]:
        for cls in ("mcp_cap", "elicitation_credential_harvest", "sampling_instruction_laundering"):
            if t == "(startup)" and cls != "mcp_cap":
                continue
            rows.append({"tool": t, "cls": cls, "verdict": "VULNERABLE" if (t, cls) in hit else "CLEAN",
                         "source": "sealed canary"})
    relisted = any(a["kind"] == "list_tools" and a["round"] >= 1 and a.get("ok") for a in rec["actions"])
    if relisted:
        rows += [{"tool": t, "cls": "rug_pull", "verdict": "VULNERABLE" if (t, "rug_pull") in hit else "CLEAN",
                  "source": "sealed canary"} for t in tools]
    return rows


def _selftest() -> None:
    proven = from_sealed({"method": "oracle", "proof": {"P1_own_netns": True}, "attempts": [{}],
                          "leaks": [{"secret": "AWS", "dst": "tcp 203.0.113.50:80", "excerpt": "POST /collect key=HT-1-AWS"}]})
    assert proven["findings"][0]["cls"] == "mcp_cap" and "PROVEN" in proven["findings"][0]["detail"], proven
    echo = from_sealed({"method": "oracle", "proof": {"P1_own_netns": True}, "leaks": [], "evidence": "arg echo"})
    assert not echo["findings"] and echo["leads"][0]["kind"] == "mcp_cap", echo      # argument echo is only a lead
    unsealed = from_sealed({"method": "sandbox_unproven", "proof_error": "unshare: Operation not permitted"})
    assert unsealed["status"].startswith("inconclusive") and not unsealed["findings"], unsealed
    assert coverage_of({"method": "sandbox_unproven", "proof_error": "x", "actions": [{}]}) == []
    phish = from_sealed({"method": "oracle", "proof": {"x": True}, "elicitations": [["password", "remember_me"]],
                         "leaks": [{"secret": "ELICIT", "dst": "tcp 203.0.113.51:80"}]})
    assert phish["findings"][0]["cls"] == "elicitation_credential_harvest"
    assert phish["leads"][0]["kind"] == "elicitation_credential_harvest"
    acts = [{"i": 0, "kind": "tool", "name": "format", "round": 1, "t0": 1, "t1": 2}]
    own = from_sealed({"method": "oracle", "proof": {"x": True}, "actions": acts,
                       "planted": [{"label": "OWN00", "kind": "own_env", "description": "own API_TOKEN"}],
                       "egress": [{"secrets": ["OWN00"], "dst": "203.0.113.9", "port": 80, "proto": "tcp", "action": 0,
                                   "attribution": "tool format (round 1)", "payload_b64": ""}]})
    assert not own["findings"] and own["leads"][0]["tool"] == "format", own          # own credential: a lead
    aws = {"method": "sandbox_no_egress", "proof": {"x": True}, "actions": acts,
           "file_access": [{"label": "AWS", "description": "fake AWS", "action": 0, "attribution": "tool format"}]}
    assert from_sealed({**aws, "claim_text": "Format code."})["leads"][0]["kind"] == "mcp_cap"
    assert not from_sealed({**aws, "claim_text": "List your S3 buckets."})["leads"]     # explained by its purpose


if __name__ == "__main__":
    _selftest()
    print("mcp00_proof selftest OK")
