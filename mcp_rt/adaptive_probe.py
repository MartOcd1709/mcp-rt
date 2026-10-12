"""Adaptive probe generation for AUTHORIZED MCP vulnerability detection (adaptive DAST).

A defensive scanner capability: given a target MCP server's *advertised* surface (its own
tools/resources/prompts), select which of our known detection techniques (the registered payload
corpus, mapped to the MCP-38 / OWASP-MCP surface) apply to THIS server, and adapt them to its
actual tool names/parameters. Each candidate is a *detection probe*, validated downstream by a
planted canary — so a reported finding is ground-truth proof, never an LLM opinion.

Guardrails (inherited from the engine, enforced by the orchestrator that drives this):
  * Authorized targets only — local/stdio by default; remote is consent-gated (`--authorized-by`).
  * Runs only inside the hardened sandbox (docker backend); synthetic honeytokens only.
  * Output is a vulnerability assessment for the operator's own / authorized servers, for
    responsible disclosure — not a general-purpose exploit tool.

This module only *generates and ranks candidate probes*. Ground-truth validation (plant canary →
drive → check egress) is done by the sandboxed executor the orchestrator injects; a candidate
becomes a finding ONLY if its canary fires.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

# Headroom for reasoning models (e.g. CSI alias2-mini emits reasoning_content before the JSON).
_MAX_TOKENS = 4000


@dataclass
class ProbeCandidate:
    """One adaptive detection probe tailored to the target (not yet validated)."""
    technique: str          # the known technique it adapts (a registered payload name / MCP class)
    target_tool: str        # the target's actual tool this probe exercises
    mcp_class: str = ""      # MCP-38 / OWASP-MCP category
    rationale: str = ""      # why this technique applies to this tool (model's reasoning)
    params: dict = field(default_factory=dict)   # canary path/url etc. filled at run time
    source: str = "mock"    # which model proposed it

    def as_dict(self) -> dict:
        return {"technique": self.technique, "target_tool": self.target_tool,
                "mcp_class": self.mcp_class, "rationale": self.rationale, "source": self.source}


def _known_techniques() -> list[dict]:
    """Our registered detection corpus as reference material (name + MCP class)."""
    from mcp_rt.payloads.registry import all_payloads
    out = []
    for p in all_payloads():
        out.append({"technique": getattr(p, "name", "?"),
                    "mcp_class": getattr(p, "mcp38", getattr(p, "mcp_id", ""))})
    return out


# --------------------------------------------------------------------------------------
# Model abstraction — mock (offline, default) now; Anthropic wired for when a key is set.
# --------------------------------------------------------------------------------------
class ProbeModel:
    name = "base"

    def propose(self, tools: list[str], techniques: list[dict], n: int, hints: str = "") -> list[dict]:
        """Return up to n {technique, target_tool, mcp_class, rationale} candidate specs."""
        raise NotImplementedError


class MockProbeModel(ProbeModel):
    """Deterministic, offline selection — pairs each known technique with applicable target tools.
    No network, no key: lets the whole pipeline be built and tested now (real model plugged later)."""
    name = "mock"

    def propose(self, tools: list[str], techniques: list[dict], n: int, hints: str = "") -> list[dict]:
        out = []
        tools = tools or ["<default-tool>"]
        for i, t in enumerate(techniques):
            tool = tools[i % len(tools)]
            out.append({"technique": t["technique"], "target_tool": tool,
                        "mcp_class": t.get("mcp_class", ""),
                        "rationale": f"technique '{t['technique']}' applies to tool '{tool}' "
                                     f"(class {t.get('mcp_class','?')})"})
            if len(out) >= n:
                break
        return out


def _prompt(tools: list[str], techniques: list[dict], n: int, hints: str = "") -> str:
    return (
        "You are an MCP security tester doing AUTHORIZED vulnerability detection. "
        "Given a target MCP server's tools and a list of known detection techniques, pick the "
        "techniques most likely to apply and say which tool each targets. Reply ONLY with a JSON "
        'array of objects {"technique","target_tool","mcp_class","rationale"}.\n\n'
        + (hints + "\n\n" if hints else "")
        + f"Target tools: {json.dumps(tools)}\n"
        f"Known techniques: {json.dumps(techniques)}\n"
        f"Return at most {n}."
    )


def _extract_json_array(text: str, n: int) -> list[dict]:
    start, end = text.find("["), text.rfind("]")
    return json.loads(text[start:end + 1])[:n] if start >= 0 and end > start else []


class OpenAICompatibleProbeModel(ProbeModel):
    """Any OpenAI-compatible chat API — covers CSI/CAI (alias2-mini / alias models via LiteLLM), a
    LiteLLM proxy, tokenharbor's OpenAI endpoint, vLLM, or local Ollama. Configure via env:
      MCPRT_AI_BASE_URL  the provider's OpenAI-compatible /v1 base
      MCPRT_AI_API_KEY   the provider/CSI key
      MCPRT_AI_MODEL_NAME e.g. alias2-mini (CSI specialized cybersecurity model)
    No SDK dependency — posts /chat/completions with httpx."""
    name = "openai"

    def __init__(self, base_url: str | None = None, api_key: str | None = None, model: str | None = None):
        # Falls back to OPENAI_BASE_URL / OPENAI_API_KEY so it works out-of-the-box inside a
        # CSI-launched shell (the `csi` proxy sets those for its local 127.0.0.1:<port> endpoint).
        self.base_url = (base_url or os.getenv("MCPRT_AI_BASE_URL") or os.getenv("OPENAI_BASE_URL", "")).rstrip("/")
        self.api_key = api_key or os.getenv("MCPRT_AI_API_KEY") or os.getenv("OPENAI_API_KEY", "")
        self.model = model or os.getenv("MCPRT_AI_MODEL_NAME", "alias2-mini")

    def propose(self, tools: list[str], techniques: list[dict], n: int, hints: str = "") -> list[dict]:
        import httpx
        r = httpx.post(
            f"{self.base_url}/chat/completions",
            headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
            json={"model": self.model, "max_tokens": _MAX_TOKENS,
                  "messages": [{"role": "user", "content": _prompt(tools, techniques, n, hints)}]},
            timeout=60,
        )
        r.raise_for_status()
        return _extract_json_array(r.json()["choices"][0]["message"]["content"], n)


class AnthropicProbeModel(ProbeModel):
    """Anthropic / Anthropic-compatible gateway (e.g. tokenharbor): set ANTHROPIC_BASE_URL +
    ANTHROPIC_API_KEY (the `anthropic` SDK reads both). Model via MCPRT_AI_MODEL_NAME."""
    name = "anthropic"

    def __init__(self, model: str | None = None):
        self.model = model or os.getenv("MCPRT_AI_MODEL_NAME", "claude-sonnet-5-5")

    def propose(self, tools: list[str], techniques: list[dict], n: int, hints: str = "") -> list[dict]:
        import anthropic
        client = anthropic.Anthropic()   # reads ANTHROPIC_API_KEY (+ ANTHROPIC_BASE_URL if set)
        msg = client.messages.create(model=self.model, max_tokens=_MAX_TOKENS,
                                     messages=[{"role": "user", "content": _prompt(tools, techniques, n, hints)}])
        text = "".join(b.text for b in msg.content if getattr(b, "type", "") == "text")
        return _extract_json_array(text, n)


def get_model() -> ProbeModel:
    """Pick the probe model from env (provider-agnostic). Default: mock (offline, no key).
      MCPRT_AI_PROVIDER=openai    + MCPRT_AI_BASE_URL + MCPRT_AI_API_KEY  -> CSI/LiteLLM/Ollama/etc.
      MCPRT_AI_PROVIDER=anthropic + ANTHROPIC_API_KEY                     -> Anthropic / gateway
    (legacy MCPRT_AI_MODEL=anthropic still honored.)"""
    provider = os.getenv("MCPRT_AI_PROVIDER", "")
    if provider == "openai" and os.getenv("MCPRT_AI_BASE_URL") and os.getenv("MCPRT_AI_API_KEY"):
        return OpenAICompatibleProbeModel()
    if provider == "anthropic" and os.getenv("ANTHROPIC_API_KEY"):
        return AnthropicProbeModel()
    if os.getenv("MCPRT_AI_MODEL") == "anthropic" and os.getenv("ANTHROPIC_API_KEY"):
        return AnthropicProbeModel()
    return MockProbeModel()


def generate_candidates(target_tools: list[str], *, n: int = 10,
                        model: ProbeModel | None = None) -> list[ProbeCandidate]:
    """Generate up to n adaptive detection probes for the target's tools.

    Generation only — each candidate must still be validated ground-truth (canary) by the
    sandboxed executor before it is ever reported as a finding.
    """
    model = model or get_model()
    techniques = _known_techniques()
    hints = ""
    try:                                  # learn from prior ground-truth wins (best-effort)
        from mcp_rt.knowledge import recall_hints
        hints = recall_hints(target_tools)
    except Exception:  # noqa: BLE001 — knowledge layer is optional; never block generation
        pass
    try:
        specs = model.propose(target_tools, techniques, n, hints)
    except Exception:  # noqa: BLE001 — model failure degrades to the offline selection, never crashes
        specs = MockProbeModel().propose(target_tools, techniques, n, hints)
        model = MockProbeModel()
    return [ProbeCandidate(technique=s.get("technique", "?"), target_tool=s.get("target_tool", "?"),
                           mcp_class=s.get("mcp_class", ""), rationale=s.get("rationale", ""),
                           source=model.name)
            for s in specs]
