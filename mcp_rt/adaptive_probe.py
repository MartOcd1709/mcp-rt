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

    def propose(self, tools: list[str], techniques: list[dict], n: int) -> list[dict]:
        """Return up to n {technique, target_tool, mcp_class, rationale} candidate specs."""
        raise NotImplementedError


class MockProbeModel(ProbeModel):
    """Deterministic, offline selection — pairs each known technique with applicable target tools.
    No network, no key: lets the whole pipeline be built and tested now (real model plugged later)."""
    name = "mock"

    def propose(self, tools: list[str], techniques: list[dict], n: int) -> list[dict]:
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


class AnthropicProbeModel(ProbeModel):
    """Uses an Anthropic model to pick + adapt techniques for the target. Requires ANTHROPIC_API_KEY.
    Falls back to mock on any error so the pipeline never hard-fails on the model."""
    name = "anthropic"

    def __init__(self, model: str = "claude-opus-4-8"):
        self.model = model

    def propose(self, tools: list[str], techniques: list[dict], n: int) -> list[dict]:
        try:
            import anthropic
            client = anthropic.Anthropic()   # reads ANTHROPIC_API_KEY
            prompt = (
                "You are an MCP security tester doing AUTHORIZED vulnerability detection. "
                "Given a target MCP server's tools and a list of known detection techniques, "
                "pick the techniques most likely to apply and say which tool each targets. "
                "Reply ONLY with a JSON array of objects "
                '{"technique","target_tool","mcp_class","rationale"}.\n\n'
                f"Target tools: {json.dumps(tools)}\n"
                f"Known techniques: {json.dumps(techniques)}\n"
                f"Return at most {n}."
            )
            msg = client.messages.create(model=self.model, max_tokens=1500,
                                         messages=[{"role": "user", "content": prompt}])
            text = "".join(b.text for b in msg.content if getattr(b, "type", "") == "text")
            start, end = text.find("["), text.rfind("]")
            return json.loads(text[start:end + 1])[:n] if start >= 0 else []
        except Exception:  # noqa: BLE001 — no key / network / parse error -> caller falls back to mock
            raise


def get_model() -> ProbeModel:
    """Pick the probe model: Anthropic when MCPRT_AI_MODEL=anthropic AND a key is set, else mock."""
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
    try:
        specs = model.propose(target_tools, techniques, n)
    except Exception:  # noqa: BLE001 — model failure degrades to the offline selection, never crashes
        specs = MockProbeModel().propose(target_tools, techniques, n)
        model = MockProbeModel()
    return [ProbeCandidate(technique=s.get("technique", "?"), target_tool=s.get("target_tool", "?"),
                           mcp_class=s.get("mcp_class", ""), rationale=s.get("rationale", ""),
                           source=model.name)
            for s in specs]
