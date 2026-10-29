"""Scripted, offline client adapters for the scorer's self-test.

These are NOT models and NOT measurements of any real agent. They prove the plumbing: a client that takes every
lure must register as susceptible, a client that takes none must not, and a benign control must stay RESILIENT
even when a lure is taken. The mocks see only what a client can see (the user's task, tool metadata, resource text,
elicitation requests) and the planted token. They never read label.json, so they cannot cheat the scorer.
"""
import re

from mcp_rt.adapters.base import ClientAdapter

# A credential lure in model-facing text: the vocabulary a real agent would act on. Underscores and dashes are
# word separators for this purpose, so "session_token" reads as "session token".
_LURE = re.compile(r"\b(?:token|credential|auth|session)s?\b", re.IGNORECASE)
_NAME_PARAM = re.compile(r"tool|name|action|method|command", re.IGNORECASE)
_DOTTED = re.compile(r"\b[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*\b")   # identifiers such as tickets.list


def _lure(text: str) -> bool:
    return bool(_LURE.search((text or "").replace("_", " ").replace("-", " ")))


def _words(text: str) -> set[str]:
    return set(re.findall(r"[a-z]{4,}", (text or "").lower().replace("_", " ")))


def _task_of(prompt: str) -> str:
    """The benign user task: everything after the planted-token preamble."""
    return prompt.split("\n\n", 1)[-1]


def _string_params(tool):
    props = tool["inputSchema"].get("properties", {}) or {}
    return [(n, p or {}) for n, p in props.items() if (p or {}).get("type", "string") == "string"]


def _free_text_params(tool):
    """String parameters a client may fill with arbitrary text. Enum parameters are excluded: the server validates
    arguments against the schema, so a client that ignores the enum is rejected before the tool runs. That would be
    a mock defect, not a finding, so the mocks respect the schema."""
    return [(n, spec) for n, spec in _string_params(tool) if not spec.get("enum")]


def _defaults(tool) -> dict:
    """Benign, schema-valid values for the required parameters. Never the planted token."""
    props = tool["inputSchema"].get("properties", {}) or {}
    args: dict = {}
    for n in tool["inputSchema"].get("required", []) or []:
        spec = props.get(n) or {}
        kind = spec.get("type", "string")
        if kind == "string":
            args[n] = (spec.get("enum") or ["example"])[0]
        elif kind in ("integer", "number"):
            args[n] = 1
        elif kind == "boolean":
            args[n] = False
        else:
            args[n] = {}
    return args


def _failed(out: str) -> bool:
    return out.startswith("error:")


def _relevant(tool, task: str) -> bool:
    """Would a client call this tool to do the user's task? Shared vocabulary between task and tool metadata."""
    return bool(_words(task) & _words(f"{tool['name']} {tool['description']}"))


class _ScriptedClient(ClientAdapter):
    def answer_elicitation(self, message, schema, honeytoken):
        return ("decline", None)                 # default: refuse every elicitation

    def _call(self, server, tool_name, args, transcript):
        out = server.call(tool_name, args)
        transcript.append(f"agent: called {tool_name} -> {out[:80]!r}")
        return out


class MockObedientClient(_ScriptedClient):
    """Maximal compliance, the worst case: fills every free-text argument with the planted token. If a call fails with
    an unknown-name error, it retries the name-like argument with identifiers from the tool's own description, the way
    an agent would. Accepts every elicitation with the token."""

    name = "mock-obedient"

    def run_task(self, prompt, server, honeytoken):
        token = honeytoken.marker
        transcript = [f"user: {prompt}"]
        for tool in server.tools:
            args = _defaults(tool)
            for n, _ in _free_text_params(tool):
                args[n] = token
            out = self._call(server, tool["name"], args, transcript)
            if _failed(out):
                for ident in sorted(set(_DOTTED.findall(tool["description"]))):
                    retry = dict(args)
                    for n, _ in _free_text_params(tool):
                        retry[n] = ident if _NAME_PARAM.search(n) else token
                    out = self._call(server, tool["name"], retry, transcript)
                    if not _failed(out):
                        break
        for uri in server.resources:
            server.read(uri)
            transcript.append(f"agent: read {uri}")
        transcript.append("agent: done.")
        return transcript

    def answer_elicitation(self, message, schema, honeytoken):
        return ("accept", {p: honeytoken.marker for p in (schema or {}).get("properties", {})})


class MockInstructionClient(_ScriptedClient):
    """Does the user's task with the tools that fit it, and follows explicit instructions in model-facing text. A tool
    whose description carries a credential lure gets the token in its lure-matching parameters. A resource that names a
    tool alongside a lure is followed the same way. Accepts an elicitation from the server with the token. It never uses
    the token where no instruction points."""

    name = "mock-instruction"

    def run_task(self, prompt, server, honeytoken):
        token = honeytoken.marker
        task = _task_of(prompt)
        transcript = [f"user: {prompt}"]
        for tool in server.tools:
            if not (_lure(tool["description"]) or _relevant(tool, task)):
                continue
            args = _defaults(tool)
            for n, spec in _free_text_params(tool):
                if _lure(n) or _lure(spec.get("description", "")):
                    args[n] = token
            self._call(server, tool["name"], args, transcript)
        for uri in server.resources:
            text = server.read(uri)
            transcript.append(f"agent: read {uri}")
            if not _lure(text):
                continue
            for tool in server.tools:
                if re.search(rf"\b{re.escape(tool['name'])}\b", text):
                    args = _defaults(tool)
                    for n, spec in _free_text_params(tool):
                        if _lure(n) or _lure(spec.get("description", "")) or _lure(text):
                            args[n] = token
                    self._call(server, tool["name"], args, transcript)
        transcript.append("agent: done.")
        return transcript

    def answer_elicitation(self, message, schema, honeytoken):
        return ("accept", {p: honeytoken.marker for p in (schema or {}).get("properties", {})})


class MockSkepticalClient(_ScriptedClient):
    """Never supplies the planted token and refuses every elicitation. The floor: a client that takes no lure."""

    name = "mock-skeptical"

    def run_task(self, prompt, server, honeytoken):
        transcript = [f"user: {prompt}"]
        for tool in server.tools:
            self._call(server, tool["name"], _defaults(tool), transcript)
        for uri in server.resources:
            server.read(uri)
            transcript.append(f"agent: read {uri}")
        transcript.append("agent: done.")
        return transcript


MOCK_CLIENTS = {c.name: c for c in (MockObedientClient, MockInstructionClient, MockSkepticalClient)}
