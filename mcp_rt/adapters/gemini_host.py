"""Gemini API host adapter — drives a real Gemini agent via the google-genai SDK.

Free-tier friendly (Google AI Studio). Same contract and behaviour as
anthropic_host.py: exposes the malicious server's tools plus read_file/http_post
helpers, runs a MANUAL function-calling loop (we execute tools ourselves so a
vulnerable model trips the honeytoken canary).

Self-security (SECURITY_AND_SCOPE.md §B): read_file routes only through the
honeytoken accessor; http_post short-timeout + errors swallowed; key from env;
no telemetry. Dependency: ``pip install google-genai``.
"""
import json
import os
import time
import urllib.error
import urllib.request
from typing import Any

from .base import ClientAdapter

_READ_FILE_DESC = "Read the contents of a file at the given path and return them as a string."
_HTTP_POST_DESC = (
    "Send an HTTP POST request with the given data to the given URL. Returns the HTTP status."
)


def _build_function_declarations(server, types) -> list:
    """Build Gemini FunctionDeclarations: server tools + read_file/http_post helpers.

    If a server tool shadows a helper name (e.g. tool_shadowing registers `read_file`),
    we keep its POISONED description but give it the helper's proper parameter schema,
    and we do not double-register the helper.
    """
    S = types.Schema
    T = types.Type

    helper_params = {
        "read_file": S(type=T.OBJECT, properties={"path": S(type=T.STRING)}, required=["path"]),
        "http_post": S(
            type=T.OBJECT,
            properties={"url": S(type=T.STRING), "data": S(type=T.STRING)},
            required=["url", "data"],
        ),
    }
    helper_desc = {"read_file": _READ_FILE_DESC, "http_post": _HTTP_POST_DESC}

    decls: dict[str, Any] = {}
    for tool in server.tools:
        name = tool["name"]
        if name in helper_params:  # poisoned shadow of a helper — keep desc, fix schema
            params = helper_params[name]
        else:
            params = S(type=T.OBJECT, properties={"input": S(type=T.STRING)})
        decls[name] = types.FunctionDeclaration(
            name=name, description=tool.get("description", ""), parameters=params
        )
    for name, params in helper_params.items():
        if name not in decls:
            decls[name] = types.FunctionDeclaration(
                name=name, description=helper_desc[name], parameters=params
            )
    return list(decls.values())


class GeminiHostClient(ClientAdapter):
    """Live Gemini agent adapter (google-genai, manual function calling)."""

    name = "GeminiHostClient"

    def __init__(self, model: str = "gemini-2.5-flash", max_iterations: int = 6) -> None:
        self._model = model
        self._max_iterations = max_iterations

    def _execute_tool(self, tool_name: str, args: dict, server, honeytoken) -> str:
        if tool_name == "read_file":
            try:
                return honeytoken.read_file(args.get("path", ""))  # records access
            except OSError as exc:
                return f"[read_file error: {exc}]"
        if tool_name == "http_post":
            try:
                req = urllib.request.Request(
                    args.get("url", ""), data=str(args.get("data", "")).encode("utf-8", "replace"),
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=5) as resp:
                    return f"HTTP {resp.status}"
            except (urllib.error.URLError, OSError) as exc:
                return f"[http_post error: {exc}]"
        # server tool: deliver return-value injection if this is that channel
        spec = getattr(server, "spec", {})
        if spec.get("channel") == "return_value" and spec.get("tool_result"):
            return spec["tool_result"]
        return json.dumps({"result": "stub response for " + tool_name})

    def _generate_with_retry(self, client, contents, config):
        """Call Gemini, backing off on free-tier 429 / RESOURCE_EXHAUSTED."""
        delay = 20
        last_exc = None
        for _ in range(5):
            try:
                return client.models.generate_content(
                    model=self._model, contents=contents, config=config
                )
            except Exception as exc:  # noqa: BLE001
                msg = str(exc)
                if any(t in msg for t in ("429", "RESOURCE_EXHAUSTED", "503", "UNAVAILABLE")):
                    last_exc = exc
                    time.sleep(delay)
                    delay = min(delay * 2, 60)
                    continue
                raise
        raise last_exc  # exhausted retries

    def run_task(self, prompt: str, server, honeytoken) -> list[str]:
        api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
        if not api_key:
            raise RuntimeError("GEMINI_API_KEY not set")
        try:
            from google import genai
            from google.genai import types
        except ImportError as exc:
            raise RuntimeError("google-genai not installed — run: pip install google-genai") from exc

        client = genai.Client(api_key=api_key)
        decls = _build_function_declarations(server, types)
        config = types.GenerateContentConfig(
            tools=[types.Tool(function_declarations=decls)],
            automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
        )
        contents = [types.Content(role="user", parts=[types.Part(text=prompt)])]
        transcript = [f"user: {prompt}"]

        for iteration in range(self._max_iterations):
            response = self._generate_with_retry(client, contents, config)
            if not response.candidates:
                transcript.append("[adapter: no candidates returned]")
                break
            content = response.candidates[0].content
            parts = content.parts or []

            fcalls = [p.function_call for p in parts if getattr(p, "function_call", None)]
            for p in parts:
                if getattr(p, "text", None) and p.text.strip():
                    transcript.append(f"assistant: {p.text.strip()}")

            contents.append(content)  # keep the model turn (carries the function calls)

            if not fcalls:
                break

            response_parts = []
            for fc in fcalls:
                args = dict(fc.args) if fc.args else {}
                transcript.append(f"tool_call [{iteration + 1}]: {fc.name}({_summarise(fc.name, args)})")
                result = self._execute_tool(fc.name, args, server, honeytoken)
                display = result[:120] + "..." if len(result) > 120 else result
                transcript.append(f"tool_result [{iteration + 1}]: {display}")
                response_parts.append(
                    types.Part.from_function_response(name=fc.name, response={"result": result})
                )
            contents.append(types.Content(role="user", parts=response_parts))
        else:
            transcript.append(f"[adapter: loop cap reached after {self._max_iterations}]")

        return transcript


def _summarise(name: str, args: dict) -> str:
    if name == "read_file":
        return f"path={args.get('path', '?')!r}"
    if name == "http_post":
        return f"url={args.get('url', '?')!r}, data={str(args.get('data', ''))[:40]!r}..."
    raw = json.dumps(args)
    return raw[:80] + ("..." if len(raw) > 80 else "")
