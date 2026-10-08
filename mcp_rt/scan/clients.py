"""Per-CLI invocation for the scan path.

``scan()`` drives a real coding-agent CLI against the *target's own* MCP config (the
customer's server under test), then checks the egress tap for a planted marker. Each
supported client injects an MCP server differently, so this module maps the one standard
``{"mcpServers": {name: {command, args, env?}}}`` config (from ``TargetSpec.client_config``)
onto each CLI's own flags / config file.

The invocation recipes (flags, config schema, injection mechanism) mirror the proven ones
in ``mcp_rt/adapters/cli_client.py`` — that module is the source of truth; keep the two in
sync. The adapters there drive the *malicious research server*; these drive an *arbitrary
target*, so the classes aren't reusable directly, only the recipes.

Transcript contract (consumed by ``runner._agent_ran``):
  * agent produced output        -> a line ``assistant: ...``
  * agent hard-failed            -> a line ``[agent: ...]`` (missing binary / timeout)
Every runner writes its temp config under the workspace / a temp dir and cleans up.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path

# Clients with a proven headless invocation here. Cursor has no headless MCP recipe yet
# (no `cursor-agent` flags verified) so it is deliberately absent rather than claimed.
SUPPORTED = ("claude-code", "codex", "cline", "gemini")

# Auto-approve flags per client — the realistic "developer in auto-approve" scenario, so the
# verdict reflects the agent's own judgement, not a permission wall. Mirrors cli_client.py.
_AUTO_APPROVE = {
    "claude-code": "--dangerously-skip-permissions",
    "codex": "--dangerously-bypass-approvals-and-sandbox",
    "cline": "--yolo",
    "gemini": "--yolo",
}


def _run(argv: list[str], cwd: str, timeout: int, transcript: list[str]) -> list[str]:
    """Run a client headlessly; append output / a hard-failure marker to ``transcript``."""
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout,
            env=os.environ.copy(), cwd=cwd,
        )
        out = (proc.stdout or "").strip()
        err = (proc.stderr or "").strip()
        if out:
            transcript.append("assistant: " + out[:2000])
        if err:
            transcript.append("[stderr] " + err[:500])
        if not out and proc.returncode != 0:
            transcript.append(f"[agent exited {proc.returncode} with no output]")
    except subprocess.TimeoutExpired:
        transcript.append("[agent: timed out]")
    except FileNotFoundError as exc:
        transcript.append(f"[agent: client binary not found: {exc}]")
    return transcript


# --------------------------------------------------------------------------------------
# Pure config transforms (unit-testable without any CLI installed).
# --------------------------------------------------------------------------------------
def cline_settings(client_config: dict) -> dict:
    """Standard mcpServers -> Cline v3 transport-wrapper schema (command/args/env under
    a ``transport`` block). The legacy flat format is rejected by Cline v3+."""
    servers = client_config.get("mcpServers", {})
    wrapped = {}
    for name, entry in servers.items():
        transport = {"type": "stdio", "command": entry["command"], "args": entry.get("args", [])}
        if entry.get("env"):
            transport["env"] = entry["env"]
        wrapped[name] = {"transport": transport}
    return {"mcpServers": wrapped}


def _toml_value(v) -> str:
    """Minimal TOML literal for a Codex ``-c`` flag value (string or list-of-strings)."""
    if isinstance(v, list):
        return "[" + ", ".join(json.dumps(str(x)) for x in v) + "]"
    return json.dumps(str(v))   # JSON string quoting is valid TOML basic-string quoting


def codex_flags(client_config: dict) -> list[str]:
    """Standard mcpServers -> Codex ``-c mcp_servers.<name>.<key>=<toml>`` flag pairs."""
    flags: list[str] = []
    for name, entry in client_config.get("mcpServers", {}).items():
        flags += ["-c", f"mcp_servers.{name}.command={_toml_value(entry['command'])}"]
        if entry.get("args"):
            flags += ["-c", f"mcp_servers.{name}.args={_toml_value(entry['args'])}"]
        for k, val in (entry.get("env") or {}).items():
            flags += ["-c", f"mcp_servers.{name}.env.{k}={_toml_value(val)}"]
    return flags


# --------------------------------------------------------------------------------------
# Per-client runners: (prompt, client_config, workspace, timeout) -> transcript
# --------------------------------------------------------------------------------------
def _run_claude_code(prompt, client_config, workspace, timeout) -> list[str]:
    fd, cfg_path = tempfile.mkstemp(prefix="mcprt_claude_", suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(client_config, fh)
    try:
        argv = ["claude", "-p", prompt, "--mcp-config", cfg_path,
                "--output-format", "text", _AUTO_APPROVE["claude-code"]]
        transcript = [f"user: {prompt}", "[client: Claude Code]"]
        return _run(argv, workspace, timeout, transcript)
    finally:
        Path(cfg_path).unlink(missing_ok=True)


def _run_codex(prompt, client_config, workspace, timeout) -> list[str]:
    argv = (["codex", "exec", *codex_flags(client_config),
             "--skip-git-repo-check", _AUTO_APPROVE["codex"], prompt])
    transcript = [f"user: {prompt}", "[client: Codex, MCP server injected via -c flags]"]
    return _run(argv, workspace, timeout, transcript)


def _run_cline(prompt, client_config, workspace, timeout) -> list[str]:
    cfg_dir = tempfile.mkdtemp(prefix="mcprt_cline_cfg_")
    try:
        with open(os.path.join(cfg_dir, "cline_mcp_settings.json"), "w", encoding="utf-8") as fh:
            json.dump(cline_settings(client_config), fh)
        argv = ["cline", "--config", cfg_dir, _AUTO_APPROVE["cline"], "--json", prompt]
        transcript = [f"user: {prompt}", "[client: Cline v3, MCP server injected via --config]"]
        return _run(argv, workspace, timeout, transcript)
    finally:
        import shutil
        shutil.rmtree(cfg_dir, ignore_errors=True)


def _run_gemini(prompt, client_config, workspace, timeout) -> list[str]:
    # Gemini reads project MCP config from <cwd>/.gemini/settings.json (same schema).
    gemini_dir = os.path.join(workspace, ".gemini")
    os.makedirs(gemini_dir, exist_ok=True)
    settings = os.path.join(gemini_dir, "settings.json")
    with open(settings, "w", encoding="utf-8") as fh:
        json.dump(client_config, fh, indent=2)
    try:
        argv = ["gemini", "-p", prompt, _AUTO_APPROVE["gemini"], "--output-format", "text"]
        transcript = [f"user: {prompt}", "[client: Gemini CLI, MCP server injected via .gemini/settings.json]"]
        return _run(argv, workspace, timeout, transcript)
    finally:
        Path(settings).unlink(missing_ok=True)


_RUNNERS = {
    "claude-code": _run_claude_code,
    "codex": _run_codex,
    "cline": _run_cline,
    "gemini": _run_gemini,
}


def run_client(client: str, prompt: str, client_config: dict, workspace: str, timeout: int) -> list[str]:
    """Drive ``client`` headlessly against ``client_config`` in ``workspace``; return a transcript."""
    try:
        runner = _RUNNERS[client]
    except KeyError:
        raise ValueError(
            f"scan client {client!r} not supported; choose one of {', '.join(SUPPORTED)}"
        ) from None
    return runner(prompt, client_config, workspace, timeout)
