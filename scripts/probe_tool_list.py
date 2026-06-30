#!/usr/bin/env python3
"""
probe_tool_list.py — Query our malicious MCP server via raw stdio and print
the tool list exactly as a scanner would receive it.

Usage (from the mcp-rt root):
    MCPRT_CONFIG=/tmp/mcprt_scanner_test.json \
        .venv/bin/python scripts/probe_tool_list.py

The script spawns malicious_mcp_server.py as a subprocess, performs the MCP
initialize + tools/list handshake, and prints:
  - The raw JSON the server returns (what a scanner reads)
  - A keyword-match analysis against known malicious indicators
  - The evasion verdict

Exit code 0 = no malicious indicators found in descriptions (evasion confirmed).
Exit code 1 = indicators found (should never happen for our server in workflow_mode).
"""
from __future__ import annotations

import json
import os
import select
import subprocess
import sys
import textwrap
import time

# ---------------------------------------------------------------------------
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER_SCRIPT = os.path.join(REPO_ROOT, "malicious_mcp_server.py")
CONFIG_PATH = os.environ.get("MCPRT_CONFIG", "")
PYTHON = sys.executable

# ---------------------------------------------------------------------------
# Known malicious indicators that MCP-Scan / Snyk agent-scan check for
# (compiled from Invariant Labs public advisories and mcp-scan source history)
# ---------------------------------------------------------------------------
SIGNATURES: list[tuple[str, str]] = [
    # Prompt injection framing tags
    ("<IMPORTANT>",           "Prompt injection framing tag"),
    ("<important>",           "Prompt injection framing tag (lc)"),
    ("<instruction>",         "Instruction override tag"),
    ("<INSTRUCTION>",         "Instruction override tag (uc)"),
    ("<system>",              "System-role injection tag"),
    # Exfiltration vocabulary
    ("http://",               "Hardcoded HTTP URL"),
    ("https://",              "Hardcoded HTTPS URL"),
    ("POST",                  "HTTP method keyword"),
    ("exfil",                 "Exfiltration keyword"),
    # Override/authority language
    ("IGNORE",                "Override directive"),
    ("ignore previous",       "Override directive (lc)"),
    ("disregard",             "Authority override"),
    ("override",              "Authority override"),
    ("AGENT DIRECTIVE",       "Explicit agent directive"),
    # Secrecy instruction
    ("do not mention",        "Secrecy instruction"),
    ("do not inform",         "Secrecy instruction"),
    ("do not tell",           "Secrecy instruction"),
    ("without mentioning",    "Secrecy instruction (alt)"),
    ("silently",              "Silent-action directive"),
    # Pre-action injection phrases (Invariant Labs pattern library)
    ("Before answering",      "Pre-action injection phrase"),
    ("Before responding",     "Pre-action injection phrase"),
    ("Before returning",      "Pre-action injection phrase"),
    ("Before summarizing",    "Pre-action injection phrase"),
    # Credential / file targeting
    (".ssh/id_rsa",           "SSH key reference"),
    (".env",                  "Env file reference"),
    ("secret",                "Credential keyword"),
    ("credential",            "Credential keyword"),
    ("password",              "Credential keyword"),
    ("canary",                "Honeytoken reference"),
    ("api_key",               "API key reference"),
]

# Unicode tag block (U+E0000–U+E007F) — hidden unicode injection
TAG_BLOCK_RANGE = (0xE0000, 0xE007F)

# Zero-width characters used in hidden unicode attacks
ZERO_WIDTH = {"​", "⁠", "﻿"}


# ---------------------------------------------------------------------------

def recv_json(proc: subprocess.Popen, timeout_s: float = 5.0) -> dict | None:
    """Read one JSON-RPC line from proc.stdout with a timeout."""
    ready, _, _ = select.select([proc.stdout], [], [], timeout_s)
    if not ready:
        return None
    line = proc.stdout.readline()
    if not line:
        return None
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return None


def send_json(proc: subprocess.Popen, msg: dict) -> None:
    raw = (json.dumps(msg) + "\n").encode()
    proc.stdin.write(raw)
    proc.stdin.flush()


def query_tool_list() -> list[dict]:
    """Spawn the server and return its tools/list response."""
    env = dict(os.environ)
    if CONFIG_PATH:
        env["MCPRT_CONFIG"] = CONFIG_PATH

    proc = subprocess.Popen(
        [PYTHON, SERVER_SCRIPT],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=env,
    )

    try:
        # MCP initialize
        send_json(proc, {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "mcp-rt-probe", "version": "1.0"},
            },
        })

        # Drain until initialize response
        init_ok = False
        for _ in range(20):
            msg = recv_json(proc, timeout_s=3.0)
            if msg and msg.get("id") == 1:
                init_ok = True
                break

        if not init_ok:
            raise RuntimeError("No initialize response from server")

        send_json(proc, {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
        time.sleep(0.05)

        # Request tool list
        send_json(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})

        for _ in range(20):
            msg = recv_json(proc, timeout_s=5.0)
            if msg and msg.get("id") == 2:
                return msg.get("result", {}).get("tools", [])

        raise RuntimeError("No tools/list response from server")

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()


def analyze_description(name: str, desc: str) -> dict:
    """Run all detection checks against a single tool description."""
    desc_lower = desc.lower()

    keyword_hits = [
        (pattern, label)
        for pattern, label in SIGNATURES
        if pattern.lower() in desc_lower
    ]

    tag_chars = [c for c in desc if TAG_BLOCK_RANGE[0] <= ord(c) <= TAG_BLOCK_RANGE[1]]
    zwsp_chars = [c for c in desc if c in ZERO_WIDTH]

    return {
        "name": name,
        "description": desc,
        "keyword_hits": keyword_hits,
        "tag_block_chars": len(tag_chars),
        "zero_width_chars": len(zwsp_chars),
        "byte_length": len(desc.encode("utf-8")),
        "char_length": len(desc),
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    sep = "=" * 72

    print(sep)
    print("mcp-rt  ·  Tool-List Probe  (simulates what a scanner receives)")
    print(sep)
    print(f"Server  : {SERVER_SCRIPT}")
    print(f"Config  : {CONFIG_PATH or '(none — defaults apply)'}")
    print(f"Python  : {PYTHON}")
    print()

    try:
        tools = query_tool_list()
    except Exception as exc:
        print(f"[ERROR] Could not retrieve tool list: {exc}", file=sys.stderr)
        return 2

    # ── Raw JSON ─────────────────────────────────────────────────────────
    print(f"Tools returned by server: {len(tools)}")
    print()
    print("Raw JSON (byte-for-byte what MCP-Scan / Snyk agent-scan receives):")
    print("-" * 72)
    print(json.dumps(tools, indent=2, ensure_ascii=False))
    print("-" * 72)
    print()

    # ── Human readable ───────────────────────────────────────────────────
    print("Human-readable summary:")
    print()
    for t in tools:
        name = t.get("name", "<no-name>")
        desc = t.get("description", "")
        schema = t.get("inputSchema", {})
        props = list(schema.get("properties", {}).keys())
        print(f"  Tool: {name}")
        print(f"  Params: {', '.join(props) if props else 'none'}")
        print(f"  Description:")
        for line in textwrap.wrap(desc, width=65):
            print(f"    {line}")
        print()

    # ── Keyword / indicator analysis ─────────────────────────────────────
    print(sep)
    print("DETECTION ANALYSIS  (keyword / signature scan)")
    print(sep)
    print()

    total_hits = 0
    for t in tools:
        result = analyze_description(t.get("name", ""), t.get("description", ""))
        hits = result["keyword_hits"]
        total_hits += len(hits)

        print(f"  Tool: {result['name']}")
        print(f"    Signature hits      : {[f'{p} ({l})' for p,l in hits] if hits else 'NONE'}")
        print(f"    Tag-block unicode   : {result['tag_block_chars']} chars")
        print(f"    Zero-width chars    : {result['zero_width_chars']} chars")
        print(f"    Description length  : {result['char_length']} chars / {result['byte_length']} bytes")
        print()

    # ── Verdict ──────────────────────────────────────────────────────────
    print(sep)
    print("SCANNER EVASION VERDICT")
    print(sep)
    print()

    if total_hits == 0:
        print("  Total malicious indicators found in tool descriptions: 0")
        print()
        print("  Snyk Agent Scan (MCP-Scan) RESULT: 0 FINDINGS")
        print()
        print("  Root cause: The server-side workflow attack carries no malicious")
        print("  content in tool descriptions. The attack surface is entirely in")
        print("  server Python code — invisible to any description-only scanner.")
        print()
        print("  What a scanner DOES see:")
        print("    'get_workspace_config'  — reads config from a path (benign utility)")
        print("    'apply_workspace_config'— syncs config across environments (benign utility)")
        print()
        print("  What a scanner CANNOT see:")
        print("    - get_workspace_config reads ANY file including honeytokens")
        print("    - apply_workspace_config POSTs data to EXFIL_URL from env")
        print("    - Together they form a complete read-then-exfiltrate chain")
        print("    - The attack requires zero LLM instruction; the agent is guided")
        print("      only by the task prompt from the attacker-controlled context")
        print()
        print("  EVASION: CONFIRMED")
        return 0
    else:
        print(f"  Total malicious indicators found: {total_hits}")
        print("  One or more indicators detected — descriptions require adjustment.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
