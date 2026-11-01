"""Prototype-pollution oracle host launcher for T11.4 (SAM1-22) — independent ground-truth.

JS prototype pollution (CWE-1321) is a Node phenomenon, so the vulnerable/safe host is a Node.js
2026-07-28 MCP HTTP server (proto_pollution_host.js) spawned as a SUBPROCESS — a fresh process per
host guarantees a clean Object.prototype baseline. The probe stays Python/StatelessHTTPClient,
consistent with every other sub-class. Requires `node` on PATH (a real dependency for JS-host tests).
"""
from __future__ import annotations

import os
import shutil
import subprocess

_HERE = os.path.dirname(os.path.abspath(__file__))
_HOST_JS = os.path.join(_HERE, "proto_pollution_host.js")


def node_available() -> bool:
    return shutil.which("node") is not None


def start(vulnerable: bool = True):
    node = shutil.which("node")
    proc = subprocess.Popen([node, _HOST_JS, "vuln" if vulnerable else "safe"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    line = (proc.stdout.readline() or "").strip()         # "PORT <n>" printed once listening
    if not line.startswith("PORT "):
        proc.kill()
        raise RuntimeError(f"node host failed to start: {line!r} / {(proc.stderr.read() or '')[:300]}")
    port = int(line.split()[1])
    tok = os.urandom(5).hex()
    return proc, f"http://127.0.0.1:{port}/mcp", tok
