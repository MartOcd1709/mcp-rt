"""Per-scan isolation — make verdicts trustworthy at scale.

Scanning means installing and running an untrusted MCP server. Done in one shared environment,
servers clash (Server A needs mcp 1.x, B needs 2.x), leave residue, and poison each other — the
bulk of the old ~35% INCONCLUSIVE rate. run_isolated() gives each scan a clean, throwaway
environment and returns a normal report dict:

  * "subprocess" (default, works everywhere — no Docker): run the scan in a child process with a
    fresh HOME + caches + TMPDIR + cwd, so npx/uvx/pip create isolated per-scan environments and
    leave no residue. Kills state contamination and most dependency clashes.
  * "docker" (opt-in, the VPS/production mode): run the scan inside a fresh --rm container (pinned
    image with mcp-rt + node + uv). Full OS isolation — clashes CAN'T happen, and a malicious
    server is boxed off the host and destroyed after.

"auto" picks docker when MCPRT_SCAN_BACKEND=docker (or =auto) and docker is present, else subprocess.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile

_IMAGE = os.getenv("MCPRT_SCAN_IMAGE", "mcp-rt:latest")
_PKG_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # repo/install root (parent of hunt/)


def docker_available() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=10).returncode == 0
    except Exception:  # noqa: BLE001
        return False


def _choose(backend: str) -> str:
    if backend == "auto":
        want_docker = os.getenv("MCPRT_SCAN_BACKEND", "subprocess") in ("docker", "auto")
        return "docker" if (want_docker and docker_available()) else "subprocess"
    return backend


def isolated_env(home: str) -> dict:
    """Env that confines a scan's package installs / caches / temp files under `home`."""
    env = os.environ.copy()
    env.update({
        "HOME": home,
        "TMPDIR": os.path.join(home, "tmp"),
        "XDG_CACHE_HOME": os.path.join(home, "cache"),
        "XDG_CONFIG_HOME": os.path.join(home, "config"),
        "npm_config_cache": os.path.join(home, "npm"),
        "UV_CACHE_DIR": os.path.join(home, "uv"),
        "PIP_CACHE_DIR": os.path.join(home, "pip"),
    })
    # mcp-rt itself must stay importable from the clean cwd (the TARGET's installs are what we isolate,
    # not the scanner's). Keep the scanner package root on PYTHONPATH.
    env["PYTHONPATH"] = os.pathsep.join([_PKG_ROOT, env.get("PYTHONPATH", "")]).rstrip(os.pathsep)
    for sub in ("tmp", "cache", "config", "npm", "uv", "pip"):
        os.makedirs(os.path.join(home, sub), exist_ok=True)
    return env


def _argv_subprocess(target: str) -> list[str]:
    import sys
    return [sys.executable, "-m", "hunt.cli", "report", "--target-stdio", target, "--json"]


def _argv_docker(target: str) -> list[str]:
    # --rm destroys the container after; --network none by default (set MCPRT_SCAN_NETWORK to allow).
    net = os.getenv("MCPRT_SCAN_NETWORK", "none")
    return ["docker", "run", "--rm", "--network", net, _IMAGE,
            "mcp-rt", "report", "--target-stdio", target, "--json"]


def run_isolated(target: str, *, backend: str = "auto", timeout: int = 300) -> dict:
    """Scan `target` in a fresh, throwaway environment; return a report dict.

    Falls back to an INCONCLUSIVE-shaped report (never raises) so an isolation/runtime failure is
    an honest non-verdict, not a crash. The caller attests over whatever this returns.
    """
    chosen = _choose(backend)
    home = tempfile.mkdtemp(prefix="mcprt_scan_")
    try:
        if chosen == "docker":
            argv, env, cwd = _argv_docker(target), os.environ.copy(), None
        else:
            argv, env, cwd = _argv_subprocess(target), isolated_env(home), home
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env=env, cwd=cwd)
        out = (proc.stdout or "").strip()
        # The report JSON is the last stdout line (servers print banners to stderr/stdout first).
        for line in reversed(out.splitlines()):
            line = line.strip()
            if line.startswith("{"):
                try:
                    return json.loads(line)
                except json.JSONDecodeError:
                    break
        return {"target": target, "verdict": "INCONCLUSIVE", "findings": [], "coverage": [],
                "note": f"isolated scan ({chosen}) produced no report "
                        f"(exit {proc.returncode}): {(proc.stderr or '')[:200]}"}
    except subprocess.TimeoutExpired:
        return {"target": target, "verdict": "INCONCLUSIVE", "findings": [], "coverage": [],
                "note": f"isolated scan ({chosen}) timed out after {timeout}s"}
    finally:
        shutil.rmtree(home, ignore_errors=True)
