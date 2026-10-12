"""`mcp-rt discover` — find the MCP servers present on this host ("nmap for MCP", host mode).

MCP servers announce themselves in two places: as entries in AI-client config files (Cursor,
Claude Desktop, Codex, Gemini, Cline, VS Code, project `.mcp.json`) and as installed packages
(pip / npm -g / uv tool). This enumerates both into an inventory you can hand straight to
`mcp-rt assess`/`attest` — turning "what MCP is even on this machine?" into an answerable question.

Read-only and secret-safe: it parses configs, never writes them, and reports only the env-var
NAMES a server declares, never their values (tokens stay redacted).

Network discovery (probe a subnet/host for ports speaking MCP over HTTP/SSE) is active recon and is
deliberately NOT done here — that belongs behind the same consent gate as `mcp-rt remote`
(`--authorized-by`); see discover_localhost() for the safe loopback-only starting point.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

# Known client config locations (home-level). Project-level files are found by walking --root.
_HOME_CONFIGS = [
    ".cursor/mcp.json", ".codex/config.toml", ".gemini/settings.json",
    ".cline/data/settings/cline_mcp_settings.json",
    ".config/Claude/claude_desktop_config.json",
    "Library/Application Support/Claude/claude_desktop_config.json",
    ".config/Code/User/settings.json", ".vscode/mcp.json",
]
_PROJECT_GLOBS = (".mcp.json", "mcp_settings.json", ".cursor/mcp.json",
                  ".gemini/settings.json", ".vscode/mcp.json")


@dataclass
class DiscoveredServer:
    name: str
    source: str                   # the config file / package manager it was found in
    transport: str = "stdio"      # "stdio" | "http"
    launch: str = ""              # the command (stdio) or URL (http) — safe to show
    env_keys: list = field(default_factory=list)   # declared env VAR NAMES only (values redacted)
    state: str = "open"           # network only: "open" (reachable) | "protected" (401, auth required)

    def as_dict(self) -> dict:
        return {"name": self.name, "source": self.source, "transport": self.transport,
                "launch": self.launch, "env_keys": self.env_keys, "state": self.state}


def _servers_from_obj(obj: dict) -> dict:
    """Pull an {name: spec} server map from any known config shape."""
    if not isinstance(obj, dict):
        return {}
    return (obj.get("mcpServers") or obj.get("mcp_servers") or obj.get("servers")
            or (obj.get("mcp") or {}).get("servers") or {})


def _parse(path: Path) -> list[DiscoveredServer]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return []
    try:
        if path.suffix == ".toml":
            import tomllib
            obj = tomllib.loads(text)
        else:
            obj = json.loads(re.sub(r"(^|\s)//.*", "", text))   # tolerate // comments (VS Code)
    except Exception:  # noqa: BLE001 — unparseable config is skipped, not fatal
        return []
    out = []
    for name, spec in _servers_from_obj(obj).items():
        if not isinstance(spec, dict):
            continue
        sp = spec.get("transport", spec)    # Cline wraps the real spec under "transport"
        url = sp.get("url", "")
        if url:
            out.append(DiscoveredServer(name, str(path), "http", url,
                                        list((sp.get("env") or {}).keys())))
        elif sp.get("command"):
            launch = (sp["command"] + " " + " ".join(sp.get("args", []))).strip()
            out.append(DiscoveredServer(name, str(path), "stdio", launch,
                                        list((sp.get("env") or {}).keys())))
    return out


def discover_configs(home: Path | None = None, roots: list | None = None) -> list[DiscoveredServer]:
    home = home or Path.home()
    found: list[DiscoveredServer] = []
    for rel in _HOME_CONFIGS:
        p = home / rel
        if p.is_file():
            found += _parse(p)
    for root in (roots or []):
        root = Path(root)
        for g in _PROJECT_GLOBS:
            for p in root.glob(f"**/{g}"):
                if "node_modules" not in str(p) and "/.venv/" not in str(p):
                    found += _parse(p)
    return found


def discover_packages() -> list[DiscoveredServer]:
    """Installed MCP-server packages (pip / npm -g / uv tool)."""
    import shutil
    import subprocess
    out = []

    def _run(argv):
        try:
            return subprocess.run(argv, capture_output=True, text=True, timeout=20).stdout
        except Exception:  # noqa: BLE001
            return ""
    for name, argv, pat in (
        ("pip", ["pip", "list"], r"^(\S*mcp\S*)\s"),
        ("uv-tool", ["uv", "tool", "list"], r"^(\S*mcp\S*)\s"),
        ("npm-g", ["npm", "ls", "-g", "--depth=0"], r"(@?[\w/-]*mcp[\w/-]*)@"),
    ):
        exe = argv[0]
        if not shutil.which(exe):
            continue
        for line in _run(argv).splitlines():
            m = re.search(pat, line, re.I)
            if m and "modelcontext" not in m.group(1).lower() or (m and "mcp" in m.group(1).lower()):
                out.append(DiscoveredServer(m.group(1), f"{name} package", "stdio", m.group(1)))
    return out


def discover(roots: list | None = None) -> list[DiscoveredServer]:
    """Full host inventory: configured servers + installed packages (deduped by name+launch)."""
    all_ = discover_configs(roots=roots) + discover_packages()
    seen, uniq = set(), []
    for s in all_:
        k = (s.name, s.launch)
        if k not in seen:
            seen.add(k)
            uniq.append(s)
    return uniq


# --------------------------------------------------------------------------------------
# Network discovery — probe for ports that SPEAK MCP over HTTP/SSE ("nmap for MCP").
# Loopback is free; scanning other hosts/subnets is active recon -> consent-gated.
# --------------------------------------------------------------------------------------
_COMMON_MCP_PORTS = [8080, 8000, 3000, 3001, 8001, 8085, 5000, 9000, 8888, 8765, 7860]
# Streamable-HTTP / JSON-RPC mount points (POST), then SSE mount points (GET).
_RPC_PATHS = ["/mcp", "/", "/api/mcp", "/v1/messages"]
_SSE_PATHS = ["/sse", "/mcp", "/"]
_PROTOCOL_VERSION = "2025-06-18"


def _rpc_body(method: str) -> dict:
    params = {"protocolVersion": _PROTOCOL_VERSION, "capabilities": {},
              "clientInfo": {"name": "mcp-rt-discover", "version": "1"}}
    return {"jsonrpc": "2.0", "id": 1, "method": method,
            "params": params if method == "initialize" else {}}


def _looks_like_mcp_rpc(body: str) -> bool:
    """A JSON-RPC handshake reply that is specifically MCP (not just any JSON-RPC)."""
    b = body.lower()
    return '"jsonrpc"' in b and ('"serverinfo"' in b or '"protocolversion"' in b
                                 or '"supportedversions"' in b or '"capabilities"' in b)


def probe_mcp_endpoint(host: str, port: int, timeout: float = 1.5) -> DiscoveredServer | None:
    """Fingerprint host:port by the MCP protocol HANDSHAKE (not a banner or substring).

    Order: POST `initialize`/`server/discover` (streamable-HTTP + spec-2026-07-28), then GET for an
    SSE content-type. A 401/403 carrying WWW-Authenticate is a PROTECTED MCP server (RFC 9728).
    Never reads an event-stream body (it may never end) — the content-type header is the signal.
    """
    import socket
    try:                                       # cheap TCP pre-check before any HTTP
        with socket.create_connection((host, port), timeout=timeout):
            pass
    except OSError:
        return None
    import httpx
    base = f"http://{host}:{port}"

    def hit(path: str, state: str) -> DiscoveredServer:
        return DiscoveredServer(f"{host}:{port}", "network probe", "http", base + path, state=state)

    try:
        with httpx.Client(timeout=timeout) as client:
            for path in _RPC_PATHS:                                    # (1) JSON-RPC / streamable-HTTP
                for method in ("server/discover", "initialize"):
                    try:
                        with client.stream("POST", base + path, json=_rpc_body(method),
                                           headers={"Accept": "application/json, text/event-stream",
                                                    "MCP-Protocol-Version": _PROTOCOL_VERSION}) as r:
                            ct = r.headers.get("content-type", "")
                            if r.status_code in (401, 403) and _has_www_auth(r.headers):
                                return hit(path, "protected")
                            if r.status_code == 200 and "text/event-stream" in ct:
                                return hit(path, "open")              # streamable-HTTP replies via SSE
                            body = _read_capped(r) if "json" in ct else ""
                        if _looks_like_mcp_rpc(body):
                            return hit(path, "open")
                    except Exception:  # noqa: BLE001
                        continue
            for path in _SSE_PATHS:                                    # (2) SSE transport (header only)
                try:
                    with client.stream("GET", base + path,
                                       headers={"Accept": "text/event-stream"}) as r:
                        if r.status_code == 200 and "text/event-stream" in \
                                r.headers.get("content-type", ""):
                            return hit(path, "open")
                        if r.status_code in (401, 403) and _has_www_auth(r.headers):
                            return hit(path, "protected")
                except Exception:  # noqa: BLE001
                    continue
    except Exception:  # noqa: BLE001
        return None
    return None


def _has_www_auth(headers) -> bool:
    return any(k.lower() == "www-authenticate" for k in headers)


def _read_capped(r, cap: int = 2048) -> str:
    """Read at most `cap` bytes of a NON-stream (JSON) body so a slow peer can't hang us."""
    buf = ""
    for chunk in r.iter_text():
        buf += chunk
        if len(buf) >= cap:
            break
    return buf[:cap]


def discover_localhost(ports: list | None = None) -> list[DiscoveredServer]:
    """Safe: probe 127.0.0.1 on common MCP ports (no external network touched)."""
    ports = ports or _COMMON_MCP_PORTS
    return [s for s in (probe_mcp_endpoint("127.0.0.1", p) for p in ports) if s]


def discover_network(cidr: str, *, authorized_by: str, ports: list | None = None,
                     max_hosts: int = 256) -> list[DiscoveredServer]:
    """Scan a subnet for MCP-speaking endpoints. ACTIVE RECON — requires an authorization
    attestation (you confirm you own / are permitted to scan this network); refuses without one."""
    if not authorized_by or not authorized_by.strip():
        raise PermissionError("network discovery requires --authorized-by (scan only networks you "
                              "own or are explicitly authorized to test)")
    import ipaddress
    from concurrent.futures import ThreadPoolExecutor
    ports = ports or _COMMON_MCP_PORTS
    hosts = [str(h) for h in ipaddress.ip_network(cidr, strict=False).hosts()][:max_hosts]
    found: list[DiscoveredServer] = []
    with ThreadPoolExecutor(max_workers=64) as pool:
        for s in pool.map(lambda hp: probe_mcp_endpoint(hp[0], hp[1]),
                          [(h, p) for h in hosts for p in ports]):
            if s:
                found.append(s)
    return found


def main(argv=None) -> int:
    import argparse
    import os
    import sys
    p = argparse.ArgumentParser(prog="mcp-rt discover",
                                description="Discover MCP servers on this host (configs + packages)")
    p.add_argument("--root", action="append", default=[os.getcwd()],
                   help="project dir to also scan for .mcp.json etc. (repeatable)")
    p.add_argument("--no-localhost", action="store_true",
                   help="skip probing 127.0.0.1 for HTTP/SSE MCP endpoints")
    p.add_argument("--network", metavar="CIDR",
                   help="scan a subnet for MCP endpoints, e.g. 192.168.1.0/24 (ACTIVE RECON)")
    p.add_argument("--authorized-by", default="",
                   help="REQUIRED for --network: who authorized scanning this network")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)

    servers = discover(roots=args.root)
    if not args.no_localhost:
        servers += discover_localhost()
    if args.network:
        try:
            servers += discover_network(args.network, authorized_by=args.authorized_by)
        except PermissionError as e:
            print(f"refused: {e}", file=sys.stderr)
            return 2
    if args.json:
        print(json.dumps([s.as_dict() for s in servers], indent=2))
        return 0
    if not servers:
        print("no MCP servers discovered on this host.", file=sys.stderr)
        return 0
    print(f"discovered {len(servers)} MCP server(s) on this host:\n")
    for s in servers:
        tag = f"[{s.transport}]" + (" 🔒auth" if s.state == "protected" else "")
        line = f"  {s.name:24} {tag}  {s.launch}"
        if s.env_keys:
            line += f"   (env: {', '.join(s.env_keys)} = ***redacted***)"
        print(line + f"\n      └─ {s.source}")
    print("\nAssess one:  mcp-rt assess --target-stdio \"<launch command>\"")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
