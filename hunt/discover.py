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
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

# Known client config locations, relative to a user's profile folder. Project-level files are found by walking --root.
# Breadth matters: a server we never enumerate is a server we can never assess ("nothing missed").
# ONE list for every OS: a location that belongs to another OS simply does not exist on this machine, so there is no
# per-platform branch to get wrong (and a Linux test can plant a macOS or Windows layout and run the real code).
# Desktop apps keep per-user data in a different folder on each OS; _per_os() writes one location out three times.
_APP_DIRS = (".config", "Library/Application Support", "AppData/Roaming")      # Linux, macOS, Windows (%APPDATA%)


def _per_os(rel: str) -> list[str]:
    return [f"{base}/{rel}" for base in _APP_DIRS]


# Locations were checked against each vendor's documentation on 2026-11-26. A "*" matches any one folder or file
# name. Three confidence groups, kept apart so a claim about coverage can say which is which.
_HOME_CONFIGS = [
    # --- documented by the vendor; a dot-folder in the profile, so the same on every OS ---
    ".cursor/mcp.json",                                            # Cursor
    ".codex/config.toml",                                          # OpenAI Codex CLI
    ".gemini/settings.json",                                       # Gemini CLI
    ".cline/data/settings/cline_mcp_settings.json",                # Cline CLI
    ".claude.json",                                                # Claude Code (user scope)
    ".copilot/mcp-config.json",                                    # GitHub Copilot CLI / Copilot agent
    ".codeium/windsurf/mcp_config.json",                           # Windsurf
    ".codeium/windsurf-next/mcp_config.json",                      # Windsurf pre-release
    ".continue/config.json", ".continue/config.yaml",              # Continue
    ".aws/amazonq/mcp.json", ".aws/amazonq/default.json",          # Amazon Q Developer (legacy file, agent file)
    ".aws/amazonq/agents/default.json", ".aws/amazonq/cli-agents/*.json",
    ".kiro/settings/mcp.json",                                     # Kiro
    ".lmstudio/mcp.json",                                          # LM Studio
    # --- documented by the vendor; a per-user app folder that sits in a different place on each OS ---
    *_per_os("Claude/claude_desktop_config.json"),                 # Claude Desktop
    *_per_os("devin/mcp_config.json"),                             # Windsurf after its rename to Devin Desktop
    ".config/zed/settings.json",                                   # Zed on macOS and Linux (context_servers)
    ".config/goose/config.yaml", "AppData/Roaming/Block/goose/config/config.yaml",     # Goose
    # --- from the vendor's source code or the platform's convention, not stated in its docs ---
    *_per_os("Code/User/mcp.json"), *_per_os("Code/User/profiles/*/mcp.json"),   # VS Code: user-level, named profiles
    *_per_os("Code/User/settings.json"),                           # VS Code before 1.102 ("mcp" key in settings)
    *_per_os("Code - Insiders/User/mcp.json"),                     # VS Code Insiders
    *_per_os("Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json"),   # Cline in VS Code
    *_per_os("Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json"),     # Roo Code in VS Code
    "AppData/Roaming/Zed/settings.json", ".var/app/dev.zed.Zed/config/zed/settings.json",          # Zed: Windows, Flatpak
    ".continue/mcpServers/*.yaml", ".continue/mcpServers/*.json",  # Continue: one file per server
    # --- candidates no vendor documents: a wrong guess costs one check for a file that is not there ---
    ".vscode/mcp.json", ".roo/mcp.json", ".witsy/mcp.json", ".codeium/mcp_config.json",
    ".config/github-copilot/mcp.json", ".config/github-copilot/intellij/mcp.json",
    "AppData/Local/github-copilot/intellij/mcp.json",
]
# Servers an administrator deployed for EVERY user of the machine, outside any profile. Relative to the filesystem
# root (the system drive on Windows); all vendor-documented.
_SYSTEM_CONFIGS = [
    "etc/claude-code/managed-mcp.json", "Library/Application Support/ClaudeCode/managed-mcp.json",
    "Program Files/ClaudeCode/managed-mcp.json",                   # Claude Code, admin-managed
    "etc/gemini-cli/settings.json", "Library/Application Support/GeminiCli/settings.json",
    "ProgramData/gemini-cli/settings.json",                        # Gemini CLI, system-wide
    "etc/codex/config.toml", "etc/codex/managed_config.toml",      # Codex CLI, system-wide
]
_PROJECT_GLOBS = (".mcp.json", "mcp_settings.json", ".cursor/mcp.json",
                  ".gemini/settings.json", ".vscode/mcp.json", ".roo/mcp.json",
                  ".kiro/settings/mcp.json", ".amazonq/mcp.json", ".amazonq/default.json", ".codex/config.toml",
                  ".devin/mcp_config.json", ".github/mcp.json")

# ---- Secret redaction: discovery must never surface a credential value, anywhere. ---------------
_SECRET_ARG = re.compile(
    r'(--?[\w-]*(?:key|token|secret|pass|pwd|auth|credential)[\w-]*[=\s]+|'
    r'[A-Za-z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD)[A-Za-z0-9_]*=)(\S+)', re.I)
_SECRET_VAL = re.compile(
    r'\b(sk-[A-Za-z0-9_\-]{6,}|gh[pousr]_[A-Za-z0-9]{16,}|xox[baprs]-[A-Za-z0-9-]{10,}|'
    r'AKIA[0-9A-Z]{12,}|eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-.]+)\b')


def _redact(s: str) -> str:
    """Mask credential-looking args/values in a command line before it is stored or shown."""
    s = _SECRET_ARG.sub(lambda m: m.group(1) + "***redacted***", s)
    return _SECRET_VAL.sub("***redacted***", s)


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


def _servers_from_obj(obj, yaml_file: bool = False) -> dict:
    """Pull an {name: spec} server map from any known config shape. Never raises on an unexpected shape: a config
    we cannot read is skipped, it must not take the whole inventory down."""
    if not isinstance(obj, dict):
        return {}
    mcp = obj.get("mcp")
    found = (obj.get("mcpServers") or obj.get("mcp_servers") or obj.get("servers")
             or (mcp.get("servers") if isinstance(mcp, dict) else None)
             or obj.get("context_servers")                         # Zed
             or (obj.get("extensions") if yaml_file else None)     # Goose (YAML only: elsewhere the word means plugins)
             or {})
    if isinstance(found, list):                                    # Continue's YAML lists servers, each with its name
        found = {str(s.get("name") or f"server-{i + 1}"): s for i, s in enumerate(found) if isinstance(s, dict)}
    return found if isinstance(found, dict) else {}


def _parse(path: Path) -> list[DiscoveredServer]:
    try:
        text = path.read_text(encoding="utf-8-sig")     # Windows editors save a byte-order mark; json.loads rejects it
    except (OSError, UnicodeError):
        return []
    is_yaml = path.suffix in (".yaml", ".yml")
    try:
        if path.suffix == ".toml":
            import tomllib
            obj = tomllib.loads(text)
        elif is_yaml:
            import yaml
            obj = yaml.safe_load(text)
        else:
            obj = json.loads(re.sub(r"(^|\s)//.*", "", text))   # tolerate // comments (VS Code)
    except Exception:  # noqa: BLE001 — unparseable config is skipped, not fatal
        return []
    out = []
    for name, spec in _servers_from_obj(obj, is_yaml).items():
        if not isinstance(spec, dict):
            continue
        # Cline wraps the real spec under "transport"; elsewhere that key is just a word like "stdio"
        sp = spec["transport"] if isinstance(spec.get("transport"), dict) else spec
        if sp.get("type") in ("builtin", "platform", "frontend"):   # Goose's own built-ins are not installed servers
            continue
        # clients name the same three things differently: read every spelling
        url = sp.get("url") or sp.get("uri") or sp.get("serverUrl") or sp.get("httpUrl") or ""
        command, args, env = sp.get("command") or sp.get("cmd"), sp.get("args") or [], sp.get("env") or sp.get("envs")
        if isinstance(command, dict):                               # older Zed: command is {path, args, env}
            command, args, env = command.get("path"), command.get("args") or [], env or command.get("env")
        elif isinstance(command, list) and command:
            command, args = command[0], [*command[1:], *args]
        env_keys = list(env.keys()) if isinstance(env, dict) else []
        if isinstance(url, str) and url:
            out.append(DiscoveredServer(str(name), str(path), "http", url, env_keys))
        elif isinstance(command, str) and command:
            launch = " ".join(str(a) for a in [command, *(args if isinstance(args, list) else [])]).strip()
            out.append(DiscoveredServer(str(name), str(path), "stdio", launch, env_keys))
    return out


def discover_system_configs(root: Path | None = None) -> list[DiscoveredServer]:
    """Servers an administrator deployed for every user of this machine (admin-managed files outside any profile)."""
    root = root or Path(os.environ.get("SystemDrive", "C:") + "\\" if os.name == "nt" else "/")
    return [s for rel in _SYSTEM_CONFIGS for s in _parse(root / rel)]


def discover_configs(home: Path | None = None, roots: list | None = None) -> list[DiscoveredServer]:
    home = home or Path.home()
    found: list[DiscoveredServer] = []
    for rel in _HOME_CONFIGS:
        for p in (sorted(home.glob(rel)) if "*" in rel else [home / rel]):
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


_PROC_HINT = re.compile(r"\b(npx|uvx|uv|node|python[0-9.]*|deno|bun)\b", re.I)


def discover_processes() -> list[DiscoveredServer]:
    """Running MCP-server processes — catches servers live on the box but in no config file we parse.

    A real blind spot: a server started by hand, by a daemon, or by a client we don't know about shows
    up here and nowhere else. Command lines are redacted (a token passed as an arg never leaks)."""
    import shutil
    import subprocess
    import sys
    if not shutil.which("ps"):                       # Windows has none: the runner lists processes its own way
        return []
    # BSD ps (macOS) reads -e as "print each process's ENVIRONMENT", which would dump every variable and still not
    # list every process; -ax is its "all processes".
    argv = ["ps", "-axww", "-o", "args="] if sys.platform == "darwin" else ["ps", "-eo", "args"]
    try:
        txt = subprocess.run(argv, capture_output=True, text=True, timeout=10).stdout
    except Exception:  # noqa: BLE001
        return []
    return processes_from_cmdlines(txt.splitlines())


def processes_from_cmdlines(cmdlines) -> list[DiscoveredServer]:
    """The name heuristic over command lines, however the caller listed the processes (`ps` here, psutil in the
    runner, so the same rule applies on Linux, macOS and Windows)."""
    out, seen = [], set()
    for line in cmdlines:
        cmd = line.strip()
        low = cmd.lower()
        if "mcp" not in low or not _PROC_HINT.search(low):
            continue
        if "mcp-rt" in low or "hunt.cli" in low or "discover" in low:   # don't flag ourselves
            continue
        safe = _redact(cmd)[:300]
        if safe in seen:
            continue
        seen.add(safe)
        out.append(DiscoveredServer(_proc_name(cmd), "running process", "stdio", safe))
    return out


def _proc_name(cmd: str) -> str:
    """Best-effort server name from a process command line: the arg that names the MCP package."""
    for tok in cmd.split():
        t = tok.strip("'\"")
        if "mcp" in t.lower() and not _PROC_HINT.fullmatch(t):
            return re.split(r"[\\/]", t)[-1][:60]
    return re.split(r"[\\/]", (cmd.split() or ["mcp-process"])[0])[-1][:60]


def discover(roots: list | None = None) -> list[DiscoveredServer]:
    """Full host inventory: configured servers + installed packages + running processes
    (deduped by name+launch). The complete local asset surface, before any assessment."""
    all_ = discover_configs(roots=roots) + discover_packages() + discover_processes()
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


def persist_discovery(servers: list[DiscoveredServer], *, db=None) -> int:
    """Align the discovered inventory to the CMDB: upsert every asset as a target (idempotent),
    stamping transport/state/source/env-key-names into meta and refreshing last_seen. This is the
    asset ledger the vulnerability-discovery stage then works from — nothing found is left unrecorded."""
    import json as _json
    from hunt.findings_db import DB
    close = db is None
    db = db or DB()
    try:
        for s in servers:
            db.add_target(name=s.name, install_cmd=s.launch,
                          source=f"discover:{s.transport}:{Path(s.source).name or s.source}",
                          meta=_json.dumps(s.as_dict()))
        return len(servers)
    finally:
        if close:
            db.close()


def main(argv=None) -> int:
    import argparse
    import os
    import sys
    p = argparse.ArgumentParser(prog="mcp-rt discover",
                                description="Discover MCP servers on this host (configs + packages + "
                                            "running processes), optionally the network")
    p.add_argument("--root", action="append", default=[os.getcwd()],
                   help="project dir to also scan for .mcp.json etc. (repeatable)")
    p.add_argument("--no-localhost", action="store_true",
                   help="skip probing 127.0.0.1 for HTTP/SSE MCP endpoints")
    p.add_argument("--network", metavar="CIDR",
                   help="scan a subnet for MCP endpoints, e.g. 192.168.1.0/24 (ACTIVE RECON)")
    p.add_argument("--authorized-by", default="",
                   help="REQUIRED for --network: who authorized scanning this network")
    p.add_argument("--save", action="store_true",
                   help="persist the discovered assets to the CMDB ledger (one target per asset)")
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
    if args.save and servers:
        n = persist_discovery(servers)
        print(f"recorded {n} asset(s) to the CMDB ledger.", file=sys.stderr)
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
