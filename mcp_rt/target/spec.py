"""TargetSpec — the customer's own MCP server, parsed from a CLI flag.

`--target-stdio "npx some-mcp-server"` -> a local subprocess we spawn (and can wrap in
an egress tap). `--target-http https://... [--header 'K: V']` -> a remote server we can
only observe at the agent<->server boundary (its own out-of-band egress is
unobservable-by-design; the runner reports that honestly).
"""
from __future__ import annotations

import shlex
from dataclasses import dataclass, field


@dataclass
class TargetSpec:
    kind: str                          # "stdio" | "http"
    command: list = field(default_factory=list)   # stdio: argv
    url: str = ""                       # http: endpoint
    headers: dict = field(default_factory=dict)    # http: auth/etc.

    # ---- constructors -------------------------------------------------------
    @classmethod
    def from_stdio(cls, command: str) -> "TargetSpec":
        argv = shlex.split(command)
        if not argv:
            raise ValueError("--target-stdio needs a command, e.g. \"npx some-mcp-server\"")
        return cls(kind="stdio", command=argv)

    @classmethod
    def from_http(cls, url: str, headers: list | None = None) -> "TargetSpec":
        if not url:
            raise ValueError("--target-http needs a URL")
        return cls(kind="http", url=url, headers=_parse_headers(headers or []))

    # ---- client config ------------------------------------------------------
    def client_config(self, name: str = "target", env: dict | None = None) -> dict:
        """The `mcpServers` config an MCP client (Claude Code, our probe driver) consumes."""
        if self.kind == "stdio":
            entry: dict = {"command": self.command[0], "args": self.command[1:]}
            if env:
                entry["env"] = dict(env)
            return {"mcpServers": {name: entry}}
        entry = {"url": self.url}
        if self.headers:
            entry["headers"] = dict(self.headers)
        return {"mcpServers": {name: entry}}

    @property
    def observable_egress(self) -> bool:
        """True when we can wrap the server's own outbound traffic (local/stdio only)."""
        return self.kind == "stdio"


def _parse_headers(raw: list) -> dict:
    out: dict = {}
    for h in raw:
        if ":" not in h:
            raise ValueError(f"--header must be 'Key: Value', got {h!r}")
        k, v = h.split(":", 1)
        out[k.strip()] = v.strip()
    return out
