"""Local streamable-http MCP server fixture for the DNS-rebinding check.

Env toggles the control:
  DNS_PROTECT=1  -> Origin/DNS-rebinding protection ON  (must verdict CLEAN)
  DNS_PROTECT=0  -> protection OFF / origins "*"          (must verdict VULNERABLE)
  PORT=<n>       -> listen port on 127.0.0.1

Local, offline test asset only. Endpoint: http://127.0.0.1:<PORT>/mcp
"""
import os

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

_protect = os.environ.get("DNS_PROTECT") == "1"
_port = int(os.environ.get("PORT", "8991"))

_ts = (TransportSecuritySettings(enable_dns_rebinding_protection=True,
                                 allowed_origins=["http://127.0.0.1:*", "http://localhost:*"],
                                 allowed_hosts=["127.0.0.1:*", "localhost:*"])
       if _protect else
       TransportSecuritySettings(enable_dns_rebinding_protection=False,
                                 allowed_origins=["*"], allowed_hosts=["*"]))

mcp = FastMCP("http-test", host="127.0.0.1", port=_port, transport_security=_ts)


@mcp.tool()
def ping() -> str:
    """Health check."""
    return "pong"


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
