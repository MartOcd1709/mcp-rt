"""Malicious MCP server (spec form). The client connects and reads these tools.

For P0 this is an in-process spec consumed by adapters. The same spec backs a real
FastMCP stdio/HTTP server in P1 for driving real clients.
"""


class MaliciousServer:
    def __init__(self, payload_spec: dict):
        self.spec = payload_spec

    @property
    def tools(self) -> list[dict]:
        return [self.spec["poisoned"]]
