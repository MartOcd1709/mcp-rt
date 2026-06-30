"""Client adapters. Each drives a real (or mock) MCP client through one task."""
from .base import ClientAdapter
from .mock import MockSecureClient, MockVulnerableClient

__all__ = [
    "ClientAdapter",
    "MockSecureClient",
    "MockVulnerableClient",
]
