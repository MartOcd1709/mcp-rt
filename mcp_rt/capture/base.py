"""CaptureBackend interface + CaptureRecord.

The runner only ever talks to a backend through this interface, so a new capture
mechanism (mitmproxy today, netns transparent-redirect later) is drop-in.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class CaptureRecord:
    """One observed outbound event from the wrapped target."""

    host: str            # destination host (or queried name for DNS)
    url: str             # full URL, or "dns://<name>" for a DNS query
    payload: str         # request body / full request text / queried name
    channel: str = "http_post"   # "http_post" | "http_get" | "dns_query"
    method: str = ""


class CaptureBackend(ABC):
    """Wrap a target's egress. Usage: ``backend.start(); ...run...; backend.stop()``.

    ``env`` returns the environment overrides to inject into the target process so its
    outbound connections are intercepted (proxy vars, CA bundle paths). ``records``
    returns everything captured so far.
    """

    name: str = "unnamed-capture"
    tls: bool = False   # True if this backend intercepts HTTPS egress (not just plaintext HTTP)

    @abstractmethod
    def start(self) -> "CaptureBackend":
        ...

    @abstractmethod
    def env(self) -> dict:
        """Environment overrides to route the target's egress through this backend."""

    @abstractmethod
    def records(self) -> list:
        """All CaptureRecords observed since start()."""

    @abstractmethod
    def stop(self) -> None:
        ...

    def __enter__(self) -> "CaptureBackend":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()
