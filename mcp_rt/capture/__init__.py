"""Egress capture backends — the ground-truth network tap.

A ``CaptureBackend`` wraps a target server so every outbound request it makes is
logged with its full payload, giving the taint monitor real egress instead of a
simulated log. Backends are pluggable: ``LoopbackProxyBackend`` (stdlib, HTTP-only,
hermetic) for tests and plaintext targets; ``MitmproxyBackend`` (TLS+HTTP, needs the
``capture`` extra) for production. A future netns transparent-redirect backend drops
in by implementing the same interface — nothing else changes.
"""
from .base import CaptureBackend, CaptureRecord

__all__ = ["CaptureBackend", "CaptureRecord"]
