"""default_capture() backend selection + the plaintext-CLEAN honesty note.

Default stays the hermetic loopback proxy (tested path). MCPRT_TLS_CAPTURE=1 opts into
TLS-intercepting mitmproxy when installed. A CLEAN verdict from a plaintext-only tap must
say so, so it can never read as a silent HTTPS-complete clean.
"""
import importlib.util

import pytest

from mcp_rt.capture.proxy import LoopbackProxyBackend, MitmproxyBackend, default_capture


def test_default_is_loopback_without_env(monkeypatch):
    monkeypatch.delenv("MCPRT_TLS_CAPTURE", raising=False)
    cap = default_capture()
    assert isinstance(cap, LoopbackProxyBackend) and cap.tls is False


@pytest.mark.skipif(importlib.util.find_spec("mitmproxy") is None, reason="mitmproxy extra not installed")
def test_env_opts_into_mitmproxy(monkeypatch):
    monkeypatch.setenv("MCPRT_TLS_CAPTURE", "1")
    cap = default_capture()
    assert isinstance(cap, MitmproxyBackend) and cap.tls is True


def test_env_set_but_mitmproxy_missing_falls_back(monkeypatch):
    monkeypatch.setenv("MCPRT_TLS_CAPTURE", "1")
    # Simulate the extra not being installed: make the availability probe import fail.
    import builtins
    real_import = builtins.__import__

    def _no_mitm(name, *a, **k):
        if name == "mitmproxy":
            raise ImportError("not installed")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", _no_mitm)
    assert isinstance(default_capture(), LoopbackProxyBackend)
