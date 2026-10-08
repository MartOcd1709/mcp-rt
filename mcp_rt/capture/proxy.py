"""Proxy capture backends.

LoopbackProxyBackend — a stdlib forward proxy on loopback. Injects HTTP(S)_PROXY into
the target so its plaintext HTTP egress is logged and short-circuited (never leaves the
host). No TLS interception, no dependencies: this is the env-proxy MVP and the hermetic
test backend.

MitmproxyBackend — the production tap: mitmproxy handles HTTPS via a generated CA
(injected as REQUESTS_CA_BUNDLE / NODE_EXTRA_CA_CERTS) so TLS egress is captured too.
Requires the ``capture`` extra; import is lazy so the core package works without it.
"""
from __future__ import annotations

import http.server
import os
import socket
import socketserver
import threading
from urllib.parse import urlparse

from .base import CaptureBackend, CaptureRecord


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port   # ponytail: tiny bind-close-rebind race; fine for a local test proxy


def default_capture() -> CaptureBackend:
    """Choose the capture backend for a scan.

    TLS-intercepting mitmproxy when enabled AND installed — set ``MCPRT_TLS_CAPTURE=1`` (the
    packaged container does this) so HTTPS egress is seen, not just plaintext HTTP. Otherwise
    the hermetic loopback proxy. ponytail: env-gated so the in-process default stays the tested
    loopback backend; mitmproxy (async, optional heavy dep) is opt-in for production.
    """
    if os.getenv("MCPRT_TLS_CAPTURE"):
        try:
            import mitmproxy  # noqa: F401  (availability probe)
            return MitmproxyBackend(listen_port=_free_port())
        except ImportError:
            pass   # requested but not installed — fall back, honestly plaintext-only
    return LoopbackProxyBackend()


class _ProxyHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _capture(self) -> None:
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        # In a forward-proxy request the path is the absolute URL.
        url = self.path
        host = urlparse(url).hostname or self.headers.get("Host", "") or url
        self.server.records.append(  # type: ignore[attr-defined]
            CaptureRecord(
                host=host, url=url, payload=body,
                channel="http_post" if self.command == "POST" else "http_get",
                method=self.command,
            )
        )
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    do_POST = _capture
    do_GET = _capture
    do_PUT = _capture

    def log_message(self, *args):  # silence
        pass


class _ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    records: list


class LoopbackProxyBackend(CaptureBackend):
    """HTTP-only forward proxy on loopback. Hermetic; no external network leaves the host."""

    name = "loopback-proxy"

    def __init__(self):
        self._httpd = None
        self._records: list = []
        self.port = None

    def start(self) -> "LoopbackProxyBackend":
        self._httpd = _ThreadingHTTPServer(("127.0.0.1", 0), _ProxyHandler)
        self._httpd.records = self._records
        self.port = self._httpd.server_address[1]
        threading.Thread(target=self._httpd.serve_forever, daemon=True).start()
        return self

    def env(self) -> dict:
        proxy = f"http://127.0.0.1:{self.port}"
        # HTTP only. HTTPS through a plain proxy needs CONNECT tunnelling we don't do —
        # that is MitmproxyBackend's job. ponytail: loopback = plaintext MVP, mitmproxy for TLS.
        return {"HTTP_PROXY": proxy, "http_proxy": proxy, "NO_PROXY": "", "no_proxy": ""}

    def records(self) -> list:
        return list(self._records)

    def stop(self) -> None:
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None


class MitmproxyBackend(CaptureBackend):
    """Production TLS+HTTP tap via mitmproxy. Requires: pip install 'mcp-rt[capture]'.

    ponytail: TLS MITM is a solved problem — we drive mitmproxy, we do not hand-roll it.
    Not exercised by the hermetic suite (mitmproxy is an optional heavy dep); validated
    manually against real HTTPS targets.
    """

    name = "mitmproxy"
    tls = True

    def __init__(self, listen_host: str = "127.0.0.1", listen_port: int = 0):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self._records: list = []
        self._master = None
        self._thread = None
        self._loop = None
        self._ca_bundle = None

    def start(self) -> "MitmproxyBackend":
        try:
            import asyncio

            from mitmproxy import options
            from mitmproxy.tools import dump
        except ImportError as exc:  # pragma: no cover - depends on optional extra
            raise RuntimeError(
                "MitmproxyBackend requires the 'capture' extra. "
                "Install it with:  pip install 'mcp-rt[capture]'"
            ) from exc

        records = self._records

        class _Tap:
            def request(self, flow):  # mitmproxy hook
                r = flow.request
                records.append(CaptureRecord(
                    host=r.pretty_host, url=r.pretty_url,
                    payload=r.get_text(strict=False) or "",
                    channel="http_post" if r.method == "POST" else "http_get",
                    method=r.method,
                ))

        async def _run():
            opts = options.Options(listen_host=self.listen_host, listen_port=self.listen_port)
            master = dump.DumpMaster(opts, with_termlog=False, with_dumper=False)
            master.addons.add(_Tap())
            self._master = master
            await master.run()

        def _thread_main():
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)
            self._loop.run_until_complete(_run())

        self._thread = threading.Thread(target=_thread_main, daemon=True)
        self._thread.start()
        # mitmproxy writes its CA to ~/.mitmproxy on first run; expose it for cert pinning-free TLS.
        from pathlib import Path
        self._ca_bundle = str(Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem")
        return self

    def env(self) -> dict:
        # Actual bound port: mitmproxy picks it; for listen_port=0 the caller should pass a
        # fixed port. We surface the configured one (0 means "let OS pick" — set a real port
        # in production use).
        proxy = f"http://{self.listen_host}:{self.listen_port}"
        e = {"HTTP_PROXY": proxy, "http_proxy": proxy, "HTTPS_PROXY": proxy, "https_proxy": proxy}
        if self._ca_bundle:
            e["REQUESTS_CA_BUNDLE"] = self._ca_bundle
            e["NODE_EXTRA_CA_CERTS"] = self._ca_bundle
            e["SSL_CERT_FILE"] = self._ca_bundle
        return e

    def records(self) -> list:
        return list(self._records)

    def stop(self) -> None:
        if self._master and self._loop:
            self._loop.call_soon_threadsafe(self._master.shutdown)
