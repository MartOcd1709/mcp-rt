"""DNS sink — catches DNS-label exfiltration (a secret encoded in subdomain labels).

A loopback UDP resolver that answers every A query with a fixed IP and logs the queried
name as an egress record. Effective only when the target actually resolves through it —
for a local subprocess that needs OS-level redirection (netns / resolv.conf), which is
the netns backend's job. Included here as a working, wire-in-able component; the http
channel is what the hermetic acceptance suite exercises.

ponytail: per-process DNS redirection has no clean env-var; full coverage needs the netns
backend. This logs queries when pointed at (manual / future), no dep required.
"""
from __future__ import annotations

import socket
import struct
import threading

from .base import CaptureRecord


def _parse_qname(data: bytes) -> str:
    """Decode the QNAME from a DNS query packet (labels after the 12-byte header)."""
    labels, i = [], 12
    while i < len(data):
        n = data[i]
        if n == 0:
            break
        labels.append(data[i + 1: i + 1 + n].decode("utf-8", "replace"))
        i += 1 + n
    return ".".join(labels)


class DnsSink:
    def __init__(self, resolve_to: str = "127.0.0.1", host: str = "127.0.0.1", port: int = 0):
        self.resolve_to = resolve_to
        self.host = host
        self.port = port
        self._sock = None
        self._records: list = []
        self._stop = threading.Event()

    def start(self) -> "DnsSink":
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind((self.host, self.port))
        self._sock.settimeout(0.5)
        self.port = self._sock.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()
        return self

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                data, addr = self._sock.recvfrom(512)
            except socket.timeout:
                continue
            except OSError:
                break
            qname = _parse_qname(data)
            self._records.append(CaptureRecord(
                host=qname, url=f"dns://{qname}", payload=qname, channel="dns_query", method="QUERY",
            ))
            self._sock.sendto(self._answer(data), addr)

    def _answer(self, query: bytes) -> bytes:
        # Minimal A-record answer pointing at resolve_to.
        txn = query[:2]
        header = txn + struct.pack(">HHHHH", 0x8180, 1, 1, 0, 0)
        question = query[12:]
        answer = (b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4)
                  + socket.inet_aton(self.resolve_to))
        return header + question + answer

    def records(self) -> list:
        return list(self._records)

    def stop(self) -> None:
        self._stop.set()
        if self._sock:
            self._sock.close()
