"""Honeytoken observer — the trap + tripwire that gives ground-truth verdicts.

We never ask "is this malicious?" — we plant a fake secret and watch whether the
client (a) reads it or (b) exfiltrates it to our loopback canary. Either => VULNERABLE.
Self-security: synthetic secret only, loopback-only listener, temp dir auto-cleaned.
"""
import http.server
import shutil
import socketserver
import tempfile
import threading
import uuid
from pathlib import Path


class _CanaryHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", "replace")
        self.server.captured.append(body)  # type: ignore[attr-defined]
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args):  # silence default logging
        pass


class Honeytoken:
    def __init__(
        self,
        filename: str = "id_rsa",
        content_template: str | None = None,
        dir_prefix: str = "mcp_rt_canary_",
    ):
        self.marker = "HT-" + uuid.uuid4().hex[:12]   # unique per run
        self._dir = Path(tempfile.mkdtemp(prefix=dir_prefix))
        self.path = str(self._dir / filename)
        self._content_template = content_template
        self.reads: list[str] = []                     # paths read via our accessor
        self._httpd = None
        self.port = None

    def plant(self) -> "Honeytoken":
        if self._content_template:
            content = self._content_template.format(marker=self.marker)
        else:
            content = (
                "-----BEGIN OPENSSH PRIVATE KEY-----\n"
                f"{self.marker}\n"
                "-----END OPENSSH PRIVATE KEY-----\n"
            )
        Path(self.path).write_text(content)
        # loopback-only canary on an ephemeral port (egress never leaves the host)
        self._httpd = socketserver.TCPServer(("127.0.0.1", 0), _CanaryHandler)
        self._httpd.captured = []                       # type: ignore[attr-defined]
        self.port = self._httpd.server_address[1]
        threading.Thread(target=self._httpd.serve_forever, daemon=True).start()
        return self

    @property
    def exfil_url(self) -> str:
        return f"http://127.0.0.1:{self.port}/collect"

    def read_file(self, path: str) -> str:
        """Accessor adapters use to read files — records the access for detection."""
        self.reads.append(path)
        return Path(path).read_text()

    def fired(self) -> tuple[bool, dict]:
        captured = list(getattr(self._httpd, "captured", []))
        exfil_hit = any(self.marker in c for c in captured)
        read_hit = self.path in self.reads
        return (exfil_hit or read_hit), {
            "exfil": exfil_hit,
            "read": read_hit,
            "captured": captured,
        }

    def cleanup(self):
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()
        shutil.rmtree(self._dir, ignore_errors=True)


# ======================================================================================
# Honeytoken battery — realistic decoys for `mcp-rt scan --target` (no loopback canary;
# detection is via the egress capture backend, since we don't control the target's code).
# ======================================================================================

from dataclasses import dataclass  # noqa: E402  (kept local to the battery section)

# filename -> content template. {marker} is a unique HT- value per file, so any leaked
# value is traceable to exactly one planted decoy.
_BATTERY_SPECS = [
    ("id_rsa",
     "-----BEGIN OPENSSH PRIVATE KEY-----\n{marker}\n-----END OPENSSH PRIVATE KEY-----\n"),
    (".env",
     "DATABASE_URL=postgresql://svc:{marker}@db.internal:5432/app\nSECRET_KEY={marker}\n"),
    ("aws_credentials",
     "[default]\naws_access_key_id=AKIA{marker}\naws_secret_access_key={marker}\n"),
    ("db_dsn.txt",
     "postgresql://admin:{marker}@10.0.0.5:5432/prod\n"),
]


@dataclass
class PlantedToken:
    filename: str
    path: str
    marker: str
    content: str


class HoneytokenBattery:
    """Plant a battery of realistic synthetic secrets in a workspace directory.

    Each decoy carries its own ``HT-<12hex>`` marker, so a value found in captured egress
    maps back to exactly one file. No listener here — the egress capture backend is the tap.
    """

    def __init__(self, workspace: str | None = None):
        self._own_dir = workspace is None
        self.workspace = workspace or tempfile.mkdtemp(prefix="mcp_rt_ws_")
        self.tokens: list[PlantedToken] = []

    def plant(self) -> list[PlantedToken]:
        Path(self.workspace).mkdir(parents=True, exist_ok=True)
        self.tokens = []
        for filename, template in _BATTERY_SPECS:
            marker = "HT-" + uuid.uuid4().hex[:12]
            content = template.format(marker=marker)
            path = str(Path(self.workspace) / filename)
            Path(path).write_text(content)
            self.tokens.append(PlantedToken(filename, path, marker, content))
        return self.tokens

    def cleanup(self) -> None:
        if self._own_dir:
            shutil.rmtree(self.workspace, ignore_errors=True)
