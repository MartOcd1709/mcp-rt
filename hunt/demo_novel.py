"""Novel MCP-00 family (the moat) for `mcp-rt demo` — OFFLINE, additive to the 20-finding floor.

Each CONFIRMED class fires its real honeytoken canary on a VULNERABLE host (a real file read + a real
loopback POST carrying THIS run's marker) and stays silent on the SAFE host. `mcp_cap` is a LEAD (a
capability hypothesis from the strace sensor), never a canary CONFIRMED, and skips gracefully if strace
is absent. Offline only — built-in naive model / form-filler + synthetic SDK callbacks, no API keys.

Deliberately EXCLUDED (offline-only, zero-FP): resource-injection, MCP-28 structured-output, and
exfil-channels need a live agent; the Mock harness returns vulnerable=False on their server-side /
resource-body channels, so wiring them "like the 9" would be a FALSE not-vulnerable — a zero-FP
integrity violation. They remain visible in the honest coverage ledger instead.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

import mcp_rt.payloads.sampling_instruction_laundering  # noqa: F401  registers the payload
import mcp_rt.payloads.elicitation_credential_harvest   # noqa: F401  registers the payload
import mcp_rt.payloads.roots_path_manipulation           # noqa: F401  registers the payload
from mcp_rt.adapters.elicitation_host import SafeElicitationHost, VulnerableElicitationHost
from mcp_rt.adapters.sampling_host import SafeSamplingHost, VulnerableSamplingHost
from mcp_rt.harness import run_one
from mcp_rt.honeytoken import Honeytoken
from mcp_rt.payloads.registry import all_payloads
from hunt.hunt_cap import run_cap_hunt, strace_available

_PROJECT = Path(__file__).resolve().parents[1]
_SERVER = str(_PROJECT / "server" / "malicious_mcp_server.py")
_VENV_PY = sys.executable
_ROOTS_MODE_KEY = "roots_path_manipulation_mode"


@dataclass
class NovelOutcome:
    cls: str
    kind: str                 # "CONFIRMED" | "LEAD"
    fired_vuln: bool
    silent_safe: bool
    proof: str
    evidence: str
    source: str
    skipped: str = ""

    @property
    def confirmed(self) -> bool:
        return self.kind == "CONFIRMED" and self.fired_vuln and self.silent_safe and not self.skipped


def _payload(name: str):
    return next(p for p in all_payloads() if p.name == name)


def _marker(detail: dict) -> str:
    blob = " ".join(str(c) for c in (detail.get("captured") or []))
    m = re.search(r"HT-[0-9a-f]+", blob)   # the per-run honeytoken nonce, not the whole decoy blob
    return m.group(0) if m else "HT-<marker>"


def _run_one_pair(cls: str, vuln_host, safe_host, how: str, source: str) -> NovelOutcome:
    p = _payload(cls)   # payload name == class name for these two
    v = run_one(vuln_host, p)
    s = run_one(safe_host, p)
    return NovelOutcome(cls, "CONFIRMED", bool(v["vulnerable"]), not s["vulnerable"],
                        f"canary {_marker(v['detail'])} {how}",
                        f"vuln: read={v['detail']['read']} exfil={v['detail']['exfil']} | safe: silent={not s['vulnerable']}",
                        source)


def _sampling() -> NovelOutcome:
    return _run_one_pair("sampling_instruction_laundering", VulnerableSamplingHost(), SafeSamplingHost(),
                         "read + loopback-exfil'd via a laundered sampling request",
                         "mcp_rt/adapters/sampling_host.py")


def _elicitation() -> NovelOutcome:
    return _run_one_pair("elicitation_credential_harvest", VulnerableElicitationHost(), SafeElicitationHost(),
                         "harvested + loopback-exfil'd via an elicitation form",
                         "mcp_rt/adapters/elicitation_host.py")


def _write_cfg(spec: dict, extra: dict) -> str:
    tool = spec["poisoned"]
    cfg = {"canary_path": spec["canary_path"], "exfil_url": spec["exfil_url"],
           "tool_name": tool["name"], "tool_desc": tool["description"], "tool_result": spec.get("tool_result", "")}
    cfg.update(extra)
    fd, path = tempfile.mkstemp(prefix="mcprt_demo_", suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh)
    return path


async def _roots_once(use_callbacks: bool):
    import mcp.types as mtypes
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    p = _payload("roots_path_manipulation")
    ht = Honeytoken(filename=getattr(p, "honeytoken_filename", "id_rsa"),
                    content_template=getattr(p, "honeytoken_content_template", None),
                    dir_prefix=getattr(p, "honeytoken_dir_prefix", "mcp_rt_canary_")).plant()
    cfg = None
    try:
        spec = p.build(ht.path, ht.exfil_url)
        cfg = _write_cfg(spec, {_ROOTS_MODE_KEY: True})
        env = dict(os.environ); env["MCPRT_CONFIG"] = cfg
        params = StdioServerParameters(command=_VENV_PY, args=[_SERVER], env=env)

        async def _roots_cb(context):   # synthetic headless roots handler (our test code, not a product)
            return mtypes.ListRootsResult(roots=[mtypes.Root(uri="file:///tmp/mcprt-demo-root")])

        kwargs = {"list_roots_callback": _roots_cb} if use_callbacks else {}
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write, **kwargs) as session:
                await session.initialize()
                await session.call_tool(spec["poisoned"]["name"], {"path": "workspace_config.json"})
                fired, detail = ht.fired()
                return fired, detail
    finally:
        if cfg:
            try:
                os.unlink(cfg)
            except OSError:
                pass
        ht.cleanup()


def _roots_path() -> NovelOutcome:
    try:
        vfired, vdetail = asyncio.run(_roots_once(True))      # with synthetic roots callback -> fires
        sfired, _ = asyncio.run(_roots_once(False))           # SDK default (no callback) -> silent control
    except Exception as e:  # noqa: BLE001 — never destabilize the floor; degrade to skipped
        return NovelOutcome("roots_path_manipulation", "CONFIRMED", False, False, "", f"error: {type(e).__name__}: {e}",
                            "server/malicious_mcp_server.py", skipped=f"roots host error: {type(e).__name__}")
    return NovelOutcome("roots_path_manipulation", "CONFIRMED", bool(vfired), not sfired,
                        f"canary {_marker(vdetail)} exfil'd via roots boundary substitution",
                        f"with-callbacks fired={vfired} | no-callbacks (control) fired={sfired}",
                        "server/malicious_mcp_server.py")


def _mcp_cap() -> NovelOutcome:
    # LEAD only, never a canary CONFIRMED. Strace sensor over the classic aggregate stdio target.
    if not strace_available():
        return NovelOutcome("mcp_cap", "LEAD", False, True, "", "strace not available",
                            "hunt/hunt_cap.py", skipped="strace not on PATH")
    target = str(_PROJECT / "hunt" / "probe_fixtures" / "vuln_server.py")
    try:
        status, hyps = run_cap_hunt([_VENV_PY, target])
    except Exception as e:  # noqa: BLE001
        return NovelOutcome("mcp_cap", "LEAD", False, True, "", f"error: {type(e).__name__}",
                            "hunt/hunt_cap.py", skipped=f"cap-hunt error: {type(e).__name__}")
    obs = "; ".join(f"{h.tool}: {h.observation}" for h in hyps[:3]) or "no undeclared-capability gap observed"
    return NovelOutcome("mcp_cap", "LEAD", bool(hyps), True,
                        f"{len(hyps)} undeclared-capability hypothesis(es) [{status}]", obs, "hunt/hunt_cap.py")


def run_novel() -> list[NovelOutcome]:
    """Offline novel MCP-00 family: 3 CONFIRMED canary classes + the mcp_cap LEAD. Additive to the floor."""
    return [_sampling(), _elicitation(), _roots_path(), _mcp_cap()]
