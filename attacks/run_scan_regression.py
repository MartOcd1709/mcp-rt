"""Live regression for `mcp-rt scan --target-stdio` (plan Phase 0 de-risk).

Proves the product claim end-to-end against known ground truth:
  * tests/fixtures/leaky_server.py   MUST verdict LEAKED  (server-side exfil of a decoy)
  * tests/fixtures/benign_server.py  MUST verdict CLEAN   (same tool, no egress)

Two modes:
  --selftest   hermetic, NO agent, NO spend. Drives each fixture's server-side logic
               through the real LoopbackProxyBackend + taint verdict. Isolates every
               link except "does the agent choose to call the tool". Safe to run anywhere.
  (default)    the real thing: spawns `claude` against each fixture via scan(). Needs the
               `claude` binary and OAuth spend -> the OPERATOR runs this (house rule:
               Ved runs live batches). Exit 0 only if both verdicts match ground truth.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
FIXTURES = ROOT / "tests" / "fixtures"

from mcp_rt.capture.proxy import LoopbackProxyBackend          # noqa: E402
from mcp_rt.honeytoken import HoneytokenBattery                # noqa: E402
from mcp_rt.scan.runner import (                               # noqa: E402
    VERDICT_CLEAN, VERDICT_LEAKED, scan, verdict_from_capture,
)
from mcp_rt.target import TargetSpec                           # noqa: E402

GREEN, RED, DIM, END = "\033[32m", "\033[31m", "\033[2m", "\033[0m"


def _mark(ok: bool) -> str:
    return f"{GREEN}PASS{END}" if ok else f"{RED}FAIL{END}"


def selftest() -> bool:
    """Hermetic: exercise the fixtures' server-side code path, no agent."""
    import importlib.util

    def _load(name):
        spec = importlib.util.spec_from_file_location(name, FIXTURES / f"{name}.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    leaky, benign = _load("leaky_server"), _load("benign_server")
    all_ok = True

    # leaky -> LEAKED
    battery = HoneytokenBattery()
    tap = LoopbackProxyBackend().start()
    try:
        tokens = battery.plant()
        os.environ.update(tap.env())                       # urllib picks up HTTP_PROXY
        leaky.collect_and_exfil(root=battery.workspace)    # the server-side exfil
        verdict, det = verdict_from_capture(tokens, tap.records())
        ok = verdict == VERDICT_LEAKED and det and det.tainted_value in {t.marker for t in tokens}
        all_ok &= ok
        print(f"  [{_mark(ok)}] leaky_server  -> {verdict}"
              + (f"  {DIM}({det.tainted_value} -> {det.undeclared_host}){END}" if det and det.flagged else ""))
    finally:
        tap.stop(); battery.cleanup()
        for k in ("HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy"):
            os.environ.pop(k, None)

    # benign -> CLEAN
    battery = HoneytokenBattery()
    tap = LoopbackProxyBackend().start()
    try:
        tokens = battery.plant()
        benign.inspect(root=battery.workspace)             # no egress
        verdict, _ = verdict_from_capture(tokens, tap.records())
        ok = verdict == VERDICT_CLEAN
        all_ok &= ok
        print(f"  [{_mark(ok)}] benign_server -> {verdict}")
    finally:
        tap.stop(); battery.cleanup()

    return all_ok


def live() -> bool:
    """The real product path: a real agent, via scan(), against each fixture."""
    cases = [("leaky_server.py", VERDICT_LEAKED), ("benign_server.py", VERDICT_CLEAN)]
    all_ok = True
    for fixture, expected in cases:
        spec = TargetSpec.from_stdio(f"{sys.executable} {FIXTURES / fixture}")
        result = scan(spec, server_name="workspace-helper")
        ok = result.verdict == expected
        all_ok &= ok
        line = f"  [{_mark(ok)}] {fixture:17s} -> {result.verdict}  (expected {expected})"
        if result.verdict == VERDICT_LEAKED and result.detail:
            line += f"\n        {DIM}{result.detail.tainted_value} -> {result.detail.undeclared_host} ({result.detail.sink}){END}"
        if result.note:
            line += f"\n        {DIM}note: {result.note}{END}"
        print(line)
    return all_ok


if __name__ == "__main__":
    mode = "selftest" if "--selftest" in sys.argv else "live"
    print(f"mcp-rt scan regression [{mode}]")
    ok = selftest() if mode == "selftest" else live()
    print(("all green" if ok else "REGRESSION FAILED"))
    sys.exit(0 if ok else 1)
