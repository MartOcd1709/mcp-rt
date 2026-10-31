"""engine_version — a digest of the DETECTION-LOGIC source, for resumable sweeps (task #19 B2).

Per CIO R2: hash the SOURCE of the probe + classifier modules, NOT just the probe names + the spine map. A
names+spine hash would NOT change when a probe's classification LOGIC changes — the #22 SSRF fix is the exact
counterexample (same probe names, same _METHOD_VERDICT, different verdict) — so it would wrongly skip
already-scanned targets on resume and keep serving the pre-fix result. Hashing the source means ANY detection
change invalidates stale results.

A sweep skips a target only when a scan already exists at the CURRENT engine_version; a changed probe source
changes engine_version, so everything re-scans.
"""
import hashlib
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent          # repo root: holds hunt/ and mcp_rt/

# Every module whose SOURCE can change a verdict. Add a new detection/classifier module here when one is added
# (a probe, the honesty spine, the egress/XXE oracle, the scan orchestration, a class-metadata/severity map).
_SOURCES = (
    "hunt/probes.py",             # all floor probes + verdict_for + the _METHOD_VERDICT spine
    "hunt/report.py",             # run_full_scan orchestration + the sealed R6 remap + CLASS_META + controls
    "hunt/family_b.py",           # token-passthrough class
    "hunt/supply_chain.py",       # supply-chain (install-hook / known-CVE) detection
    "mcp_rt/runtime/observe.py",  # egress classification (classify_egress) + integrity
    "mcp_rt/tool_xxe.py",         # XXE oracle logic
)


def engine_version(root: Path | str | None = None) -> str:
    """12-hex-char digest over the detection-logic source. Stable across runs; changes iff a probe/classifier
    source changes. `root` overrides the repo root (for tests)."""
    base = Path(root) if root is not None else _ROOT
    h = hashlib.sha256()
    for rel in _SOURCES:
        p = base / rel
        h.update(rel.encode())
        h.update(p.read_bytes() if p.exists() else b"<missing>")
    return h.hexdigest()[:12]
