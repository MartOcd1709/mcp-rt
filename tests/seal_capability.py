"""Test-infra capability probe for the Unit-3 sealed sandbox.

The seal needs a rootless user+net namespace (`unshare -rn`). GitHub-hosted runners usually cannot create
one (`write failed /proc/self/uid_map: Operation not permitted`), so tests that require a BUILT seal must
skip there — the same gating idea as the mitmproxy/weasyprint-dependent tests. This does NOT weaken
production: with no seal, the runtime verdict is INCONCLUSIVE (sandbox_unproven), fail-closed, which is the
correct behavior and is covered by the always-on pure tests.
"""
import functools
import shutil
import subprocess


@functools.lru_cache(maxsize=1)
def can_seal() -> bool:
    """True when this host can build the seal (a minimal `unshare -rn true` succeeds). Cached per process."""
    if not shutil.which("unshare"):
        return False
    try:
        return subprocess.run(["unshare", "-rn", "true"], capture_output=True, timeout=15).returncode == 0
    except Exception:  # noqa: BLE001 — any failure to create the namespace means "cannot seal here"
        return False


SEAL_REASON = "sealed namespace unavailable (no `unshare -rn` / CAP) — gated like mitmproxy/weasyprint tests"
