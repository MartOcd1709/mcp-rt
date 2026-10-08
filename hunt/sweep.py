"""Mass-sweep — auto-discover MCP servers and benchmark each, collecting data to the ledger.

The data-collection engine behind the dashboard. It (1) discovers real MCP server packages
from the npm registry across risky categories, (2) installs + runs the full benchmark on each
(all 6 ground-truth classes + OWASP posture), (3) preserves a report per server and records
every result to findings.db, and (4) prints aggregate stats (tested / vulnerable / grade
distribution / findings by class). Install or launch failures are recorded INCONCLUSIVE, never
dropped — the honest denominator ("N tested") is the asset.

    python -m hunt.sweep                 # discover + sweep the default categories
    python -m hunt.sweep --cap 20        # test up to 20 discovered servers
    python -m hunt.sweep --names a b c   # sweep an explicit list of packages instead

Guardrail: local, open-source servers only; synthetic probes; responsible disclosure before
any public listing (see the mcp-hunt skill). Runs best where installs are reliable (a VPS);
in a throttled sandbox expect some INCONCLUSIVE.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request
from collections import Counter

_SANDBOX = tempfile.mkdtemp(prefix="mcprt_sandbox_")   # cwd for prewarm/diagnose spawns (no repo pollution)


def _missing_env(reason: str) -> list[str]:
    """Extract required-but-unset env var names from a startup error, for config recovery."""
    import re as _re
    vars_ = set()
    for m in _re.finditer(r"\b([A-Z][A-Z0-9]{2,}(?:_[A-Z0-9]+)+|[A-Z]{3,}_[A-Z0-9_]+)\b", reason):
        vars_.add(m.group(1))
    # also "X and Y" / "X, Y" after a 'required'/'missing' cue
    return sorted(v for v in vars_ if v not in ("CLIENT",))[:6]

from hunt.benchmark import grade_report
from hunt.findings_db import DB
from hunt.report import preserve, record, run_full_scan

FS_DIR = "/tmp/fs_allowed"
GIT_REPO = "/tmp/gitrepo"
# Niche risky-category queries — the long tail is where real bugs live (your GHSAs all came
# from low-star shell/exec/git/fs servers, not the hardened top results).
_QUERIES = ["mcp shell", "mcp exec", "mcp command", "mcp terminal", "mcp bash", "mcp cli",
            "mcp ssh", "mcp sftp", "mcp filesystem", "mcp file", "mcp sqlite", "mcp sql",
            "mcp git", "mcp fetch", "mcp http", "mcp code", "mcp run", "mcp subprocess",
            # widened 2026-10-06 — other injection-prone categories (DB/browser/cloud/data-I-O)
            "mcp database", "mcp postgres", "mcp mysql", "mcp mongodb", "mcp redis",
            "mcp browser", "mcp playwright", "mcp puppeteer", "mcp scrape", "mcp crawl",
            "mcp docker", "mcp kubernetes", "mcp aws", "mcp s3", "mcp cloud",
            "mcp download", "mcp upload", "mcp pdf", "mcp api"]
# Packages that match but are not stdio MCP servers we can meaningfully probe.
_DENY = {"@modelcontextprotocol/sdk", "@modelcontextprotocol/server", "firebase-tools",
         "node-fetch", "supergateway", "@ai-sdk/mcp", "@langchain/mcp-adapters", "mcp-typegen"}
# Substrings of packages that are MCP *plumbing*, not probeable stdio tool servers (the popular-lane
# lesson: high-download = infra). Kept SAFE on purpose: "porter"/"ui"/"remote"/"bridge" are NOT here —
# they'd wrongly exclude real tool servers (exporter, builder, remote-shell, file-bridge).
_SKIP_SUBSTR = ("sdk", "adapter", "client", "typegen", "gateway", "inspector", "devtools",
                "proxy", "handler", "middleware")
_RISKY = re.compile(r"shell|exec|command|terminal|bash|\bcli\b|ssh|sftp|file|\bfs\b|sqlite|sql|"
                    r"git|fetch|http|\bcode\b|\brun\b|process|subprocess|proxy|"
                    # widened 2026-10-06: DB · browser/web · cloud/infra · data-I/O (injection-prone)
                    r"database|postgres|mysql|mongo|redis|mariadb|duckdb|"
                    r"browser|playwright|puppeteer|scrape|crawl|selenium|chromium|"
                    r"docker|kubernetes|\bk8s\b|\baws\b|\bs3\b|\bgcp\b|azure|cloud|"
                    r"download|upload|\bpdf\b|image|convert", re.I)


def _repo_url(pkg: dict) -> str:
    links = pkg.get("links") or {}
    for key in ("repository", "homepage", "bugs"):
        r = links.get(key) or ""
        if "github.com" in r:
            return r
    return ""


def _is_maintained(repo_url: str) -> tuple[bool, str]:
    """True iff the GitHub repo is live (not 404/private), not archived, pushed within ~15 months.
    This structurally excludes dead-repo orphans (like d33naz) that have no disclosure channel."""
    import datetime
    import re as _re
    import urllib.error
    m = _re.search(r"github\.com[:/]+([^/]+)/([^/#?]+?)(?:\.git|/|#|\?|$)", repo_url)
    if not m:
        return (False, "no github repo")
    req = urllib.request.Request(f"https://api.github.com/repos/{m.group(1)}/{m.group(2)}")
    tok = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")  # 60/hr unauth -> 5000/hr with a token
    if tok:
        req.add_header("Authorization", f"Bearer {tok}")
    try:
        d = json.load(urllib.request.urlopen(req, timeout=10))
        if d.get("archived"):
            return (False, "archived")
        pushed = d.get("pushed_at", "")
        if pushed:
            dt = datetime.datetime.fromisoformat(pushed.replace("Z", "+00:00"))
            days = (datetime.datetime.now(datetime.timezone.utc) - dt).days
            return (days <= 460, f"pushed {days}d ago")
        return (True, "live repo")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return (False, "repo 404")                      # genuinely dead — exclude
        # 403/429 = rate-limited, other codes = transient: UNKNOWN, not dead — don't drop the candidate
        return (True, f"github {e.code} (rate-limit/unknown) — included unchecked")
    except Exception as e:  # noqa: BLE001 — network/timeout: unknown, include rather than silently zero discovery
        return (True, f"github check unavailable ({type(e).__name__}) — included unchecked")


def discover(queries, cap: int, max_downloads: int, min_downloads: int = 10,
             maintained: bool = True, popular: bool = False) -> list[dict]:
    """Discovery of MAINTAINED risky servers: niche queries, a weekly-downloads band (real usage,
    not dead), then (if maintained) each verified to have a LIVE, recently-pushed GitHub repo — so
    there's a real disclosure channel and no dead-repo orphans. Ranking: long-tail (least-downloaded
    first) by default; `popular=True` ranks most-downloaded first (the high-usage servers big orgs
    embed — where a credibility-grade finding lands). Caller sets the band (min/max_downloads)."""
    cands: dict[str, tuple[int, str, str, str]] = {}
    for q in queries:
        for frm in (0, 20, 40, 60):   # page deeper into the long tail (top 80/query) to un-saturate discovery
            url = (f"https://registry.npmjs.org/-/v1/search?size=20&from={frm}&text="
                   + urllib.parse.quote(q))
            try:
                data = json.load(urllib.request.urlopen(url, timeout=12))
            except Exception:  # noqa: BLE001
                continue
            for o in data.get("objects", []):
                pk = o["package"]
                name, low, desc = pk["name"], pk["name"].lower(), (pk.get("description") or "")
                if name in _DENY or "mcp" not in low or any(x in low for x in _SKIP_SUBSTR):
                    continue
                if not (_RISKY.search(low) or _RISKY.search(desc)):
                    continue
                dl = ((o.get("downloads") or {}).get("weekly")) or 0
                if min_downloads <= dl <= max_downloads and name not in cands:
                    cands[name] = (dl, desc[:60], _repo_url(pk), pk.get("version", ""))  # pin the latest version
    ranked = sorted(cands.items(), key=lambda kv: kv[1][0], reverse=popular)  # popular: most-downloaded first
    out = []
    for name, (dl, desc, repo, ver) in ranked:
        if maintained:
            ok, why = _is_maintained(repo)
            if not ok:
                continue
            out.append({"name": name, "cmd": _cmd_for(name, ver), "downloads": dl, "desc": desc,
                        "repo": repo, "maint": why, "version": ver})
        else:
            out.append({"name": name, "cmd": _cmd_for(name, ver), "downloads": dl, "desc": desc,
                        "repo": repo, "version": ver})
        if len(out) >= cap:
            break
    return out


def _fs_args(name: str) -> str:
    low = name.lower()
    return FS_DIR if any(x in low for x in ("filesystem", "files", "-fs", "fs-")) else ""


_SUBCOMMANDS = ("", "stdio", "serve", "start", "mcp", "run")   # try bare first, then common ones
_NEEDS_SUB_RE = re.compile(r"usage:|<command>|--help|unknown command|display help|available commands|"
                           r"missing (required )?command|specify a command", re.I)


def _cmd_for(name: str, version: str = "") -> str:
    """Build the base launch command, resolving the REAL bin name from the registry, and PINNING the
    version so we always test the latest published build (not a stale npx cache). `version` is the
    exact latest from discovery; absent (e.g. curated servers) we pin `@latest`.
    npx runs the bin matching the package's unscoped name; when the bin differs (e.g.
    @vuetify/mcp-cli exposes `vuetify-mcp`) a bare `npx -y <pkg>` fails, so use `-p <pkg> <bin>`."""
    args = _fs_args(name)
    short = name.split("/")[-1]
    spec = f"{name}@{version or 'latest'}"
    try:
        u = "https://registry.npmjs.org/" + urllib.parse.quote(name, safe="@/") + "/latest"
        binf = json.load(urllib.request.urlopen(u, timeout=10)).get("bin")
        if isinstance(binf, dict) and binf:
            keys = list(binf)
            b = (short if short in keys
                 else next((k for k in keys if "mcp" in k or "server" in k), sorted(keys)[0]))
            if b != short or len(keys) > 1:
                return f"npx -y -p {spec} {b} {args}".strip()
    except Exception:  # noqa: BLE001
        pass
    return f"npx -y {spec} {args}".strip()


def _resolve_launch(cmd: str) -> str:
    """If the base command prints usage/help (a multi-command CLI, not a stdio server), retry with
    common MCP subcommands and return the first that doesn't print usage. Recovers the
    'needs a subcommand' failure class (vuetify-mcp, mcp-fte, commander CLIs)."""
    base = _diagnose(cmd)                                   # one quick run of the bare command
    if not _NEEDS_SUB_RE.search(base):
        return cmd                                          # bare command is fine (or failed for another reason)
    fs = _fs_args(cmd.split()[-1]) if False else ""         # keep args attached to cmd already
    for sub in _SUBCOMMANDS[1:]:
        trial = f"{cmd} {sub}"
        out = _diagnose(trial)
        if not _NEEDS_SUB_RE.search(out) and "unknown" not in out.lower():
            return trial                                    # this subcommand didn't bounce to usage
    return cmd                                              # none worked; leave bare (will be INCONCLUSIVE, classified)


def _classify(reason: str) -> str:
    """Bucket an INCONCLUSIVE reason so the denominator is honest (recoverable vs not-a-target)."""
    r = reason.lower()
    if _NEEDS_SUB_RE.search(reason):
        return "NEEDS_SUBCOMMAND"
    if any(x in r for x in ("required environment", "client_id", "api key", "missing env",
                            "must be set", "not configured", "credentials")):
        return "NEEDS_CONFIG"
    if any(x in r for x in ("syntaxerror", "does not provide an export", "cannot find module",
                            "err_module", "unexpected token")):
        return "BROKEN_PACKAGE"
    if any(x in r for x in ("npm err", "404", "etarget", "install")):
        return "INSTALL_FAILED"
    if "not found" in r:
        return "ENTRYPOINT_NOT_FOUND"
    return "OTHER"


def _diagnose(cmd: str) -> str:
    """Run the launch command briefly to capture WHY it failed, for the INCONCLUSIVE record."""
    try:
        p = subprocess.run(shlex.split(cmd), input="", capture_output=True, text=True, timeout=25, cwd=_SANDBOX)
        lines = [ln.strip() for ln in ((p.stderr or "") + "\n" + (p.stdout or "")).splitlines() if ln.strip()]
        errs = [ln for ln in lines if re.search(r"error|not found|cannot|could not|denied|invalid|"
                                                r"ENOENT|missing|executable|\b404\b", ln, re.I)
                and "_logs/" not in ln]
        pick = errs[-1] if errs else (lines[-1] if lines else f"exited {p.returncode} with no output")
        return pick[:160]
    except Exception as e:  # noqa: BLE001
        return f"{type(e).__name__}: {str(e)[:120]}"


def prewarm(cmd: str) -> None:
    try:
        subprocess.run(shlex.split(cmd), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=240, cwd=_SANDBOX)
    except Exception:  # noqa: BLE001
        pass


def scan_one(t: dict, db: DB, timeout: int = 120, source: str = "npm") -> dict:
    """Resolve launch → prewarm → full scan (with dummy-env config recovery) → record to the ledger.
    The single per-target unit shared by `sweep` and `daily`; the opaque anyio TaskGroup is already
    unwrapped to a real reason upstream (hunt.probes.scan_target). Returns a result dict."""
    print(f"== {t['name']} ==")
    t["cmd"] = _resolve_launch(t["cmd"])                 # recover 'needs a subcommand' servers
    prewarm(t["cmd"])
    rep = None
    try:
        rep = asyncio.run(asyncio.wait_for(run_full_scan(shlex.split(t["cmd"])), timeout=timeout))
    except (asyncio.TimeoutError, TimeoutError):
        # Got far enough to be slow (a fast crash raises ScanError, not a timeout): the server is
        # probeable, just over budget (e.g. a live network call per tool). Distinct from can't-start.
        cat = "SCAN_TIMEOUT"
        why = f"scan exceeded {timeout}s (server started but slow — probeable; raise --timeout to complete)"
        tid = db.add_target(name=t["name"], install_cmd=t["cmd"], source=source)
        db.add_scan(tid, mode="sweep", verdict="INCONCLUSIVE", agent="n/a", notes=f"[{cat}] {why}")
        print(f"   -> INCONCLUSIVE [{cat}] (over {timeout}s; raise --timeout to complete)")
        return {"name": t["name"], "verdict": "INCONCLUSIVE", "cat": cat, "why": why}
    except Exception:  # noqa: BLE001
        why = _diagnose(t["cmd"]); cat = _classify(why)  # honest category, not "ExceptionGroup"
        miss = _missing_env(why) if cat == "NEEDS_CONFIG" else []
        if miss:                                          # config recovery: retry with dummy env
            try:
                rep = asyncio.run(asyncio.wait_for(
                    run_full_scan(shlex.split(t["cmd"]),
                                  env={**os.environ, **{v: "mcprt-dummy" for v in miss}}),
                    timeout=timeout))
                print(f"   (config-recovered via dummy env: {', '.join(miss)})")
            except Exception:  # noqa: BLE001
                rep = None
        if rep is None:
            tid = db.add_target(name=t["name"], install_cmd=t["cmd"], source=source)
            db.add_scan(tid, mode="sweep", verdict="INCONCLUSIVE", agent="n/a", notes=f"[{cat}] {why}")
            print(f"   -> INCONCLUSIVE [{cat}] ({why[:70]})")
            return {"name": t["name"], "verdict": "INCONCLUSIVE", "cat": cat, "why": why}
    rdir = preserve(rep)
    record(rep, rdir)
    b = grade_report(rep)
    fired = ", ".join(f"{f['cls']}:{f['tool']}" for f in rep["findings"]) or "clean"
    print(f"   -> Grade {b['grade']} ({b['score']}/100)  {fired}")
    return {"name": t["name"], "verdict": rep["verdict"], "grade": b["grade"],
            "score": b["score"], "findings": rep["findings"], "report_dir": rdir}


# --- PyPI / uvx discovery (the Python MCP ecosystem — npm's search misses it entirely) -----------
_PYPI_CACHE = os.path.join(tempfile.gettempdir(), "mcprt_pypi_simple.txt")


def _pypi_names() -> list[str]:
    """All PyPI package names containing 'mcp', from the simple index (cached 6h — it's ~10MB).
    PyPI has no usable JSON search API, but the simple index lists every package name."""
    if os.path.exists(_PYPI_CACHE) and (__import__("time").time() - os.path.getmtime(_PYPI_CACHE)) < 6 * 3600:
        return open(_PYPI_CACHE, encoding="utf-8").read().splitlines()
    try:
        raw = urllib.request.urlopen("https://pypi.org/simple/", timeout=90).read().decode("utf-8", "ignore")
    except Exception:  # noqa: BLE001 — fall back to a stale cache rather than lose discovery
        return open(_PYPI_CACHE, encoding="utf-8").read().splitlines() if os.path.exists(_PYPI_CACHE) else []
    names = re.findall(r">([^<>]*mcp[^<>]*)</a>", raw, re.I)
    open(_PYPI_CACHE, "w", encoding="utf-8").write("\n".join(names))
    return names


def _pypi_maintained(name: str) -> tuple[bool, str, str]:
    """Liveness + latest version via PyPI JSON (not rate-limited like GitHub): release within ~15 months.
    Returns (is_live, why, latest_version)."""
    import datetime
    try:
        d = json.load(urllib.request.urlopen(
            "https://pypi.org/pypi/" + urllib.parse.quote(name) + "/json", timeout=10))
    except Exception:  # noqa: BLE001 — gone/yanked/transient: skip this candidate (we only check up to cap)
        return (False, "pypi lookup failed", "")
    v = d.get("info", {}).get("version", "")
    files = (d.get("releases", {}) or {}).get(v) or []
    ts = (files[0].get("upload_time_iso_8601") if files else "") or ""
    if ts:
        dt = datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
        days = (datetime.datetime.now(datetime.timezone.utc) - dt).days
        return (days <= 460, f"pypi {days}d ago", v)
    return (True, "pypi live", v)


def _pypi_cmd_for(name: str, version: str = "") -> str:
    """Launch a PyPI MCP server with uvx, PINNING the latest version (not a stale uvx cache).
    fs-servers get an allowed dir."""
    args = _fs_args(name)
    return f"uvx {name}@{version or 'latest'} {args}".strip()


def discover_pypi(cap: int, seen: set | None = None) -> list[dict]:
    """Risky-category Python MCP servers from PyPI, deduped against `seen`, each verified live.
    Candidates are scanned alphabetically; dedup makes successive runs advance through the pool."""
    seen = seen or set()
    cands = [n for n in _pypi_names()
             if "mcp" in n.lower() and _RISKY.search(n.lower())
             and not any(x in n.lower() for x in _SKIP_SUBSTR) and n not in seen]
    out = []
    for n in cands:
        if len(out) >= cap:
            break
        ok, why, ver = _pypi_maintained(n)
        if ok:
            out.append({"name": n, "cmd": _pypi_cmd_for(n, ver), "ecosystem": "pypi",
                        "maint": why, "version": ver})
    return out


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="hunt.sweep", description="mass-sweep MCP servers")
    p.add_argument("--cap", type=int, default=10, help="max servers to test")
    p.add_argument("--names", nargs="*", help="explicit package names instead of discovery")
    p.add_argument("--timeout", type=int, default=120, help="per-server scan timeout (s)")
    p.add_argument("--max-downloads", type=int, default=2000,
                   help="weekly-downloads ceiling (long-tail bias)")
    p.add_argument("--min-downloads", type=int, default=10,
                   help="weekly-downloads floor (skip dead/unused packages)")
    p.add_argument("--include-unmaintained", action="store_true",
                   help="do NOT require a live/maintained GitHub repo (default: maintained only)")
    p.add_argument("--popular", action="store_true",
                   help="target the most-DOWNLOADED (high-usage) servers instead of the long tail")
    p.add_argument("--discover-only", action="store_true",
                   help="list the discovered targets and exit (no install/scan)")
    args = p.parse_args(argv)
    if args.popular:   # flip the band + ranking to high-usage servers (unless an explicit --max given)
        args.min_downloads = max(args.min_downloads, 2000)
        if args.max_downloads <= 2000:
            args.max_downloads = 10_000_000

    os.makedirs(FS_DIR, exist_ok=True)
    open(os.path.join(FS_DIR, "readme.txt"), "w").write("allowed dir")
    if not os.path.isdir(os.path.join(GIT_REPO, ".git")):
        os.makedirs(GIT_REPO, exist_ok=True)
        subprocess.run(["git", "init", "-q", GIT_REPO], check=False)

    targets = ([{"name": n, "cmd": _cmd_for(n)} for n in args.names] if args.names
               else discover(_QUERIES, args.cap, args.max_downloads, args.min_downloads,
                             maintained=not args.include_unmaintained, popular=args.popular))
    if args.discover_only:
        for t in targets:
            print(f"  {str(t.get('downloads', '?')):>6} dl/wk  {t['name']:40} "
                  f"[{t.get('maint', 'repo not verified')}]  {t.get('repo', '')}")
        kind = "unmaintained-allowed" if args.include_unmaintained else "maintained (live repo)"
        print(f"\n{len(targets)} {kind} target(s) [{args.min_downloads}-{args.max_downloads} dl/wk]")
        return 0
    print(f"sweep: {len(targets)} target(s)\n")

    db = DB()
    grades, classes, inconclusive, incat = Counter(), Counter(), 0, Counter()
    for t in targets:
        r = scan_one(t, db, timeout=args.timeout, source="npm")
        if r["verdict"] == "INCONCLUSIVE":
            inconclusive += 1
            incat[r["cat"]] += 1
        else:
            grades[r["grade"]] += 1
            for f in r["findings"]:
                classes[f["cls"]] += 1
    db.close()

    print("\n=== sweep summary ===")
    print(f"servers tested:   {sum(grades.values())}  (+{inconclusive} inconclusive)")
    if incat:
        print(f"inconclusive by cause: {dict(incat)}")
    print(f"grade distribution: {dict(grades)}")
    print(f"findings by class:  {dict(classes)}")
    print(f"total findings:     {sum(classes.values())}")
    print("ledger:", DB().summary())
    return 0


if __name__ == "__main__":
    sys.exit(main())
