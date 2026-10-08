# mcp-rt WORKLOG

A plain chronological log of each session's work, so a laptop shutdown never loses the thread.
Durable companions: `findings.db` (ledger) · `hunt/runs/*.md` (per-scan logs) · `hunt/scorecard.html` ·
`~/Videos/*_Advisory_Draft_*.md` (findings) · memory `project_mcprt_engine_state.md` (structured resume).
Newest day on top.

---

## 2026-10-06 — enrichment campaign + first new confirmed finding

**Theme:** scan many servers, hold zero-FP discipline. **Result: ledger 62 → 101 targets; a 2nd
confirmed finding (CWE-78) ground-truthed.**

- **Yield fix:** tightened popular-lane `_SKIP_SUBSTR` (+proxy/handler/middleware; deliberately NOT
  porter/ui/remote/bridge — would wrongly drop real servers). `tests/test_discovery_filter.py`.
- **Enrich pass #1 (`daily --cap 25`):** +14 servers. 2 VULNERABLE candidates → BOTH triaged by-design
  (source-verified): `terminal-driver-mcp` (PTY shell by design), `@iflow-mcp/mcp-ssh-manager`
  (runs over SSH on user's own host = no boundary). 0 new confirmed. Reclassified to CLEAN w/ notes.
- **Saturation hit:** pass #2 = 0 new (npm risky-category pool tapped). Fixed run-log clobber
  (timestamped filename) + 0-target no-op; deepened pagination to top-80/query.
- **Widened discovery (Ved-approved scope call):** `_RISKY`+`_QUERIES` extended to DB / browser /
  cloud / data-I/O categories (postgres/mongo/redis, playwright/puppeteer/scrape, docker/k8s/aws/s3,
  pdf/download…). Short tokens word-bounded so `aws`≠`flaws`. `tests/test_discovery_filter.py`.
- **ROOT-CAUSE BUG (the real unlock):** widened pass still returned 0 — the per-candidate GitHub
  `_is_maintained` check (unauth **60/hr**) was rate-limited and the error path treated rate-limit as
  "dead repo → exclude", silently zeroing ALL discovery. Fixed: honor `GITHUB_TOKEN`; 404 still
  excludes, but 403/429/network-error = UNKNOWN → include unchecked. Verified it surfaces new servers
  while rate-limited.
- **Enrich pass #3 (post-fix):** +25 servers (the DB/git/cloud population opened up). 2 VULNERABLE
  candidates:
  - `@achmadya-dev/mcp-sqlite-query` → `sql_injection:sqlite_select` = **by-design** (dedicated
    read-SQL tool w/ SELECT/PRAGMA/EXPLAIN allowlist). Reclassified CLEAN.
  - `yl-mcp-git-server` v1.1.4 → **CONFIRMED OS COMMAND INJECTION (CWE-78)** 🎯. `git_add(files)` →
    `execGitCommand`→`execSync(shell)`, no sanitization; ground-truth PoC `files="; touch <sentinel>"`
    fired the sentinel. Also `git_init(remote_url/branch)`, `git_smart_commit(message)`. Local exec on
    the MCP host = real privilege boundary. osv.dev dedup = 0 (novel). Repo is a placeholder orphan →
    file via npm security + GitHub Advisory DB / MITRE (NOT huntr). Advisory:
    `~/Videos/yl-mcp-git-server_Advisory_Draft_20261006.md` (PRIVATE until disclosed).
- **Discipline scoreboard today:** 4 candidates reviewed → 1 real (git cmd-injection), 3 rejected as
  by-design. Zero false positives in reported findings.
- **Tests:** 25 passing. **Ledger end-of-day:** 101 targets · 102 CLEAN · 61 INCONCLUSIVE · 2 confirmed
  (d33naz CWE-22, yl-mcp-git-server CWE-78).
- **Also today:** promoted the product-first storefront README (local, not pushed); wrote the Platform
  v2.0 enriched plan (`docs/PLATFORM_V2_PLAN.md`, documented-only); baked CTO-energy into skills.md rule 5.

- **PyPI / `uvx` discovery SHIPPED (4th lane):** we were npm-only, blind to the Python MCP ecosystem.
  Added `discover_pypi` (sweep.py) — greps the PyPI simple index for `mcp`+risky names (cached 6h,
  21k mcp pkgs / 1,564 risky), liveness via PyPI JSON (no GitHub rate-limit), launches via `uvx <pkg>`
  (scan_one already runs arbitrary argv). `daily --pypi N` (default 10) lane. `tests/test_daily.py::
  test_pypi_discovery_filter`. 26 tests green. Verified: surfaces live Python servers (sql/postgres/
  mysql/github/terminal) as uvx cmds. ~10× the addressable universe vs npm long tail.

- **Latest-version pinning:** `_cmd_for`/`_pypi_cmd_for` now pin the exact latest version from
  discovery (`npx -y pkg@1.2.3` / `uvx pkg@0.5.0`; curated → `@latest`) — no stale-cache scans, version
  recorded in ledger. 
- **11th detection class — deserialization (CWE-502), SHIPPED + maintained properly:** `probe_deserialization`
  (sentinel/sink ground truth, yaml.load + pickle gadgets), `_DESER_PARAM`/`_DESER_DESC` regexes, vuln+safe
  fixtures (`load_config` yaml.load vs yaml.safe_load), selftest entry, `CLASS_META` (Critical/CWE-502/MCP05/
  remediation). No by-design carve-out (deser RCE is never intended). Scorecard auto → 11 classes. 26 tests green.

- **Source-of-truth system (so the website can't drift from the backend):** `mcp-rt stats` →
  `hunt/stats.json`, derived live from the ledger via the SAME `_gather()` the scorecard uses (no
  parallel counting, nothing hardcoded). `docs/DATA_MODEL.md` is the dev contract (ledger = truth →
  stats.json → website/scorecard; regenerate on every deploy; disclosure-safe = count-not-name).
  `tests/test_stats.py` locks shape + derivation + disclosure safety. 27 tests green. Current:
  classes=11 tested=111 confirmed=2 clean=53 inconclusive=56 triaged_out=48; published_findings=[]
  (both confirmed are under coordinated disclosure — counted, not named).
- **DATA-HYGIENE TODO (backend-mismatch risk):** a few ledger target names are full command strings
  (`npx -y @m_sea_bass/... /tmp/fs_allowed`, `npx -y @zhxblcdx/mcp-ssh`) that DUPLICATE properly-named
  rows → website would show a server twice, once mangled. Fix: normalize `targets.name` to the package
  name + merge dup rows (one-off ledger migration). Forward code already derives clean names.

- **Competitor research: Appsecco** (consultancy, MCP testing $3.5k–$15k, coverage ≈ our 11 classes,
  manual/point-in-time). Full analysis `docs/COMPETITIVE.md`. Validates+prices the market.
- **Commercial roadmap** `docs/COMMERCIAL_ROADMAP.md` — free core stays (funnel; they have none); PAID =
  A parity (exec summary/compliance/PDF/diff) → B continuous+CI+fleet → C proxy(prevention)+chaining+
  auto-remediation; flywheel = public leaderboard. Milestones M1–M9 each test-gated.
- **M1 DONE (A1+A2), tested+verified (29 tests):** `report.py` now renders a leadership **exec summary**
  (attestation tone when CLEAN) + an **OWASP→SOC2/ISO27001/PCI compliance crosswalk** (`COMPLIANCE_XWALK`,
  "not a certification claim"). `tests/test_report_render.py`. Closes 2 of 3 Appsecco-parity deliverable gaps.

- **M2 DONE (A3, 31 tests):** `report --pdf`/`--html` = branded client deliverable (markdown→HTML+print
  CSS→PDF via weasyprint; both already installed, no new dep; HTML fallback if PDF libs missing).
  Verified a real 22KB PDF from a live scan. Phase A now 3/4 — matches Appsecco's deliverable.

- **M3 DONE (A4, 34 tests):** `mcp-rt diff --target-stdio` re-tests a target → RESOLVED/NEW/UNCHANGED vs
  its last findings; version-agnostic (base-name match). `hunt/diff.py` + `tests/test_diff.py`.
  **PHASE A COMPLETE → full deliverable parity with Appsecco.** All 11 attack vectors self-test green.

- **M4 DONE (B1, 36 tests):** `mcp-rt monitor --from-ledger N | --targets ...` re-scans at LATEST
  version (`_relatest` re-pins @ver→@latest) and ALERTS on any NEW finding → `hunt/alerts.jsonl`.
  `hunt/monitor.py` + `tests/test_monitor.py`; live smoke CLEAN/no-FP. Phase B started.

- **M5 DONE (B2, 39 tests):** `mcp-rt ci` = CI/CD gate — parses repo MCP configs → scans each stdio
  server → REAL SARIF 2.1.0 (per-class rules + GitHub security-severity) → fails build per --fail-on.
  `hunt/ci.py` + `tests/test_ci.py` + `.github/action/` (action.yml/Dockerfile+node+uv/entrypoint/README).
  E2E: vuln fixture → 11 findings → valid SARIF → exit 1. Marketplace-ready distribution lever.

- **Ship-lane prep (2026-10-06):** (1) BOTH advisories finalized paste-ready in `~/Videos/`:
  `d33naz_GHSA_submission_paste_ready.md` + NEW `yl-mcp-git-server_GHSA_submission_paste_ready.md`
  (route: GitHub Advisory DB / MITRE CNA-LR — orphan repos; osv.dev dedup=0). (2) `docs/CI_DEPLOY.md`
  = exact push/publish steps for Ved. (3) FIXED before-push: `pyproject` now declares `pyyaml`+`markdown`
  (CI was going to go red without them) + `[pdf]`=weasyprint extra; action Dockerfile fixed (Docker-action
  context is `.github/action/`, not repo root → now `pip install git+https://…@main` + `COPY entrypoint.sh`).
  39 tests green. Advisories stay OUT of the repo (unpublished).

- **M6 DONE (B3, 41 tests) → PHASE B COMPLETE:** `mcp-rt fleet` = whole-fleet report + per-package
  supply-chain risk flags (single-maintainer/stale/high-blast-radius = MCP04). `hunt/fleet.py` +
  `tests/test_fleet.py`. Phase B (monitor/CI/fleet) all shipped + test-gated.
- **Filing:** one finding SUBMITTED to VulnCheck (ID 2b7c9906…, CVD 2-3d); second still to file (same
  portal). Deps/Dockerfile fixed before push (pyyaml+markdown declared, action builds). `docs/CI_DEPLOY.md`.
- **Triage discipline (2026-10-06):** enrichment pass pushed ledger to 151 tested; confirmed briefly
  inflated to 10 → triaged ALL back to **2** (d33naz, yl). @sajithrw/mcp-mysql=FP, akamai=INCONCLUSIVE
  (unfetchable, not counted). 92 signals triaged out lifetime, 0 FP. stats.json + scorecard accurate.

- **Checklist-parity win (2026-10-07):** tool-by-tool **coverage matrix** added to the report —
  `run_full_scan` now returns `coverage` (every tool×class×verdict), `render_markdown` renders a
  "Tool-by-tool coverage" table (clean/vulnerable per tool). Answers Appsecco's buyer-checklist
  "tool-by-tool coverage" item + strengthens the beta deliverable. `tests/test_report_render.py`, 42 tests.
  Remaining cheap checklist wins queued: surface-map output · OAuth AS-metadata probe.
- **Surface-map ✅ DONE (2026-10-07, 43 tests):** `scan_target(surface=)` inventories tools+resources
  in-session (no 2nd connect); report renders an "Attack surface" section (transport · tool count ·
  resource count · tool→params). Answers Appsecco checklist item #1 (map the surface), automated.
  Last checklist win = OAuth AS-metadata probe (remote/HTTP, heaviest, queued).
- **OAuth AS-metadata probe ✅ DONE (2026-10-07, 47 tests):** `remote.py::check_oauth_metadata` fetches
  the OAuth AS metadata → flags missing PKCE S256 + CONFIRMS open dynamic client registration via one
  synthetic unauth registration (never flags unconfirmed/None); wired into consent-gated `scan_remote`;
  kept SEPARATE from the 11 ground-truth classes (posture, not sentinel). `tests/test_oauth.py`.
  **→ ALL 3 CHECKLIST-PARITY WINS DONE: coverage matrix · surface-map · OAuth. We satisfy Appsecco's
  entire buyer checklist.** Future: redirect_uri-validation via a crafted DCR registration.

- **Path-traversal precision FP — FIXED (2026-10-07, 50 tests):** probe now learns the server's allowed
  roots (`list_allowed_directories`, name-match) and plants the out-of-root canary OUTSIDE them
  (`_outside_root_dir`/`_under`); root spanning everything (`/`) → NOT_APPLICABLE. Proven: server-filesystem
  with root=/tmp went VULNERABLE(FP)→CLEAN. Caught live while demoing a sample report — the zero-FP
  discipline stopped us shipping a report that falsely flagged Anthropic's own server. `tests/test_path_scope.py`.

**RESUME NEXT — CTO stance (unchanged):** Phase A+B shipped. Phase C (proxy/chaining/auto-fix) is weeks
and should WAIT for a real user/design partner — don't out-run the business. Highest-value now = the SHIP
lane: **(Ved) push the storefront README · file the 2nd finding · land 1 design partner.** Flywheel
(public leaderboard from stats.json) is the one marketing build worth doing without a user. The PyPI
pool is huge (1,564 risky) so passes won't saturate soon. **Ved to file:** d33naz + yl-mcp-git-server
(npm security + GitHub Advisory DB/MITRE); push the storefront README. Tip: set `GITHUB_TOKEN` for
clean npm-side maintained-checks (5000/hr).
