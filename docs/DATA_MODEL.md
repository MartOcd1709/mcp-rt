# Data Model & Source-of-Truth Contract

Read this before building the website/dashboard or any surface that shows numbers. It exists so the
**frontend can never disagree with the backend.**

## The one rule
**`findings.db` (the ledger) is the single source of truth. Every number is DERIVED from it — never
hardcoded.** The one artifact the frontend reads is **`hunt/stats.json`**, produced by `mcp-rt stats`
from `hunt/stats.py::stats()`. The public scorecard (`mcp-rt scorecard`) reads the *same* `_gather()`
function, so scorecard and website cannot drift.

```
findings.db  ──_gather()──►  stats()  ──►  hunt/stats.json  ──►  website / dashboard
                     └────────────────────►  hunt/scorecard.html
```

Do NOT: hardcode "11 classes" / "N servers" in the site, keep a second counter, or query the DB with
ad-hoc SQL in the frontend. Read `stats.json`. Regenerate it on every deploy (`mcp-rt stats`).

## stats.json shape (schema_version 1)
- `schema_version` — bump on any shape change; the site should refuse a mismatched backend.
- `generated_at` — ISO timestamp (detect stale data).
- `class_count`, `detection_classes[]` — `{id,title,severity,cwe,owasp}` from `report.CLASS_META`.
- `research_agent_exfils` — the Black Hat research figure (e.g. "23/26").
- `owasp_top10[]` — `{id,title,tested}`.
- `ledger`: `servers_tested`, `confirmed` (distinct targets with a real finding), `clean`,
  `inconclusive`, `under_coordinated_disclosure`, `candidates_triaged_out`, `clean_named[]`,
  `published_findings[]`.

## Disclosure safety (non-negotiable on any public surface)
A confirmed-but-unpublished finding is **counted** (`confirmed`, `under_coordinated_disclosure`) but
**never named** — `published_findings[]` lists a target only after its advisory is public/patched.
The site must render names only from `published_findings` / `clean_named`, never invent one.

## Verdicts (ledger `scans.verdict`)
`CLEAN` · `INCONCLUSIVE` (+ a `[CATEGORY]` cause in notes: NEEDS_SUBCOMMAND / NEEDS_CONFIG /
BROKEN_PACKAGE / INSTALL_FAILED / ENTRYPOINT_NOT_FOUND / SCAN_TIMEOUT / OTHER) · `VULNERABLE`
(ground-truth finding) · `LEAKED` (agent credential-exfil, research) · reclassified by-design →
`CLEAN` with a `reclassified …` note (these are the `candidates_triaged_out`).

## On deploy
1. run the test suite, 2. `mcp-rt stats` (regenerate stats.json), 3. `mcp-rt scorecard`,
4. deploy — the site reads the fresh `stats.json`. Keep `docs/WORKLOG.md` current.
