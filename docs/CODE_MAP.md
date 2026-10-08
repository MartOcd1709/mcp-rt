# mcp-rt — code map & reading guide

Read in this order to understand the engine. Two layers to know up front:

- **`hunt/`** = the **product engine** (what we built into a VAPT tool: probes, benchmark, CLI,
  remote, scorecard, sweep). This is where to spend your time. ~2,500 lines total.
- **`mcp_rt/`** = the **original research corpus** (the 37 Black Hat agent-attack payloads +
  the `python -m mcp_rt.scan` credential-exfil path + honeytoken/harness/adapters). Older,
  separate from `hunt/`. Skim after `hunt/`.

Conceptual overview first (open in a browser): `~/Desktop/mcp-rt_field_manual.html`.

## Reading order (hunt/ — the engine)
1. **`hunt/cli.py`** (~50 lines) — the `mcp-rt` command and every subcommand. Start here: it's the product's whole surface in one file.
2. **`hunt/findings_db.py`** (~170) — the SQLite ledger: `targets`, `scans`, `disclosures`. How every result is stored.
3. **`hunt/probes.py`** (~660, THE HEART) — the 8 ground-truth detection classes (ssrf, command_injection, path_traversal, tool_poisoning, sql_injection, ssti, rug_pull, arg_injection) + `_scan_conceal` + the candidate-selection heuristics + the precision gates (by-design vs real). The core IP.
4. **`hunt/probe_fixtures/vuln_server.py` + `safe_server.py`** — the deliberately-vulnerable and the hardened twin. Each probe must FIRE on vuln and STAY QUIET on safe. Reading these makes every probe concrete.
5. **`hunt/report.py`** (~210) — `CLASS_META` (each class → severity/CWE/OWASP MCP Top 10 + remediation) and the unified VAPT + compliance report.
6. **`hunt/benchmark.py`** (~105) — scoring → letter grade + scorecard, vs OWASP MCP Top 10. Spec: `docs/MCP_SECURITY_BENCHMARK.md`.
7. **`hunt/family_b.py` + `hunt/oauth_harness.py`** — token passthrough / confused-deputy, with a mock OAuth environment.
8. **`hunt/remote.py`** (~210) — consent-gated hosted-server scanning (streamable-http/SSE) + the DNS-rebinding Origin check + the active no-auth check.
9. **`hunt/sweep.py`** (~280) — discovery (maintained-repo / long-tail npm) + the mass-sweep loop + reliability (bin resolution, subcommand recovery, failure classification).
10. **`hunt/scorecard.py`** (~130) — the read-only public HTML scorecard (disclosure-safe) generated from the ledger.

## How to see each piece run
```bash
mcp-rt probe --selftest          # all probes fire on vuln fixture, stay quiet on safe (fast)
mcp-rt benchmark --target-stdio "<python> hunt/probe_fixtures/vuln_server.py"   # full grade/scorecard
mcp-rt report    --target-stdio "..."    # VAPT + OWASP report
mcp-rt sweep --discover --cap 10         # list maintained long-tail targets (no install)
mcp-rt scorecard                         # -> hunt/scorecard.html (open in browser)
python -m pytest -q                      # 16 hermetic tests
```

## Supporting
- `.claude/skills/mcp-hunt/` — the repeatable hunt loop (the methodology).
- `.claude/agents/mcp-research.md` — the threat-intel research subagent.
- `docs/THREAT_INTEL/` — COVERAGE_MATRIX.md (every attack class → covered/missing) + INTEL briefs.
- `hunt/findings.db` (gitignored) — the live ledger; `hunt/reports/`, `hunt/logs/`, `hunt/benchmark_results/` — preserved evidence.

## Discipline baked into the code (the "why")
Every verdict is GROUND TRUTH (planted honeytoken/sentinel/canary/captured-response), never a
heuristic. A tool doing its stated job (a fetch tool fetching, a SQL tool running SQL, a
terminal running commands) is BY-DESIGN, not a finding — see the precision gates in `probes.py`.
This is what keeps the grades credible.
