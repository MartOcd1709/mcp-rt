# MCP Security Benchmark — v1.0

An open, reproducible benchmark that assigns any MCP server a security **grade** and **score**
from **ground-truth** testing — not heuristics. Run it with `python -m hunt.benchmark
--target-stdio "<server command>"`.

## Why ground truth
Existing MCP scanners inspect tool descriptions and ask "does this *look* malicious?" This
benchmark plants a real synthetic artifact (honeytoken credential, sentinel file, canary host,
honeytoken bearer token) and records whether it was **actually** leaked, executed, or replayed.
Every FAIL is backed by captured evidence; false positives are near-zero by construction.

## What it tests (v1.0)
Six ground-truth detection classes, each mapped to the OWASP MCP Top 10:

| Check | Ground-truth signal | CWE | OWASP MCP |
|---|---|---|---|
| Command / code injection (incl. allowlist bypass) | sentinel file created / sink hit | CWE-78 | MCP05 |
| SQL injection (error-based) | SQL parser error from a quote | CWE-89 | MCP05 |
| SSRF (+ internal/metadata, redirect-follow) | loopback sink receives the request | CWE-918 | MCP05, MCP02 |
| Path traversal (read) + arbitrary write escape | planted canary returned / file written outside root | CWE-22 | MCP05, MCP02 |
| Tool-metadata concealment (tool poisoning) | invisible-Unicode payload in metadata (decoded) | CWE-74 | MCP03 |
| Token passthrough / confused deputy | honeytoken bearer token replayed downstream | CWE-287 | MCP01, MCP07 |

**Actively tested OWASP controls: MCP01, MCP02, MCP03, MCP05, MCP07 (5 of 10).** The other
five (MCP04 supply chain, MCP06 context prompt-injection, MCP08 telemetry, MCP09 shadow
servers, MCP10 context oversharing) are out of active probe scope in v1.0 and reported as
"not tested" — never silently counted as passing.

## Scoring
- Start at 100. Deduct per confirmed finding by severity: **Critical −40, High −25, Medium −10, Low −3**. Floor at 0.
- **Grade bands:** A ≥ 90 · B ≥ 75 · C ≥ 60 · D ≥ 40 · F < 40.
- The scorecard also reports **controls passed / tested** and **coverage (5/10)** so a grade is
  never read as a claim of total security — only of the controls this version tests.

## Methodology guarantees
- Local, open-source servers only; synthetic artifacts only; loopback-only capture. Nothing real leaves the host.
- Each run preserves a full evidence report (`hunt/reports/`) and scorecard (`hunt/benchmark_results/`).
- Reproducible: same server + same version → same verdicts (ground-truth, not model-dependent).
- Confirmed findings are responsibly disclosed before any public listing.

## Versioning
`v1.0` is the first public cut. New detection classes (e.g. SSTI, rug-pull detection, DNS
rebinding) land in minor versions; the scoring model and grade bands are fixed within a major
version so scores stay comparable. The current coverage matrix lives in
`docs/THREAT_INTEL/COVERAGE_MATRIX.md`.
