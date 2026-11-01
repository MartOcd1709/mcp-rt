# MCP Security Benchmark — v2.0

An open, reproducible benchmark that assigns any MCP server a security **grade** and **score**
from **ground-truth** testing — not heuristics. Run it with `python -m hunt.benchmark
--target-stdio "<server command>"`.

## Why ground truth
Existing MCP scanners inspect tool descriptions and ask "does this *look* malicious?" This
benchmark plants a real synthetic artifact (honeytoken credential, sentinel file, canary host,
honeytoken bearer token) and records whether it was **actually** leaked, executed, or replayed.
Every FAIL is backed by captured evidence; false positives are near-zero by construction.

## What it tests (v2.0)
Thirteen ground-truth detection classes, each mapped to the OWASP MCP Top 10. This table is the
engine's `CLASS_META` — the single source of truth; the live count is whatever `mcp-rt stats`
reports (currently **13 classes**), never a number hand-maintained here.

| Check | Ground-truth signal | CWE | OWASP MCP |
|---|---|---|---|
| Command / code injection (incl. allowlist bypass) | unique nonce echoed by an injected shell/eval | CWE-78 | MCP05 |
| SQL injection | boolean true-vs-false row-set delta (or parser error) | CWE-89 | MCP05 |
| SSRF (+ internal/metadata, redirect-follow) | loopback sink hit / `file://` local read | CWE-918 | MCP05, MCP02 |
| Path traversal (read) + arbitrary write escape | out-of-root canary returned / file written outside root | CWE-22 | MCP05, MCP02 |
| Server-side template injection (SSTI) | `{{a*b}}` evaluated to the product, literal gone | CWE-1336 | MCP05 |
| Argument injection / CLI-flag smuggling | a smuggled flag altered the carrier command | CWE-88 | MCP05 |
| Insecure deserialization | `yaml.load`/`pickle` payload executed code (sentinel RCE) | CWE-502 | MCP05 |
| Tool-metadata concealment (tool poisoning) | invisible-Unicode payload decoded from metadata | CWE-74 | MCP03 |
| Dynamic tool redefinition (rug pull) | tool definition changed after approval | CWE-494 | MCP03 |
| Token passthrough / confused deputy | honeytoken bearer token replayed downstream | CWE-287 | MCP01, MCP07 |
| DNS rebinding / missing Origin validation | foreign Origin/Host accepted on an HTTP server | CWE-346 | MCP07 |
| Supply chain / install-time code execution | install-hook ACE / OSV known-CVE dependency | CWE-829 | MCP04 |
| Context oversharing / environment leak | planted env canary returned in a tool result | CWE-200 | MCP10 |

**Actively tested OWASP controls: MCP01, MCP02, MCP03, MCP04, MCP05, MCP07, MCP10 (7 of 10).** The
other three (MCP06 intent-flow / prompt-injection — surfaced as an enabling-conditions signal,
confirmation requires the Advanced agent red-team; MCP08 telemetry; MCP09 shadow servers) are out
of active probe scope and reported as "not tested" — never silently counted as passing.

## Scoring
- Start at 100. Deduct per confirmed finding by severity: **Critical −40, High −25, Medium −10, Low −3**. Floor at 0.
- **Grade bands:** A ≥ 90 · B ≥ 75 · C ≥ 60 · D ≥ 40 · F < 40.
- The scorecard also reports **controls passed / tested** and **coverage (7/10)** so a grade is
  never read as a claim of total security — only of the controls this version tests.

## Methodology guarantees
- Local, open-source servers only; synthetic artifacts only; loopback-only capture. Nothing real leaves the host.
- Each run preserves a full evidence report (`hunt/reports/`) and scorecard (`hunt/benchmark_results/`).
- Reproducible: same server + same version → same verdicts (ground-truth, not model-dependent).
- Confirmed findings are responsibly disclosed before any public listing.

## Versioning
`v2.0` is the current cut — **13 ground-truth classes** (v1.0's six plus SSTI, argument injection,
rug-pull, DNS rebinding, insecure deserialization, supply chain, and context oversharing). New
classes land in minor versions; the scoring model and grade bands are fixed within a major version
so scores stay comparable. The authoritative class list is the engine's `CLASS_META` (surfaced by
`mcp-rt stats`); the coverage matrix lives in `docs/THREAT_INTEL/COVERAGE_MATRIX.md`.
