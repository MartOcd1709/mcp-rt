# INTEL 2026-10-05 — new attack classes to build next

`mcp-research` gap-check: MCP / AI-agent-server attack classes published ~2026 that mcp-rt
does **not** already cover. Scored on **confirmability** (can we ground-truth it with no live
LLM agent — via the tool's response, a local sink/sentinel/canary, or advertised metadata?),
novelty vs our 8 probes + 37-payload corpus, and likelihood of real findings.

Already covered (not re-flagged): ssrf, command_injection (+allowlist-bypass +code-eval),
path_traversal (+write-escape), tool_poisoning (invisible-unicode/TAG/zero-width/bidi),
sql_injection, token_passthrough/confused-deputy, ssti, rug_pull, + the Mode-A corpus.

## Candidate classes

### 1. ANSI terminal-escape concealment  — **NOVEL variant (extends tool_poisoning)**
- Mechanism: malicious text hidden in tool descriptions/outputs with ANSI escape sequences
  (`\x1b[` CSI cursor-move / screen-clear, OSC-8 deceptive hyperlinks) — invisible in the
  terminal approval view but ingested verbatim by the model. Same "approval-view fidelity gap"
  as our TAG-block probe, different carrier.
- Source: Trail of Bits, *Deceiving users with ANSI terminal codes in MCP*, 2025-04-29
  (https://blog.trailofbits.com/2025/04/29/deceiving-users-with-ansi-terminal-codes-in-mcp/);
  ATR-2026-00579 line-jumping rule (https://agentthreatrule.org/en/rules/ATR-2026-00579).
- Novelty: our `_scan_conceal` catches TAG/zero-width/bidi but **NOT** ANSI CSI/OSC. Gap.
- **Confirmability: HIGH.** Pure deterministic scan of model-facing metadata (+ tool outputs)
  for `\x1b[`/`\x9b` CSI, `\x1b]...` OSC, and OSC-8 hyperlink sequences. Identical proof model
  to the existing probe: presence of the sequence = finding. No agent, no fixture needed.
- Effort: **S**. Add an ANSI regex to `_scan_conceal` + scan `_result_text` of a benign call.

### 2. Argument injection / CLI flag smuggling  — **NOVEL mechanism (sibling of command_injection)**
- Mechanism: server shells out *safely* (no `shell=True`, no metacharacters) but passes user
  input as an `argv` element. Input beginning with `-`/`--` is parsed by the carrier binary as
  a **flag**, not data — e.g. `git diff` ref → `--output=/path`, truncating/overwriting files
  outside the workspace. Defeats allowlists that only block `; | & $( )`.
- Source: CVE-2026-97662 / GHSA-8g28-rj54-p5p2, AWS `security-agent-mcp-server` diff scan,
  published 2026-10-01 (https://aws.amazon.com/security/security-bulletins/2026-121-aws/);
  class also in MST-10 "Command Injection" family (arXiv:2608.00150v1, 2026-07-31,
  https://arxiv.org/html/2608.00150v1).
- Novelty: PARTIAL vs our `command_injection` — our payloads rely on shell metacharacters /
  carrier `-exec`. Flag-smuggling needs **no** metacharacters and bypasses a different control.
- **Confirmability: HIGH.** Ground-truth by sentinel, reusing existing infra: for params on
  tools whose desc names a CLI tool (git/tar/grep/rsync/curl/ffmpeg…), inject a flag that
  writes our sentinel outside the workspace (`--output=<tmp>/sentinel`, `-o <tmp>/sentinel`,
  tar `--to-command`) and assert the sentinel appears. File-on-disk proof, no agent.
- Effort: **S–M**. Reuses `_Sink`/sentinel + `_candidate_params`; add a flag-payload set and a
  git/tar fixture.

### 3. DNS rebinding / missing Origin+Host validation (HTTP/SSE transport)  — **NOVEL**
- Mechanism: HTTP-transport MCP servers on localhost without auth don't validate `Origin`/`Host`
  on inbound JSON-RPC. A malicious web page uses DNS rebinding (TTL-0) to point its hostname at
  127.0.0.1 and drives the local server cross-origin → unauthorized tool invocation / SSRF to
  metadata.
- Source: CVE-2025-66416 / GHSA-9h52-p55h-vw2f, MCP Python SDK <1.23.0, patched 2025-12-02
  (https://github.com/advisories/GHSA-9h52-p55h-vw2f); CVE-2026-35568 MCP Java SDK
  (https://www.mallory.ai/vulnerabilities/019d6a0f-df11-7713-9472-9e2744403687);
  CVE-2026-27826 TOCTOU rebind bypass in mcp-atlassian
  (https://github.com/sooperset/mcp-atlassian/security/advisories/GHSA-72fm-whvq-jghf);
  ATR-2026-01307 (https://agentthreatrule.org/en/rules/ATR-2026-01307).
- Novelty: our matrix marks this ❌ "transport-level". SDK-level defect → **huge** affected
  population (every HTTP/SSE server on vulnerable SDK versions).
- **Confirmability: HIGH (for HTTP/SSE servers).** Deterministic: connect to the HTTP endpoint,
  send an `initialize` JSON-RPC with a foreign `Origin: http://evil.example` and/or
  `Host: attacker.test`; a valid JSON-RPC response (not 403/400) = vulnerable, rejection = clean.
  No agent. Caveat: only applies to HTTP/SSE transport — our probes are stdio-only today, so this
  needs a small HTTP-transport harness + HTTP fixtures.
- Effort: **M**. New transport path + 1 vuln / 1 safe HTTP fixture. Biggest finding-population.

### 4. Cursor-based path traversal  — NOVEL, lower priority
- Mechanism: the pagination `cursor` primitive is used as a file/offset reference and escapes the
  resource root (`cursor=../../etc/passwd`). Source: arXiv:2608.00150v1, 2026-07-31
  (https://arxiv.org/html/2608.00150v1).
- **Confirmability: MEDIUM.** Reuse the path_traversal canary: list resources, feed a traversal
  cursor, assert the out-of-root marker returns. Only hits servers that paginate resources —
  narrow population. Effort M + fixture.

### 5. Cross-client response leakage (shared transport)  — NOVEL, flaky
- Mechanism: a single reused Server/transport across concurrent HTTP clients leaks client A's
  response to client B (race / CWE-362). Source: CVE-2026-25536, MCP TypeScript SDK
  1.10.0–1.25.3 (https://www.sentinelone.com/vulnerability-database/cve-2026-25536/).
- **Confirmability: MEDIUM.** Two concurrent clients + unique markers, watch for a foreign
  marker in the wrong response — but it's a race, nondeterministic, HTTP-only. Lower value.

### 6. Full-Schema Poisoning (FSP)  — PARTIAL, mostly agent-dependent
- Mechanism: injection text in **non-description** schema fields (param names, `required[]`,
  defaults, enums, extra fields). Source: CyberArk FSP/ATPA, ATR-2026-02025 (MCP-11)
  (https://agentthreatrule.org/en/rules/ATR-2026-02025); MCPTox benchmark arXiv:2508.14925.
- Novelty/overlap: our `tool_poisoning` already `json.dumps` the whole schema, so **concealed-
  unicode** FSP is caught. The remaining gap is *plaintext imperatives* in schema fields — whose
  effect needs a live LLM to confirm. **Confirmability: LOW** for the semantic part. Not a strong
  ground-truth probe; leave to the Mode-A corpus.

### 7. Sensitive-data exposure in errors  — lower priority
- Mechanism: bearer tokens / API creds / connection strings reflected in tool error messages.
  Source: arXiv:2608.00150v1 MST-10 (https://arxiv.org/html/2608.00150v1).
- **Confirmability: HIGH but noisy.** Scan responses for secret-shaped patterns; false-positive
  prone and often needs a planted secret to be meaningful. Fold into exfil detection, not a new
  class.

## Ranking (confirmability × novelty × real-finding likelihood) — build next

1. **ANSI terminal-escape concealment** — HIGH confirmability, near-zero build (extends an
   existing deterministic probe), real findings already documented in the wild.
2. **Argument injection / flag smuggling** — HIGH confirmability via file sentinel, NOVEL
   mechanism our command_injection misses, fresh GHSA-backed (AWS, 2026-10-01), reuses our infra.
3. **DNS rebinding / Origin-Host validation** — HIGH deterministic confirmability (foreign
   `Origin`/`Host` → accept vs reject), SDK-level → largest affected population; costs an
   HTTP-transport harness (M) but the finding volume justifies it.

Deferred: cursor-traversal (#4, narrow), cross-client leak (#5, flaky), FSP semantic part
(#6, agent-only), secret-in-errors (#7, fold into exfil).
