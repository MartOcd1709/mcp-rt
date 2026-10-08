# INTEL 2026-10-05 (batch 2) — next build targets after ANSI / arg-injection / DNS-rebinding

Batch-1 top-3 (ANSI concealment, argument injection, DNS-rebinding/Origin) are now **BUILT**
(see COVERAGE_MATRIX: `tool_poisoning` ANSI carrier, `arg_injection` probe, `remote.py`
Origin check). This batch gap-checks again for server-side, **no-live-LLM-confirmable** classes
we still miss. Scoring = confirmability × novelty × real-finding-likelihood.

Bottom line up front: **one** genuinely-new high-value class since the last brief
(OAuth authorization-server metadata posture), plus **one** worthwhile refinement of an existing
crude check. The rest of the fresh 2026 disclosures are already covered, client-side (wrong
target for a server scanner), noisy, or agent-only. Stated honestly below rather than padded.

---

## 1. OAuth AS-metadata posture — open DCR + redirect_uri non-validation + PKCE-not-advertised  — **NOVEL, build next**

- **Mechanism (three sub-checks, one probe):** An OAuth-protected MCP server advertises
  `/.well-known/oauth-authorization-server` (RFC 8414; `oauth-protected-resource` /
  `openid-configuration` fallbacks). Three deterministic defects live there:
  - **(a) Open Dynamic Client Registration** — the advertised `registration_endpoint` issues a
    `client_id` to an unauthenticated POST with arbitrary client metadata.
  - **(b) redirect_uri non-validation** — registration accepts an arbitrary off-origin
    `redirect_uris` (e.g. `https://attacker.evil/cb`) without an allowlist → auth-code
    interception / one-click session takeover.
  - **(c) PKCE not advertised** — `code_challenge_methods_supported` is absent / lacks `S256`;
    the 2026-07-28 spec makes PKCE a MUST, so absence is a spec-violation posture flag
    (auth-code-injection risk).
- **Sources:**
  - CVE-2026-79786, Coroot MCP OAuth DCR accepts any syntactically-valid redirect_uri without
    validation, v1.20.2–1.24.5, CVSS 7.1, published **2026-08-25**
    (https://cyberstrike.io/cve/CVE-2026-79786/).
  - Voorivex, *Shaking the MCP Tree* — open DCR, missing/weak consent, direct-token MCP access,
    all raw-HTTP confirmable, **2026-02-03** (https://blog.voorivex.team/shaking-the-mcp-tree).
  - ssojet, *MCP Authentication Vulnerabilities: 7 Failure Modes, With the CVEs* — mode 6 (skipped
    PKCE / `code_challenge_methods_supported` absent), 2026
    (https://ssojet.com/blog/mcp-authentication-vulnerabilities).
  - MCP 2026-07-28 authorization spec (PKCE MUST; audience MUST)
    (https://ssojet.com/blog/mcp-authentication-oauth-tokens-security-ai-connections).
- **Novelty vs our 10:** our `token_passthrough`/family_b harness (`hunt/oauth_harness.py`) only
  detects the server **replaying a client token verbatim** to a downstream. It does **not** touch
  the server-under-test's *own* `registration_endpoint`, redirect_uri policy, or advertised PKCE
  support. Different flaw, different endpoint, different proof. Matrix had "privilege
  escalation / unauthorized access ❌ — needs auth context"; this needs **none**.
- **CONFIRMABILITY: HIGH** (raw HTTP + advertised metadata, identical accept/reject proof model
  to the existing `check_origin_validation`):
  1. `GET /.well-known/oauth-authorization-server` (+ `oauth-protected-resource`,
     `openid-configuration` fallbacks). No metadata / no `registration_endpoint` → **NOT
     APPLICABLE** (stdio or non-OAuth server).
  2. `POST` the `registration_endpoint` with
     `{"client_name":"mcp-rt-probe","redirect_uris":["https://attacker.evil/cb"],"grant_types":["authorization_code"]}`.
     - 200/201 + `client_id` in body echoing our off-origin redirect_uri → **VULNERABLE** (open
       DCR + redirect_uri non-validation). The returned `client_id` is the ground truth — no LLM.
     - `invalid_redirect_uri` / 400 / 403 / auth-required → **CLEAN**.
  3. Metadata missing `code_challenge_methods_supported: ["S256"]` → **PKCE-not-advertised** flag
     (advertised-metadata ground truth).
  - Low-intrusiveness: one registration of one throwaway client (no auth flow completed, no victim
    involved). Consent-gated behind the existing `--authorized-by` attestation in `remote.py`.
- **Build effort: S–M.** New `check_oauth_posture(url)` in `hunt/remote.py` mirroring
  `check_origin_validation` (urllib, status-code verdict); reuse the well-known parse already in
  `oauth_harness.py`. Wire its verdict into `scan_remote`'s findings like the `dns_rebinding` row,
  and add a `report.py` entry. HTTP/OAuth servers only (same population the Origin check already
  serves).
- **Needs-new-fixture? Yes, small.** Extend `hunt/remote_fixtures/http_server.py` with a
  `DCR_OPEN=1/0` flag (and a PKCE-advertised toggle): open → issues client_id for any
  redirect_uri (must verdict VULNERABLE); closed → allowlist-rejects + advertises S256 (CLEAN).
  One fixture, two env toggles, mirrors the existing `DNS_PROTECT` pattern. Leave one runnable
  assert (VULNERABLE vs CLEAN against the toggle).

---

## 2. Harden the `unauthenticated_session` check (REFINEMENT of an existing crude flag)

- **Current state:** `remote.py` sets `unauthenticated_session = not headers` — i.e. it only
  reports "unauth" when *we* passed no auth header. That is a tautology, not a test: it never
  distinguishes a server that *requires* auth from one that doesn't.
- **Refinement:** actively connect with **no** Authorization header and assert whether
  `initialize` + `tools/list` + a benign `tools/call` actually **succeed**. Success with no token
  = genuine missing-auth finding; 401/403 = correctly protected.
- **Sources:** CVE-2025-66414 (TS SDK) / CVE-2025-66416 (Python SDK), unauthenticated localhost
  transport, CVSS 8.1, published **2025-12-02**; CVE-2026-8446 (IBM Langflow 1.0.0–1.10.3,
  CVSS 7.5, **2026-08-05**); ssojet mode 3
  (https://ssojet.com/blog/mcp-authentication-vulnerabilities).
- **Novelty:** refinement, not a new class — but it converts a non-signal into a real verdict and
  pairs naturally with the dns_rebinding row (no-auth + no-Origin-validation = the full remote
  RCE/SSRF-exposure pattern in CVE-2026-33032 nginx-ui, CVE-2026-5058 aws-mcp).
- **CONFIRMABILITY: HIGH** (the no-auth `tools/call` either returns a result or a 401 — binary).
- **Build effort: S.** A few lines in `scan_remote`. **No new fixture** (the http_server fixture
  already serves without auth; add one AUTH_REQUIRED toggle if a CLEAN case is wanted).
- **Caveat:** localhost-only stdio-style deployments are often unauth **by design** — report as a
  posture flag scoped to HTTP/SSE + non-loopback bind, not an automatic "VULNERABLE", to avoid
  noise.

---

## 3. SSRF through OAuth discovery (CVE-2026-45609 / CVE-2026-27826) — MEDIUM, mostly wrong-target

- **Mechanism:** a client/framework fetches untrusted URLs from OAuth discovery docs
  (issuer, protected-resource-metadata, DCR discovery) without SSRF controls → internal/metadata
  reach.
- **Sources:** CVE-2026-45609, Spring AI `mcp-security` < 0.1.9, DCR-enabled only, CVSS 6.5,
  published **2026-05-29** (https://github.com/advisories/GHSA-qjp4-4jvr-xqg3); CVE-2026-27826,
  mcp-atlassian < 0.17.0, CVSS 8.2, **2026-03-10**.
- **Why not top-ranked:** this is a **client-side** fetch (the MCP *client* framework following a
  malicious server's metadata). `mcp-rt` scans servers, not clients, so confirming it means
  standing up a malicious server that advertises a collaborator metadata URL and watching a
  client-under-test fetch it — a different harness and a different target than everything we ship.
  It is also a variant of our existing `ssrf` sink class. **Confirmability: MEDIUM**, build L,
  needs a client-under-test. Defer unless a client-scanning mode is ever added.

---

## Already-covered / correctly-deferred (not re-flagging)
- **Token passthrough / confused-deputy** (CVE-2026-48039 Meta Ads MCP, 2026-08-07) — DONE,
  family_b honeytoken replay.
- **DNS rebinding / Origin** (CVE-2025-66416, CVE-2026-35568) — DONE, `remote.py`.
- **Credentials-in-error-responses** (CVE-2026-48039 mode 4) — still folds into exfil detection,
  noisy, not a standalone class (as batch-1 ruled).
- **Cross-client response leak** (CVE-2026-25536, TS SDK) — still deferred: race, HTTP-only, flaky.
- **Audit-trail gap** (ssojet mode 7) — not confirmable without log access; agent/ops concern.
- **Missing audience validation** (ssojet mode 1) — close sibling of token_passthrough; hard to
  ground-truth without a token the server will accept. Leave with family_b.

---

## Ranking (build next)

1. **OAuth AS-metadata posture probe** (open DCR + redirect_uri non-validation + PKCE-not-advertised)
   — HIGH confirmability via raw HTTP + advertised metadata, genuinely novel vs our 10, CVE-backed
   and fresh (Coroot 2026-08-25; Voorivex 2026-02-03), reuses the `check_origin_validation`
   pattern and the `oauth_harness` well-known parse. **S–M, one small fixture.**
2. **Harden `unauthenticated_session`** into a real no-auth `tools/call` verdict — HIGH
   confirmability, converts a dead heuristic into signal, pairs with dns_rebinding. **S, no new
   fixture.**
3. (Deferred) OAuth-discovery SSRF — client-side target, MEDIUM, revisit only with a
   client-scanning mode.

Honest note: a day after batch-1, the OAuth authorization-layer is the only vein with new
server-side, agent-free, confirmable signal. If #1 and #2 ship, the next sweep should look
for fresh arXiv cs.CR / GHSA items rather than expect another batch immediately — the current
taxonomy is well-covered.
