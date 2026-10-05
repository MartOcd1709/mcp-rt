# mcp-rt — Ground-Truth Security Testing for MCP

> **Scan any MCP server for real vulnerabilities — proven by a planted canary, not guessed from a description. Get a finding, or a clean attestation you can show your customers.**

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Black Hat Arsenal](https://img.shields.io/badge/Black%20Hat-Arsenal%202026-red.svg)](https://www.blackhat.com/html/arsenal.html)

AI coding agents (Claude Code, Codex, Cursor, Cline, Gemini) connect to MCP servers that read your
files, credentials, and network. Thousands are published; each is privileged by design. **mcp-rt tells
you — with ground truth, not heuristics — whether a given MCP server is actually exploitable.**

---

## 60-second quickstart

```bash
git clone https://github.com/MartOcd1709/mcp-rt && cd mcp-rt
python3 -m venv .venv && source .venv/bin/activate
pip install -e .

# Point it at any local MCP server — get a full VAPT + OWASP MCP Top 10 report
mcp-rt report --target-stdio "npx -y @modelcontextprotocol/server-filesystem /tmp"
```

You get a per-finding report (severity, CWE, OWASP MCP control, evidence, remediation) and a verdict:
**VULNERABLE** (with a reproduced proof) or **CLEAN** (an attestation across every tested class).
Use `--exit-code` to gate CI. JSON output for pipelines; `mcp-rt scorecard` for a shareable HTML posture page.

---

## Why it's different: ground truth, zero false positives

Existing scanners read a tool's *description* and ask *"does this look malicious?"* — so they miss
server-side behavior and flag benign tools. mcp-rt asks *"did the attack actually work?"* and proves
the answer:

- **Every verdict is evidence.** A planted honeytoken/sentinel/canary fired, or it didn't. No probabilities.
- **By-design ≠ vulnerability.** A fetch tool fetching, a SQL tool running SQL, a shell tool running a
  command — that's the tool's job, not a finding. We only report a *restricted* control bypassed or a
  *non-executor* made to execute. That discipline is why a finding from mcp-rt is believable.
- **Honest denominator.** Clean and inconclusive results are recorded, not hidden. Across **62 MCP
  servers tested to date, zero false positives** in reported findings.

---

## What it tests — 10 ground-truth classes + OWASP MCP Top 10

| Class | CWE | What "VULNERABLE" means (proven) |
|---|---|---|
| Command / code injection | CWE-78 | a restricted tool's input reached a shell / eval (allowlist bypass, carrier binaries) |
| Path traversal / write-escape | CWE-22 | a read/write tool escaped its root (out-of-root canary returned) |
| SSRF | CWE-918 | a non-fetch tool reached a loopback/internal sink we own |
| SQL injection | CWE-89 | a parser error surfaced from concatenated input (FTS5 excluded) |
| Tool poisoning | CWE-74 | invisible Unicode (TAG/zero-width/bidi/ANSI) hidden in tool metadata |
| Token passthrough / confused deputy | CWE-287 | the client's bearer token forwarded downstream |
| Missing auth enforcement | CWE-287 | a credential-free session accepted despite auth being configured |
| SSTI · arg injection · rug pull · DNS rebinding | CWE-1336/88/494/346 | template eval · CLI-flag smuggling · tool redefinition · foreign Origin accepted |

Each class ships with a vuln+safe fixture that must fire on the vulnerable one and stay silent on the
safe one — the test suite proves the detector both catches and doesn't false-positive.

---

## Two ways to use it

**1. You run or ship an MCP server** → scan it before you (or your customers) trust it:
```bash
mcp-rt report  --target-stdio "npx -y your-mcp-server"    # VAPT + OWASP attestation
mcp-rt benchmark --target-stdio "npx -y your-mcp-server"  # letter grade vs OWASP MCP Top 10
mcp-rt sweep --cap 20          # discover + test many servers (long-tail + popular lanes)
```

**2. You red-team the agent itself** → the framework that broke the best-defended agents shipping.
Full matrix, transcripts, and run commands: [`docs/RESEARCH_REPORT.md`](docs/RESEARCH_REPORT.md) and
[`docs/README_RESEARCH_FRAMEWORK.md`](docs/README_RESEARCH_FRAMEWORK.md).

> Local, open-source servers only. Hosted scanning is **consent-gated** (`mcp-rt remote --authorized-by …`
> refuses without an authorization attestation). Synthetic markers only; nothing leaves the host.

---

## Proof: it breaks the strongest agent shipping

Beyond server scanning, mcp-rt's research harness connects *real* installed agents to a controlled
malicious server and watches a loopback canary for exfiltration — ground truth, byte-for-byte identical
to a real secret leaving.

**23 confirmed credential exfiltrations across 26 tested payloads — Claude Code 8 · Codex 14 · Gemini 1 —
every one invisible to MCP-Scan, ghostprobe, and Cisco's scanner.** The structural attacks reproduce on
*two independent vendors* (Claude Code + Codex), so it's a protocol gap, not one vendor's bug:

```
server_side_workflow   [ClaudeCode + Codex]  exfil logic lives in server code the agent never sees
egress_evasion         [ClaudeCode + Codex]  credential leaves as an allowlist-approved webhook — a firewall won't stop it
proxy_aggregator       [ClaudeCode + Codex]  a trusted aggregator launders a malicious downstream tool
roots_path_manipulation[ClaudeCode]          a 2025 MCP protocol feature turned into a silent server-side read
```

And a **protocol-level finding (MCP-00):** the MCP spec routes attacker-controlled resource content to
the model with no mandated client-side sanitization — no single vendor can close it alone (corroborated
by the NSA AI Security Center's 2026 MCP guidance). Full matrix and transcripts:
[`docs/RESEARCH_REPORT.md`](docs/RESEARCH_REPORT.md).

---

## Roadmap (in development — not yet shipping)

Clearly marked so nothing here is sold as present-tense:

- **CI/CD GitHub Action** — scan the MCP servers in a repo's `.mcp.json` on every pull request, results to
  the GitHub Security tab (SARIF), fail the build on critical/high.
- **Runtime proxy** — inline protection that taint-tracks planted markers and *blocks* exfiltration in
  real time (scanner → protection).
- **Exploit-chain correlation** — compose individually-confirmed low/medium findings into a *proven*
  high-severity chain, demonstrated end-to-end (never speculated).
- **Multi-agent cascade detection** — track a compromise propagating across agents.

---

## Responsible use

Synthetic honeytokens only · loopback canary (nothing leaves the host) · auto-cleanup after each test ·
test only servers/agents you own or are authorized to test · hosted scanning is consent-gated ·
**responsible disclosure before any public discussion** of a vulnerability found with it.

## Citation

```bibtex
@tool{mcp-rt-2026, title={mcp-rt: Ground-Truth Security Testing for MCP},
  author={Pandya, Ved}, year={2026}, url={https://github.com/MartOcd1709/mcp-rt}}
```

MIT — see [LICENSE](LICENSE). *Built in India* 🇮🇳
