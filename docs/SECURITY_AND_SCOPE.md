# mcp-rt — Scope & Self-Security (doubles as repo SECURITY.md)

## A. Scope — what mcp-rt does and doesn't cover
- **Primary target:** systems using **MCP** (Claude Desktop, Cursor, Cline, Goose, VS Code Copilot, MCP servers). Growing standard, under-served.
- **No LLM agent at all → out of scope** (normal pentest territory). Honest boundary.
- **Protocol-agnostic by design:** the vulnerability is *agents trusting tool metadata/return values*, not MCP itself. Engine separates:
  - `payloads/` + `observer/`  → **universal** (work for any tool-using agent)
  - `delivery/`                → pluggable: **MCP adapter (v1)**, later **non-MCP** (OpenAI function-calling, LangChain/LlamaIndex, custom agents)
- **Arsenal positioning:** lead with MCP (focused/novel); non-MCP delivery = roadmap, so "they don't use MCP" is not a dead end.

## B. Self-security — the tool must never become the vulnerability
Hard requirements (also the repo's responsible-use guarantees):

| Risk | Guarantee / control |
|---|---|
| Real data leak | **Honeytokens only** — synthetic secrets; never read/transmit real user files or creds |
| Internet exfil | **Loopback-only by default** (127.0.0.1 canary); **egress mode opt-in + explicit consent** |
| Host harm | Payloads are **inert instruction text**, not executed; "compromise" = a canary touch, never real RCE on the operator host |
| Lab escape | Bundled vulnerable server/client **sandboxed**, cannot reach the internet |
| Weaponization vs third parties | **No auto-attack/auto-discovery**; explicit target config required; loud authorized-use banner |
| Residue | Canary in **temp dir, auto-cleaned** after each run |
| Codebase | **No hardcoded secrets** (env/secret store); input validation; **no eval of untrusted data**; **pinned deps + SBOM + signed releases**; no rug-pull of our own users |
| Privacy | **Offline-first, no telemetry** |
| Supply chain | Reproducible build; integrity-verify our own tool manifest (we eat our own dogfood) |

## C. Ethics / authorized use
- Tool is for testing **your own** clients / authorized engagements only.
- README ships a clear **authorized-use-only** statement + responsible-disclosure guidance for any client vuln found.
- "A secure, sandboxed, ethical offensive tool" is an explicit Arsenal credibility point.

## D. Verification owner
- The **Verifier/QA seat (`poc-validator`)** runs a self-security checklist each phase: no real exfil, loopback default holds, cleanup works, no secrets in repo, deps pinned. Sign-off required before P3 (public repo) and P4 (submit).
