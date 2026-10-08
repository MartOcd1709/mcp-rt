# Black Hat MEA 2026 — Arsenal Call for Tools — Submission Package

Portal: **bhmea2026.awardsplatform.com** (login-gated awards platform — fields are entry/Q&A style, not the BH Sessionize form).
Deadline: **Sun 31 Aug 2026, 23:00 KSA** (submit EARLY today — do not cut to the wire). Notifications ~14 Sep.
Event: Black Hat MEA 2026, 1–3 Dec, Riyadh.

Numbers are locked to the confirmed corpus (**23 confirmed / 26 tested**; Gemini 1, Claude Code 8,
Codex 14) — consistent with README.md, FINDINGS.md, docs/ARSENAL_PROPOSAL.md.

The awards portal shows a set of questions rather than named BH fields, so blocks below are
**modular** — paste the one that matches each question (one-liner, short summary, full description,
links, bio, notes). Ved's call (revised 2026-08-30): the Black Hat **Europe 2026 Arsenal (Call for
Tools) acceptance IS cited — but ONLY as one line in the verified-speaker-evidence field**, phrased
"selected," never "presented" (MEA Dec 1-3 precedes Europe Dec 9-10). It stays OUT of the title,
overview, new-research, and reviewer-notes blocks so the pitch stands on its own — Europe reads as a
credential, not a crutch. No similar-content risk (Tahaluf and Informa are different organizers).

---

## BLOCK: Entry / Session Title

**Primary (recommended):**
> mcp-rt: Ground-Truth Red-Teaming of AI Coding Agents Against Malicious MCP Servers

Alternates (professional register):
- mcp-rt: A Honeytoken Framework for Measuring Credential Exfiltration in MCP Client Agents
- mcp-rt: Empirically Testing Credential Exfiltration in MCP-Enabled AI Coding Agents
- mcp-rt: Cross-Vendor Credential-Exfiltration Testing for AI Coding Agents on the Model Context Protocol

## BLOCK: Category / Track
Primary: **AI, ML & Data Science Security**
Secondary: **Exploitation & Ethical Hacking** *(or Red Teaming / Offensive — pick whichever the portal lists closest)*
Format: **Arsenal — Tool Demonstration (station)**

## BLOCK: Links
- Source Code URL: https://github.com/MartOcd1709/mcp-rt
- Tool URL: https://github.com/MartOcd1709/mcp-rt
- Display Name (schedule): Ved Pandya

---

## BLOCK: One-line summary (~30 words — for a "summary" / "elevator" field if present)

mcp-rt connects real AI coding agents (Claude Code, Codex, Gemini) to malicious MCP servers and uses honeytoken ground truth to prove, per attack, whether your credentials actually get stolen — 23 confirmed across 26 tested payloads.

---

## BLOCK: Short abstract (~230 words — use if the field enforces a hard limit)

MCP (the Model Context Protocol) connects AI coding agents — Claude Code, Codex, Gemini, Cursor, Cline — to thousands of external tool servers. Every server is a trust boundary. Existing scanners (MCP-Scan/Snyk, ghostprobe, Cisco) only ask whether a server's tool descriptions look malicious. mcp-rt asks the question that matters: when a real installed agent connects to a server, does a planted credential actually leave the machine?

mcp-rt produces ground-truth verdicts through honeytoken detection. It plants a synthetic secret, connects a real CLI agent to a malicious MCP server, and watches a loopback canary for exfiltration, giving a binary VULNERABLE or RESILIENT result per attack, per client. It confirms 23 credential exfiltrations across 26 tested payloads on three production agents (Gemini 1, Claude Code 8, Codex 14), and it is client-agnostic: any MCP-capable agent plugs in through one adapter.

Every Generation 1 and 2 confirmed finding returns zero results from all three static scanners on the same server, the same moment the canary fires. server_side_workflow hides the theft in server code the agent never sees; egress_evasion shows the credential can leave disguised as allowlist-approved traffic, so a firewall does not stop it either. Underlying it all is MCP-00, a specification-level gap no single vendor can close, corroborated by the NSA's 2026 MCP guidance.

---

## BLOCK: Full abstract / Tool Description (in-depth — use where the field allows depth)

MCP (the Model Context Protocol), introduced by Anthropic in November 2024, has become the de facto standard for connecting AI coding agents to external capabilities: file readers, web fetchers, code runners, database clients, and internal enterprise services. In under eighteen months more than five thousand MCP servers have been published, and production usage is already at enterprise scale; Atlassian reported its Rovo MCP server processing over five million agent tool calls per working day for more than one million monthly users in 2026, with nearly a third of those calls writing or modifying data rather than only reading it. Every connected server is a trust boundary, and the security question that had not been answered empirically is direct: when a real agent is connected to a compromised or malicious server, will it exfiltrate the user's credentials?

Existing tooling cannot answer this question. Scanners such as MCP-Scan (Invariant Labs, acquired by Snyk), Cisco's mcp-scanner, and ghostprobe inspect a server's tool descriptions and metadata for known-malicious patterns, on the assumption that malicious behavior must be visible in the description. mcp-rt takes the opposite, behavioral approach. It plants a synthetic credential, a honeytoken carrying a unique marker, connects a real installed CLI agent to a malicious MCP server, and observes a cross-process loopback HTTP canary. If the marker reaches the canary, the credential was exfiltrated. The outcome is a binary, ground-truth VULNERABLE or RESILIENT verdict for each attack against each client, not a heuristic score. Everything is synthetic and loopback-only: no real secret and no real network destination is ever involved, and every artifact is cleaned up after each run.

Across three generations of attacks plus a corpus targeting the 2025 protocol feature set, mcp-rt confirms 23 credential exfiltrations across 26 tested payloads on three production agents: Google Gemini CLI (1), Anthropic Claude Code (8), and OpenAI Codex CLI (14). The framework is client-agnostic. Every agent is driven through a single adapter interface, so any MCP-capable coding agent, including Cursor, Zed, Windsurf, Cline, or an organization's own internal agent, can be evaluated by adding a small adapter rather than rewriting the framework. Because those agents are built on different underlying models, testing across agents is inherently testing across LLM vendors, and the methodology is not tied to any single model or company.

The findings are structural rather than incidental. The server_side_workflow attack places the exfiltration logic entirely inside server-side code the agent never inspects; MCP-Scan returns zero findings on the same server at the same moment the canary records the theft. The proxy_aggregator and tool_annotation attacks reproduce on both Claude Code and Codex, evidence of a gap in how the protocol delegates trust rather than a single vendor's implementation error. The egress_evasion attack demonstrates that the stolen credential can leave shaped as allowlist-approved webhook traffic, and, over a second channel, encoded in DNS query labels — confirmed on both Claude Code and Codex — so neither a destination-allowlist egress firewall nor a policy that permits only DNS stops it. Three controls a defender is most likely to reach for against this class — static server scanning, destination egress filtering, and a DNS-only egress policy — all fail against the same server.

mcp-rt also addresses the common objection that a victim must knowingly install something malicious. A project-level .mcp.json file auto-registers its servers the moment a repository is cloned, with no install step; an already-trusted server can be turned against the user; and malicious MCP servers are documented in the wild, including postmark-mcp, the OX Security typosquat study in which nine of eleven MCP directories accepted an unreviewed clone, and the Agentjacking campaign that compromised 2,388 organizations through a trusted server. The victim performs an ordinary action and the malicious server arrives as a side effect.

Underlying every client behavior is MCP-00, a specification-level finding: the specification routes attacker-controlled resource content to the model with no mandated client-side sanitization, so no single vendor can close the gap unilaterally. This is independently corroborated by the NSA AI Security Center's 2026 MCP Cybersecurity Information Sheet, which states that the protocol does not define how a session maps to a verifiable identity and that authentication is optional rather than required. mcp-rt additionally ships a runtime taint monitor that flags the precise server-side class every static scanner misses, providing the detection primitive the ecosystem currently lacks. The framework is open source, MIT-licensed, tested in continuous integration, and every result shown is reproducible from a clean checkout with a single command.

---

## BLOCK: Detailed Tool Description / Tool Details

**The problem.** MCP lets AI coding agents call external tools through a standardized server protocol; over 5,000 servers have been published in 18 months, and enterprises are already taking write-capable, consequential actions through them at scale (Atlassian reported its Rovo MCP server processing 5M+ agent tool calls per working day for 1M+ monthly users in 2026). The security question that had not been answered empirically is simple: connected to a compromised server, will a real agent hand over the user's credentials? Existing tooling cannot answer it — every scanner inspects tool *descriptions* for known-bad patterns and assumes malicious behavior must be visible in metadata.

**What mcp-rt does.** It plants a synthetic credential (a honeytoken with a unique marker), launches a real installed CLI agent against a malicious MCP server, and observes a cross-process loopback HTTP canary. If the marker reaches the canary, the credential was exfiltrated — a binary, ground-truth VULNERABLE/RESILIENT verdict, not a heuristic. Everything is synthetic and loopback-only; nothing leaves the host.

**Results.** 23 confirmed credential exfiltrations across 26 tested payloads on three production agents — Gemini CLI 1, Claude Code 8, Codex CLI 14 — organized across three attack generations plus a 2025 protocol-feature corpus and mapped to MITRE-style IDs (MCP-38). Headline findings:
- **server_side_workflow** — the exfiltration logic is ordinary server-side code the agent never inspects. MCP-Scan reports 0 findings on the same server, the same second the canary fires. Confirmed on Claude Code and Codex.
- **Cross-vendor architecture attacks** — proxy_aggregator_trust_laundering and tool_annotation_self_attestation both reproduce on Claude Code *and* Codex (gpt-5.4), evidence of a structural trust gap, not a single-vendor implementation flaw.
- **roots_path_manipulation** — the first confirmed exfiltration against a 2025-era protocol feature (roots), server-side and instruction-free.
- **egress_evasion** — the stolen credential leaves over two channel shapes: disguised as allowlist-approved webhook traffic, and encoded in DNS query labels — both confirmed on Claude Code and Codex. Three controls a defender is most likely to propose against this corpus — static server scanning, destination-based egress filtering, and a DNS-only egress policy — all fail against the same server.
- **MCP-00** — a specification-level finding: the spec routes attacker-controlled resource content to the model with no mandated client-side sanitization, so no single vendor can close it. Independently corroborated by the NSA AI Security Center's 2026 MCP Cybersecurity Information Sheet.

**Delivery is real, not hypothetical.** The corpus also removes the "the user installed something malicious" objection: a project `.mcp.json` auto-loads a server on `git clone`; an already-trusted server can be turned against the user; and malicious MCP servers are documented in the wild (postmark-mcp stole users' emails; OX Security found 9 of 11 MCP directories accepted a typosquatted clone with no review; the Agentjacking campaign compromised 2,388 organizations through a trusted MCP server).

**Defensive counterpart.** mcp-rt ships a runtime taint monitor (file-read source → undeclared-egress sink) that flags exactly the server-side class every static scanner misses — demonstrating the detection defenders actually need.

**Client-agnostic — bring your own agent.** mcp-rt is not tied to Claude Code and Codex. Every agent is driven through a single `ClientAdapter` interface; three are fully tested here (Claude Code, Codex CLI, Gemini CLI) and a fourth (Cline) is adapter-built. Testing another agent — Cursor, Zed, Windsurf, an enterprise's internal coding agent, or a new vendor CLI — is a new adapter against the same interface, not a rewrite. Because those agents are built on different underlying models, testing across agents is inherently testing across LLM vendors, so the ground-truth methodology applies to any MCP-capable agent a defender actually runs, not a fixed list.

**Engineering.** Production-quality headless adapters for Claude Code, Codex CLI, Gemini CLI, and Cline, all behind one `ClientAdapter` interface; a drop-in payload registry (Metasploit-style modules); honeytoken observer; HTML/JSON reporting; CI (pytest on 3.11/3.12); MIT-licensed. Over three pages of documentation live in the repository (README, FINDINGS, RESEARCH_REPORT, SPEC_GAP_AUDIT, and per-attack docs).

**The live demo (≈4 minutes, terminal only).** Point a fully-updated Claude Code at a malicious server, give it a routine task, watch it report success — then show the stolen credential in the attacker's inbox and MCP-Scan reporting 0 findings on the same server. Repeat on Codex to prove it is cross-vendor. Every result on stage is reproducible with one command.

**Anticipated questions, answered.** *Why would anyone connect a malicious server?* Often with no bad decision at all: a project `.mcp.json` auto-registers on `git clone`, an already-trusted server can be turned against the user, and malicious MCP servers are documented in the wild (postmark-mcp, the OX Security typosquat study, Agentjacking's 2,388 organizations). *Doesn't a firewall stop the exfiltration?* No — the `egress_evasion` attack sends the credential shaped as allowlist-approved webhook traffic, confirmed on Claude Code and Codex, so static scanning and egress filtering both fail on the same server. *Isn't this a single-vendor bug?* No — the structural attacks reproduce across vendors and the framework tests any MCP-capable agent; the root cause is the specification-level MCP-00 gap.

**Run it:**
```
git clone https://github.com/MartOcd1709/mcp-rt && cd mcp-rt
python -m venv .venv && .venv/bin/pip install -e .
.venv/bin/python attacks/run_egress_evasion.py --client claude-code --variant webhook --reset
```

---

## BLOCK: 🆕 What's new (the MEA differentiator — READY TO PASTE)

> Two current-edge items. (A) is live-confirmed cross-vendor (markers below); (B) is shipped
> and CI-tested. Both are absent from the Black Hat Europe package — this is the fresh angle.

**(A) NEW FINDING — credential exfiltration over DNS (three defensive layers, all bypassed).**
The `egress_evasion` attack now demonstrates a second exfiltration channel: the stolen
credential leaves encoded in DNS query labels (port 53). This extends the firewall result
into a clean escalation — against the same server, **three controls a defender would reach
for all fail**: (1) static server scanning (MCP-Scan / Cisco / ghostprobe → 0 findings),
(2) a destination-allowlist egress firewall (webhook channel, allowlist-approved shape),
and (3) a strict egress policy that only permits DNS/53 (the DNS channel). Everything is
loopback-only — a local UDP catcher stands in for the attacker's authoritative resolver;
no real resolver or public domain is contacted.
**Confirmed cross-vendor:** VULNERABLE on Claude Code (marker HT-c42cf35ceb33) and OpenAI
Codex (marker HT-b77f7d6010ad); in both, the honeytoken was reassembled from the DNS labels
at the loopback catcher (exfil→canary). The Claude Code agent completed the routine task and
raised no suspicion about the exfiltration — silent over DNS.
> Reproduce: `.venv/bin/python attacks/run_egress_evasion.py --client claude-code --variant dns --reset`

**(B) NEW CAPABILITY — scan your OWN MCP server + CI gate (`mcp-rt scan`).**
Beyond the built-in attack corpus, mcp-rt now points at any third-party MCP server. It
plants a honeytoken battery, runs a real agent through routine tasks against your server,
and returns a ground-truth verdict — **LEAKED**, **CLEAN**, or **UNOBSERVABLE_BY_DESIGN**
(honest for remote/HTTP servers it cannot instrument) — with a `--exit-code` CI gate that
fails a build the moment a planted credential physically leaves the host. This turns mcp-rt
from a research corpus into something a team runs against its own stack before shipping.
```
python -m mcp_rt.scan --target-stdio "npx your-mcp-server" --exit-code
```
> Booth demo beat: run it live against a benign server (→ CLEAN, exit 0) and against a
> leaking one (→ LEAKED, exit 1) — a defender's yes/no in one command.

---

## BLOCK: Notes for Reviewers (honesty + novelty — preempts skepticism)

- Claims are stated precisely. mcp-rt is the first tool to *confirm these attacks empirically against real installed CLI agents with honeytoken ground truth*; where a general attack surface was already named in prior work (e.g. server-initiated sampling in arXiv:2601.17549), the claim is narrowed to "first reproducible cross-client harness," not "first to identify." No first-identification claim is made for the general delivery vectors (typosquatting, supply-chain), which are cited as documented prior art.
- Vendor status is reported honestly: earlier findings were disclosed to Anthropic and OpenAI and triaged/responded to, not "awarded." Those responses motivated the Generation 2+ attacks that need no malicious-server *installation* and the protocol-level MCP-00 framing no single vendor can close.
- The count is disciplined: 23 confirmed / 26 tested payloads. Scientific controls that held RESILIENT (three frontier-corpus payloads) and a tested-negative saturation sweep are deliberately excluded from the count. A network-position delivery module and a DNS-channel egress variant are built but not yet confirmed and are excluded.
- Verdicts are non-deterministic run to run; the discipline is a fresh `--reset` reproduction per cited result, and confirmed findings have ≥2 reproductions. If a live demo flips to RESILIENT on stage, that is disclosed and re-run — honesty about non-determinism is part of the method.
- Everything is synthetic and loopback-only (see SECURITY.md and the README "Responsible Use" section); no third-party service, real credential, or real network destination is touched.

---

## BLOCK: Speaker Bio (first person)

> Ved Pandya is an independent security researcher focused on AI system and application security. He is the author of mcp-rt, an offensive-security framework that red-teams real AI coding agents against malicious MCP servers with honeytoken ground truth. His prior work spans firmware and web application security, including a router vulnerability submitted to the Zero Day Initiative and authorized security assessments of multiple fintech and enterprise web platforms. He holds Anthropic's MCP, Claude API, AI Fluency, and Agent Skills certifications and an Offensive Agent AI (Red Team Leaders) certification, and ranks in the top 9% on TryHackMe. He also builds AI-driven autonomous penetration-testing systems.

**Speaker contact for the portal:** Ved Pandya · pandyaved96@gmail.com · +91 8238668898 · Gujarat, India · Website: https://github.com/MartOcd1709/mcp-rt

---

## PORTAL FIELDS (bhmea2026 awards platform — length-bounded, paste-ready, word-counts verified)

**Job Title:** Security Researcher (Independent)  ·  **Company:** Independent
**Nationality:** Indian  ·  **2nd nationality:** No  ·  **Country of Residence:** India
**City of Residence:** Vadodara
**Gender:** Male
**Spoken at previous BHMEA editions?:** No
**Session Attendee Skill Level:** Intermediate
**Delivered this session elsewhere?:** No   ·   **Additional speaker?:** No   ·   **In-person Riyadh:** I Agree

### Short Biography (≤100 words — this is 94)
> I am an independent offensive-security researcher specializing in the security of AI systems — where autonomous agents meet real-world attack surface. I design, test, and break AI coding agents, LLM-driven tools, and the protocols connecting them, and I build AI-driven autonomous penetration-testing systems. My background spans firmware, web, and application security, including a router zero-day reported to the Zero Day Initiative and authorized assessments of fintech and enterprise platforms. I hold Anthropic's MCP, Claude API, AI Fluency, and Agent Skills certifications and an Offensive Agent AI (Red Team Leaders) certification, and rank in the top 9% on TryHackMe.

TryHackMe percentile confirmed by Ved: top 9%.

### Session Overview (≤250 words — use the ~230w Short abstract block above, verbatim)

### Session Outcomes / key takeaways (≤100 words — this is 86)
> Attendees will leave able to: (1) explain why description-based MCP scanners miss the attacks that matter, and why behavioral honeytoken testing gives a ground-truth verdict instead; (2) name the structural, cross-vendor failure classes — server-side workflow, trust-laundering aggregators, self-attesting annotations, and egress evasion over webhook and DNS — that reproduce across Claude Code and Codex; (3) understand MCP-00, the specification-level gap no single vendor can close; and (4) run mcp-rt against their own MCP servers with a CI exit-code gate that fails a build the moment a planted credential leaves the host.

### New research / concept / technique (≤200 words — this is 168)
> The core contribution is behavioral honeytoken ground truth for MCP: rather than judging whether a server's descriptions look malicious, mcp-rt plants a uniquely-marked synthetic credential, connects a real installed agent, and confirms via a loopback canary whether that specific secret physically leaves the host — a binary VULNERABLE/RESILIENT verdict per attack, per client. This yields the first reproducible cross-client harness for these attacks against production agents.
>
> New this cycle: credential exfiltration over a DNS channel (secret encoded in query labels), confirmed cross-vendor on Claude Code and Codex. Combined with the webhook channel, this escalates the firewall result into a clean proof that three controls a defender would reach for — static scanning, destination-allowlist egress filtering, and a DNS-only egress policy — all fail against the same server.
>
> Also new: a scan-your-own-server capability with a CI exit-code gate, turning the research corpus into a tool teams run against their own MCP stack. Underlying everything is MCP-00, a specification-level gap corroborated by the NSA's 2026 MCP guidance, that no single vendor can close.

### Equipment / needs
> Self-contained. I bring my own laptop with the full toolkit pre-installed and can run the entire demo offline (everything is loopback-only). On site I need an Arsenal station/table, power, and a monitor or screen for the audience. Venue internet is helpful but not required.

### Verified-speaker evidence  ← the ONE place the Europe acceptance is cited
> Selected for **Black Hat Europe 2026 Arsenal (Call for Tools)** — mcp-rt. Open-source tool + full docs: https://github.com/MartOcd1709/mcp-rt (MIT-licensed, CI-tested, 3+ pages of documentation including FINDINGS, RESEARCH_REPORT, and per-attack writeups). Certifications: Anthropic MCP, Claude API, AI Fluency, Agent Skills; Offensive Agent AI (Red Team Leaders). Router vulnerability submitted to the Zero Day Initiative. A recorded demo walkthrough and technical brief can be provided before the event.

### Additional comments to review panel (≤100 words — this is 98; = the Notes-for-Reviewers block, trimmed)
> Claims are stated precisely: mcp-rt is the first tool to confirm these attacks empirically against real installed CLI agents with honeytoken ground truth; where a surface was named in prior work, the claim is narrowed to "first reproducible cross-client harness." Vendor status is honest — earlier findings were disclosed to Anthropic and OpenAI and triaged, not awarded. The count is disciplined (23 confirmed / 26 tested); controls that held RESILIENT and unconfirmed modules are excluded. Verdicts are non-deterministic, so each cited result is a fresh reproduction. Everything is synthetic and loopback-only — no real credential or destination is ever touched.

---

## ATTACHMENTS (MEA awards portal — JPEG/PDF only, ≤5MB each, max 5 pieces; + video/website URLs)
**HARD RULE: no further WRITTEN material** — judges will not consider it; the written case must live in the form fields (it does). So do NOT upload the .txt brief, RESEARCH_REPORT, FINDINGS, or any proposal/report doc.
Portal-compliant set, priority order:
1. **Website URL** — https://github.com/MartOcd1709/mcp-rt (public, no login; verify `private:false` before submit). Must-have.
2. **Video URL (YouTube/Vimeo)** — ~4-min demo from docs/VIDEO_DEMO_SCRIPT.md. Highest-value for a tool submission; record + upload unlisted. VED-DO.
3. **JPEG/PDF visual proof — 3 pieces BUILT + ready in ~/Downloads (attach these):**
   - `mcp-rt_10second_proof.pdf` — HERO. Split view: agent reports success (green) vs attacker receives honeytoken HT-c42cf35ceb33 (red); "same server, same second, 0 findings; VULNERABLE cross-vendor CC+Codex". Authored, real markers, zero leaks.
   - `mcp-rt_architecture_results.pdf` — 5-step pipeline + 23/26 results (Codex 14/CC 8/Gemini 1) + "three defenses all fail" + MCP-00 root cause.
   - `mcp-rt_live_matrix_MCP32.pdf` — REAL tool output rendered from an actual run (tool_annotation MCP-32 resilience matrix; Gemini RESILIENT / CC mixed / Codex VULNERABLE). Authentic, leak-checked clean.
   - ⚠️ DO NOT attach report_cli.html / report_gen2.html / report_flagship.html — their transcripts leak KAVACH file paths ([[feedback-public-profile-disclosure]]). They are gitignored/local-only (not public), but must never be shared.

---

## PRE-SUBMIT CHECKLIST
- [ ] Repo public + clone-and-run block works from a clean checkout (CI green). Check: `curl -s https://api.github.com/repos/MartOcd1709/mcp-rt | grep private` → false.
- [ ] README front page shows 23/26 + the 10-second proof.
- [x] TryHackMe percentile = top 9% (confirmed 2026-08-30). City Vadodara, Gender Male filled.
- [ ] Pick the Session Title (primary recommended).
- [ ] Map the portal's actual category names to Primary/Secondary.
- [ ] Recorded demo video: not required at submit; organizers usually request one before the event — docs/VIDEO_DEMO_SCRIPT.md is ready.
- [ ] Save as draft, re-read once, submit EARLY (not 23:00 KSA).
- [x] Europe acceptance cited as ONE line in verified-speaker-evidence ONLY ("selected," not "presented"); absent from title/overview/new-research/notes.
