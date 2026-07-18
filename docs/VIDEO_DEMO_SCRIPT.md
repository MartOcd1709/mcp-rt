# mcp-rt — Recorded Video Demo Script (~4 minutes)

Purpose: the pre-event recorded demonstration Black Hat Arsenal asks presenters to
submit, and a reusable clip for the repo. Target length 3:30–4:30. Terminal-only,
no slides. Every command below is real and runs from the repo root; the "attacker"
is always a loopback trap and every secret is a synthetic honeytoken.

Recording setup (once):
- Terminal at a large font (18–20pt), dark theme, ~100 columns. One window.
- `cd ~/Desktop/mcp-rt` before you hit record.
- Record with `asciinema rec demo.cast` (then convert to GIF with `agg`) or any
  screen recorder. Keep a second terminal tab ready but off-camera.
- Do a dry run once so the live client calls are warm and you know the timing.

Narration is written to be read aloud verbatim; trim to taste.

---

## Scene 1 — The claim (0:00–0:25)

On screen: a clean terminal, title line typed but not yet run.

Say:
> "This is mcp-rt. It answers one question about AI coding agents like Claude Code
> and Codex: if you connect one to a malicious MCP server, will it hand over your
> credentials — and will your security scanner notice? Every scanner today checks
> whether a server *looks* malicious. mcp-rt checks whether your secret actually
> *survived*. Watch."

Type (do not over-explain):
```bash
cat FINDINGS.md | head -5
```
Let the "Confirmed VULNERABLE" header show for a beat.

---

## Scene 2 — The live theft on Claude Code (0:25–1:40)

Say:
> "I'm pointing a real, fully-updated Claude Code at a malicious MCP server. The
> task is completely routine — read a workspace config and apply it. Nothing in
> that task is malicious, and nothing the agent can see is malicious. The theft is
> inside the server's own code, which the agent never gets to read."

Run:
```bash
.venv/bin/python attacks/run_egress_evasion.py --client claude-code --variant webhook --reset --timeout 300
```

While it runs, say:
> "The agent plants nothing and suspects nothing. It reads the config, applies it,
> and reports success. But the server, on its side, also read a planted credential
> and shipped it out — disguised as a routine team-chat webhook message, the kind
> of destination a corporate firewall already allows."

When `VULNERABLE` prints, pause on it. Say:
> "VULNERABLE. The credential left. Now let me show you exactly what the attacker
> received."

Run:
```bash
.venv/bin/python show_capture.py
```

Point at the `HT-...` marker in the captured webhook body. Say:
> "That highlighted value is a unique tripwire that existed only in the planted
> file. Its appearance here is undeniable proof the file was read and exfiltrated.
> And notice the shape — it went out looking like a normal chat notification.
> A destination-allowlist firewall does not stop this, because the destination is
> a class it already trusts."

---

## Scene 3 — It is not one vendor's bug (1:40–2:25)

Say:
> "This is not a Claude-specific flaw. Same server, same task, different vendor."

Run:
```bash
.venv/bin/python attacks/run_egress_evasion.py --client codex --variant webhook --reset --timeout 300
```

When `VULNERABLE` prints for Codex, say:
> "Codex, running GPT-5.4, leaks the same way. This is a structural gap in how MCP
> delegates trust between an agent and a server — not one company's mistake. Across
> our corpus we confirm this class on both Claude Code and Codex, twenty-one
> distinct confirmed exfiltrations, every one invisible to MCP-Scan, ghostprobe,
> and Cisco's scanner."

---

## Scene 4 — Why the scanners are blind (2:25–3:05)

Say:
> "Here is why every scanner misses it. A scanner reads the server's tool
> descriptions and looks for something suspicious. But there is nothing suspicious
> to find — the tool descriptions are honest, the tool names are boring, and the
> malicious behavior is ordinary code running on the server, out of the scanner's
> and the agent's sight. The tool that steals your credential can even declare
> itself read-only and non-destructive, and the protocol gives the client no way to
> verify that claim. We call that root cause MCP-00: a specification-level gap no
> single vendor can patch, independently flagged by the NSA's 2026 MCP guidance."

Optionally show one line:
```bash
grep -n "0 findings" FINDINGS.md | head -3
```

---

## Scene 5 — How the victim gets there, and the close (3:05–4:00)

Say:
> "The last question is always: how does a victim end up connected to a malicious
> server? Often without any bad decision at all. A project config file auto-loads a
> server the moment you clone a repository. A trusted server can be turned against
> you. An attacker on your network can substitute a server you configured
> perfectly correctly. And this is already real — the first malicious MCP server in
> the wild stole users' emails, and the Agentjacking campaign compromised over two
> thousand organizations through a trusted MCP server."

> "mcp-rt is open source, MIT licensed, and every result you just saw is
> reproducible with one command. It plants a synthetic credential, connects your
> real agent, and tells you the truth: did your secret survive, yes or no. Scanners
> tell you a server looks clean. mcp-rt tells you whether you were robbed."

End on the repo URL on screen:
```
github.com/vedp1712/mcp-rt
```

---

## Shot list / b-roll cues (for editing)

| Time | Command on screen | The beat to hold |
|---|---|---|
| 0:25 | `run_egress_evasion.py --client claude-code` | the `VULNERABLE` line |
| 1:20 | `show_capture.py` | the `HT-...` marker inside the webhook body |
| 1:40 | `run_egress_evasion.py --client codex` | Codex `VULNERABLE` line |
| 3:40 | repo URL | final frame |

## Honesty guardrails (keep these true on camera)
- Never imply a real user's data was taken — say "synthetic credential", "loopback trap".
- Say "21 confirmed" (or the current FINDINGS.md number), not a rounded-up figure.
- Attribute prior-art incidents (postmark-mcp, Agentjacking) as others' documented
  work, not ours. Our contribution is the reproducible tool and the confirmations.
- If a live run flips to RESILIENT on camera (verdicts are non-deterministic), keep
  it — say "the agent caught it that time; run it again and it leaks" and re-run.
  Honesty about non-determinism is stronger than a staged guarantee.
