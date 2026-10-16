"""Autonomous agent loop — a reasoning model drives an MCP security assessment with a tool it can
call step-by-step, PentAGI/CAI-style, but scoped and ground-truthed for mcp-rt.

What this is (and is not):
  * The model (e.g. CSI alias2-mini) reasons, proposes ONE action per step (a shell command inside
    the sandbox, or an MCP tool-call against the authorized target, or `conclude`), observes the
    result, and iterates — a ReAct loop. This gives depth a fixed probe matrix can't: the agent
    adapts to what it sees.
  * **Freedom lives inside a locked sandbox.** Commands run only via a SandboxExecutor; the real one
    (DockerExecutor) uses `docker run --rm` with no network, non-root, read-only host, resource
    limits, no host mounts — the container holds the authorized target + tooling and nothing else.
    The default executor is DryRun (plans only, executes nothing), so the loop is safe to build and
    test without running anything.
  * **Scope: authorized targets only** (local / consent-gated), for vulnerability assessment and
    responsible disclosure — not a general-purpose attack tool. Every command is audit-logged.
  * **Ground truth still decides.** Anything the agent *claims* is a finding is returned as
    `agent_claimed` and must be confirmed by the ground-truth oracle before it counts — the agent's
    say-so is never a verdict (keeps the zero-false-positive guarantee).
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field

_FINAL_NUDGE = ("FINAL STEP — wrap up. Reply with ONLY a conclude action listing every vulnerability "
                "you DEMONSTRATED with concrete evidence from an observation (empty list if none): "
                '{"thought":"...","action":"conclude","findings":[{"class":"...","tool":"...",'
                '"detail":"...","evidence":"..."}]}')


@dataclass
class AgentPolicy:
    """Governs how long the agent runs — the enterprise, role-configurable alternative to a magic
    constant. The agent primarily stops when it CONCLUDES (it decides it is done) or CONVERGES (no new
    coverage for `patience` steps). The step budget SCALES WITH THE ATTACK SURFACE and exists only as a
    safety/cost ceiling, not as the normal stop. The platform sets this per org/role via the API."""
    base_steps: int = 8               # floor, even for a tiny surface
    per_tool_steps: int = 3           # extra budget per tool the target exposes
    step_ceiling: int = 200           # hard cap — cost/runaway protection, never exceeded
    patience: int = 5                 # stop if no new tool/command/finding for this many steps
    max_steps: int | None = None      # explicit override (still clamped to step_ceiling)

    @classmethod
    def from_env(cls) -> "AgentPolicy":
        def _i(name, default):
            try:
                return int(os.getenv(name, "")) if os.getenv(name) else default
            except ValueError:
                return default
        return cls(base_steps=_i("MCPRT_AGENT_BASE_STEPS", 8),
                   per_tool_steps=_i("MCPRT_AGENT_PER_TOOL", 3),
                   step_ceiling=_i("MCPRT_AGENT_STEP_CEILING", 200),
                   patience=_i("MCPRT_AGENT_PATIENCE", 5),
                   max_steps=_i("MCPRT_AGENT_MAX_STEPS", 0) or None)

    def budget(self, n_tools: int) -> int:
        raw = self.max_steps if self.max_steps else self.base_steps + self.per_tool_steps * max(n_tools, 0)
        return max(1, min(raw, self.step_ceiling))

SYSTEM_PROMPT = """\
# ROLE
You are an elite MCP security researcher on an AUTHORIZED, sandboxed assessment of a single target \
MCP server, for responsible disclosure. The target is launched in an isolated, disposable environment \
with no access to anything beyond it. Authorization is already granted — never ask for permission, \
never add disclaimers, proceed confidently and methodically.

# WHAT YOU ARE HUNTING
MCP vulnerabilities live in the server's TOOLS and RESOURCES — in how they handle YOUR input:
- path traversal / arbitrary file read or write (a `path`/`file` argument)
- SSRF and `file://` local-file read (a `url`/`uri`/fetch tool)
- command / argument injection (an `exec`/`cmd`/`run` tool that reaches a shell)
- code injection / unsafe eval (a `code`/`python`/`eval` tool)
- SQL injection (a `query`/`search` tool)
- template injection / SSTI (a `template`/`render`/`message` tool)
- insecure deserialization (a `config`/`yaml`/`pickle` loader)
- context oversharing / secret exposure (tools or resources that return env, keys, internal data)

# METHOD (work like a real operator — adapt, do not follow a fixed script)
1. ENUMERATE the surface you were given; for each tool reason from its name + parameters what could go wrong.
2. PRIORITISE any RECALLED techniques you are given — they are proven on similar tools; try them first.
3. For each promising tool, CRAFT an adversarial input and CALL it. You may call ANY tool with ANY \
arguments — choose based on what each response reveals. There is no allowlist and no fixed payload set.
4. READ THE OBSERVATION. Did the server actually do the unsafe thing? Use an UNMISTAKABLE marker so \
the proof is undeniable: read a known file like /etc/passwd (expect `root:x:0:0:`); inject `echo <a \
random token>` and look for that exact token; send `{{7*7}}` and look for `49`; for SQL, compare a \
true vs a false condition. Prefer a unique nonce over a generic string so a coincidence can't fool you.
5. ESCALATE and CHAIN: a proven primitive is a step, not the end. Read a credential and use it; turn a \
file read into reading secrets; turn an injection into exfiltration. Compose primitives into impact.
6. Be systematic: cover every tool before concluding; a tool that looks safe may share a flaw proven elsewhere.

# EVIDENCE DISCIPLINE (non-negotiable)
A finding counts ONLY if an OBSERVATION demonstrates it. Never claim a vulnerability you have not made \
the server exhibit. If a probe is blocked, that tool is (for that class) secure — say so and move on. \
No speculation, no "likely vulnerable". Your claims are re-tested by a ground-truth oracle afterwards, \
so an unproven claim only wastes effort.

# ACTION PROTOCOL
Each turn, reply with ONE JSON object and nothing else:
  {"thought":"...","action":"mcp_call","method":"list_tools"}
  {"thought":"...","action":"mcp_call","method":"call_tool","name":"<tool>","arguments":{...}}
  {"thought":"...","action":"mcp_call","method":"read_resource","uri":"<uri>"}
  {"thought":"...","action":"shell","command":"..."}        # sandbox shell, for host-side checks
  {"thought":"...","action":"conclude","findings":[{"class":"<vuln class>","tool":"<tool>",\
"detail":"what & why","evidence":"the exact observation that proves it"}]}
Keep `thought` short and concrete. Conclude once you have exercised the surface and escalated what you proved."""


# --------------------------------------------------------------------------------------
# Sandbox executors
# --------------------------------------------------------------------------------------
class SandboxExecutor:
    name = "base"

    def run(self, command: str) -> str:
        raise NotImplementedError


class DryRunExecutor(SandboxExecutor):
    """Default: executes NOTHING. Returns a placeholder so the loop can be built/tested/planned
    safely. Use DockerExecutor for real (sandboxed) execution."""
    name = "dry-run"

    def run(self, command: str) -> str:
        return f"[dry-run] would execute in sandbox: {command!r} (no execution)"


class DockerExecutor(SandboxExecutor):
    """Real execution, hard-isolated. Each command runs in a throwaway container with NO network,
    non-root, read-only root fs (+ writable /tmp), dropped caps, and CPU/mem/pid limits. The image
    should contain the authorized target + tooling and nothing sensitive."""
    name = "docker"

    def __init__(self, image: str | None = None, timeout: int = 60):
        self.image = image or os.getenv("MCPRT_AGENT_IMAGE", "mcp-rt:latest")
        self.timeout = timeout

    def run(self, command: str) -> str:
        if not shutil.which("docker"):
            return "[error] docker not available — cannot execute safely"
        argv = ["docker", "run", "--rm", "--network", "none", "--user", "1000:1000",
                "--read-only", "--tmpfs", "/tmp", "--cap-drop", "ALL",
                "--pids-limit", "256", "--memory", "512m", "--cpus", "1",
                self.image, "bash", "-lc", command]
        try:
            p = subprocess.run(argv, capture_output=True, text=True, timeout=self.timeout)
            out = (p.stdout or "") + (("\n[stderr] " + p.stderr) if p.stderr else "")
            return out[:4000] or f"[exit {p.returncode}, no output]"
        except subprocess.TimeoutExpired:
            return f"[timeout after {self.timeout}s]"
        except Exception as exc:  # noqa: BLE001
            return f"[error] {type(exc).__name__}: {str(exc)[:200]}"


# --------------------------------------------------------------------------------------
# Chat model (ReAct driver) — mock (offline) now; CSI/OpenAI-compatible when configured.
# --------------------------------------------------------------------------------------
class ChatModel:
    name = "base"

    def chat(self, messages: list[dict]) -> str:
        raise NotImplementedError


class MockChatModel(ChatModel):
    """Offline, deterministic ReAct trace: list tools → probe the first one with a traversal arg →
    conclude. Exercises the mcp_call path so no-key runs and tests are meaningful. For tests only."""
    name = "mock"

    def __init__(self):
        self._step = 0
        self._first_tool = ""

    def chat(self, messages: list[dict]) -> str:
        self._step += 1
        last = messages[-1]["content"] if messages else ""
        if self._step == 1:
            return json.dumps({"thought": "enumerate the attack surface",
                               "action": "mcp_call", "method": "list_tools"})
        if self._step == 2:
            try:                                            # grab a tool name from the observation
                self._first_tool = (json.loads(last.split("Observation:\n", 1)[-1]) or [{}])[0].get("name", "")
            except Exception:  # noqa: BLE001
                self._first_tool = ""
            if self._first_tool:
                return json.dumps({"thought": "probe for path traversal", "action": "mcp_call",
                                   "method": "call_tool", "name": self._first_tool,
                                   "arguments": {"path": "../../../../etc/passwd"}})
        return json.dumps({"thought": "assessed the surface; nothing demonstrated",
                           "action": "conclude", "findings": []})


class OpenAIChatModel(ChatModel):
    """CSI / any OpenAI-compatible chat endpoint (reuses MCPRT_AI_BASE_URL/API_KEY/MODEL_NAME)."""
    name = "openai"

    def __init__(self):
        self.base_url = (os.getenv("MCPRT_AI_BASE_URL") or os.getenv("OPENAI_BASE_URL", "")).rstrip("/")
        self.api_key = os.getenv("MCPRT_AI_API_KEY") or os.getenv("OPENAI_API_KEY", "")
        self.model = os.getenv("MCPRT_AI_MODEL_NAME", "alias2-mini")

    def chat(self, messages: list[dict]) -> str:
        import httpx
        r = httpx.post(f"{self.base_url}/chat/completions",
                       headers={"Authorization": f"Bearer {self.api_key}"},
                       json={"model": self.model, "max_tokens": 4000, "messages": messages},
                       timeout=90)
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"] or ""


def get_chat_model() -> ChatModel:
    if os.getenv("MCPRT_AI_PROVIDER") == "openai" and \
            (os.getenv("MCPRT_AI_BASE_URL") or os.getenv("OPENAI_BASE_URL")) and \
            (os.getenv("MCPRT_AI_API_KEY") or os.getenv("OPENAI_API_KEY")):
        return OpenAIChatModel()
    return MockChatModel()


# --------------------------------------------------------------------------------------
# The loop
# --------------------------------------------------------------------------------------
@dataclass
class AgentResult:
    target: str
    steps: int = 0
    commands: list = field(default_factory=list)      # audit log of every command issued
    transcript: list = field(default_factory=list)    # [{role, content}]
    agent_claimed: list = field(default_factory=list)  # claimed findings — NOT confirmed until oracle checks
    note: str = ""

    plan: list = field(default_factory=list)          # the assessment plan the agent was handed (coverage)

    def as_dict(self) -> dict:
        return {"target": self.target, "steps": self.steps, "commands": self.commands,
                "agent_claimed": self.agent_claimed, "note": self.note, "plan": self.plan}


def _parse_action(text: str) -> dict:
    s, e = text.find("{"), text.rfind("}")
    try:
        return json.loads(text[s:e + 1]) if s >= 0 and e > s else {}
    except json.JSONDecodeError:
        return {}


def build_target_context(target: str, *, client=None) -> tuple[str, list]:
    """Give the agent the REAL attack surface up front: the target's actual tools + resources, plus
    techniques recalled from prior ground-truth-confirmed attacks on similar tools (self-learning).
    Returns (context_text, tools). Degrades to an honest note if the server can't be enumerated."""
    lines, tools = [], []
    try:
        from mcp_rt.mcp_client import MCPClient
        client = client or MCPClient(target)
        tools = client.list_tools()
        lines.append(f"TARGET SURFACE — {len(tools)} tool(s) you can call via mcp_call:")
        for t in tools[:40]:
            schema = t.get("input_schema") or {}
            props = ", ".join((schema.get("properties") or {}).keys()) if isinstance(schema, dict) else ""
            lines.append(f"  • {t['name']}({props}): {t.get('description', '')[:160]}")
        resources = client.list_resources()
        if resources:
            lines.append(f"RESOURCES ({len(resources)}):")
            for r in resources[:20]:
                lines.append(f"  • {r['uri']} {r.get('name', '')}")
    except Exception as exc:  # noqa: BLE001 — enumeration is best-effort; the agent can still shell
        lines.append(f"(surface enumeration unavailable: {type(exc).__name__}: {str(exc)[:120]})")
    try:
        from mcp_rt.knowledge import recall_hints
        hint = recall_hints([t["name"] for t in tools])
        if hint:
            lines.append("\nRECALLED — techniques proven on similar tools before (try these first):")
            lines.append(hint)
    except Exception:  # noqa: BLE001 — learning is optional
        pass
    return "\n".join(lines), tools


def _do_mcp_call(client, action: dict) -> str:
    """Dispatch one mcp_call action against the target; return the observation text."""
    method = action.get("method", "")
    try:
        if method == "list_tools":
            return json.dumps(client.list_tools())[:3000]
        if method == "list_resources":
            return json.dumps(client.list_resources())[:3000]
        if method == "call_tool":
            return client.call_tool(action.get("name", ""), action.get("arguments") or {})
        if method == "read_resource":
            return client.read_resource(action.get("uri", ""))
        return f"[unknown mcp method {method!r}]"
    except Exception as exc:  # noqa: BLE001 — a failing call is an observation, not a crash
        return f"[mcp_call error] {type(exc).__name__}: {str(exc)[:200]}"


def _emit(progress, msg: str) -> None:
    if progress:
        try:
            progress(msg)
        except Exception:  # noqa: BLE001 — progress is cosmetic, never fail the run over it
            pass


def run_agent(target: str, *, task: str | None = None, executor: SandboxExecutor | None = None,
              model: ChatModel | None = None, mcp_client=None, policy: AgentPolicy | None = None,
              max_steps: int | None = None, with_context: bool = True,
              use_plan: bool = False, progress=None) -> AgentResult:
    """Drive the ReAct assessment loop. The agent is in charge of when it is DONE: it runs until it
    CONCLUDES (decides the surface is assessed) or CONVERGES (no new coverage for policy.patience
    steps). The step budget scales with the target's surface and is only a safety/cost ceiling — not a
    magic constant. `policy` (or per-org/role policy from the platform API) governs all of that;
    `max_steps` is a convenience override. Safe by default (shell = DryRun). Claimed findings are
    returned UNCONFIRMED — the ground-truth oracle decides what counts (zero-false-positive)."""
    executor = executor or DryRunExecutor()
    model = model or get_chat_model()
    policy = policy or AgentPolicy.from_env()
    if max_steps is not None:
        from dataclasses import replace
        policy = replace(policy, max_steps=max_steps)
    if mcp_client is None:
        from mcp_rt.mcp_client import MCPClient
        mcp_client = MCPClient(target)

    _emit(progress, "connecting to target + enumerating its tools…")
    context, tools = build_target_context(target, client=mcp_client) if with_context else ("", [])
    res = AgentResult(target=target)

    # PLAN handoff: the planner derives an exhaustive test plan from the surface; the agent is told to
    # work EVERY point (guaranteed coverage) while still free to add its own. Budget covers the plan.
    plan_block, cover = "", len(tools)
    if use_plan and tools:
        from mcp_rt.planner import build_plan
        plan = build_plan(target, {"tools": tools}, model=model)
        res.plan = [p.as_dict() for p in plan.points]
        cover = max(cover, len(plan.points))
        _emit(progress, f"planned {len(plan.points)} test point(s) across {len(tools)} tool(s)")
        def _eg(pr):
            return next(iter(pr.values()), "") if isinstance(pr, dict) else pr
        pts = "\n".join(f"  {i}. {p.target}.{p.param or '(name)'} — test {p.vuln_class} "
                        f"e.g. {_eg(p.probe)}" for i, p in enumerate(plan.points, 1))
        plan_block = ("\n\nASSESSMENT PLAN — work EVERY point below with mcp_call, read each "
                      "observation, and record a finding for any that demonstrates the issue. Cover "
                      "them all before you conclude; add your own points if you spot more:\n" + pts)

    budget = policy.budget(cover)                  # scales with surface/plan size; ceiling-capped
    _emit(progress, f"surface: {len(tools)} tool(s); step budget {budget}")
    task = task or (f"Assess the MCP server launched by `{target}` for real, reproducible "
                    "vulnerabilities (authorized, sandboxed). Drive its tools with adversarial inputs, "
                    "read each observation, and conclude with evidence-backed findings only.")
    if context:
        task += "\n\n" + context
    task += plan_block

    messages = [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": task}]
    seen, stale = set(), 0                         # coverage set + steps since last new coverage

    for step in range(1, budget + 1):
        res.steps = step
        final = step == budget or stale >= policy.patience   # budget edge OR converged -> wrap up
        if final:
            messages.append({"role": "user", "content": _FINAL_NUDGE})
        _emit(progress, f"[{step}/{budget}] reasoning…")
        reply = model.chat(messages)
        res.transcript.append({"role": "assistant", "content": reply[:2000]})
        action = _parse_action(reply)
        kind = action.get("action")
        thought = (action.get("thought") or "")[:80]
        if kind == "conclude":
            res.agent_claimed = action.get("findings", []) or []
            res.note = (f"agent concluded after {step} step(s); {len(res.agent_claimed)} claimed "
                        "finding(s) — require ground-truth confirmation before counting")
            _emit(progress, f"[{step}/{budget}] concluded — {len(res.agent_claimed)} claim(s)")
            break
        if final:                                  # was told to wrap up but didn't — stop with a note
            res.note = (f"stopped after {step} step(s): "
                        + ("converged (no new coverage)" if stale >= policy.patience
                           else f"surface budget reached ({budget})"))
            break
        if kind == "mcp_call":
            key = f"mcp:{action.get('method')}:{action.get('name', action.get('uri', ''))}"
            res.commands.append(key)
            _emit(progress, f"[{step}/{budget}] call {action.get('name') or action.get('method')} — {thought}")
            observation = _do_mcp_call(mcp_client, action)
        elif kind == "shell":
            cmd = action.get("command", "")
            key = f"sh:{cmd}"
            res.commands.append(cmd)
            _emit(progress, f"[{step}/{budget}] shell {cmd[:40]} — {thought}")
            observation = executor.run(cmd) if cmd else "[no command]"
        else:
            messages.append({"role": "user", "content":
                             "Reply with ONE valid JSON action object (mcp_call, shell, or conclude)."})
            continue
        stale = 0 if key not in seen else stale + 1   # progress = a new, distinct action
        seen.add(key)
        messages.append({"role": "assistant", "content": reply[:2000]})
        messages.append({"role": "user", "content": f"Observation:\n{observation[:3000]}"})
    return res


def main(argv=None) -> int:
    import argparse
    import sys
    p = argparse.ArgumentParser(prog="mcp-rt agent",
                                description="Autonomous sandboxed MCP assessment agent (ReAct loop)")
    p.add_argument("--target-stdio", required=True, metavar="CMD",
                   help="authorized target MCP server to assess")
    p.add_argument("--docker", action="store_true",
                   help="execute in the hardened Docker sandbox (default: dry-run, executes nothing)")
    p.add_argument("--image", default=None, help="sandbox image (default mcp-rt:latest)")
    p.add_argument("--max-steps", type=int, default=None,
                   help="override the step budget (default: scales with the target's surface, "
                        "ceiling-capped; the agent normally stops by concluding or converging)")
    p.add_argument("--patience", type=int, default=None,
                   help="stop if no new coverage for this many steps (default from policy)")
    p.add_argument("--plan", action="store_true",
                   help="derive an exhaustive test plan from the surface and hand it to the agent to "
                        "work every point (planner -> vuln-agent handoff; guaranteed coverage)")
    p.add_argument("--confirm", action="store_true",
                   help="after the agent concludes, confirm its claims against a ground-truth scan "
                        "(a claim counts only if the engine independently proves it)")
    p.add_argument("--quiet", action="store_true", help="suppress live progress on stderr")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    ex = DockerExecutor(image=args.image) if args.docker else DryRunExecutor()
    # Live progress to STDERR so the run never looks frozen; stdout stays clean for --json.
    prog = None if args.quiet else (lambda m: print(f"  ▸ {m}", file=sys.stderr, flush=True))
    if args.docker:
        _emit(prog, "running in the hardened Docker sandbox (no network, non-root, read-only)")
    policy = AgentPolicy.from_env()
    if args.patience is not None:
        from dataclasses import replace
        policy = replace(policy, patience=args.patience)
    from mcp_rt.mcp_client import MCPClient
    client = MCPClient(args.target_stdio)             # one client for both the loop and confirmation
    res = run_agent(args.target_stdio, executor=ex, policy=policy, max_steps=args.max_steps,
                    use_plan=args.plan, progress=prog, mcp_client=client)

    confirmation = None
    if args.confirm and res.agent_claimed:
        _emit(prog, "confirming claims by RE-DEMONSTRATION (ground truth)…")
        from mcp_rt import oracle
        orc = oracle.confirm_claims(client, res.agent_claimed)   # re-prove each freely-chosen claim
        confirmation = orc.as_dict()
        _emit(prog, f"ground truth: {confirmation['note']}")
        try:                                                     # feed CONFIRMED wins back into the KG (self-learning)
            from mcp_rt.knowledge import get_store
            kg = get_store()
            for p in orc.confirmed:                              # only ground-truth-proven, never a raw claim
                kg.record(p.vuln_class, p.tool, outcome="confirmed", target=args.target_stdio)
            if hasattr(kg, "close"):
                kg.close()
        except Exception:  # noqa: BLE001 — learning is optional; never fail a run over it
            pass
    if args.json:
        d = res.as_dict()
        d["confirmation"] = confirmation
        d["transcript"] = res.transcript        # the model's step-by-step reasoning (thoughts+actions)
        print(json.dumps(d, indent=2))
    else:
        print(f"agent: {res.steps} step(s) · executor={ex.name} · commands issued={len(res.commands)}")
        print(f"note: {res.note}")
        if confirmation is not None:
            print(f"ground-truth confirmation: {confirmation['note']}")
            for f in confirmation["confirmed"]:
                print(f"  [PROVEN ✓ {f.get('vuln_class')}] {f.get('tool')}: {str(f.get('signal',''))[:70]}")
            for f in confirmation["unconfirmed"]:
                print(f"  [not proven {f.get('vuln_class')}] {f.get('tool')}: {str(f.get('signal',''))[:60]}")
        else:
            for f in res.agent_claimed:
                print(f"  [claimed · UNCONFIRMED — run --confirm] {f.get('class')}: {str(f.get('detail',''))[:80]}")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
