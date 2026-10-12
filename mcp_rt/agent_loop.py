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

MAX_STEPS = int(os.getenv("MCPRT_AGENT_MAX_STEPS", "12"))

SYSTEM_PROMPT = (
    "You are an authorized MCP security assessor working INSIDE an isolated, disposable sandbox "
    "(no access to any real system or network beyond the target under test). Your job: assess the "
    "target MCP server for REAL, reproducible vulnerabilities, for responsible disclosure. "
    "Work step by step. Each turn, reply with ONE JSON object and nothing else:\n"
    '  {"thought":"...","action":"shell","command":"..."}  to run a command in the sandbox, or\n'
    '  {"thought":"...","action":"conclude","findings":[{"class":"...","detail":"...","evidence":"..."}]}\n'
    "Prefer minimal, targeted commands. A finding only counts if backed by concrete evidence; do not "
    "claim a vulnerability you have not demonstrated. Conclude as soon as you have assessed the surface."
)


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
    """Offline, deterministic: inspects the surface once then concludes. For tests / no-key runs."""
    name = "mock"

    def __init__(self):
        self._step = 0

    def chat(self, messages: list[dict]) -> str:
        self._step += 1
        if self._step == 1:
            return json.dumps({"thought": "enumerate the target's tools",
                               "action": "shell", "command": "mcp-rt report --help"})
        return json.dumps({"thought": "assessed; no demonstrated vulnerability",
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

    def as_dict(self) -> dict:
        return {"target": self.target, "steps": self.steps, "commands": self.commands,
                "agent_claimed": self.agent_claimed, "note": self.note}


def _parse_action(text: str) -> dict:
    s, e = text.find("{"), text.rfind("}")
    try:
        return json.loads(text[s:e + 1]) if s >= 0 and e > s else {}
    except json.JSONDecodeError:
        return {}


def run_agent(target: str, *, task: str | None = None, executor: SandboxExecutor | None = None,
              model: ChatModel | None = None, max_steps: int = MAX_STEPS) -> AgentResult:
    """Drive the ReAct assessment loop. Safe by default: executor defaults to DryRun (no execution).
    Pass DockerExecutor for real sandboxed runs. Claimed findings are returned unconfirmed."""
    executor = executor or DryRunExecutor()
    model = model or get_chat_model()
    task = task or (f"Assess the MCP server launched by `{target}` for real vulnerabilities "
                    "(authorized, sandboxed). Enumerate its tools, probe for issues, conclude with "
                    "evidence-backed findings only.")
    res = AgentResult(target=target)
    messages = [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": task}]

    for step in range(1, max_steps + 1):
        res.steps = step
        reply = model.chat(messages)
        res.transcript.append({"role": "assistant", "content": reply[:2000]})
        action = _parse_action(reply)
        kind = action.get("action")
        if kind == "conclude":
            res.agent_claimed = action.get("findings", []) or []
            res.note = (f"agent concluded after {step} step(s); {len(res.agent_claimed)} claimed "
                        "finding(s) — require ground-truth confirmation before counting")
            break
        if kind == "shell":
            cmd = action.get("command", "")
            res.commands.append(cmd)
            observation = executor.run(cmd) if cmd else "[no command]"
            messages.append({"role": "assistant", "content": reply[:2000]})
            messages.append({"role": "user", "content": f"Observation:\n{observation[:3000]}"})
        else:
            messages.append({"role": "user", "content":
                             "Reply with a single valid JSON action object (shell or conclude)."})
    else:
        res.note = f"reached step limit ({max_steps}) without concluding"
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
    p.add_argument("--max-steps", type=int, default=MAX_STEPS)
    p.add_argument("--confirm", action="store_true",
                   help="after the agent concludes, confirm its claims against a ground-truth scan "
                        "(a claim counts only if the engine independently proves it)")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    ex = DockerExecutor(image=args.image) if args.docker else DryRunExecutor()
    if args.docker:
        print("[authorized assessment] running in the hardened Docker sandbox (no network, "
              "non-root, read-only).", file=sys.stderr)
    res = run_agent(args.target_stdio, executor=ex, max_steps=args.max_steps)

    confirmation = None
    if args.confirm and res.agent_claimed:
        from hunt.sandbox import run_isolated          # ground-truth oracle (sandboxed)
        from hunt.executor import confirm_claims
        report = run_isolated(args.target_stdio, backend="auto")
        confirmation = confirm_claims(res.agent_claimed, report.get("findings", []) or [])
    if args.json:
        d = res.as_dict()
        d["confirmation"] = confirmation
        print(json.dumps(d, indent=2))
    else:
        print(f"agent: {res.steps} step(s) · executor={ex.name} · commands issued={len(res.commands)}")
        print(f"note: {res.note}")
        if confirmation is not None:
            print(f"ground-truth confirmation: {confirmation['note']}")
            for f in confirmation["confirmed"]:
                print(f"  [CONFIRMED ✓] {f.get('class')}: {str(f.get('detail',''))[:80]}")
            for f in confirmation["unconfirmed"]:
                print(f"  [unconfirmed] {f.get('class')}: {str(f.get('detail',''))[:80]}")
        else:
            for f in res.agent_claimed:
                print(f"  [claimed · UNCONFIRMED — run --confirm] {f.get('class')}: {str(f.get('detail',''))[:80]}")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
