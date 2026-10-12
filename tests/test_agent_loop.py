"""Autonomous agent loop: safe-by-default ReAct loop, audited, ground-truth-gated.

Runs with the mock model + DryRun executor — NOTHING is executed, no API key. Verifies the loop
drives/observes/concludes, every command is audit-logged, and claimed findings are returned
UNCONFIRMED (the agent's say-so is never a verdict).
"""
import json

from mcp_rt import agent_loop as al


class FakeClient:
    """Stand-in MCP client: no real server launched; records tool calls for assertions."""
    def __init__(self, tools=None):
        self._tools = tools or [{"name": "read_file", "description": "read a file",
                                 "input_schema": {"properties": {"path": {}}}}]
        self.calls = []

    def list_tools(self):
        return self._tools

    def list_resources(self):
        return []

    def call_tool(self, name, arguments=None):
        self.calls.append((name, arguments))
        return f"contents for {name} args={arguments}"

    def read_resource(self, uri):
        return f"resource {uri}"


def test_dry_run_executes_nothing():
    out = al.DryRunExecutor().run("rm -rf /")        # must NOT run — placeholder only
    assert "dry-run" in out and "no execution" in out


def test_get_chat_model_defaults_to_mock(monkeypatch):
    for k in ("MCPRT_AI_PROVIDER", "MCPRT_AI_BASE_URL", "MCPRT_AI_API_KEY",
              "OPENAI_BASE_URL", "OPENAI_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    assert al.get_chat_model().name == "mock"


def test_loop_drives_and_concludes_with_audit():
    client = FakeClient()
    res = al.run_agent("npx -y demo-mcp", mcp_client=client)   # mock model + dry-run default
    assert res.steps >= 1
    assert res.commands                               # every action was audit-logged
    assert "conclude" in res.note or "step limit" in res.note


def test_agent_drives_target_mcp_tools_with_crafted_args():
    """The keystone: the agent EXERCISES the target's tools (not just shell). The mock lists tools
    then probes the first with a traversal arg — the fake client must receive that call."""
    client = FakeClient()
    res = al.run_agent("npx -y demo-mcp", mcp_client=client)
    assert client.calls, "agent never called a target tool"
    name, args = client.calls[0]
    assert name == "read_file" and "etc/passwd" in str(args)          # adversarial input reached the tool
    assert any(c.startswith("mcp:") for c in res.commands)            # mcp_call audit-logged


def test_build_context_exposes_real_surface():
    ctx, tools = al.build_target_context("x", client=FakeClient())
    assert "read_file" in ctx and "TARGET SURFACE" in ctx and tools


def test_context_degrades_when_target_unreachable():
    # a bogus target can't be launched -> honest note, never a crash
    ctx, tools = al.build_target_context("this-command-does-not-exist-xyz")
    assert "unavailable" in ctx and tools == []


def test_claimed_findings_are_unconfirmed():
    class Claimer(al.ChatModel):
        name = "claimer"
        def chat(self, messages):
            return json.dumps({"thought": "found it", "action": "conclude",
                               "findings": [{"class": "command_injection", "detail": "x", "evidence": "y"}]})
    res = al.run_agent("t", model=Claimer(), with_context=False)
    assert res.agent_claimed and "require ground-truth confirmation" in res.note   # not a verdict


def test_bad_action_is_nudged_not_crashed():
    class Garbage(al.ChatModel):
        name = "garbage"
        def __init__(self): self.n = 0
        def chat(self, messages):
            self.n += 1
            return "not json at all" if self.n == 1 else json.dumps({"action": "conclude", "findings": []})
    res = al.run_agent("t", model=Garbage(), max_steps=4, with_context=False)
    assert res.steps >= 2 and "conclude" in res.note   # recovered, didn't crash


def test_docker_executor_builds_isolated_argv(monkeypatch):
    monkeypatch.setattr(al.shutil, "which", lambda x: "/usr/bin/docker")
    captured = {}
    monkeypatch.setattr(al.subprocess, "run",
                        lambda argv, **k: captured.setdefault("argv", argv) or
                        type("P", (), {"stdout": "ok", "stderr": "", "returncode": 0})())
    al.DockerExecutor(image="mcp-rt:test").run("whoami")
    argv = captured["argv"]
    assert "--network" in argv and "none" in argv and "--rm" in argv
    assert "--cap-drop" in argv and "--read-only" in argv        # hard isolation enforced
