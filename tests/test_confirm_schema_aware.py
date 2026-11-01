"""Regression: the agent->oracle confirm bridge must hit the RIGHT tool argument.

The agent's claims carry {class, tool} but no param. Real tools name their args (read_doc->path,
render_message->template, ...). The old bridge put the payload in {"input": ...}, which real tools
don't have, so every genuine finding was rejected as 'not proven' (6/6 false negatives on a live
run). The fix resolves each tool's input schema. These tests use an ARG-NAME-SENSITIVE mock — it
fires ONLY when the payload lands on the correct parameter — so they fail if the bridge regresses.
"""
import re

from mcp_rt import oracle as orc

SCHEMAS = {
    "read_doc":       {"properties": {"path": {"type": "string"}}, "required": ["path"]},
    "render_message": {"properties": {"template": {"type": "string"}}, "required": ["template"]},
    "run_python":     {"properties": {"code": {"type": "string"}}, "required": ["code"]},
    "web_fetch":      {"properties": {"url": {"type": "string"}}, "required": ["url"]},
}


class SchemaVulnClient:
    """Vulnerable AND arg-name-sensitive: fires only when the payload is in the real param."""
    def list_tools(self):
        return [{"name": n, "input_schema": s} for n, s in SCHEMAS.items()]

    def call_tool(self, name, args):
        args = args or {}
        if name == "read_doc":
            return "root:x:0:0:root:/root:/bin/bash" if "etc/passwd" in str(args.get("path", "")) else "doc"
        if name == "render_message":
            m = re.search(r"\{\{(\d+)\*(\d+)\}\}", str(args.get("template", "")))
            return str(int(m.group(1)) * int(m.group(2))) if m else "msg"
        if name == "run_python":
            m = re.search(r"mcprtC[0-9a-f]+", str(args.get("code", "")))
            return m.group(0) if m else "executed"
        if name == "web_fetch":
            v = str(args.get("url", ""))
            return "root:x:0:0:root" if v.startswith("file://") or "etc/passwd" in v else "page"
        return ""


class SchemaSafeClient(SchemaVulnClient):
    def call_tool(self, name, args):
        return "access denied: outside allowed root"


_CLAIMS = [  # exactly what the agent emits: class + tool, NO param
    {"class": "path_traversal", "tool": "read_doc"},
    {"class": "ssti", "tool": "render_message"},
    {"class": "code_injection", "tool": "run_python"},
    {"class": "ssrf", "tool": "web_fetch"},
]


def test_resolve_picks_the_real_param():
    assert orc._resolve_attack_target(SCHEMAS["read_doc"], "path_traversal")[0] == "path"
    assert orc._resolve_attack_target(SCHEMAS["render_message"], "ssti")[0] == "template"
    assert orc._resolve_attack_target(SCHEMAS["run_python"], "code_injection")[0] == "code"
    assert orc._resolve_attack_target(SCHEMAS["web_fetch"], "ssrf")[0] == "url"
    _, base = orc._resolve_attack_target(SCHEMAS["read_doc"], "path_traversal")
    assert base.get("path") == "x"                          # required arg pre-filled benign


def test_confirm_claims_proves_all_paramless_claims():
    res = orc.confirm_claims(SchemaVulnClient(), _CLAIMS)
    proven = {p.tool for p in res.confirmed}
    assert proven == {"read_doc", "render_message", "run_python", "web_fetch"}, res.as_dict()


def test_confirm_claims_no_false_positive_on_safe_server():
    res = orc.confirm_claims(SchemaSafeClient(), _CLAIMS)
    assert res.confirmed == []                              # zero-FP preserved


def test_old_behavior_would_miss_without_schema():
    # The bug, pinned: a param-less confirm with no schema lands on the wrong arg -> not proven.
    p = orc.confirm(SchemaVulnClient(), "read_doc", "path_traversal", param="")
    assert not p.confirmed
