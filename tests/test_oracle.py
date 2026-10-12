"""Evidence oracle: confirm a vuln by RE-DEMONSTRATION + unique nonce, not by matching a class label.

A simulated-vulnerable client proves each class confirms on real behavior; a safe client proves the
oracle does NOT false-positive (zero-FP is the whole point).
"""
import re

from mcp_rt import oracle as orc


class VulnClient:
    """Simulates a vulnerable server so the oracle's proof logic can be checked offline."""
    def call_tool(self, name, args):
        v = str(next(iter(args.values()), "")) if args else ""
        if name == "read_doc":                                   # path traversal
            return "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1" if "etc/passwd" in v else "normal"
        if name == "run_cmd":                                    # command injection (shell)
            m = re.search(r"echo (\S+)", v)
            return f"output\n{m.group(1)}" if m else "no-op"
        if name == "render":                                     # SSTI
            m = re.search(r"\{\{(\d+)\*(\d+)\}\}", v)
            return str(int(m.group(1)) * int(m.group(2))) if m else v
        if name == "run_py":                                     # code injection
            m = re.search(r"print\('([^']+)'\)", v)
            return m.group(1) if m else ""
        if name == "search":                                     # SQL injection (boolean-based)
            return "('a',) ('b',) ('c',)" if "'1'='1'" in v else ""
        return ""


class SafeClient:
    def call_tool(self, name, args):
        return "access denied: path outside allowed root"        # a secure server


def test_confirms_path_traversal_by_passwd_signature():
    p = orc.confirm(VulnClient(), "read_doc", "path_traversal", param="path")
    assert p.confirmed and "etc/passwd" in p.signal


def test_confirms_command_injection_by_unique_nonce():
    p = orc.confirm(VulnClient(), "run_cmd", "command_injection", param="cmd")
    assert p.confirmed and "nonce" in p.signal


def test_confirms_ssti_by_arithmetic_evaluation():
    p = orc.confirm(VulnClient(), "render", "ssti", param="template")
    assert p.confirmed and "=" in p.signal                        # A*B=product proven


def test_confirms_code_injection_by_nonce():
    p = orc.confirm(VulnClient(), "run_py", "code_injection", param="code")
    assert p.confirmed


def test_confirms_sql_injection_by_boolean_diff():
    p = orc.confirm(VulnClient(), "search", "sql_injection", param="term")
    assert p.confirmed and "boolean" in p.signal


def test_safe_server_is_never_false_positived():
    for cls in ("path_traversal", "command_injection", "ssti", "sql_injection", "code_injection"):
        assert orc.confirm(SafeClient(), "t", cls, param="x").confirmed is False


def test_normalize_free_form_class_labels():
    assert orc.normalize_class("ssrf_local_file_read") == "ssrf"
    assert orc.normalize_class("OS Command Injection") == "command_injection"
    assert orc.normalize_class("arbitrary_file_read") == "path_traversal"
    assert orc.normalize_class("SQLi") == "sql_injection"


def test_confirm_claims_reproves_a_free_agents_findings():
    # the agent freely chose tools/labels; the oracle re-demonstrates each claim
    claims = [{"class": "ssrf_local_file_read", "tool": "read_doc"},   # proven via /etc/passwd read
              {"class": "command injection", "tool": "run_cmd"},       # proven via nonce
              {"class": "made_up_thing", "tool": "ghost"}]             # cannot be proven
    res = orc.confirm_claims(VulnClient(), claims)
    proven = {p.tool for p in res.confirmed}
    assert "read_doc" in proven and "run_cmd" in proven and "ghost" not in proven


def test_confirm_plan_splits_confirmed_and_unconfirmed():
    from mcp_rt.planner import TestPoint
    plan = [TestPoint("read_doc", "path_traversal", param="path"),
            TestPoint("search", "sql_injection", param="term"),
            TestPoint("ghost", "command_injection", param="cmd")]   # not vulnerable
    res = orc.confirm_plan(VulnClient(), plan)
    proven = {p.tool for p in res.confirmed}
    assert "read_doc" in proven and "search" in proven and "ghost" not in proven
