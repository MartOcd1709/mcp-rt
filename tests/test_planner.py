"""Planner: turn a discovered surface into an exhaustive, surface-derived test plan.

Verifies the deterministic enumerator covers every attackable tool×param×class (completeness, so
nothing on the surface is missed), derives points from the target's OWN schema (not a hardcoded list),
fills benign args so probes actually run, and that a planner model can add creative points (union).
"""
from mcp_rt import planner as pl


def _tool(name, params, desc=""):
    return {"name": name, "description": desc,
            "input_schema": {"type": "object",
                             "properties": {p: {"type": "string"} for p in params},
                             "required": list(params)}}


def test_param_name_drives_the_class():
    pts = pl.plan_tool(_tool("read_doc", ["path"]))
    pt = next(p for p in pts if p.vuln_class == "path_traversal")
    assert pt.param == "path" and "etc/passwd" in pt.probe["path"]      # payload targets the right param


def test_every_signal_param_becomes_a_point():
    # a tool with url + cmd + query params must plan SSRF + cmd-injection + SQLi — nothing skipped
    pts = pl.plan_tool(_tool("mega", ["url", "command", "query"]))
    classes = {p.vuln_class for p in pts}
    assert {"ssrf", "command_injection", "sql_injection"} <= classes


def test_tool_name_fallback_when_params_are_generic():
    # generic param name, but the TOOL name says "fetch" -> still planned as SSRF (surface-derived)
    pts = pl.plan_tool(_tool("web_fetch", ["input"]))
    assert any(p.vuln_class == "ssrf" for p in pts)


def test_probe_fills_other_required_args_benignly():
    tool = _tool("write_doc", ["path", "content"])
    pt = next(p for p in pl.plan_tool(tool) if p.param == "path")
    assert pt.probe["path"].startswith("../") and pt.probe["content"] == "test"   # callable, not partial


def test_build_plan_coverage_over_a_surface():
    surface = {"tools": [_tool("read_doc", ["path"]), _tool("run_cmd", ["cmd"]),
                         _tool("search_notes", ["term"], desc="search notes"),
                         _tool("import_from_url", ["url"])]}
    plan = pl.build_plan("vuln", surface)
    cov = plan.coverage()
    assert cov["tools_covered"] == 4
    assert {"path_traversal", "command_injection", "ssrf"} <= set(cov["classes_covered"])


def test_model_probe_as_string_is_normalized_to_dict():
    # the LLM planner may return probe as a string/non-dict — must not crash downstream
    class P:
        def chat(self, m):
            return '[{"target":"t","vuln_class":"ssrf","param":"url","probe":"http://169.254.169.254"}]'
    plan = pl.build_plan("t", {"tools": []}, model=P())
    pt = next(p for p in plan.points if p.source == "planner-model")
    assert isinstance(pt.probe, dict) and pt.probe["url"] == "http://169.254.169.254"


def test_model_augments_with_creative_points():
    class Planner:
        def chat(self, messages):
            return '[{"target":"edit_file","vuln_class":"path_traversal","param":"path",' \
                   '"rationale":"second write path","probe":{"path":"../../x"}}]'
    plan = pl.build_plan("t", {"tools": [_tool("read_doc", ["path"])]}, model=Planner())
    assert any(p.source == "planner-model" and p.target == "edit_file" for p in plan.points)
