"""Code / expression injection oracle (CWE-94) — unit coverage for the by-design gate + registration.

The fires-on-vuln / silent-on-safe integration is enforced by `mcp-rt probe --selftest` against
hunt/probe_fixtures/ (filter_rows evals -> VULNERABLE; the safe twin does not -> silent). These unit
tests lock the precision discriminator: a tool that DECLARES it evaluates code/expressions is by-design,
while a restricted-purpose tool (filter/view/query) that evaluates is the finding.
"""
from hunt.probes import _DECLARES_EVAL, _CODE_MARK, _CODE_PAYLOADS, ALL_PROBES, probe_code_injection
from hunt.report import CLASS_META


def test_declared_evaluator_is_by_design():
    # declared code/expression runners -> the gate matches -> by_design (not a finding), like a shell tool
    for desc in ["Execute a Python code snippet and return the result",
                 "Run arbitrary Python code",
                 "A Python code interpreter",
                 "Evaluate an arbitrary expression and return it"]:
        assert _DECLARES_EVAL.search(desc), desc


def test_restricted_purpose_tool_is_not_by_design():
    # a restricted tool that happens to eval must NOT be excused by the gate -> stays VULNERABLE
    for desc in ["Filter rows by a boolean field expression",
                 "Build a view from stage specifications",   # the fiftyone shape
                 "Search the notes database by term",
                 "Apply a transform to the dataset",
                 # verb + "<restricted> expression" must NOT be excused (false-negative gap, CIO-found):
                 "Evaluate the filter expression against each row",
                 "Run the filter expression",
                 "Evaluate the formula expression for the column",
                 "Execute the query expression"]:
        assert not _DECLARES_EVAL.search(desc), desc


def test_mark_is_the_distinctive_product():
    assert str(9973 * 9967) == _CODE_MARK            # the oracle marker is the real product
    assert any("9973*9967" in p for p in _CODE_PAYLOADS)


def test_probe_registered_and_mapped():
    assert probe_code_injection in ALL_PROBES
    assert CLASS_META["code_injection"]["cwe"] == "CWE-94"
