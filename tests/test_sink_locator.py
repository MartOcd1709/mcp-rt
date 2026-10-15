"""T7 / SAM1-14 self-check: the explain-the-exploit chain locates the right root-cause sink for a
CONFIRMED finding, defaults to candidates-with-confidence when reachability is ambiguous (never a
false-precise line — CIO condition), emits NO chain for a lead (confirmed-only), and degrades honestly
to COULD-NOT-LOCATE. Additive: nothing here decides a verdict."""
from pathlib import Path

import pytest

from hunt import sink_locator as SL
from mcp_rt.oracle import Proof

VULN = str(Path(__file__).parents[1] / "hunt" / "probe_fixtures" / "vuln_server.py")


# ---- happy path: readable source, unambiguous sink per §2 baseline ----
@pytest.mark.parametrize("cls,tool,line,needle", [
    ("command_injection", "restricted_cmd", 120, "getoutput"),
    ("command_injection", "run_cmd", 113, "getoutput"),
    ("path_traversal", "read_doc", 115, "open("),
    ("ssti", "render_message", 46, "eval("),          # one hop: handler -> _render -> eval
    ("sql_injection", "search_notes", 128, "execute"),
])
def test_source_sink_unambiguous(cls, tool, line, needle):
    res = SL.locate_sink(cls, tool, source_path=VULN)
    assert isinstance(res, SL.SinkResult), res
    assert res.confidence == "unambiguous", res
    c = res.candidates[0]
    assert c.line == line and needle in c.expr and c.reached, (cls, tool, c)
    assert res.provenance == "source"


def test_chain_renders_for_confirmed():
    proof = Proof(tool="restricted_cmd", vuln_class="command_injection", confirmed=True, signal="canary touch fired")
    chain = SL.explain_chain(proof, source_path=VULN)
    assert chain and "VULNERABLE: command_injection in restricted_cmd" in chain
    assert "vuln_server.py:120" in chain and "canary touch fired" in chain
    assert "Fix:" in chain


# ---- confirmed-only guard: a LEAD gets no chain, ever ----
def test_unconfirmed_gets_no_chain():
    lead = Proof(tool="restricted_cmd", vuln_class="command_injection", confirmed=False)
    assert SL.explain_chain(lead, source_path=VULN) is None


# ---- ambiguous reachability: list candidates with confidence, do NOT collapse to one line ----
def test_ambiguous_lists_candidates(tmp_path):
    src = tmp_path / "amb.py"
    src.write_text(
        "async def call_tool(name, arguments):\n"
        "    def work():\n"
        "        if name == 'double':\n"
        "            a = eval(arguments['a'])\n"
        "            b = eval(arguments['b'])\n"
        "            return a + b\n")
    res = SL.locate_sink("ssti", "double", source_path=str(src))
    assert isinstance(res, SL.SinkResult) and res.confidence == "ambiguous"
    assert len(res.candidates) == 2 and all("eval(" in c.expr for c in res.candidates)


# ---- honest failure: no readable source / unsupported runtime ----
def test_could_not_locate_when_no_source():
    res = SL.locate_sink("command_injection", "x")   # no source_path, no installed_dir
    assert isinstance(res, SL.CouldNotLocate) and res.fix   # still carries the generic class fix

def test_chain_shows_could_not_locate_honestly():
    proof = Proof(tool="x", vuln_class="command_injection", confirmed=True, signal="canary fired")
    chain = SL.explain_chain(proof)   # no source -> honest COULD-NOT-LOCATE, never a guessed line
    assert chain and "COULD-NOT-LOCATE" in chain and "Fix:" in chain
