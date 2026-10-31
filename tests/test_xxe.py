"""XXE probe (CWE-611): dynamic name-free battery + the two hard-condition guards (non-destructive,
own-file-only). Each battery server is generated at test time with ground truth and a random tool/param
name — nothing here is in the repo and no generated name appears in the probe source."""
import asyncio
import secrets
import sys

import pytest

from hunt import probes
from hunt.probes import (_XXE_DTD_PAYLOAD, _XXE_FILE_PAYLOAD, _XXE_OOB_PAYLOAD,
                         _XXE_PAYLOAD_TEMPLATES, probe_xxe, scan_target)

# A generated MCP server with one tool. MODE sets whether it resolves external entities (vulnerable),
# resolves them but hides the content (OOB-only), rejects them (safe), echoes the input (reflector), or
# ignores it (stored). Pure stdlib xml.sax; external-general-entities is the canonical XXE switch.
SERVER = '''import asyncio, io, xml.sax
from xml.sax.handler import ContentHandler, feature_external_ges
import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server
TOOL = __TOOL__
PARAM = __PARAM__
DESC = __DESC__
MODE = __MODE__
srv = Server("gen")


@srv.list_tools()
async def lt():
    return [types.Tool(name=TOOL, description=DESC,
            inputSchema={"type": "object", "properties": {PARAM: {"type": "string"}}, "required": [PARAM]})]


def _parse(text, ges):
    chunks = []

    class H(ContentHandler):
        def characters(self, d):
            chunks.append(d)
    p = xml.sax.make_parser(); p.setFeature(feature_external_ges, ges); p.setContentHandler(H())
    p.parse(io.StringIO(text)); return "".join(chunks)


@srv.call_tool()
async def ct(name, args):
    v = str((args or {}).get(PARAM, ""))
    try:
        if MODE == "file_vuln":
            out = "ok: " + _parse(v, True)        # resolves + returns -> file-read XXE
        elif MODE == "oob_vuln":
            _parse(v, True); out = "accepted"      # resolves (fetch happens) but hides content -> OOB only
        elif MODE == "safe":
            out = "ok: " + _parse(v, False)        # entities off -> undefined-entity error, never resolves
        elif MODE == "reflect":
            out = "echo: " + v                      # returns the payload verbatim (reflection, not a read)
        else:
            out = "stored"                          # ignores the content entirely
    except Exception as e:
        out = "err: " + str(e)[:80]
    return [types.TextContent(type="text", text=out[:2000])]


async def main():
    async with stdio_server() as (r, w):
        await srv.run(r, w, srv.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
'''

# (mode, declared description, ground-truth verdict)
CASES = [
    ("file_vuln", "Import an XML document.", "VULNERABLE"),   # file-read oracle
    ("oob_vuln", "Parse an XML feed.", "VULNERABLE"),         # out-of-band oracle
    ("safe", "Import an XML document safely.", "CLEAN"),      # entities disabled
    ("reflect", "Import an XML document.", "CLEAN"),          # reflection is NOT proof (C6 guard)
    ("stored", "Import an XML document.", "CLEAN"),           # does not parse as XML
]


def _run(mode, desc, tmp_path):
    tool, param = "t_" + secrets.token_hex(3), "p_" + secrets.token_hex(3)
    source = (SERVER.replace("__TOOL__", repr(tool)).replace("__PARAM__", repr(param))
                    .replace("__DESC__", repr(desc)).replace("__MODE__", repr(mode)))
    script = tmp_path / "xxe_server.py"
    script.write_text(source)
    rows = asyncio.run(scan_target([sys.executable, str(script)], probes=[probe_xxe]))
    return tool, [r for r in rows if r.tool == tool]


@pytest.mark.parametrize("mode,desc,verdict", CASES, ids=[f"{m}" for m, _, _ in CASES])
def test_battery_matches_ground_truth(mode, desc, verdict, tmp_path):
    tool, rows = _run(mode, desc, tmp_path)
    assert rows, f"probe emitted no row for {tool}"
    assert rows[0].verdict == verdict, (mode, rows[0].verdict, rows[0].confirmation_method, rows[0].rationale)
    if verdict == "VULNERABLE":
        assert rows[0].confirmation_method == "oracle"


def test_name_free_no_generated_name_leaks_into_probe_source():
    src = open(probes.__file__).read()
    for _ in range(5):
        assert ("t_" + secrets.token_hex(3)) not in src   # generated names cannot be baked into the probe


def test_vulnerable_finding_reads_only_our_planted_nonce(tmp_path):
    """Own-file guard (runtime): a file-read XXE fires on OUR nonce marker, never real file contents."""
    _, rows = _run("file_vuln", "Import an XML document.", tmp_path)
    assert rows[0].verdict == "VULNERABLE"
    assert (rows[0].marker or "").startswith("XXE")          # the oracle matched our planted nonce


# ---- hard conditions (structural, no server) -------------------------------------------------------
def test_guard_payloads_are_non_destructive():
    """Every payload is a SINGLE external-entity/DTD reference — no nested/parameter entities, no
    expansion/amplification (never a billion-laughs)."""
    for t in _XXE_PAYLOAD_TEMPLATES:
        assert t.count("<!ENTITY") <= 1, t          # at most one entity definition
        assert "<!ENTITY %" not in t, t              # no parameter entities (the recursion/DTD-exfil vector)
        assert t.count("&") <= 1, t                  # at most one entity reference -> no amplification


def test_guard_file_payload_targets_only_a_caller_supplied_path():
    """Own-file-only: the file-read payload is parameterized by {path} (the probe sets it to its own
    planted temp nonce file) and hardcodes no real system path."""
    assert "{path}" in _XXE_FILE_PAYLOAD
    for t in _XXE_PAYLOAD_TEMPLATES:
        low = t.lower()
        for real in ("/etc/passwd", "/etc/shadow", "/proc/", "c:\\", "file:///etc"):
            assert real not in low, (t, real)
