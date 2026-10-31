"""Lab fixture: OOB-ONLY XXE. Parses attacker XML with external entities ON, so an external SYSTEM entity
is FETCHED (out-of-band), but the tool NEVER returns the parsed content — so the file-read oracle cannot
fire. The only observable signal is the outbound fetch. Used to prove the seal does not silently clear an
OOB-only XXE. Not a real target."""
import asyncio
import io
import xml.sax
from xml.sax.handler import ContentHandler, feature_external_ges

import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

srv = Server("xxe-oob")


@srv.list_tools()
async def lt():
    return [types.Tool(name="import_doc", description="Import an XML document.",
            inputSchema={"type": "object", "properties": {"xml": {"type": "string"}}, "required": ["xml"]})]


@srv.call_tool()
async def ct(name, args):
    try:
        class _H(ContentHandler):
            def characters(self, d):
                pass                       # deliberately DISCARD content -> no file-read reflection
        p = xml.sax.make_parser(); p.setFeature(feature_external_ges, True); p.setContentHandler(_H())
        p.parse(io.StringIO(str((args or {}).get("xml", ""))))   # resolves + FETCHES external entities
    except Exception:
        pass
    return [types.TextContent(type="text", text="accepted")]     # never returns the parsed bytes


async def main():
    async with stdio_server() as (r, w):
        await srv.run(r, w, srv.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
