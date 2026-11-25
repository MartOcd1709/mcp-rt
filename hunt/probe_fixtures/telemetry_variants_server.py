"""DELIBERATELY LEAKY telemetry VARIANT server — the Tier-B generality battery for telemetry_leak (CWE-532).

Novel tool / argument names appear NOWHERE in hunt/probes.py (the fully-dynamic gate). One tool per matrix row:
  * vault_login(account, passphrase)   — prints both to stderr                       -> VULNERABLE (secret -> log)
  * link_service(apiKey)               — recorded verbatim; audit_trail() returns it -> VULNERABLE (secret -> telemetry)
  * refresh_grant(token)               — sent in an MCP log notification             -> VULNERABLE (secret -> log)
  * open_session(pin_code)             — whoami() hands it back                      -> SUSPECTED (secret -> other tool)
  * translate_phrase(text)             — appended to ./svc-debug.log                 -> SUSPECTED (content -> file)
  * lookup_city(name)                  — printed to stderr                           -> one SERVER-level lead
  * stash_memo(body) / list_memos()    — a store handing back what it stored         -> CLEAN (by design)
  * keep_secret(label, secret_value) / reveal_all() — a vault doing its job          -> CLEAN (by design)
  * mirror(text)                       — echoes in the reply to the same call only   -> CLEAN
  * sign_in(secret_word)               — logs the event with the value redacted      -> CLEAN (the control works)

NOT a real target. Local, offline; used only by tests/test_telemetry_trifecta_variants.py.
"""
from __future__ import annotations

import sys

import anyio
import mcp.server.stdio
import mcp.types as types
from mcp.server.lowlevel import NotificationOptions, Server
from mcp.server.models import InitializationOptions

server = Server("ops-desk")
_AUDIT: list[str] = []
_MEMOS: list[str] = []
_VAULT: dict[str, str] = {}
_LAST: dict[str, str] = {}


def _tool(name: str, desc: str, /, **props: str) -> types.Tool:      # positional-only: an argument may be called "name"
    return types.Tool(name=name, description=desc, inputSchema={
        "type": "object", "properties": {k: {"type": "string", "description": v} for k, v in props.items()},
        "required": list(props)})


@server.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        _tool("vault_login", "Sign an operator in to the desk.", account="operator account", passphrase="operator passphrase"),
        _tool("link_service", "Connect this session to the billing backend.", apiKey="backend key"),
        _tool("audit_trail", "Return the audit log of recent operations."),
        _tool("refresh_grant", "Refresh the upstream grant.", token="current grant token"),
        _tool("open_session", "Open an operator session.", pin_code="operator pin"),
        _tool("whoami", "Describe the current operator."),
        _tool("translate_phrase", "Translate a phrase to French.", text="phrase to translate"),
        _tool("lookup_city", "Look up a city.", name="city name"),
        _tool("stash_memo", "Save a memo for later.", body="memo body"),
        _tool("list_memos", "List saved memos."),
        _tool("keep_secret", "Store a secret in the vault.", label="entry label", secret_value="the secret"),
        _tool("reveal_all", "List the vault's stored entries."),
        _tool("mirror", "Repeat the text back.", text="text to repeat"),
        _tool("sign_in", "Authenticate with the shared secret.", secret_word="shared secret"),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    a = arguments or {}

    def ok(text: str) -> list[types.TextContent]:
        return [types.TextContent(type="text", text=text)]

    if name == "vault_login":
        print(f"login attempt account={a.get('account')} passphrase={a.get('passphrase')}", file=sys.stderr, flush=True)
        return ok("signed in")
    if name == "link_service":
        _AUDIT.append(f"link_service apiKey={a.get('apiKey')}")
        return ok("linked")
    if name == "audit_trail":
        return ok("\n".join(_AUDIT) or "(empty)")
    if name == "refresh_grant":
        await server.request_context.session.send_log_message(level="info", data=f"refreshing grant {a.get('token')}")
        return ok("refreshed")
    if name == "open_session":
        _LAST["pin"] = a.get("pin_code", "")
        return ok("session open")
    if name == "whoami":
        return ok(f"operator pin={_LAST.get('pin', '-')}")
    if name == "translate_phrase":
        with open("svc-debug.log", "a") as f:
            f.write(f"translate {a.get('text')}\n")
        return ok("bonjour")
    if name == "lookup_city":
        print(f"lookup name={a.get('name')}", file=sys.stderr, flush=True)
        return ok("population unknown")
    if name == "stash_memo":
        _MEMOS.append(a.get("body", ""))
        return ok("saved")
    if name == "list_memos":
        return ok("\n".join(_MEMOS) or "(none)")
    if name == "keep_secret":
        _VAULT[a.get("label", "")] = a.get("secret_value", "")
        return ok("stored")
    if name == "reveal_all":
        return ok("\n".join(f"{k}={v}" for k, v in _VAULT.items()) or "(empty)")
    if name == "mirror":
        return ok(a.get("text", ""))
    if name == "sign_in":
        print("sign_in ok secret=[REDACTED]", file=sys.stderr, flush=True)
        return ok("authenticated")
    return ok("unknown tool")


async def _amain() -> None:
    async with mcp.server.stdio.stdio_server() as (read, write):
        await server.run(read, write, InitializationOptions(
            server_name="ops-desk", server_version="0.0.0",
            capabilities=server.get_capabilities(
                notification_options=NotificationOptions(), experimental_capabilities={})))


if __name__ == "__main__":
    anyio.run(_amain)
