"""Host driver for the sealed runtime unit. Starts a server inside the launcher, drives it over MCP stdio, and
assembles the verdict from what the recorder and the strace witness saw. The server runs only after the seal is proven.
"""
import asyncio
import base64
import hashlib
import json
import os
import random
import re
import secrets
import sys
import tempfile
import time
from pathlib import Path

import mcp.types as types
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from hunt import synth  # valid-input synthesis (pure, stdlib-only): make a REAL tool actually execute

from mcp_rt.runtime import observe

LAUNCHER = Path(__file__).with_name("sandbox.py")
CANARY = "http://127.0.0.1:9999/collect"
CALL_TIMEOUT = 10.0
GRACE = 2.0                       # shallow drive (redirect oracle): fixed wait after the last call
# Deep canary run: watch at least WATCH_MIN after the last action, keep watching while new attempts arrive (until
# WATCH_QUIET of silence), never longer than WATCH_MAX. A timer/background exfil inside that window is caught.
WATCH_MIN, WATCH_QUIET, WATCH_MAX = 6.0, 3.0, 15.0
# Calls are bounded so a server with many tools cannot stall the engagement (the rest is reported as not reached).
BUDGET = {"per_tool": 6, "round1": 60, "round2": 30, "resources": 10, "prompts": 10}
EVIDENCE_CAP = 16 * 1024          # captured bytes kept per attempt as evidence (the sha256 covers the full capture)
LIMITS = [
    "seals IP egress only: unix-domain sockets to host daemons are not sealed in this unit",
    "payloads are inspected in plaintext; TLS payloads are opaque and can clear nothing",
    "IPv6 attempts are not captured by the IPv4 recorder and yield INCONCLUSIVE",
    f"behaviour is observed for {WATCH_MIN:g}-{WATCH_MAX:g}s after the last action: a longer timer is not seen",
    "environment reads are in-process (not traced): an env secret counts only when it is seen leaving",
]


def _sample(spec, token, depth=0):
    """A benign value for one schema node. Every string carries the test token."""
    if not isinstance(spec, dict):
        return token
    if spec.get("enum"):
        return spec["enum"][0]
    kind = spec.get("type")
    if isinstance(kind, list):
        kind = next((k for k in kind if k != "null"), None)
    if kind is None and spec.get("anyOf"):
        return _sample(spec["anyOf"][0], token, depth)
    if kind in (None, "string"):
        return f"{token} sample"
    if kind in ("integer", "number"):
        return 1
    if kind == "boolean":
        return True
    if kind == "array":
        return [_sample(spec.get("items", {}), token, depth + 1)] if depth < 3 else []
    if kind == "object":
        props = spec.get("properties") or {}
        return {k: _sample(v, token, depth + 1) for k, v in props.items()} if depth < 3 else {}
    return token


HINTS_PATH = Path(__file__).with_name("hints.json")


def apply_hints(spec, token):
    """Operator-supplied argument values for one tool. A string may carry {token}, replaced by this run's test value."""
    return {k: v.replace("{token}", token) if isinstance(v, str) else v for k, v in (spec or {}).items()}


def load_hints():
    """Per-target operator inputs, as data (hints.json). The runtime code never names a target."""
    return json.loads(HINTS_PATH.read_text())["targets"]


# Parameter shapes that reach other code paths. Decided on the schema (name + description), never on a tool name.
_URL_NAME = re.compile(r"(?i)url|uri|endpoint|webhook|href|link")
_URL_DESC = re.compile(r"(?i)\b(?:url|uri|endpoint|webhook|link)\b")
_PATH_NAME = re.compile(r"(?i)path|file|dir|folder")
_PATH_DESC = re.compile(r"(?i)\b(?:path|file|directory|folder)\b")


def _variants(schema, base, token, doc_path):
    """Extra argument sets for one tool: every other enum value (up to 3 per parameter), a planted document for a
    path-like parameter, an in-seal URL for a URL-like parameter. The caller bounds how many run."""
    out = []
    for k, spec in ((schema or {}).get("properties") or {}).items():
        if not isinstance(spec, dict):
            continue
        for v in (spec.get("enum") or [])[1:4]:
            out.append({**base, k: v})
        if spec.get("type") in (None, "string") and not spec.get("enum"):
            desc = spec.get("description") or ""
            if _URL_NAME.search(k) or _URL_DESC.search(desc):
                out.append({**base, k: f"{CANARY}?ref={token}-ARG"})
            elif doc_path and (_PATH_NAME.search(k) or _PATH_DESC.search(desc)):
                out.append({**base, k: doc_path})
    return out


def _clip(obj, n=400):
    try:
        text = json.dumps(obj, sort_keys=True, default=str)
    except (TypeError, ValueError):
        text = repr(obj)
    return text[:n]


def _defs(tools):
    return {t["name"]: (t["description"], json.dumps(t["inputSchema"], sort_keys=True)) for t in tools}


def _diff_defs(before, after, after_round, notified):
    """Tool definitions that changed between two listings in ONE session (a rug pull happens after approval)."""
    out = []
    for name in sorted(set(before) | set(after)):
        b, a = before.get(name), after.get(name)
        if b == a:
            continue
        change = "added" if b is None else "removed" if a is None else "changed"
        out.append({"tool": name, "change": change, "after_round": after_round, "notified": notified,
                    "before": (b or ("", ""))[0][:600], "after": (a or ("", ""))[0][:600],
                    "schema_changed": bool(a and b and a[1] != b[1])})
    return out


def _size(path):
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


async def _watch(events_path):
    """Keep the server alive after the last action: catch delayed / background exfiltration."""
    start = last = time.time()
    size = _size(events_path)
    while True:
        await asyncio.sleep(0.25)
        now, cur = time.time(), _size(events_path)
        if cur != size:
            size, last = cur, now
        if now - start >= WATCH_MAX or (now - start >= WATCH_MIN and now - last >= WATCH_QUIET):
            return round(now - start, 2)


async def _drive(params, token, timeout, hints=None, *, deep=False, events_path=None, doc_path=None, budget=None,
                 target_argv=(), workdir=None):
    """Drive the server over MCP. shallow: one benign call per tool (the redirect oracle). deep (the canary run):
    every tool with schema variants, every resource and prompt, the tool list re-read mid-session, a second round of
    calls, then a watch window. Every action is timestamped so egress and file access can be tied to it.

    Tool arguments are SYNTHESIZED (hunt.synth) to be valid-shaped for real servers: from each parameter's schema and
    meaning, from paths the server was launched with, and from strings its own read tools return — then, if a call is
    rejected, repaired once from the validation error. Without this, a real tool rejects a placeholder argument and its
    code path never runs (found in the real-OSS trial)."""
    b = {**BUDGET, **(budget or {})}
    ctx = synth.Context(base_dir=workdir or ".", url=CANARY, token=token, paths=synth.harvest_argv(list(target_argv)))

    def _learn(text):  # a successful read tool's output yields real identifiers (tables, branches) for later calls
        for s in synth.harvest_strings(text or "", 20):
            if s not in ctx.strings and len(ctx.strings) < 80:
                ctx.strings.append(s)
    out = {"instructions": None, "server_name": None, "tools": [], "calls": [], "elicitations": [], "samplings": [],
           "hinted_tools": [], "error": None, "actions": [], "redefinitions": [], "list_changed": 0,
           "elicitation_log": [], "watch_s": None, "not_reached": 0}
    cur = {"i": None}
    deadline = time.time() + max(timeout, 30.0)

    def begin(kind, name, round_, args=None):
        out["actions"].append({"i": len(out["actions"]), "kind": kind, "name": name, "round": round_,
                               "args": None if args is None else _clip(args), "t0": time.time(), "t1": None,
                               "ok": None, "note": None})
        cur["i"] = len(out["actions"]) - 1
        return out["actions"][-1]

    def end(a, ok, note=None):
        a["t1"], a["ok"], a["note"] = time.time(), ok, (str(note)[:200] if note else None)

    async def sample(context, params):
        # A server that asks the CLIENT's model to complete something gets a completion carrying our token, so if it
        # ships the model's output anywhere, the seal sees it. The request text is kept for the laundering lead.
        text = " ".join(getattr(m.content, "text", "") or "" for m in (getattr(params, "messages", None) or []))
        sys_prompt = getattr(params, "systemPrompt", None) or ""
        out["samplings"].append({"text": (sys_prompt + " " + text).strip()[:2000], "action": cur["i"]})
        return types.CreateMessageResult(role="assistant", model="mcprt-sealed-sampler", stopReason="endTurn",
                                         content=types.TextContent(type="text", text=f"Summary ready. {token}-SAMPLE"))

    async def elicit(context, request):
        # Every elicitation is answered with the token, so a server that asks for a secret gets ours.
        schema = getattr(request, "requestedSchema", None) or {}
        fields = sorted((schema.get("properties") or {}).keys())
        out["elicitations"].append(fields)
        out["elicitation_log"].append({"fields": fields, "action": cur["i"]})
        content = {k: (f"{token}-ELICIT" if (v or {}).get("type", "string") == "string" and not (v or {}).get("enum")
                       else _sample(v, token)) for k, v in (schema.get("properties") or {}).items()}
        return types.ElicitResult(action="accept", content=content)

    async def on_message(msg):
        if isinstance(getattr(msg, "root", None), types.ToolListChangedNotification):
            out["list_changed"] += 1

    async def call(session, tool, args, round_, record_compat=False):
        a = begin("tool", tool["name"], round_, args)

        async def once(aa):  # a failing tool is a result, not a harness crash
            try:
                res = await asyncio.wait_for(session.call_tool(tool["name"], aa), CALL_TIMEOUT)
                return (not res.isError), " ".join(getattr(c, "text", "") or "" for c in res.content)
            except Exception as exc:
                return False, repr(exc)

        ok, text = await once(args)
        if not ok:  # rejected by validation? the error names the valid shape — fix one param and retry once
            fixed = synth.repair(args, tool.get("inputSchema") or {}, ctx, text)
            if fixed and fixed != args:
                ok2, text2 = await once(fixed)
                a["repaired"] = ok2
                if ok2:
                    a["args"], ok, text = _clip(fixed), ok2, text2
        end(a, ok, text[:200])
        if ok:
            _learn(text)
        if record_compat:
            out["calls"].append({"tool": tool["name"], "isError": not ok, "text": text[:200]} if ok
                                else {"tool": tool["name"], "error": text[:200]})

    async def listing(session, round_):
        a = begin("list_tools", "tools/list", round_)
        tools = (await asyncio.wait_for(session.list_tools(), timeout)).tools
        end(a, True)
        return [{"name": t.name, "description": t.description or "", "inputSchema": t.inputSchema or {}} for t in tools]

    try:
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write, elicitation_callback=elicit, sampling_callback=sample,
                                     message_handler=on_message) as session:
                a = begin("initialize", "initialize", 0)
                init = await asyncio.wait_for(session.initialize(), timeout)
                end(a, True)
                out["instructions"] = init.instructions
                out["server_name"] = init.serverInfo.name if init.serverInfo else None
                out["tools"] = await listing(session, 0)
                lc_at_list = out["list_changed"]
                base = {}
                for tool in out["tools"]:
                    args = {k: synth.value(k, v, ctx) for k, v in (tool["inputSchema"].get("properties") or {}).items()}
                    if hints and tool["name"] in hints:
                        args.update(apply_hints(hints[tool["name"]], token))
                        out["hinted_tools"].append(tool["name"])
                    base[tool["name"]] = args
                for tool in out["tools"]:                                     # round 1: every tool, benign baseline
                    await call(session, tool, base[tool["name"]], 1, record_compat=True)
                if not deep:
                    await asyncio.sleep(GRACE)
                    return out
                extra = [(t, v) for t in out["tools"]
                         for v in _variants(t["inputSchema"], base[t["name"]], token, doc_path)[:b["per_tool"] - 1]]
                room = max(b["round1"] - len(out["tools"]), 0)
                out["not_reached"] += max(len(extra) - room, 0)
                for tool, args in extra[:room]:                               # round 1: variants that reach other paths
                    if time.time() > deadline:
                        out["not_reached"] += 1
                        continue
                    await call(session, tool, args, 1)
                for kind, lister, getter in (("resource", "list_resources", "read_resource"),
                                             ("prompt", "list_prompts", "get_prompt")):
                    try:
                        listed = await asyncio.wait_for(getattr(session, lister)(), timeout)
                    except Exception:  # noqa: BLE001 - the server does not offer this capability
                        continue
                    items = (listed.resources if kind == "resource" else listed.prompts)[:b[kind + "s"]]
                    for it in items:
                        if time.time() > deadline:
                            out["not_reached"] += 1
                            continue
                        if kind == "resource":
                            a = begin("resource", str(it.uri), 1)
                            coro = session.read_resource(it.uri)
                        else:
                            pargs = {arg.name: synth.value(arg.name, {"type": "string"}, ctx) for arg in (it.arguments or [])}
                            a = begin("prompt", it.name, 1, pargs)
                            coro = session.get_prompt(it.name, pargs)
                        try:
                            await asyncio.wait_for(coro, CALL_TIMEOUT)
                            end(a, True)
                        except Exception as exc:  # noqa: BLE001
                            end(a, False, repr(exc))
                # "announced" = a tools/list_changed arrived since the PREVIOUS listing (it is sent while a call is
                # being handled, so it lands before the re-list, never after it)
                defs0 = _defs(out["tools"])
                after1 = await listing(session, 1)                            # rug pull after first use?
                out["redefinitions"] += _diff_defs(defs0, _defs(after1), 1, out["list_changed"] > lc_at_list)
                lc_at_list = out["list_changed"]
                for tool in after1[:b["round2"]]:                             # round 2: Nth-call triggers
                    if time.time() > deadline:
                        out["not_reached"] += 1
                        continue
                    args = base.get(tool["name"]) or {k: synth.value(k, v, ctx)
                                                      for k, v in (tool["inputSchema"].get("properties") or {}).items()}
                    await call(session, tool, args, 2)
                after2 = await listing(session, 2)
                out["redefinitions"] += _diff_defs(_defs(after1), _defs(after2), 2, out["list_changed"] > lc_at_list)
                cur["i"] = None
                out["watch_s"] = await _watch(events_path) if events_path else None
    except Exception as exc:
        out["error"] = repr(exc)[:300]
    return out


def _read_json(path):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return {}


def _read_events(path):
    try:
        return [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()]
    except OSError:
        return []


def _read_text(path):
    try:
        return Path(path).read_text()
    except OSError:
        return None


def _summary(ev, token):
    payload = base64.b64decode(ev["payload"])
    return {"proto": ev["proto"], "dst": ev["dst"], "port": ev["port"], "bytes": len(payload),
            "truncated": ev["truncated"], "inspectable": observe.inspectable(payload, ev["truncated"], ev["port"]),
            "token_hits": observe.token_hits(payload, token)}


_PEM_HEAD, _PEM_TAIL = "-----BEGIN " + "OPENSSH PRIVATE KEY-----", "-----END " + "OPENSSH PRIVATE KEY-----"
# Fake credentials planted in the sealed HOME, which is also the server's working directory (MCP-00 proof). Every
# secret value is the run token plus a label, so a leak names exactly WHAT was stolen. Formats mirror the real files a
# credential-hunting server goes after.
HONEYFILES = {
    ".aws/credentials": "[default]\naws_access_key_id = AKIA-MCPRT-CANARY\naws_secret_access_key = {t}-AWS\n",
    ".ssh/id_rsa": _PEM_HEAD + "\n{t}-SSH\n" + _PEM_TAIL + "\n",
    ".config/gcloud/application_default_credentials.json": '{{"type": "authorized_user", "client_secret": "{t}-GCP"}}\n',
    ".netrc": "machine api.github.com login ci-bot password {t}-NETRC\n",
    ".env": "OPENAI_API_KEY={t}-ENV\nDATABASE_URL=postgres://app:{t}-ENV@db.internal/prod\n",
    ".cursor/mcp.json": '{{"mcpServers": {{"internal": {{"command": "srv", "env": {{"API_TOKEN": "{t}-MCPCFG"}}}}}}}}\n',
    ".bash_history": "export GITHUB_TOKEN={t}-HIST\n",
    ".kube/config": "users:\n- name: admin\n  user:\n    token: {t}-KUBE\n",
    ".git/config": '[remote "origin"]\n\turl = https://ci-bot:{t}-GIT@github.com/acme/app.git\n',
}
HONEYFILE_LABELS = {rel: re.search(r"\{t\}-([A-Z0-9]+)", tmpl).group(1) for rel, tmpl in HONEYFILES.items()}
HONEYFILE_DESC = {
    "AWS": "fake AWS credentials (~/.aws/credentials)", "SSH": "fake SSH private key (~/.ssh/id_rsa)",
    "GCP": "fake Google Cloud credentials (~/.config/gcloud)", "NETRC": "fake ~/.netrc login",
    "ENV": "fake .env secrets", "MCPCFG": "fake MCP client config token (~/.cursor/mcp.json)",
    "HIST": "fake token in shell history (~/.bash_history)", "KUBE": "fake Kubernetes credentials (~/.kube/config)",
    "GIT": "fake Git remote credentials (.git/config)",
}
# Ambient credentials a developer shell carries: a server that ships one out is stealing it.
ENV_CANARIES = {"OPENAI_API_KEY": "EOPENAI", "ANTHROPIC_API_KEY": "EANTHROPIC", "GITHUB_TOKEN": "EGITHUB",
                "AWS_SECRET_ACCESS_KEY": "EAWS", "DATABASE_URL": "EDB", "SLACK_BOT_TOKEN": "ESLACK"}
DOC_NAME = "project-notes.md"     # handed to path-like parameters: argument-supplied, never a planted secret
# An environment variable NAME that holds a credential (decided on the name, generically). Only these are replaced by a
# canary; a configuration variable (allowed commands, a mode, a path) keeps the operator's real value, or the server
# would be assessed in a state it never runs in.
_SECRET_NAME = re.compile(r"(?i)key|token|secret|passw|pwd|credential|auth|cookie|session|private|dsn|"
                          r"connection_string|database_url")


def operator_env(environ=None) -> dict:
    """The operator's explicit passthrough (MCPRT_TARGET_ENV="NAME,NAME" + those variables): the server's real
    configuration. Names only reach reports; values never do."""
    environ = os.environ if environ is None else environ
    names = [n.strip() for n in (environ.get("MCPRT_TARGET_ENV") or "").split(",") if n.strip()]
    return {n: environ[n] for n in names if n in environ}


def plant_honeyfiles(home, token):
    for rel, tmpl in HONEYFILES.items():
        f = Path(home) / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(tmpl.format(t=token))
        os.chmod(f, 0o600)


def plant_canaries(home, token, declared_env=(), passthrough=None):
    """Plant every canary for one sealed run. Returns (planted, env): planted = [{label, kind, where, description}]
    with kind file | env | own_env | doc. own_env = a credential variable of the server's OWN configuration (its leak is
    a lead: it may be the server's own API), env = ambient developer-shell secrets (their leak is proof).

    The server's own variables come from its client configuration (`declared_env`, names) and from the operator's
    passthrough (`passthrough`, name -> value):
      credential-looking name (declared or passed)   -> a canary replaces it (the seal has no network: the real secret
                                                        is useless there, and a canary makes its leak visible)
      configuration name with an operator value      -> the real value is passed (the server runs as configured)
      configuration name with no value               -> left unset (we do not invent configuration)"""
    plant_honeyfiles(home, token)
    planted = [{"label": lab, "kind": "file", "where": rel, "path": str(Path(home) / rel),
                "description": HONEYFILE_DESC.get(lab, rel)} for rel, lab in HONEYFILE_LABELS.items()]
    doc = Path(home) / DOC_NAME
    doc.write_text(f"Q3 roadmap notes (internal). ref {token}-DOC\n")
    planted.append({"label": "DOC", "kind": "doc", "where": DOC_NAME, "path": str(doc),
                    "description": "the document handed to a path parameter"})
    passthrough = dict(passthrough or {})
    env = {}
    own = [k for k in dict.fromkeys([*declared_env, *passthrough]) if k and _SECRET_NAME.search(k)]
    for i, key in enumerate(own[:20]):
        lab = f"OWN{i:02d}"
        env[key] = f"{token}-{lab}"
        planted.append({"label": lab, "kind": "own_env", "where": key,
                        "description": f"the server's own configured credential {key}"})
    for key, value in passthrough.items():
        if key not in env:
            env[key] = value                       # configuration, as the operator supplied it
    for key, lab in ENV_CANARIES.items():
        if key in env:
            continue
        env[key] = f"postgres://app:{token}-{lab}@db.internal:5432/prod" if key == "DATABASE_URL" else f"{token}-{lab}"
        planted.append({"label": lab, "kind": "env", "where": key, "description": f"fake {key} from the environment"})
    return planted, env


def leaks_of(events, token, planted=None):
    """Which PLANTED values left the server: [{secret, dst, excerpt}] (labels: planted canaries + ELICIT, SAMPLE)."""
    labels = [p["label"] for p in (planted or []) if p["kind"] != "doc"] or list(HONEYFILE_LABELS.values())
    labels += ["ELICIT", "SAMPLE"]
    out, seen = [], set()
    for e in events:
        payload = base64.b64decode(e.get("payload") or "")
        for lab in labels:
            if (lab, e.get("dst"), e.get("port")) in seen or not observe.token_hits(payload, f"{token}-{lab}"):
                continue
            seen.add((lab, e.get("dst"), e.get("port")))
            out.append({"secret": lab, "dst": f"{e.get('proto', 'tcp')} {e.get('dst')}:{e.get('port')}",
                        "excerpt": payload[:400].decode("utf-8", "replace")})
    return out


def attribute(ts, actions):
    """Tie a timestamped event to the action that caused it: inside an action's window, else after the last one."""
    if ts is None:
        return {"action": None, "attribution": "time unknown"}
    inside = [a for a in actions if a["t0"] <= ts <= (a["t1"] or a["t0"])]   # strict: windows never overlap
    if inside:
        a = inside[-1]
        if a["kind"] == "initialize":    # the seal is proven while the client waits on initialize: that is load time
            return {"action": None, "attribution": "server startup"}
        return {"action": a["i"], "attribution": f"{a['kind']} {a['name']} (round {a['round']})"}
    used = [a for a in actions if a["kind"] in ("tool", "resource", "prompt") and a["t0"] <= ts]
    if not used:                     # before the first call: the server did it on its own at load
        return {"action": None, "attribution": "server startup"}
    a = used[-1]                     # "after", never "during": a delayed event is tied to the last call, honestly
    return {"action": a["i"],
            "attribution": f"after {a['kind']} {a['name']} (round {a['round']}, +{ts - (a['t1'] or a['t0']):.1f}s)"}


_SYS = re.compile(r'^(?:(\d+)\s+)?(\d+\.\d+)\s+(openat|open|creat|rename|renameat2?)\((.*)$')
_RESUMED = re.compile(r'^(?:(\d+)\s+)?(\d+\.\d+)\s+<\.\.\. (\w+) resumed>(.*)$')
_STR = re.compile(r'"((?:[^"\\]|\\.)*)"')
_RES = re.compile(r"\)\s*=\s*(-?\d+)")
_WRITE_FLAGS = re.compile(r"O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_APPEND")


def file_ops(strace_text, workdir):
    """[{ts, path, write}] for every SUCCESSFUL open/creat/rename in the server trace (paths made absolute)."""
    ops, pending = [], {}

    def add(ts, call, rest_args, result_text):
        m = _RES.search(result_text)
        if not m or int(m.group(1)) < 0:
            return
        paths = _STR.findall(rest_args)
        if not paths:
            return
        if call.startswith("rename"):
            path, write = paths[-1], True                       # the destination is what got written
        else:
            path, write = paths[0], call == "creat" or bool(_WRITE_FLAGS.search(rest_args))
        ops.append({"ts": ts, "path": os.path.normpath(os.path.join(workdir, path)), "write": write})

    for line in (strace_text or "").splitlines():
        m = _SYS.match(line)
        if m:
            pid, ts, call, rest = m.group(1), float(m.group(2)), m.group(3), m.group(4)
            if "<unfinished" in rest:
                pending[(pid, call)] = (ts, rest)
            else:
                add(ts, call, rest, rest)
            continue
        m = _RESUMED.match(line)
        if m and (m.group(1), m.group(3)) in pending:
            ts, rest = pending.pop((m.group(1), m.group(3)))
            add(ts, m.group(3), rest, m.group(4))
    return ops


def _tamper_targets(home):
    """Files a server has no business writing: shell startup, SSH trust, autostart, other MCP clients' configs."""
    rels = [".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile", ".ssh/authorized_keys", ".ssh/config",
            ".gitconfig"]
    try:
        from hunt.discover import _HOME_CONFIGS        # every MCP client config the product knows (one source of truth)
        rels += list(_HOME_CONFIGS)
    except Exception:  # noqa: BLE001
        pass
    return {os.path.normpath(os.path.join(home, r)): r for r in rels}


def analyse(drive, events, strace_text, token, planted, workdir):
    """Enrich the raw run: every egress attempt (secrets it carried, sha256, bytes, the action that caused it), every
    open of a planted secret, every write to a tamper target. Pure: reads only what the run recorded."""
    actions = drive.get("actions") or []
    egress = []
    for e in events:
        payload = base64.b64decode(e.get("payload") or "")
        hits = [p["label"] for p in planted if p["kind"] != "doc" and observe.token_hits(payload, f"{token}-{p['label']}")]
        hits += [lab for lab in ("ELICIT", "SAMPLE") if observe.token_hits(payload, f"{token}-{lab}")]
        egress.append({"ts": e.get("ts"), "proto": e.get("proto"), "dst": e.get("dst"), "port": e.get("port"),
                       "bytes": len(payload), "truncated": bool(e.get("truncated")),
                       "inspectable": observe.inspectable(payload, e.get("truncated"), e.get("port")),
                       "token_forms": observe.token_hits(payload, token), "secrets": hits,
                       "sha256": hashlib.sha256(payload).hexdigest(),
                       "payload_b64": base64.b64encode(payload[:EVIDENCE_CAP]).decode(),
                       **attribute(e.get("ts"), actions)})
    by_path = {p["path"]: p for p in planted if p.get("path")}
    tamper_paths = _tamper_targets(workdir)
    access, tamper, seen = [], [], set()
    for op in file_ops(strace_text, workdir):
        p = by_path.get(op["path"])
        if p and p["kind"] != "doc" and not op["write"] and (p["label"], op["path"]) not in seen:
            seen.add((p["label"], op["path"]))
            access.append({"label": p["label"], "where": p["where"], "description": p["description"], "ts": op["ts"],
                           **attribute(op["ts"], actions)})
        rel = tamper_paths.get(op["path"]) or (p["where"] if p and p["kind"] == "file" else None)
        if op["write"] and rel and ("w", op["path"]) not in seen:
            seen.add(("w", op["path"]))
            tamper.append({"where": rel, "ts": op["ts"], **attribute(op["ts"], actions)})
    return egress, access, tamper


def build_sealed_launcher(target_argv, workdir, token, extra_env=None, redirect=None, declared_env=(),
                          passthrough=None):
    """The sealed-launch recipe shared by the one-shot scan and the agent tier's long-lived session.
    Returns (StdioServerParameters, paths): a stdio command that is `unshare -rn sandbox.py … --server-json
    <target argv>`, which proves the seal and only then execs the target with stdio inherited. The host opens
    an ordinary ClientSession against it. `paths` names the launcher's report/events/strace files, plus the planted
    canaries (`planted`) and the document for path parameters (`doc`).

    `redirect` (#28, optional): {sentinel_port, canary_host, canary_port, nonce}. When set, the sealed
    recorder answers EXACTLY the sentinel dst with a 302 to the internal canary in the SERVER phase — the
    upstream-redirect SSRF oracle. Everything still routes to the one recorder; nothing leaves the seal."""
    names = {"report": "report.json", "events": "events.jsonl", "strace_server": "server.strace",
             "strace_probe": "probe.strace", "server_json": "server.json"}
    paths = {k: os.path.join(workdir, v) for k, v in names.items()}
    Path(paths["server_json"]).write_text(json.dumps(list(target_argv)))
    # HOME is the workdir (and the server's cwd): the planted secrets are what a thief would find
    passthrough = operator_env() if passthrough is None else passthrough
    planted, canary_env = plant_canaries(workdir, token, declared_env, passthrough)
    paths["planted"], paths["doc"] = planted, str(Path(workdir) / DOC_NAME)
    paths["config_env"] = sorted(k for k in passthrough if not _SECRET_NAME.search(k))   # names only
    port = random.SystemRandom().randint(20000, 60000)
    host_ino = os.stat("/proc/self/ns/net").st_ino
    launcher = ["unshare", "-rn", "--", sys.executable, "-I", str(LAUNCHER),
                "--report", paths["report"], "--events", paths["events"], "--workdir", workdir,
                "--host-netns-ino", str(host_ino), "--port", str(port), "--server-json", paths["server_json"],
                "--strace-server", paths["strace_server"], "--strace-probe", paths["strace_probe"]]
    if redirect:
        launcher += ["--redirect", json.dumps(redirect)]
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": workdir, "LANG": "C.UTF-8",
           "MCPRT_TEST_VALUE": token, "MCPRT_CANARY": CANARY, **canary_env,
           # a launcher that strips the environment to an allowlist (the console runner's cleanenv.py) passes the
           # canary variables through: that is the documented passthrough, the allowlist itself is not widened
           "MCPRT_TARGET_ENV": ",".join(canary_env)}
    if extra_env:                     # e.g. dummy vars for config recovery; sandbox.py execs the target with
        env.update(extra_env)         # no env= so the target inherits this env (see sandbox.py Popen)
    return StdioServerParameters(command=launcher[0], args=launcher[1:], env=env, cwd=workdir), paths


def run_server(argv, *, token=None, timeout=120.0, hints=None, declared_env=(), deep=True, passthrough=None):
    """Run one server under the sealed launcher and return its verdict record (deep canary run by default)."""
    token = token or "HT-" + secrets.token_hex(8)
    workdir = tempfile.mkdtemp(prefix="mcprt-rt-")
    started = time.time()
    params, paths = build_sealed_launcher(argv, workdir, token, declared_env=declared_env, passthrough=passthrough)
    drive = asyncio.run(_drive(params, token, timeout, hints, deep=deep, events_path=paths["events"],
                               doc_path=paths["doc"], target_argv=list(argv), workdir=workdir))

    report = _read_json(paths["report"])
    server_events = [e for e in _read_events(paths["events"]) if e.get("phase") == "server"]
    strace_text = _read_text(paths["strace_server"]) if report.get("server_started") else None

    parts = [drive.get("server_name") or "", drive.get("instructions") or ""]
    for tool in drive["tools"]:
        parts += [tool["name"], tool["description"]]
        for spec in (tool["inputSchema"].get("properties") or {}).values():
            if isinstance(spec, dict):
                parts.append(spec.get("description") or "")
    refused = [c["tool"] for c in drive["calls"]
               if c.get("isError") or "error" in c or observe.REFUSAL.match(c.get("text") or "")]
    # egress to the in-seal URL WE handed a URL parameter is the requested fetch, not unexplained behaviour; a planted
    # secret riding along to it still counts (leaks are read from every event)
    requested = {("127.0.0.1", 9999)} if any(CANARY in (a.get("args") or "") for a in drive["actions"]) else set()
    problem = observe.integrity_problem(bool(report.get("sealed")), bool(report.get("server_started")),
                                        strace_text, server_events)
    result = problem if problem is not None else observe.classify_egress(
        [e for e in server_events if (e["dst"], e["port"]) not in requested], token, " \n ".join(parts), refused)
    egress, access, tamper = analyse(drive, server_events, strace_text, token, paths["planted"], workdir)
    return {"server": list(argv), "token": token, **result,
            "attempts": [_summary(ev, token) for ev in server_events],
            "proof": report.get("checks", {}), "proof_error": report.get("error"),
            "sealed": bool(report.get("sealed")), "server_started": bool(report.get("server_started")),
            "tools": [t["name"] for t in drive["tools"]], "calls": drive["calls"],
            "driver_error": drive["error"], "elicitations": drive["elicitations"], "refused": refused,
            "samplings": drive["samplings"], "leaks": leaks_of(server_events, token, paths["planted"]),
            "hinted": bool(hints), "hinted_tools": drive["hinted_tools"],
            "claim_text": " \n ".join(parts)[:4000], "planted": paths["planted"], "actions": drive["actions"],
            "egress": egress, "file_access": access, "tamper": tamper, "redefinitions": drive["redefinitions"],
            "list_changed": drive["list_changed"], "elicitation_log": drive["elicitation_log"],
            "watch_s": drive["watch_s"], "not_reached": drive["not_reached"], "deep": deep,
            "config_env": paths["config_env"],
            "duration_s": round(time.time() - started, 2), "limits": LIMITS, "workdir": workdir}


def assess_redirect_follow(argv, *, upstream_keys, env=None, token=None, timeout=120.0):
    """#28 upstream-redirect SSRF oracle (sealed, black-box). Point the server's CONFIGURED upstream — the
    RoE-supplied env key(s) that hold its base URL (server is DATA; NO hardcoded key) — at a loopback
    sentinel. The sealed recorder answers that sentinel with a 302 to an internal canary and records whether
    the server FOLLOWS it. Integrity first (seal proven, recorder vs strace), then classify_redirect_follow.
    Returns a verdict record (run_server shape)."""
    if not upstream_keys:
        return {"server": list(argv), "verdict": "INCONCLUSIVE", "method": "redirect_not_confirmed",
                "evidence": "no upstream URL key supplied (the RoE must name the env/config key that holds the "
                            "server's base URL); cannot configure the sentinel", "attempts": []}
    token = token or "HT-" + secrets.token_hex(8)
    workdir = tempfile.mkdtemp(prefix="mcprt-rr-")
    rnd = random.SystemRandom()
    p1 = rnd.randint(20000, 60000)
    p2 = rnd.randint(20000, 60000)
    while p2 == p1:
        p2 = rnd.randint(20000, 60000)
    nonce = "rr" + secrets.token_hex(8)
    redirect = {"sentinel_port": p1, "canary_host": "127.0.0.1", "canary_port": p2, "nonce": nonce}
    merged = dict(env or {})                                          # RoE-supplied auth/config (reach the vuln branch)
    merged.update({k: "http://127.0.0.1:%d/" % p1 for k in upstream_keys})   # point every named upstream at the sentinel
    params, paths = build_sealed_launcher(argv, workdir, token, extra_env=merged, redirect=redirect)
    drive = asyncio.run(_drive(params, token, timeout))

    report = _read_json(paths["report"])
    server_events = [e for e in _read_events(paths["events"]) if e.get("phase") == "server"]
    strace_text = _read_text(paths["strace_server"]) if report.get("server_started") else None
    problem = observe.integrity_problem(bool(report.get("sealed")), bool(report.get("server_started")),
                                        strace_text, server_events)
    result = problem if problem is not None else observe.classify_redirect_follow(
        server_events, sentinel_port=p1, canary_port=p2, nonce=nonce)
    return {"server": list(argv), "token": token, "upstream_keys": list(upstream_keys),
            "sentinel_port": p1, "canary_port": p2, **result,
            "attempts": [_summary(ev, token) for ev in server_events],
            "proof": report.get("checks", {}), "proof_error": report.get("error"),
            "tools": [t["name"] for t in drive["tools"]], "calls": drive["calls"],
            "driver_error": drive["error"], "workdir": workdir}
