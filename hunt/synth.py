"""Valid-input synthesis: a type/semantics/context/error-aware value factory so a REAL tool actually EXECUTES.

The problem it solves (found in the real open-source-server trial): a probe or the canary run fed a tool a generic
placeholder ("<token> sample") for every parameter. Real tools reject that at their input-validation boundary
("Invalid URL", "Invalid timezone", "outside the allowed repository"), so the code path behind the validation never
runs and nothing is tested. This builds a value that is VALID enough to execute, for the parameters we are not
attacking, so a probe's payload reaches the sink and the canary run actually exercises the server.

It is generic — a new server is DATA, never code:
  schema first    const / enum / default / example / format / pattern / min-max (authoritative, use as-is)
  then semantics  the parameter NAME + DESCRIPTION (url, path, timezone, email, table, host, branch, date, duration…)
  then context    values harvested from the SERVER itself: its launch argv (a --repository / --db-path value is a
                  real path), and strings returned by its own read-only tools (real table names, branches, ids)
  then repair     when the first call fails, the validation error usually names the valid shape or lists the valid
                  options — parse them out and retry once
No tool name or server name is ever special-cased. Pure and deterministic; the caller supplies the live Context.
"""
from __future__ import annotations

import datetime as _dt
import os
import re
import shlex
import uuid
from dataclasses import dataclass, field


@dataclass
class Context:
    """What the caller harvested about THIS server. Everything is optional; more context = more tools that run."""
    base_dir: str = "."                       # a real, writable directory the harness owns (workdir)
    url: str | None = None                    # a real URL that resolves inside the seal (the recorder), for url params
    paths: list[str] = field(default_factory=list)      # real paths harvested from argv (repo, db, dirs, files)
    strings: list[str] = field(default_factory=list)    # identifier-like strings harvested from read-tool output
    token: str = ""                           # the run token (so a synthesized value still carries it when harmless)

    def file(self, name: str = "probe-input.txt") -> str:
        p = os.path.join(self.base_dir, name)
        try:
            if not os.path.exists(p):
                with open(p, "w") as fh:
                    fh.write("sample\n")
        except OSError:
            pass
        return p


# ---- parameter semantics: name/description -> a kind. Order matters (first match wins). -------------------------
_SEMANTICS = [
    ("timezone", re.compile(r"(?i)time[_ ]?zone|\btz\b")),
    ("url", re.compile(r"(?i)\burl\b|\buri\b|endpoint|webhook|href|\blink\b|\bhref\b|address")),
    ("email", re.compile(r"(?i)e[-_ ]?mail")),
    ("repo", re.compile(r"(?i)repo(sitory)?|git[_ ]?dir|work[_ ]?tree")),
    ("path", re.compile(r"(?i)\bpath\b|\bfile\b|\bdir(ectory)?\b|folder|filename|location|db[_ ]?path|source|dest")),
    ("sql_object", re.compile(r"(?i)\btable\b|\bcollection\b|\bschema\b|\bdatabase\b|\bdb[_ ]?name\b")),
    ("host", re.compile(r"(?i)\bhost(name)?\b|\bserver\b|\bdomain\b")),
    ("port", re.compile(r"(?i)\bport\b")),
    ("branch", re.compile(r"(?i)\bbranch\b|\bref\b|\brevision\b|\bcommit\b")),
    ("date", re.compile(r"(?i)\bdate\b|\btime\b|\btimestamp\b|\bwhen\b|_at$|_on$")),
    ("duration", re.compile(r"(?i)\bseconds?\b|\bminutes?\b|\bhours?\b|\bdays?\b|\btimeout\b|\bduration\b|\bage\b|_ago$")),
    ("query", re.compile(r"(?i)\bquery\b|\bsql\b|\bfilter\b|\bsearch\b")),
    ("name", re.compile(r"(?i)\bname\b|\bidentifier\b|\bslug\b|\bkey\b")),
    ("text", re.compile(r"(?i)\btext\b|\bmessage\b|\bcontent\b|\bbody\b|\bnote\b|\bdescription\b|\bsnippet\b|\bcode\b")),
]
_FORMAT = {
    "uri": "url", "url": "url", "iri": "url", "email": "email", "idn-email": "email",
    "hostname": "host", "idn-hostname": "host", "ipv4": "ipv4", "date-time": "datetime", "date": "dateonly",
    "time": "timeonly", "uuid": "uuid", "duration": "iso-duration",
}
_IANA_TZ = "UTC"
_BRANCHES = ("main", "master", "HEAD")


def _looks_repo(p: str) -> bool:
    return p.rstrip("/").endswith(".git") or os.path.isdir(os.path.join(p, ".git")) or "repo" in p.lower()


def _enum_from_error(text: str) -> list[str]:
    """Pull the valid options a validation error lists: 'must be one of [a, b]', 'expected a|b|c', '(a, b)'."""
    for m in re.finditer(r"(?:one of|expected|allowed|choices?|valid values?)\s*[:\-]?\s*[\[\(]?([^\]\)\.\n]+)[\]\)]?", text, re.I):
        parts = re.split(r"\s*(?:,|\||/| or )\s*", m.group(1).strip())
        parts = [p.strip().strip("'\"`") for p in parts if p.strip().strip("'\"`")]
        if 2 <= len(parts) <= 40:
            return parts
    inside = re.search(r"[\[\(]\s*([^\]\)]+?)\s*[\]\)]", text)   # a bare bracketed list
    if inside:
        parts = [p.strip().strip("'\"`") for p in re.split(r"\s*(?:,|\|)\s*", inside.group(1)) if p.strip().strip("'\"`")]
        if 2 <= len(parts) <= 40:
            return parts
    return []


def _quoted_path(text: str) -> str | None:
    """A path the error quotes as the allowed/valid one: 'must be under /srv/app', 'allowed: /data'."""
    m = re.search(r"(?:under|within|inside|allowed|valid|must be|relative to)[^/]{0,24}(/[\w./-]+)", text, re.I)
    return m.group(1) if m else None


def _kind(name: str, schema: dict) -> str:
    desc = " ".join(str(schema.get(k, "")) for k in ("description", "title"))
    hay = f"{name} {desc}"
    for kind, rx in _SEMANTICS:
        if rx.search(hay):
            return kind
    return "string"


# ---- the factory ------------------------------------------------------------------------------------------------
def value(name: str, schema: dict, ctx: Context, *, want_string_payload: str | None = None, depth: int = 0):
    """A valid value for one parameter. `want_string_payload`: for the parameter under attack, carry this exact
    string INSTEAD of a synthesized value (so the payload reaches the sink) — still valid-shaped by type."""
    schema = schema if isinstance(schema, dict) else {}
    if "const" in schema:
        return schema["const"]
    enum = schema.get("enum")
    if enum:
        return enum[0]
    t = schema.get("type")
    if isinstance(t, list):
        t = next((x for x in t if x != "null"), "string")
    # object / array first (recurse), independent of the string payload
    if t == "object" or (t is None and "properties" in schema):
        props = schema.get("properties", {}) or {}
        req = set(schema.get("required", list(props)))
        return {k: value(k, v, ctx, depth=depth + 1) for k, v in props.items() if k in req or depth < 1} if depth < 4 else {}
    if t == "array":
        if depth >= 3:
            return []
        item = schema.get("items", {}) if isinstance(schema.get("items"), dict) else {}
        inner = want_string_payload if want_string_payload is not None else value("item", item, ctx, depth=depth + 1)
        return [inner]
    if t in ("integer", "number"):
        return _number(name, schema, t)
    if t == "boolean":
        return bool(schema.get("default", False))
    # string (or untyped): attack payload wins; else default/example/format/semantics
    if want_string_payload is not None:
        return want_string_payload
    for k in ("default", "example"):
        if isinstance(schema.get(k), str):
            return schema[k]
    if isinstance(schema.get("examples"), list) and schema["examples"]:
        return schema["examples"][0]
    fmt = _FORMAT.get(str(schema.get("format", "")).lower())
    return _string(_kind(name, schema), schema, ctx, fmt)


def _number(name: str, schema: dict, t: str):
    lo = schema.get("minimum", schema.get("exclusiveMinimum"))
    hi = schema.get("maximum", schema.get("exclusiveMaximum"))
    if lo is not None and hi is not None:
        v = (lo + hi) / 2
    elif lo is not None:
        v = lo + 1
    elif hi is not None:
        v = hi - 1
    elif re.search(r"(?i)port", name):
        v = 8080
    else:
        v = schema.get("default", 1)
    return int(v) if t == "integer" else float(v)


def _string(kind: str, schema: dict, ctx: Context, fmt: str | None):
    f = fmt or kind
    if f in ("url", "ipv4") or kind == "url":
        return ctx.url or "http://127.0.0.1:9/"
    if f == "host" or kind == "host":
        return "127.0.0.1"
    if f == "email" or kind == "email":
        return "dev@example.com"
    if f == "uuid":
        return str(uuid.UUID(int=0))
    if f == "datetime":
        return _dt.datetime(2026, 1, 1, tzinfo=_dt.timezone.utc).isoformat()
    if f == "dateonly":
        return "2026-01-01"
    if f == "timeonly":
        return "12:00:00"
    if f == "iso-duration":
        return "PT1S"
    if kind == "timezone":
        return _IANA_TZ
    if kind == "repo":
        return next((p for p in ctx.paths if _looks_repo(p)), None) or next(iter(ctx.paths), ctx.base_dir)
    if kind == "path":
        desc = (str(schema.get("description", "")) + " " + str(schema.get("title", ""))).lower()
        if re.search(r"dir(ectory)?|folder", desc):
            return next((p for p in ctx.paths if os.path.isdir(p)), ctx.base_dir)
        return next((p for p in ctx.paths if os.path.isfile(p)), None) or ctx.file()
    if kind == "sql_object":
        return next((s for s in ctx.strings if re.fullmatch(r"[A-Za-z_][\w]*", s)), None) or "data"
    if kind == "branch":
        return next((s for s in ctx.strings if s in _BRANCHES), None) or _BRANCHES[0]
    if kind == "query":
        return "1"
    _min = schema.get("minLength", 0)
    base = next((s for s in ctx.strings if len(s) >= _min), None)
    if base:
        return base
    return (ctx.token + " sample").strip() if (ctx.token and _min <= len(ctx.token) + 7) else ("x" * max(_min, 1))


# ---- repair: a failed call's error usually tells us the valid shape; fix one param and retry -------------------
_TZ_ERR = re.compile(r"(?i)time[_ ]?zone")
_URL_ERR = re.compile(r"(?i)\burl\b|\buri\b")
_PATH_ERR = re.compile(r"(?i)outside|not allowed|permitted|does not exist|no such file|not a directory|invalid path")


def repair(args: dict, schema: dict, ctx: Context, error_text: str) -> dict | None:
    """Given the args that failed and the server's error, return a corrected args dict, or None if we can't tell.
    Fixes the kind of error that validation raises: an unlisted enum, an invalid url/timezone/path/number."""
    if not error_text:
        return None
    props = (schema.get("properties") or {})
    new = dict(args)
    changed = False
    options = _enum_from_error(error_text)
    allowed_path = _quoted_path(error_text)
    for pname, pval in args.items():
        if not isinstance(pval, (str, int, float)):
            continue
        hay = f"{pname} {(props.get(pname) or {}).get('description', '')}"
        if options and isinstance(pval, str) and pval not in options:
            new[pname] = options[0]
            changed = True
        elif _TZ_ERR.search(error_text) and _kind(pname, props.get(pname) or {}) == "timezone":
            new[pname] = _IANA_TZ
            changed = True
        elif _URL_ERR.search(error_text) and (_kind(pname, props.get(pname) or {}) == "url"):
            new[pname] = ctx.url or "http://127.0.0.1:9/"
            changed = True
        elif (allowed_path or _PATH_ERR.search(error_text)) and _kind(pname, props.get(pname) or {}) in ("path", "repo"):
            new[pname] = allowed_path or next(iter(ctx.paths), ctx.base_dir)
            changed = True
    return new if changed else None


# ---- context harvest --------------------------------------------------------------------------------------------
_PATH_FLAG = re.compile(r"(?i)^--?(repo(sitory)?|db([_-]?path)?|dir|root|path|file|work([_-]?tree)?|cwd|source)$")


def harvest_argv(argv) -> list[str]:
    """Real paths the server was launched with: a `--repository /srv/x` value, a bare absolute path argument, and
    the parent directory of a file argument (its directory is usually a valid target too)."""
    toks = argv if isinstance(argv, list) else shlex.split(str(argv))
    paths, i = [], 0
    while i < len(toks):
        tok = toks[i]
        val = None
        if _PATH_FLAG.match(tok) and i + 1 < len(toks):
            val = toks[i + 1]
            i += 1
        elif "=" in tok and _PATH_FLAG.match(tok.split("=", 1)[0]):
            val = tok.split("=", 1)[1]
        elif tok.startswith("/") and not tok.endswith(".py"):
            val = tok
        if val and val.startswith("/"):
            paths.append(val)
            d = os.path.dirname(val)
            if d and d != "/" and d not in paths:
                paths.append(d)
        i += 1
    # de-dup, keep order
    seen, out = set(), []
    for p in paths:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


_IDENT = re.compile(r"(?<![\w.])[A-Za-z_][A-Za-z0-9_]{1,40}(?![\w.])")


def harvest_strings(text: str, limit: int = 40) -> list[str]:
    """Identifier-like strings a read tool returned (real table names, branch names, ids) — reused as valid inputs."""
    if not text:
        return []
    out, seen = [], set()
    for m in _IDENT.finditer(text):
        s = m.group(0)
        if s.lower() in ("the", "and", "for", "with", "null", "true", "false", "none", "error", "sample") or s in seen:
            continue
        seen.add(s)
        out.append(s)
        if len(out) >= limit:
            break
    return out
