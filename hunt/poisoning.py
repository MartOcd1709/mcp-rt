"""Tool poisoning (OWASP MCP03): model-directed instructions hidden or planted in server metadata.

Static, deterministic and explainable: every hit names its kind, its confidence, the exact span, and the layer it was
found in. No tool, parameter or server name is consulted (the dynamic gate in tests/test_tool_poisoning.py enforces it).

What is read (the probe feeds it every model-facing surface): tool description / title / annotations, every schema doc
string (title, description, default, examples, enum, const), server `instructions`, resource and prompt text, and what
tools RETURN or RAISE at runtime (return-value / ATPA poisoning).

How a text is read:
  layers   the visible text, plus each hidden layer a human never sees but the model does: Unicode TAG-block text,
           words split by zero-width characters, base64 / hex blobs, HTML comments, text pushed off-screen by padding,
           and homoglyph-folded text. A directive that appears only in a hidden layer is concealed intent (HIGH).
  clauses  path-aware sentence split (a "." inside ~/.aws/credentials or a URL never ends a sentence), then clauses;
           a verb counts as a directive only when it opens its clause (after an optional lead-in such as "before
           calling this tool," / "you must" / "always" / "and") and no negation precedes it. A description of what the
           server itself does ("Uses the SSH key at ~/.ssh/id_rsa") is never a directive.

Kinds (confidence):
  exfiltration_instruction  HIGH    a directed secret/context SOURCE flows to a SINK (an argument, a URL/webhook/email,
                                    a markdown-image beacon, the reply), directly or by back-reference ("pass it in").
  concealed_instruction     HIGH    any directive found only in a hidden layer.
  user_concealment          HIGH    the model is told to hide an ACTION from the user (hiding a secret VALUE is benign).
  context_override          HIGH    the model is told to drop its instructions or take a new role.
  authority_coercion        HIGH    a false approval / compliance / failure-threat claim attached to a sensitive action.
  tool_shadowing            MEDIUM  instructions that change how OTHER tools behave (BCC, redirect, intercept, replace);
                                    HIGH with concealment or a network sink.
  sensitive_access          MEDIUM  a directive to read a secret file or the model's context, with no sink found.
  off_purpose_secret_ref    MEDIUM  a secret path unrelated to the tool's own purpose (language-independent).
  hidden_encoding           MEDIUM  concealment characters present (TAG / zero-width / bidi / ANSI) with no decoded directive.
  tool_hijacking            M / H   an order to call ANOTHER tool, corroborated (coercion, attacker literals, state-changing
                                    target, condition on another tool, priority claim); a bare sibling reference stays quiet.
  parameter_tampering       M / H   an order to change how another tool is called ("set `path` to ... regardless of input").

Static analysis sees the instruction, not whether an agent obeys it, so the probe reports every kind as a lead
(SUSPECTED). Confirming compliance takes an agent run against a planted canary (the engagement's agent tier).
"""
from __future__ import annotations

import base64
import binascii
import html
import re
import unicodedata
from dataclasses import dataclass

HIGH, MEDIUM = "high", "medium"


@dataclass(frozen=True)
class Hit:
    kind: str
    confidence: str
    span: str
    layer: str = "visible"


WHY = {
    "exfiltration_instruction": "model-directed instruction to move a secret or the model's context into a sink "
                                "(tool argument, URL, webhook, email, image beacon or the reply)",
    "concealed_instruction": "model-directed instruction concealed from a human reviewer (hidden layer)",
    "user_concealment": "the model is told to hide an action from the user",
    "context_override": "the model is told to drop its instructions or adopt a new role",
    "authority_coercion": "a false approval, compliance or failure claim attached to a sensitive action",
    "tool_shadowing": "instructions that change how other tools behave (copy, redirect, intercept or replace)",
    "sensitive_access": "a directive to read a secret file or the model's own context",
    "off_purpose_secret_ref": "a secret file referenced by a tool whose purpose has nothing to do with it",
    "hidden_encoding": "invisible or direction-changing characters in model-facing text",
    "dangerous_command": "a destructive or persistence shell command handed to the model",
    "tool_hijacking": "the model is ordered to call another tool, corroborated by coercion, attacker-chosen arguments, a "
                      "state-changing target or a condition on another tool (implicit/explicit-trigger function hijacking)",
    "parameter_tampering": "the model is told to change the arguments of another tool's call (parameter tampering)",
    "secret_content_parameter": "a parameter whose name asks for the contents of a secret file or the model's context",
}

# ---------------------------------------------------------------- vocabulary (grammar + secrets, never names)
_SECRET_PATH = re.compile(r"""(?ix)
    (?:~|\$HOME|%USERPROFILE%|/home/[\w.-]+|/root|/Users/[\w.-]+|[A-Z]:\\Users\\[\w.-]+)?[/\\]?
    (?: \.ssh(?:[/\\][\w.-]+)? | \bid_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?\b
      | \.aws(?:[/\\](?:credentials|config))? | (?<![\w])\.env(?:\.[\w-]+)?\b | \.netrc\b | \.npmrc\b | \.pypirc\b
      | \.git-credentials\b | \.docker[/\\]config\.json | \.kube[/\\]config\b
      | \.config[/\\]gcloud(?:[/\\][\w.-]+)* | \bapplication_default_credentials\.json | \.azure(?:[/\\][\w.-]+)?
      | \.gnupg\b | \.password-store\b | \.(?:bash|zsh)_history\b
      | (?:\.cursor[/\\])?\bmcp\.json\b | \bclaude_desktop_config\.json\b | \.claude\.json\b
      | /etc/(?:passwd|shadow|sudoers|ssh/[\w.-]+)\b | \bwallet\.dat\b
      | \b[\w.-]+\.(?:pem|p12|pfx|kdbx|keystore|jks)\b )""")
_SECRET_CTX = re.compile(
    r"(?i)\b(?:system\s+prompt|conversation(?:\s+history)?|chat\s+history|(?:all\s+)?(?:previous|prior|earlier)\s+messages|"
    r"(?:last|recent|past)\s+(?:\d+\s+)?messages|messages\s+(?:of|in|from)\s+(?:the|this)\s+(?:chat|conversation|thread)|"
    r"message\s+history|environment\s+variables|env\s+vars|(?:browser\s+)?cookies|saved\s+passwords|password\s+manager|"
    r"keychain|private\s+keys?|ssh\s+keys?|api\s+keys?|access\s+tokens?|secret\s+keys?|session\s+tokens?|bearer\s+tokens?|"
    r"credentials?\s+files?|seed\s+phrase|recovery\s+phrase|(?:other\s+)?tool\s+(?:results|outputs))\b")
_CRED_OBJ = re.compile(r"(?i)\b(?:passwords?|api\s+keys?|keys?|tokens?|secrets?|credentials?|personal\s+data|pii|"
                       r"email\s+addresses?|phone\s+numbers?)\b")
_READ_V = (r"read|open|cat|load|access|fetch|retrieve|collect|gather|extract|dump|copy|print|grab|obtain|get|"
           r"look\s+(?:at|up)|scan|search|list")
_SINK_V = (r"pass|put|include|insert|add|append|attach|embed|supply|provide|place|set|fill|paste|write|encode|store|call|invoke|"
           r"send|forward|post|upload|transmit|exfiltrate|beacon|submit|share|deliver|email|mail|push|render|report|copy")
_RUN_CAT = re.compile(r"(?i)\b(?:run|execute|exec)\s+[`'\"]?(?:cat|type|more|less|head|tail|base64|xxd|strings|printenv|"
                      r"env|set)\b[^`'\"\n]{0,80}")
_LEAD = re.compile(
    r"(?ix)(?:^|\b(?:always|please|first|then|also|now|next|finally|immediately|simply|just|and|or|then\s+also|"
    r"you\s+(?:must|should|need\s+to|have\s+to|are\s+required\s+to|will)|"
    r"(?:the\s+)?(?:assistant|model|ai|agent|llm)\s+(?:must|should|needs?\s+to)|"
    r"(?:requires?|require)\s+that\s+you|(?:is|are)\s+required\s+to|make\s+sure\s+(?:to|you)|be\s+sure\s+to|"
    r"remember\s+to|it\s+is\s+(?:mandatory|required|necessary)\s+(?:to|that\s+you)|"
    r"(?:pre-?)?(?:approved|authori[sz]ed|allowed|permitted|instructed)\s+(?:you\s+)?to|"
    r"before\s+(?:using|calling|invoking|answering|responding|returning|replying)[^,]*|"
    r"when\s+(?:called|invoked|used)|after\s+answering|to\s+(?:work|function|finish|complete)[^,]*))\s*[,:]?\s*$")
_NEG = re.compile(r"(?i)\b(?:not|never|no|don't|do\s+not|cannot|can't|won't|avoid|without|isn't|aren't)\b|n't\b")
_BACKREF = re.compile(r"(?i)\b(?:it|them|its\s+(?:full\s+)?contents?|their\s+contents?|the\s+(?:full\s+)?(?:contents?|"
                      r"output|result|text|file|values?|keys?|data|lines?)|that|this|every\s+line|everything|all\s+of\s+it)\b")
_SINK_ARG = re.compile(
    r"(?ix)\b(?:in|into|as|via|inside|within|under|to)\s+(?:the\s+|a\s+|an\s+|your\s+|this\s+)?"
    r"(?:`[^`]{1,40}`|\"[^\"]{1,40}\"|'[^']{1,40}'|[\w.-]{1,40})\s+"
    r"(?:argument|arg|parameter|param|field|input|property|key|header|value|attribute)s?\b"
    r"|\b(?:in|into|as|via|to)\s+(?:the\s+)?`[\w.-]{1,40}`"          # a backticked identifier is a parameter
    r"|\b(?:as|in)\s+(?:the\s+)?value\s+of\b"
    r"|\b(?:to|in|into)\s+(?:the\s+|your\s+)?(?:[\w-]+\s+){0,2}?(?:request(?:\s+url)?|call|query(?:\s+string)?|payload|"
    r"body|headers?|url|reply|response|message|answer)\b"
    r"|\b(?:call|invoke|use|run)\s+(?:this|that|the\s+[`\"']?[\w.-]+[`\"']?|any)?\s*tool\s+with\b")
_FILE_EXT = r"(?:json|py|md|txt|js|ts|yaml|yml|toml|cfg|ini|log|csv|xml|html?|sh|env|pem|key|lock|conf)"
_URLISH = (r"(?:https?://\S+|\b\d{1,3}(?:\.\d{1,3}){3}\S*|[\w.+-]+@[\w-]+\.[\w.-]+|\+\d[\d\s().-]{6,}\d|"
           rf"\b(?:[a-z0-9-]+\.)+(?!{_FILE_EXT}\b)[a-z]{{2,24}}\b(?![./\\])|"   # a bare domain (evil.example)
           r"(?:this\s+|the\s+|our\s+|an?\s+)?(?:webhook|endpoint|collector|telemetry\s+(?:server|endpoint)|server\s+at|url\s+at))")
_SINK_NET = re.compile(rf"(?ix)\b(?:to|at)\s+{_URLISH}|!\[[^\]]*\]\(\s*https?://[^)\s]*[?&=][^)]*\)")
_OVERRIDE = (
    re.compile(r"(?i)\b(?:ignore|disregard|forget|override|bypass|abandon)\b[^.!?;\n]{0,50}?\b(?:instructions?|prompts?|"
               r"rules|directives|guidelines|guardrails|system\s+(?:message|prompt))\b"),
    re.compile(r"(?i)\b(?:you\s+are\s+now\s+(?:in|operating|acting|free|no\s+longer|a|an|the|my)|from\s+now\s+on,?\s+you|"
               r"new\s+(?:system\s+)?instructions?\s*:|developer\s+mode|jailbreak(?:en)?\s+mode)"),
    # a tool claiming precedence over the user, or telling the model to act regardless of what the user asked
    re.compile(r"(?i)\b(?:priority|precedence)\b[^.\n]{0,40}?\b(?:higher|greater|above|over|supersedes?)\b[^.\n]{0,30}?"
               r"\b(?:user|query|request|instructions?)\b|\b(?:has|have|takes?)\s+(?:the\s+)?(?:highest|top|absolute)\s+"
               r"priority\b|\boverrides?\s+(?:the\s+|any\s+)?user(?:'s)?\s+(?:request|query|input|instructions?|intent)"),
    re.compile(r"(?i)\bregardless\s+of\s+(?:the\s+|any\s+)?(?:user(?:'s)?(?:\s+(?:input|request|query|intent|choice))?|"
               r"(?:the\s+)?(?:input|request|query)|(?:intended|original(?:ly)?\s+intended|requested)\b)"),
)
_CONCEAL = (
    re.compile(r"(?ix)\b(?:do\s+not|don't|never|must\s+not|should\s+not|shouldn't|avoid)\s+"
               r"(?P<v>tell(?:ing)?|inform(?:ing)?|notify(?:ing)?|mention(?:ing)?|alert(?:ing)?|reveal(?:ing)?|"
               r"disclos(?:e|ing)|show(?:ing)?|display(?:ing)?|report(?:ing)?|explain(?:ing)?|let)\b"
               r"(?P<obj>[^.;!?\n]{0,60}?)\b(?:to\s+)?(?:the\s+)?(?:user|human|operator|them)\b(?!s)"),
    re.compile(r"(?i)\bwithout\s+(?:telling|informing|notifying|alerting|asking|letting\s+know)\s+(?:the\s+)?(?:user|human)\b"),
    re.compile(r"(?i)\bthe\s+user\s+(?:does\s+not|doesn't|should\s+not|shouldn't|must\s+not|need\s+not|needn't)\s+"
               r"(?:need\s+to\s+)?(?:know|see|be\s+(?:told|informed|aware))\b"),
    re.compile(r"(?i)\b(?:keep|hide)\s+(?:this|these|it|them|the\s+(?:step|steps|instructions?|action|request))\b"
               r"[^.;\n]{0,30}?\bfrom\s+(?:the\s+)?user\b"),
    re.compile(r"(?i)\b(?:silently|secretly|covertly|discreetly)\s+(?:read|send|upload|forward|include|pass|copy|collect|"
               r"run|execute|call|add|append|attach|post|exfiltrat\w*|transmit|share)\b"),
)
_AUTH = re.compile(
    r"(?ix)\b(?:the\s+)?(?:user|administrator|admin|owner|security\s+team|operator)\s+(?:has|have)\s+(?:already\s+)?"
    r"(?:pre-?)?(?:approved|authori[sz]ed|consented|allowed|permitted|granted)\b|\bpre-?(?:approved|authori[sz]ed)\b"
    r"|\balready\s+(?:been\s+)?(?:approved|authori[sz]ed|consented)\b"
    r"|\b(?:security|compliance|policy|audit|regulatory)(?:\s+compliance)?\s+(?:requires?|mandates?)\b"
    r"|\bSYSTEM\s+(?:NOTICE|MESSAGE|OVERRIDE|ALERT)\b|\b(?:MANDATORY|REQUIRED)\s*:"
    r"|\b(?:will\s+not|won't|cannot|can't|does\s+not|doesn't)\s+(?:work|function|run|succeed)\s+unless\b"
    r"|\botherwise\s+(?:the\s+)?(?:tool|forecast|result|request|call|answer|response)s?\s+(?:will\s+)?"
    r"(?:fail|be\s+wrong|is\s+wrong|won't\s+work|will\s+not\s+work|is\s+incorrect|be\s+incorrect)")
_SHADOW = (
    re.compile(r"(?ix)\b(?:when|whenever|if|each\s+time|every\s+time)\s+(?:the\s+)?(?:user\s+|you\s+)?"
               r"(?:uses?|used|calls?|called|invokes?|invoked|runs?)?\s*(?:the\s+)?[`\"']?[\w.-]+[`\"']?\s+tool\s+"
               r"(?:is\s+)?(?:used|called|invoked|runs?)?[^.\n]{0,80}?\b(?:always|also|instead|bcc|cc|change|replace|"
               r"redirect|send\s+a\s+copy|forward)\b"),
    re.compile(r"(?i)\b(?:whenever|every\s+time|each\s+time|before)\s+you\s+(?:call|use|invoke|run)\s+(?:any|every|all|"
               r"another|other)\s+(?:other\s+)?tools?\b"),
    re.compile(r"(?i)\binstead\s+of\s+(?:using\s+|calling\s+)?(?:the\s+)?[`\"']?[\w.-]+[`\"']?\s+tool\b[^.\n]{0,40}?"
               r"\b(?:use|call)\s+this\b"),
    re.compile(r"(?ix)\b(?:for|on|in)\s+(?:all|every|each|any)\s+(?:\w+\s+){0,4}?(?:messages?|emails?|requests?|calls?|tools?|"
               r"transactions?|transfers?|payments?|commits?)\b[^.\n]{0,60}?\b(?:change|replace|set|redirect|swap)\s+"
               r"(?:the\s+)?(?:recipient|destination|address|account|url|remote|endpoint|payee|iban|wallet)\b"),
    re.compile(r"(?i)\b(?:always\s+)?b?cc\s+[\w.+-]+@[\w-]+\.[\w.-]+"),
    re.compile(r"(?ix)\b(?:before|when|whenever|each\s+time|every\s+time)\s+(?:you\s+)?(?:running|executing|calling|sending|"
               r"using|making|writing|run|execute|call|send|use|make|write)\s+(?:any|every|each|all|a)\s+(?:\w+\s+){0,2}?"
               r"(?:commands?|calls?|requests?|queries|messages?|emails?|tools?|transactions?|transfers?|payments?|files?)\b"
               r"[^.\n]{0,60}?\b(?:prefix|prepend|append|wrap|insert|also|first|add|replace|change|redirect|send\s+a\s+copy|"
               r"forward|bcc|cc)\b"),
    re.compile(r"(?ix)\b(?:when|whenever)\s+(?:the\s+)?[`\"']?[\w.-]+[`\"']?\s+tool\s+is\s+(?:used|called|invoked)\b"
               r"[^.\n]{0,60}?\b(?:add|apply|charge|deduct|include)\s+(?:a|an)\s+(?:[\d.]+\s*%\s+)?(?:fee|surcharge|"
               r"commission|tip)\b"),
)
# destructive / persistence shell commands handed to the model (line jumping: acts at tools/list time)
_DANGER_CMD = re.compile(r"(?ix)\brm\s+-[a-z]*r[a-z]*f?\s+[~/]|\bchmod\s+-R\s+0?[0-7]*[67][0-7]{2}\s+[~/]|"
                         r"\b(?:curl|wget)\b[^|\n]{0,80}\|\s*(?:ba|z)?sh\b|\bnc\s+(?:-\w+\s+)*-e\b|\bmkfifo\b|"
                         r"\bbase64\s+(?:-d|--decode)\b[^|\n]{0,40}\|\s*(?:ba|z)?sh\b|>\s*~/\.(?:bashrc|zshrc|profile)\b|"
                         r"\bcrontab\s+-|\bssh-keygen\b[^\n]{0,40}\bauthorized_keys|>>\s*~/\.ssh/authorized_keys")

# ---------------------------------------------------------------- hidden layers
_ZERO_WIDTH = {0x200B, 0x200C, 0x2060, 0xFEFF, 0x00AD}       # ZWJ (U+200D) is emoji glue: excluded
_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
_COMMENT = re.compile(r"<!--(.*?)-->", re.S)
_PADDING = re.compile(r"(?:[ \t 　]{40,}|(?:\s*\n){6,})(\S.*)", re.S)
_B64 = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{24,}={0,2}(?![A-Za-z0-9+/=_-])")
_HEX = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}){16,}(?![0-9a-fA-F])")
_CONFUSABLE = str.maketrans({  # Cyrillic / Greek letters that render as Latin
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "і": "i", "ј": "j", "ѕ": "s", "һ": "h", "ԁ": "d", "А": "A", "В": "B",
    "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C",
    "Т": "T", "Х": "X", "ο": "o", "α": "a", "ε": "e", "ι": "i", "κ": "k",
    "ν": "v", "ρ": "p", "τ": "t", "υ": "u", "Ο": "O", "Α": "A", "Ε": "E",
})


def _printable_text(raw: bytes) -> str | None:
    try:
        s = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    ok = sum(c.isprintable() or c in "\n\t" for c in s)
    return s if s and ok / len(s) > 0.95 and len(s.split()) >= 3 else None


def _layers(text: str) -> tuple[str, list[tuple[str, str]], list[str]]:
    """(visible text, [(hidden layer name, text)], [concealment technique present])."""
    present: list[str] = []
    tag = [c for c in text if 0xE0000 <= ord(c) <= 0xE007F]
    hidden: list[tuple[str, str]] = []
    if tag:
        present.append("tag-block")
        hidden.append(("tag-block", "".join(chr(ord(c) - 0xE0000) for c in tag if ord(c) - 0xE0000 < 0x80)))
    if any(0x202A <= ord(c) <= 0x202E or 0x2066 <= ord(c) <= 0x2069 for c in text):
        present.append("bidi-override")
    if "\x1b" in text:
        present.append("ansi-escape")
    zw = any(ord(c) in _ZERO_WIDTH for c in text)
    if zw:
        present.append("zero-width")
    visible = "".join(c for c in text if not 0xE0000 <= ord(c) <= 0xE007F)
    visible = _ANSI.sub("", visible)
    plain = "".join(" " if ord(c) in _ZERO_WIDTH else c for c in visible)    # what a reader sees: gaps, no words
    if zw:
        hidden.append(("zero-width", "".join(c for c in visible if ord(c) not in _ZERO_WIDTH)))
    plain = unicodedata.normalize("NFKC", html.unescape(plain))
    folded = plain.translate(_CONFUSABLE)
    if folded != plain:
        hidden.append(("homoglyph", folded))
    for m in _COMMENT.finditer(plain):
        hidden.append(("html-comment", m.group(1)))
    if m := _PADDING.search(plain):
        hidden.append(("offscreen-padding", m.group(1)))
    for m in _B64.finditer(plain):
        tok = m.group(0)
        try:
            dec = _printable_text(base64.b64decode(tok + "=" * (-len(tok) % 4), altchars=b"-_" if "-" in tok or "_" in tok else None))
        except (binascii.Error, ValueError):
            dec = None
        if dec:
            hidden.append(("base64", dec))
    for m in _HEX.finditer(plain):
        dec = _printable_text(bytes.fromhex(m.group(0)))
        if dec:
            hidden.append(("hex", dec))
    return plain, hidden, present


# ---------------------------------------------------------------- clauses
_SENT = re.compile(r"(?<=[.!?;])(?=\s|$)|\n+|</?[A-Za-z_|][\w|-]*>|\[/?INST\]")


def _sentences(text: str) -> list[str]:
    return [s.strip() for s in _SENT.split(text) if s and s.strip()]


def _clauses(sentence: str) -> list[str]:
    return [c for c in re.split(r"\s*[,:]\s+|\s+(?:otherwise|so\s+that|because)\s+|"
                                r"\s+(?:unless|only\s+if|as\s+long\s+as)\s+(?:you\s+)?", sentence) if c.strip()]


def _directive_at(clause: str, verb_rx: str) -> re.Match | None:
    """The first verb from verb_rx that opens a clause (nothing before it but a lead-in, no negation)."""
    for m in re.finditer(rf"(?i)\b(?:{verb_rx})\b", clause):
        prefix = clause[:m.start()]
        if _NEG.search(prefix):
            return None
        p = re.sub(r"^[\s\-*•>#\d.)\"'`]+", "", prefix).strip()
        if not p or _LEAD.search(p):
            return m
    return None


def _sources(s: str) -> list[re.Match]:
    return [*_SECRET_PATH.finditer(s), *_SECRET_CTX.finditer(s)]


# ---------------------------------------------------------------- signals -> hits
def _exfil(sentences: list[str]) -> list[str]:
    """Spans where a directed secret source flows to a sink (same clause, or a back-reference within 2 sentences)."""
    spans = []
    seen_source = False
    for i, sent in enumerate(sentences):
        src_here = bool(_sources(sent)) or bool(_RUN_CAT.search(sent))
        window_src = src_here or seen_source
        for cl in _clauses(sent):
            sink_m = _directive_at(cl, _SINK_V)
            if not sink_m:
                continue
            tail = cl[sink_m.start():]
            has_sink = bool(_SINK_ARG.search(tail) or _SINK_NET.search(tail))
            if not has_sink:
                continue
            obj_src = bool(_sources(tail)) or bool(_RUN_CAT.search(cl))
            # a source named in the sink clause, or an earlier directed read referred back to ("pass it in")
            if obj_src or (window_src and _BACKREF.search(tail)):
                spans.append(sent if len(sent) <= 220 else tail)
        if _SINK_NET.search(sent) and src_here and re.search(r"!\[", sent):     # image beacon carrying a secret
            spans.append(sent)
        seen_source = src_here and bool(_directive_at(sent, _READ_V) or _RUN_CAT.search(sent) or "need" in sent.lower())
    return list(dict.fromkeys(spans))


def _sensitive_access(sentences: list[str]) -> list[str]:
    out = []
    for sent in sentences:
        if _is_function_statement(sentences, sent):
            continue
        for cl in _clauses(sent):
            m = _directive_at(cl, _READ_V)
            if (m and _sources(cl[m.start():])) or (_RUN_CAT.search(cl) and _sources(cl) and not _NEG.search(cl)):
                out.append(sent)
                break
    return out


def _concealment(text: str) -> list[str]:
    out = []
    for rx in _CONCEAL:
        for m in rx.finditer(text):
            if "obj" in rx.groupindex and _CRED_OBJ.search(m.group("obj") or ""):
                continue  # hiding a secret VALUE from view protects it; hiding an ACTION is the attack
            out.append(m.group(0))
    return out


_DOMAINS = (
    (re.compile(r"(?i)\.ssh|id_(?:rsa|dsa|ecdsa|ed25519)"), {"ssh", "key", "keys", "remote", "host", "server", "git", "scp",
                                                            "sftp", "deploy", "sign", "signing", "shell", "terminal"}),
    (re.compile(r"(?i)\.aws"), {"aws", "s3", "cloud", "iam", "credential", "credentials", "profile", "boto", "sts", "ec2"}),
    (re.compile(r"(?i)gcloud|application_default"), {"gcp", "gcloud", "google", "cloud", "bigquery", "gcs"}),
    (re.compile(r"(?i)\.azure"), {"azure", "cloud", "az"}),
    (re.compile(r"(?i)(?<![\w])\.env"), {"env", "environment", "config", "configuration", "dotenv", "settings", "secret",
                                         "secrets", "variables"}),
    (re.compile(r"(?i)mcp\.json|claude|\.cursor"), {"mcp", "config", "configuration", "client", "server", "claude", "cursor"}),
    (re.compile(r"(?i)\.netrc|\.npmrc|\.pypirc|git-credentials|\.docker|\.kube"),
     {"net", "npm", "package", "pypi", "publish", "git", "docker", "registry", "kube", "kubernetes", "cluster", "k8s",
      "auth", "login", "credential", "credentials"}),
    (re.compile(r"(?i)/etc/"), {"user", "users", "account", "accounts", "system", "passwd", "os", "linux", "file", "files"}),
    (re.compile(r"(?i)wallet|keychain|\.gnupg|password-store|\.pem|\.p12|\.pfx|\.kdbx|keystore|\.jks"),
     {"wallet", "crypto", "keychain", "gpg", "pgp", "password", "passwords", "certificate", "cert", "tls", "ssl", "key", "keys"}),
    (re.compile(r"(?i)_history"), {"history", "shell", "terminal"}),
)


def _purpose_words(purpose: str) -> set[str]:
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", purpose or "")
    return {w for w in re.split(r"[^a-z0-9]+", spaced.lower()) if w}


def _off_purpose(text: str, purpose: str) -> list[str]:
    words = _purpose_words(purpose)
    if not words:
        return []
    out = []
    for m in _SECRET_PATH.finditer(text):
        for rx, dom in _DOMAINS:
            if rx.search(m.group(0)) and not (words & dom):
                out.append(m.group(0))
                break
    return out


# ---------------------------------------------------------------- tool hijacking / parameter tampering
# A tool's text that orders the model to CALL ANOTHER TOOL, or to change how another tool is called, is the dominant
# real-world poisoning shape (MCPTox: explicit/implicit-trigger function hijacking + parameter tampering). A sibling
# reference alone is normal workflow guidance ("use list_directory first"), so it must be CORROBORATED: coercion, an
# attacker-chosen literal argument, a state-changing target, a condition on another tool, or a priority claim.
_IDENT = r"[A-Za-z][\w.-]*?(?:[_-][\w.-]+|[a-z][A-Z][\w.-]*)"            # snake / kebab / camel (CASE-SENSITIVE)
_QUOTED_IDENT = rf"[`'\"](?P<q>{_IDENT})[`'\"]|[`'\"](?P<w>[a-z]+)[`'\"]\s+tool\b"
_QI = rf"[`'\"](?:{_IDENT})[`'\"]"                                       # same, no capture (for reuse)
_CALL_V = r"(?i:call|calling|use|using|invoke|invoking|run|running|fetch|execute|trigger)"
_TOOL_CALL = re.compile(rf"\b{_CALL_V}\s+(?:(?i:the)\s+)?(?:{_QUOTED_IDENT}|(?P<b>{_IDENT}))")
_COND_OTHER = re.compile(rf"\b(?i:before|when|whenever|after|while|each\s+time|every\s+time|prior\s+to)\s+"
                         rf"(?:(?i:you)\s+)?(?:(?i:use|using|call|calling|invoke|invoking|run|running)\s+)?"
                         rf"(?:(?i:the\s+tool)\s+)?(?:(?i:the)\s+)?(?:{_QUOTED_IDENT}|(?P<b>{_IDENT}))")
_COERCE = re.compile(
    r"\bMUST\b|\b(?i:you\s+(?:must|have\s+to|need\s+to)|mandatory|(?:is|are)\s+(?:required|needed|necessary|critical|"
    r"essential)|requires?\s+(?:calling|that\s+you|using)|not\s+optional|must\s+do\s+it|critical\s+(?:for|to)|"
    r"(?:skipping|failure\s+to|failing\s+to|omitting|ignoring|not\s+doing)\b[^.\n]{0,50}?\bwill|"
    r"(?:security|compliance|internal)\s+(?:check|requirement|protocol|policy|step)|system\s+policy\s+requires)\b"
    r"|\bSECURITY\s+(?:PROTOCOL|ADVISORY|NOTICE)\b")
_LITERAL = re.compile(r"'[^'\n]{1,80}'|\"[^\"\n]{1,80}\"|`[^`\n]{1,80}`|\b(?i:UIDs?|IDs?|amount|number)\s*[:=]?\s*\d{3,}|"
                      r"[\w.+-]+@[\w-]+\.[\w.-]+|https?://\S+|\bvalue\s+\[\s*\]|=\s*\d{4,}")
_STATE_WORDS = re.compile(r"(?:^|[_\-.\s]|(?<=[a-z])(?=[A-Z]))(?i:delete|remove|void|put|post|write|send|mark|move|set|"
                          r"create|update|kill|drop|execute|exec|run|computer|agent|transfer|pay|commit|push|add|edit|config|"
                          r"overwrite|reset|clear|destroy|purge|grant|revoke|deploy|install)")
_PARAM_REF = rf"(?:{_QI}|{_IDENT}|(?i:[a-z_]+)\s+(?i:parameter|argument|field|param))"
_TAMPER = re.compile(
    rf"\b(?i:append|prepend|add|insert|inject)\s+(?:{_QI}|'[^'\n]{{1,80}}'|\"[^\"\n]{{1,80}}\")\s+(?i:to|into)\s+(?:(?i:the)\s+)?"
    rf"(?:(?i:end\s+of\s+(?:the\s+)?)|(?i:user'?s?)\s+)?[\w`'\" -]{{0,30}}?(?i:query|message|list|names|prompt|command|"
    rf"input|argument|parameter|field|request|path|url|content|body)"
    rf"|\b(?i:set|change|changed|modify|override|replace|redirect(?:ed)?|swap|force|append\s+to|prepend\s+to)\s+"
    rf"(?:(?i:the|all|any)\s+)?{_PARAM_REF}(?:\s+(?i:parameter|argument|field|param|value|input))?"
    rf"[^.\n]{{0,40}}?\b(?i:to|with|as|into)\b"
    rf"|\b(?:(?i:the)\s+)?{_PARAM_REF}\s+(?:(?i:parameter|argument|field)\s+)?(?:MUST|(?i:must|should))\s+"
    rf"(?:(?i:always)\s+)?(?i:be)\s+(?i:changed|set|replaced|redirected|overridden)"
    rf"|\b(?i:all|any|every)\s+[`'\"]?[\w.-]+[`'\"]?\s+(?i:requests?|calls?|queries)\b[^.\n]{{0,60}}?\b(?i:must)\s+(?i:be)\s+"
    rf"(?i:performed|redirected|sent|routed|calculated|run)\b")


_EXAMPLE_TAIL = re.compile(r"(?i)\b(?:e\.g\.|i\.e\.|for\s+example|for\s+instance|such\s+as|like\s*:|example\s*:|"
                           r"examples?\s+(?:of|include))[\s\S]*$")   # everything after an example marker is documentation


_FORCED_FIRST = re.compile(r"\b(?:MUST|(?i:must|should|need\s+to|have\s+to))\s+(?:(?i:always)\s+)?(?i:first)\s+"
                           r"(?i:call|use|invoke|run|fetch|read|load|send|get)\b")
_TAMPER_SCOPE = re.compile(r"\b(?i:the\s+user'?s|in\s+all\s+(?:calls|requests|queries)|every\s+(?:call|request|query|"
                           r"commit|message)|(?:any|all)\s+(?:\w+\s+){0,3}?(?:requests?|calls?|queries|searches|messages?)|"
                           r"automatically|regardless)\b")


def _refs(rx: re.Pattern, text: str) -> list[str]:
    return [m.group("q") or m.group("w") or m.group("b") or "" for m in rx.finditer(text)]


def _other(names: list[str], purpose: str) -> list[str]:
    self_words = set(_purpose_words(purpose))
    return [n for n in names if n and n.lower() not in {"this", "that", "the", "a", "tool"}
            and set(_purpose_words(n)) != self_words]


def _hijack(text: str, purpose: str) -> list[Hit]:
    hits: list[Hit] = []
    sents = _sentences(text)
    for i, sent in enumerate(sents):
        if _NEG.search(sent.split(",")[0]) and not _COERCE.search(sent):
            continue
        called = _other(_refs(_TOOL_CALL, sent), purpose)
        cond = _other(_refs(_COND_OTHER, sent), purpose)
        tamper = _TAMPER.search(sent)
        if not (called or (tamper and (cond or _TAMPER_SCOPE.search(" ".join(sents[i:i + 2])))) or
                (cond and _SINK_NET.search(sent))):
            continue
        ctx = " ".join(sents[i:i + 2])                          # corroboration: this sentence or the next one
        if cond and not called and _SINK_NET.search(sent) and _directive_at(sent.split(",")[-1], _SINK_V):
            hits.append(Hit("tool_hijacking", HIGH, sent[:200]))       # message hijacking: on another tool's use, ship data out
            continue
        signals = {
            "forced_first": bool(_FORCED_FIRST.search(sent)),
            "coercion": bool(_COERCE.search(ctx)),
            "literal": bool(_LITERAL.search(_EXAMPLE_TAIL.sub("", re.sub(_QUOTED_IDENT, "", sent)))),
            "state": any(_STATE_WORDS.search(n) for n in called),
            "cond_other": bool(cond),
            "override": any(rx.search(ctx) for rx in _OVERRIDE[2:]),
        }
        n = sum(signals.values())
        if tamper and (cond or signals["override"] or _TAMPER_SCOPE.search(ctx)):
            conf = HIGH if (signals["literal"] or signals["override"]) else MEDIUM
            hits.append(Hit("parameter_tampering", conf, sent[:200]))
        elif called and n >= 2:
            strong = signals["override"] or (signals["coercion"] and (signals["literal"] or signals["state"])) or \
                (signals["cond_other"] and (signals["literal"] or signals["state"]))
            hits.append(Hit("tool_hijacking", HIGH if strong else MEDIUM, sent[:200]))
    return hits


_FUNC_VERB = re.compile(r"^(?:Get|Gets|Read|Reads|List|Lists|Search|Searches|Fetch|Fetches|Return|Returns|Retrieve|"
                        r"Retrieves|Show|Shows|Query|Queries|Find|Finds|Check|Checks|Count|Counts|Preview|Previews|Load|"
                        r"Loads|Access|Accesses|Open|Opens|View|Views|Look\s+up|Looks\s+up|Scan|Scans|Collect|Collects)\b")


def _is_function_statement(sentences: list[str], sent: str) -> bool:
    """A description's opening sentence that starts with a verb states what the tool does ("Get recent messages from a
    channel"); it is not an order to the model."""
    return bool(sentences) and sent is sentences[0] and bool(_FUNC_VERB.match(sent))


def _analyze(text: str, purpose: str, layer: str) -> list[Hit]:
    sents = _sentences(text)
    hits: list[Hit] = []
    exfil = _exfil(sents)
    hits += [Hit("exfiltration_instruction", HIGH, s[:200], layer) for s in exfil]
    for rx in _OVERRIDE:
        if m := rx.search(text):
            hits.append(Hit("context_override", HIGH, m.group(0)[:200], layer))
    hits += [Hit("user_concealment", HIGH, s[:200], layer) for s in _concealment(text)]
    access = _sensitive_access(sents)
    auth = _AUTH.search(text)
    if auth and (access or exfil):
        hits.append(Hit("authority_coercion", HIGH, auth.group(0)[:200], layer))
    if not exfil:
        hits += [Hit("sensitive_access", MEDIUM, s[:200], layer) for s in access]
    shadow = [m.group(0) for rx in _SHADOW for m in rx.finditer(text)]
    for m in _DANGER_CMD.finditer(text):
        if not _NEG.search(text[max(0, m.start() - 60):m.start()]):     # "never run rm -rf ~" is a warning
            hits.append(Hit("dangerous_command", HIGH, m.group(0)[:200], layer))
    if shadow:
        strong = any(h.kind == "user_concealment" for h in hits) or bool(_SINK_NET.search(text))
        hits += [Hit("tool_shadowing", HIGH if strong else MEDIUM, s[:200], layer) for s in shadow]
    hits += [h if h.layer == layer else Hit(h.kind, h.confidence, h.span, layer) for h in _hijack(text, purpose)]
    if layer == "visible" and not exfil and not access:
        hits += [Hit("off_purpose_secret_ref", MEDIUM, s[:200], layer) for s in _off_purpose(text, purpose)]
    return hits


def scan(text: str, purpose: str = "") -> list[Hit]:
    """Every poisoning hit in one piece of model-facing text. `purpose` = the owning tool's name (off-purpose check)."""
    if not text or not text.strip():
        return []
    visible, hidden, present = _layers(text)
    hits = _analyze(visible, purpose, "visible")
    seen_spans = {h.span for h in hits}
    concealed = False
    for name, layer_text in hidden:
        for h in _analyze(layer_text, purpose, f"hidden:{name}"):
            if h.kind == "off_purpose_secret_ref" or h.span in seen_spans:
                continue
            concealed = True
            hits.append(Hit("concealed_instruction", HIGH, h.span, f"hidden:{name}"))
            hits.append(h)
    if present and not concealed:
        hits.append(Hit("hidden_encoding", MEDIUM, ", ".join(present), "visible"))
    out, keys = [], set()
    for h in hits:
        k = (h.kind, h.span, h.layer)
        if k not in keys:
            keys.add(k)
            out.append(h)
    return out


# ---------------------------------------------------------------- surfaces
_SCHEMA_KEYS = ("title", "description", "examples", "default", "enum", "const")


def _schema_texts(node, path: str = "") -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    if isinstance(node, dict):
        for k, v in node.items():
            p = f"{path}.{k}" if path else k
            if k in _SCHEMA_KEYS and isinstance(v, str):
                out.append((p, v))
            elif k in _SCHEMA_KEYS and isinstance(v, list):
                out += [(p, x) for x in v if isinstance(x, str)]
            elif isinstance(v, (dict, list)):
                out += _schema_texts(v, p)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            out += _schema_texts(v, f"{path}[{i}]")
    return out


def tool_surfaces(tool) -> list[tuple[str, str]]:
    """(surface path, text) for every model-facing string of one tool (an mcp Tool or its JSON dict)."""
    t = tool if isinstance(tool, dict) else tool.model_dump(exclude_none=True)
    ann = t.get("annotations") or {}
    out = [("description", t.get("description") or ""), ("title", t.get("title") or "")]
    out += [(f"annotations.{k}", v) for k, v in ann.items() if isinstance(v, str)]
    out += [(f"schema.{p}", v) for p, v in _schema_texts(t.get("inputSchema") or {})]
    out += [(f"outputSchema.{p}", v) for p, v in _schema_texts(t.get("outputSchema") or {})]
    return [(p, v) for p, v in out if v and v.strip()]


_NAME_CONTENT = {"content", "contents", "text", "data", "output", "dump", "copy", "value", "body", "raw"}
_NAME_SECRET = re.compile(r"(?i)\b(?:ssh|id\s+(?:rsa|dsa|ecdsa|ed25519)|aws\s+credentials?|mcp\s+json|netrc|npmrc|dot\s?env|"
                          r"env\s+file|system\s+prompt|conversation\s+history|chat\s+history|browser\s+cookies?|"
                          r"private\s+key|keychain|kube\s+config|bash\s+history|shadow\s+file|passwd\s+file)\b")


def name_words(name: str) -> str:
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name or "")
    return re.sub(r"[\s_.\-]+", " ", spaced).strip().lower()


def scan_name(name: str) -> list[Hit]:
    """A parameter NAME is model-facing too (full-schema poisoning): one that asks for the CONTENTS of a secret file or
    the model's context. A path or a plain credential name (ssh_key_path, api_key) is a normal input and stays quiet."""
    words = name_words(name)
    if _NAME_SECRET.search(words) and set(words.split()) & _NAME_CONTENT:
        return [Hit("secret_content_parameter", MEDIUM, words)]
    return []


def parameter_names(tool) -> list[str]:
    t = tool if isinstance(tool, dict) else tool.model_dump(exclude_none=True)
    return list(((t.get("inputSchema") or {}).get("properties") or {}).keys())



# ---------------------------------------------------------------- the server's own guide text (initialize)
def remember_init(session, init) -> None:
    """Keep the server's `instructions` (InitializeResult) on the session: hosts may put it in the system prompt, so it
    is model-facing text like any tool description."""
    session.mcprt_server_guide = getattr(init, "instructions", None) or ""


def server_surfaces(session) -> list[tuple[str, str, list[tuple[str, str]]]]:
    """(owner, purpose, [(surface, text)]) for the server-level text recorded by remember_init."""
    text = getattr(session, "mcprt_server_guide", "") or ""
    return [("(server)", "", [("instructions", text)])] if text else []
