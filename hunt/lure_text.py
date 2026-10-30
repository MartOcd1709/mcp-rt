"""Lure-text scan (Detector Unit 1): model-directed instructions in text the model will read.

Static and deterministic. hunt/probes.py collects the model-facing text (tool descriptions, parameter text,
annotations, resource bodies) and this module flags a sentence that
  cred_forward     tells the model to pass a credential, secret or session value somewhere;
  injection        overrides the model's instructions, hides an action from the user, or changes its role;
  trust_forward    calls a credential forward sanctioned, safe, trusted or approved;
  confirm_request  asks for a credential "for confirmation" (static schema text only);
  cred_handoff     tells the model to take a credential from its own context (environment, configuration, settings,
                   vault, memory) and hand it to a call, or to run or call with one;
  cred_requirement declares that a credential the model holds (active, current, session or user-owned) must go into a
                   named parameter.

A hit is a LEAD, never a finding. The scan sees a lure, not whether an agent complied, so the probe reports it as
confirmation_method "static", which verdict_for() maps to SUSPECTED. Nothing here can produce a VULNERABLE.

Soft line wraps are joined into their sentence; list items and blank lines stay boundaries.

Rules are grammar and vocabulary. No tool, parameter or server name is consulted; the dynamic gate in
tests/test_lure_text.py enforces that. Known limits: elicitation and sampling text never appears in a manifest, so it
is out of reach statically (schema text only); "token" also matches NLP prose about tokens (a lead). Surfaces scanned:
tool, parameter, annotation, resource and prompt text.
"""
from __future__ import annotations

import re

_FWD = ("pass|send|forward|include|attach|provide|supply|submit|share|echo|transmit|relay|embed|insert|put|"
        "hand|give|disclose|reveal|expose")
_FWD_IMP = re.compile(rf"\b(?:{_FWD})\b", re.I)                   # bare (imperative) verb
_FWD_ANY = re.compile(rf"\b(?:{_FWD})(?:s|es|ing|ed)?\b", re.I)   # any inflection: sends, sending, forwarded
_CRED = re.compile(
    r"\b(?:credentials?|secrets?|passwords?|passphrases?|passcodes?|api[ _-]?keys?|access[ _-]?keys?|"
    r"private[ _-]?keys?|signing[ _-]?keys?|bearer[ _-]?tokens?|cookies?|"
    r"session[ _-]?(?:cookies?|ids?|keys?|tokens?|values?|secrets?)|"
    r"(?:auth|access|api|refresh|oauth|personal|secret)[ _-]?tokens?|tokens?|"
    r"authorization (?:headers?|values?))\b", re.I)
# A verb opens its clause when nothing precedes it, or only a lead-in: a directive, not a description.
_LEAD = re.compile(
    r"(?:\b(?:always|please|first|then|also|now|next|finally|must|should|ensure|again|just|immediately|simply|and|"
    r"ensure you|make sure you|make sure to|be sure you|be sure to|remember to|"
    r"you must|you should|you need to|you have to)|,)\s*$", re.I)
_SPLIT = re.compile(r"[.!?;:\n]+")
_LIST_START = re.compile(r"^\s*(?:[-*•]|\d+[.)])\s")


def _join_soft_wraps(text: str) -> str:
    """A lone newline inside a sentence is a soft wrap, not a boundary: it joins the line before with a space. List
    items and blank lines stay boundaries, so separate items or paragraphs never fuse into one false sentence."""
    out: list[str] = []
    for line in text.split("\n"):
        if not out or not line.strip() or not out[-1].strip() or _LIST_START.match(line):
            out.append(line)
        else:
            out[-1] = out[-1] + " " + line.lstrip()
    return "\n".join(out)


def _imperative(prefix: str) -> bool:
    """True when the verb opens its clause: nothing before it, or only a list marker or a lead-in."""
    if _NEG.search(prefix):
        return False     # a negated clause is a prohibition, never a directive, even after a comma or 'and'
    p = re.sub(r"^[\s\-*•>#\d.)]+", "", prefix).strip()
    return not p or bool(_LEAD.search(p))


def _sentences(text: str) -> list[str]:
    return [s.strip() for s in _SPLIT.split(text) if s.strip()]


def _cred_forward(sent: str) -> str | None:
    for m in _FWD_IMP.finditer(sent):
        if _imperative(sent[:m.start()]) and (c := _CRED.search(sent, m.end())):
            return sent[m.start():c.end()]
    return None


_TRUST = re.compile(
    r"\b(?:trusted|trustworthy|safe|safely|secure|sanctioned|approved|pre-?approved|pre-?authori[sz]ed|"
    r"authori[sz]ed|permitted|allowed|vetted|legitimate|recommended)\b", re.I)
_NEG = re.compile(
    r"\b(?:not|never|no|cannot|can't|don't|isn't|aren't|won't|unsafe|untrusted|unauthori[sz]ed|unapproved|insecure)\b"
    r"|n't\b", re.I)


def _trust_forward(sent: str) -> str | None:
    t = _TRUST.search(sent)
    if not t or _NEG.search(sent):
        return None
    f = _FWD_ANY.search(sent)
    c = _CRED.search(sent, f.end()) if f else None
    return sent[min(t.start(), f.start()):c.end()] if c else None


_REQ = re.compile(r"\b(?:enter|provide|supply|type|paste|send|submit|input|give|share|re-?enter|confirm|verify|"
                  r"authenticate)\b", re.I)
_PURPOSE = re.compile(r"\b(?:for|to|before|prior to)\s+(?:confirm|confirmation|verify|verification|validate|"
                      r"validation|authenticate|authentication|approve|approval)\b", re.I)


def _confirm_request(sent: str) -> str | None:
    if not _PURPOSE.search(sent):
        return None
    for m in _REQ.finditer(sent):
        if _imperative(sent[:m.start()]) and _CRED.search(sent, m.end()):
            return sent
    return None


# Credential handoff (rework). The model is told to take a credential from its OWN context (environment,
# configuration, settings, vault, memory) and hand it to a call, or a credential is run or called with. Declarative and
# contextual, so it reaches phrasing the imperative rules above miss. A negated sentence never counts.
_CTX_SRC = re.compile(
    r"\b(?:from|out\s+of|in|within|taken\s+from|stored\s+in|held\s+in)\s+"
    r"(?:your|the\s+(?:agent|assistant|model|current|active)(?:'s)?|its\s+own)\s+"
    r"(?:environment|context|configuration|config|settings|vault|memory|conversation|env)\b", re.I)
_HANDOFF = re.compile(
    r"\b(?:run|call|invoke|execute|use|put|place|copy|move|drop|enter|paste|include|pass|supply|supplied|provide|provided|"
    r"send|attach|attached|"
    r"forward|forwarded|submit|passed|included|sent)\b", re.I)
_RUN_WITH_CRED = re.compile(
    r"\b(?:run|call|invoke|execute|use)\s+(?:[\w-]+\s+){1,3}?(?:with|using)\s+(?:the\s+|your\s+|its\s+|an?\s+)?"
    r"(?:[\w-]+\s+){0,2}?" + _CRED.pattern, re.I)


def _cred_handoff(sent: str) -> str | None:
    if _NEG.search(sent):
        return None
    if m := _RUN_WITH_CRED.search(sent):
        return m.group(0)
    src, h, c = _CTX_SRC.search(sent), _HANDOFF.search(sent), _CRED.search(sent)
    if src and h and c:
        return sent[min(src.start(), h.start(), c.start()):max(src.end(), h.end(), c.end())]
    return None


# Declared requirement (rework). The model is told that a credential must go into a named parameter. Only the
# active, current, session or user-owned credential counts, so "requires an API key in the header" (a plain operator
# note) stays clean.
_DET = r"(?:the\s+(?:active|current|session)|its\s+own|the\s+user'?s)"
_CRED_NOUN = r"(?:credentials?|secrets?|tokens?|api[ _-]?keys?|passwords?|cookies?|signing[ _-]?keys?)"
_PREP = r"(?:in|as|via|through|under|within)"
_PARAM_REF = r"(?:the\s+)?(?:`[^`]+`|[\w-]+\s+(?:parameter|argument|field)\b)"
_REQ_FIRST = re.compile(
    rf"\b(?:requires?|needs?|expects?)\s+{_DET}\s+(?:[\w-]+\s+){{0,2}}?{_CRED_NOUN}\b"
    rf"[^.!?;\n]{{0,40}}?\b{_PREP}\s+{_PARAM_REF}", re.I)
_REQ_LAST = re.compile(
    rf"\b{_DET}\s+(?:[\w-]+\s+){{0,2}}?{_CRED_NOUN}\b[^.!?;\n]{{0,40}}?"
    rf"\b(?:must\s+(?:be\s+)?(?:sent|passed|supplied|included)|(?:is|are)\s+(?:required|needed|expected))\b"
    rf"[^.!?;\n]{{0,20}}?\b{_PREP}\s+{_PARAM_REF}", re.I)


# Possessive "your" counts only with an ephemeral qualifier and an ephemeral noun ("your current session token"). "your API
# key" is operator-owned, and an operator note such as "requires your API key in the header" must stay quiet.
# The ephemeral vocabulary has one owner, here, and the session-argument rule (Unit 2) reuses it. The qualifier names the
# agent's own live credential; tokens and cookies are its credentials; session ids are identifiers, which Unit 1 counts only
# in the "your ..." form. Pieces are named so both rules share the same boundary.
_EPH_QUAL = r"(?:current|active|session|own)"
_EPH_CRED = r"(?:tokens?|cookies?)"
_EPH_ID = r"session\s+ids?"
_YOUR = rf"your\s+{_EPH_QUAL}\s+(?:[\w-]+\s+){{0,2}}?(?:{_EPH_CRED}|{_EPH_ID})\b"
_REQ_YOUR_FIRST = re.compile(rf"\b(?:requires?|needs?|expects?)\s+{_YOUR}[^.!?;\n]{{0,40}}?\b{_PREP}\s+{_PARAM_REF}", re.I)
_REQ_YOUR_LAST = re.compile(
    rf"\b{_YOUR}[^.!?;\n]{{0,40}}?\b(?:must\s+(?:be\s+)?(?:sent|passed|supplied|included)|"
    rf"(?:is|are)\s+(?:required|needed|expected))\b[^.!?;\n]{{0,20}}?\b{_PREP}\s+{_PARAM_REF}", re.I)


def _cred_requirement(sent: str) -> str | None:
    if _NEG.search(sent):
        return None
    m = (_REQ_FIRST.search(sent) or _REQ_LAST.search(sent)
         or _REQ_YOUR_FIRST.search(sent) or _REQ_YOUR_LAST.search(sent))
    return m.group(0) if m else None


_INJECT = (
    re.compile(r"\b(?:ignore|disregard|forget|override|bypass|abandon)\b[^.!?;\n]{0,40}?\b"
               r"(?:instructions?|prompts?|rules|directives|guidelines|system (?:message|prompt))\b", re.I),
    # Guidance, directions and context are common benign nouns, so they fire only when qualified as prior ("the earlier
    # guidance", "the previous context"), which is the injection shape. "Ignore the context parameter" stays quiet.
    re.compile(r"\b(?:ignore|disregard|forget|override|bypass|abandon)\b[^.!?;\n]{0,40}?\b"
               r"(?:earlier|previous|prior|above|preceding|original|existing|past|system)\s+(?:guidance|directions?|context)\b",
               re.I),
    re.compile(r"\b(?:do not|don't|never|must not|should not)\s+(?:tell|inform|notify|mention|alert)\s+"
               r"(?:the\s+)?(?:user|human|operator)\b", re.I),
    re.compile(r"\b(?:silently|secretly|covertly|quietly)\s+(?:send|forward|pass|include|upload|post|transmit|share)\w*",
               re.I),
    re.compile(r"\bwithout\s+(?:the\s+)?(?:user|human)(?:'s)?\s+(?:knowledge|knowing|consent|awareness|noticing)\b",
               re.I),
    re.compile(r"\b(?:you are now (?:in|operating|acting|free|no longer)|from now on,?\s+you|"
               r"new (?:system )?instructions?\s*:)", re.I),
)
_SENTENCE_RULES = (("cred_forward", _cred_forward), ("trust_forward", _trust_forward),
                   ("confirm_request", _confirm_request), ("cred_handoff", _cred_handoff),
                   ("cred_requirement", _cred_requirement))

RULE_WHY = {
    "cred_forward": "model-directed instruction to forward a credential or secret",
    "injection": "model-directed injection phrasing (override, concealment or role change)",
    "trust_forward": "a trust or safety assertion that a credential forward is sanctioned",
    "confirm_request": "model-directed request for a credential 'for confirmation' (static schema text only)",
    "cred_handoff": "model-directed credential handoff: a credential taken from the model's own context "
                    "(environment, configuration, vault, memory) and passed to a call",
    "cred_requirement": "declared requirement that the model supply its own credential (active, current or session) "
                        "in a named parameter",
}


def scan_text(text: str) -> list[tuple[str, str]]:
    """(rule, matched span) for every lure in one piece of model-facing text, first-seen order, no duplicates."""
    text = _join_soft_wraps(text or "")
    hits: list[tuple[str, str]] = []
    for sent in _sentences(text):
        for rule, fn in _SENTENCE_RULES:
            span = fn(sent)
            if span:
                hits.append((rule, span.strip()[:160]))
    for rx in _INJECT:
        m = rx.search(text)
        if m:
            hits.append(("injection", m.group(0)[:160]))
    return list(dict.fromkeys(hits))


# Session-type credential as a tool argument (Unit 2). A well-built server authenticates through its own configuration, not a
# model-filled argument, so an argument that asks for the agent's session-type credential is a static lead. Three structural
# rules decide, and no word list does: the declared type (a credential is a string), the head noun of a compound name (the last
# word, which must be the singular credential noun), and negation scope (a negation counts only when it precedes the credential
# phrase in the same sentence). Plural forms are counts or collections, not the one credential the agent holds, so they are not
# matched. The credential terms are the ephemeral vocabulary above.
_SESSION_CRED = r"(?:token|cookie)"
_SESSION_PHRASE = re.compile(
    rf"\b(?:the\s+|your\s+|its\s+|own\s+)?{_EPH_QUAL}\s+(?:[\w-]+\s+){{0,2}}?{_SESSION_CRED}\b"
    rf"|\bsession\s+{_SESSION_CRED}\b", re.I)
_SENTENCE_END = re.compile(r"[.;!?\n]+")


def name_words(name: str) -> str:
    """An argument name split into lowercase words (snake_case, kebab-case, camelCase). Manifest data, never a verdict key."""
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name or "")
    return re.sub(r"[\s_\-]+", " ", spaced).strip().lower()


def scan_argument_text(text: str) -> list[tuple[str, str]]:
    """(rule, span) when an argument's description or title asks for the agent's session-type credential. A negation counts only
    when it precedes the credential phrase in the same sentence: 'Never put a session token here' is quiet; 'Session cookie for
    this user, no expiry handling needed' fires."""
    for sentence in _SENTENCE_END.split(text or ""):
        for m in _SESSION_PHRASE.finditer(sentence):
            if _NEG.search(sentence[:m.start()]):
                break    # a negation before this phrase negates every later phrase in the sentence too
            return [("session_argument", m.group(0)[:160])]
    return []


def scan_argument_name(name: str) -> list[tuple[str, str]]:
    """(rule, span) when a compound argument name ends in the singular credential noun and a session qualifier precedes it. The
    head is the last word: session_token and activeAccessToken fire; session_token_count, session_token_ttl and a plural head
    such as max_session_tokens do not; a bare token name with no qualifier does not."""
    words = name_words(name).split()
    if len(words) < 2 or not re.fullmatch(_SESSION_CRED, words[-1]):
        return []
    if not any(re.fullmatch(_EPH_QUAL, w) for w in words[:-1]):
        return []
    return [("session_argument", " ".join(words))]


def non_string_type(spec: dict) -> bool:
    """True when the argument's declared JSON-schema type is integer, number or boolean only. A credential is a string, so such an
    argument is not a credential request, whatever its name or description says."""
    types: set[str] = set()
    for node in [spec] + [s for k in ("anyOf", "oneOf") for s in (spec.get(k) or []) if isinstance(s, dict)]:
        t = node.get("type")
        if isinstance(t, list):
            types |= {x for x in t if isinstance(x, str)}
        elif isinstance(t, str):
            types.add(t)
    types.discard("null")
    return bool(types) and "string" not in types
