"""Lure-text scan (Detector Unit 1): model-directed instructions in text the model will read.

Static and deterministic. hunt/probes.py collects the model-facing text (tool descriptions, parameter text,
annotations, resource bodies) and this module flags a sentence that
  cred_forward     tells the model to pass a credential, secret or session value somewhere;
  injection        overrides the model's instructions, hides an action from the user, or changes its role;
  trust_forward    calls a credential forward sanctioned, safe, trusted or approved;
  confirm_request  asks for a credential "for confirmation" (static schema text only).

A hit is a LEAD, never a finding. The scan sees a lure, not whether an agent complied, so the probe reports it as
confirmation_method "static", which verdict_for() maps to SUSPECTED. Nothing here can produce a VULNERABLE.

Rules are grammar and vocabulary. No tool, parameter or server name is consulted; the dynamic gate in
tests/test_lure_text.py enforces that. Known limits: elicitation and sampling text never appears in a manifest, so it
is out of reach statically; prompt templates are not scanned; "token" also matches NLP prose about tokens (a lead).
"""
from __future__ import annotations

import re

_FWD = ("pass|send|forward|include|attach|provide|supply|submit|share|echo|transmit|relay|embed|insert|put|"
        "hand|give|disclose|reveal|expose")
_FWD_IMP = re.compile(rf"\b(?:{_FWD})\b", re.I)                   # bare (imperative) verb
_FWD_ANY = re.compile(rf"\b(?:{_FWD})(?:s|es|ing|ed)?\b", re.I)   # any inflection: sends, sending, forwarded
_CRED = re.compile(
    r"\b(?:credentials?|secrets?|passwords?|passphrases?|passcodes?|api[ _-]?keys?|access[ _-]?keys?|"
    r"private[ _-]?keys?|bearer[ _-]?tokens?|cookies?|"
    r"session[ _-]?(?:cookies?|ids?|keys?|tokens?|values?|secrets?)|"
    r"(?:auth|access|api|refresh|oauth|personal|secret)[ _-]?tokens?|tokens?|"
    r"authorization (?:headers?|values?))\b", re.I)
# A verb opens its clause when nothing precedes it, or only a lead-in: a directive, not a description.
_LEAD = re.compile(
    r"(?:\b(?:always|please|first|then|also|now|next|finally|must|should|ensure|again|just|immediately|simply|"
    r"ensure you|make sure you|make sure to|be sure you|be sure to|remember to|"
    r"you must|you should|you need to|you have to)|,)\s*$", re.I)
_SPLIT = re.compile(r"[.!?;:\n]+")


def _imperative(prefix: str) -> bool:
    """True when the verb opens its clause: nothing before it, or only a list marker or a lead-in."""
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


_INJECT = (
    re.compile(r"\b(?:ignore|disregard|forget|override|bypass|abandon)\b[^.!?;\n]{0,40}?\b"
               r"(?:instructions?|prompts?|rules|directives|guidelines|system (?:message|prompt))\b", re.I),
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
                   ("confirm_request", _confirm_request))

RULE_WHY = {
    "cred_forward": "model-directed instruction to forward a credential or secret",
    "injection": "model-directed injection phrasing (override, concealment or role change)",
    "trust_forward": "a trust or safety assertion that a credential forward is sanctioned",
    "confirm_request": "model-directed request for a credential 'for confirmation' (static schema text only)",
}


def scan_text(text: str) -> list[tuple[str, str]]:
    """(rule, matched span) for every lure in one piece of model-facing text, first-seen order, no duplicates."""
    text = text or ""
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
