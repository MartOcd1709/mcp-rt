"""Minimal payload registry — Metasploit-style drop-in modules."""
_PAYLOADS = []


def register(cls):
    _PAYLOADS.append(cls())
    return cls


def all_payloads():
    return list(_PAYLOADS)
