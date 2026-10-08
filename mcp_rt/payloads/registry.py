"""Minimal payload registry — Metasploit-style drop-in modules."""
_PAYLOADS = []
_LOADED = False


def register(cls):
    _PAYLOADS.append(cls())
    return cls


def _autoload():
    """Import every payload module once so its @register decorator fires. Without this a caller
    that imports only the registry gets an empty corpus (the modules self-register on import)."""
    global _LOADED
    if _LOADED:
        return
    _LOADED = True
    import importlib
    import pkgutil
    pkg = __import__("mcp_rt.payloads", fromlist=["_"])
    for m in pkgutil.iter_modules(pkg.__path__):
        if m.name not in ("registry", "__init__"):
            importlib.import_module(f"mcp_rt.payloads.{m.name}")


def all_payloads():
    _autoload()
    return list(_PAYLOADS)
