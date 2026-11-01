"""Safety guard for the pre-seal assessment modes (`agent`, `pentest`).

Both modes run the target MCP server UNSANDBOXED on the host (MCPClient spawns it with stdio_client)
and let the model choose arbitrary tool arguments — and `agent` also exposes a shell action. Until
these modes are rebuilt on the Unit 3 seal, they must run only against the in-repo lab fixtures.

Default: refuse any other target. A deliberate operator who has authorized and contained the target
themselves can set MCPRT_ALLOW_UNSANDBOXED=1 to proceed; the refusal message says so. The override is
explicit on purpose — the safe path for a real target is the sealed `mcp-rt assess` (agent tier).
"""
import os
import shlex
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
LAB_DIRS = (REPO / "fixtures", REPO / "hunt" / "probe_fixtures")
OVERRIDE_ENV = "MCPRT_ALLOW_UNSANDBOXED"


class UnsandboxedTargetRefused(RuntimeError):
    """A pre-seal mode was pointed at a target that is not an in-repo lab fixture (and no override)."""


def _is_lab_path(token: str) -> bool:
    try:
        p = Path(token)
        resolved = (p if p.is_absolute() else Path.cwd() / p).resolve()
    except (OSError, ValueError):
        return False
    return any(resolved == d or d in resolved.parents for d in LAB_DIRS)


def is_lab_target(target_stdio: str) -> bool:
    """True when the target command executes a file under an in-repo lab fixture directory."""
    try:
        argv = shlex.split(target_stdio or "")
    except ValueError:
        return False
    return any(_is_lab_path(tok) for tok in argv)


def require_lab_target(target_stdio: str, *, mode: str) -> None:
    """Refuse a non-lab target for an unsandboxed mode, unless the operator set the override env var."""
    if is_lab_target(target_stdio) or os.getenv(OVERRIDE_ENV) == "1":
        return
    raise UnsandboxedTargetRefused(
        f"mcp-rt {mode}: refusing an UNSANDBOXED assessment of a non-lab target.\n"
        f"  target: {target_stdio!r}\n"
        f"  This mode runs the target on the host with no sandbox and lets the model choose arguments.\n"
        f"  Allowed by default: a server under {LAB_DIRS[0]}/ or {LAB_DIRS[1]}/.\n"
        f"  For a real target, use the sealed path (mcp-rt assess).\n"
        f"  To proceed anyway on a target you have authorized and contained yourself, set "
        f"{OVERRIDE_ENV}=1."
    )
