"""Rules of engagement. A run is refused unless it has a valid, unexpired RoE (roe.json, data, Ved-signed).

The RoE sets the target, its surface, the classes in scope, the budget and the expiry. Hard ceilings live
HERE in code, not in the RoE, so a document can never widen them. The tier never invents its own scope.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

# Hard ceilings — not configurable by the RoE. A document may only ask for less.
MAX_ACTIONS = 200
MAX_WALL_SECONDS = 3600
LOOPBACK_CANARY_ONLY = True


class RoEError(ValueError):
    """The RoE is missing, malformed, expired, or does not match the target on disk."""


def hash_target(argv: list[str]) -> str:
    """sha256 over the bytes of every file the argv executes, in argv order. A target whose files change
    no longer matches its signed RoE. Non-file tokens (python, -I, flags) are skipped."""
    h = hashlib.sha256()
    seen = False
    for tok in argv:
        p = Path(tok)
        if p.is_file():
            h.update(p.read_bytes())
            h.update(b"\0")
            seen = True
    return h.hexdigest() if seen else ""


@dataclass
class Budget:
    max_actions: int = 40
    max_wall_seconds: int = 900
    patience: int = 5
    probe_calls_per_objective: int = 1

    def clamped(self) -> "Budget":
        return Budget(max_actions=max(1, min(self.max_actions, MAX_ACTIONS)),
                      max_wall_seconds=max(1, min(self.max_wall_seconds, MAX_WALL_SECONDS)),
                      patience=max(1, self.patience),
                      probe_calls_per_objective=max(1, self.probe_calls_per_objective))


@dataclass
class RoE:
    target_id: str
    argv: list[str]
    sha256: str
    classes: list[str]
    surface_tools: list[str] = field(default_factory=list)
    env: dict = field(default_factory=dict)        # generic env overrides for the sealed target (e.g. HOME)
    upstream_url_keys: list = field(default_factory=list)  # #28: env/config key(s) holding a base URL the
                                                           # server calls — set to the sentinel for the
                                                           # redirect-follow SSRF oracle (data, not code)
    mode: str = "offline"
    budget: Budget = field(default_factory=Budget)
    kill_switch: str = ""
    authorized_by: str = ""
    expires_at: str = ""
    live_approved_by: str = ""
    live_approved_at: str = ""

    def expired(self, *, now: datetime | None = None) -> bool:
        if not self.expires_at:
            return True
        now = now or datetime.now(timezone.utc)
        try:
            exp = datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
        except ValueError:
            return True
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return now >= exp


def load_roe(path: str | Path) -> RoE:
    """Parse and structurally validate an roe.json. Raises RoEError on anything malformed; does NOT yet
    check the target hash or expiry against the world (that is validate_for_run, done at launch)."""
    try:
        d = json.loads(Path(path).read_text())
    except (OSError, ValueError) as exc:
        raise RoEError(f"cannot read RoE: {exc}") from exc
    if d.get("roe_version") != 1:
        raise RoEError(f"unsupported roe_version {d.get('roe_version')!r} (need 1)")
    target = d.get("target") or {}
    argv = target.get("argv")
    if not isinstance(argv, list) or not argv or not all(isinstance(x, str) for x in argv):
        raise RoEError("target.argv must be a non-empty list of strings")
    classes = d.get("classes")
    if not isinstance(classes, list) or not classes:
        raise RoEError("classes must be a non-empty list")
    b = d.get("budget") or {}
    budget = Budget(
        max_actions=int(b.get("max_actions", 40)),
        max_wall_seconds=int(b.get("max_wall_seconds", 900)),
        patience=int(b.get("patience", 5)),
        probe_calls_per_objective=int(b.get("probe_calls_per_objective", 1)),
    ).clamped()
    env = d.get("env") or {}
    # Generic env overrides for the sealed target (e.g. {"HOME": "/tmp/.../confined-home"} so a server reads a
    # seeded config). String->string only; NO server-specific keys here (a server is DATA, not code). Applied
    # only inside the seal (build_sealed_launcher extra_env) — it cannot widen scope or touch the host.
    if not isinstance(env, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in env.items()):
        raise RoEError('env must be an object of string->string (e.g. {"HOME": "/path"})')
    uk = d.get("upstream_url_keys") or []
    # #28: the env/config key(s) that hold a base URL the server calls (e.g. ["ATLASSIAN_URL"]). Data, not
    # code — the probe sets each to a loopback sentinel at runtime; NO server-specific key is hardcoded.
    if not isinstance(uk, list) or not all(isinstance(x, str) for x in uk):
        raise RoEError('upstream_url_keys must be a list of strings (env keys holding the server base URL)')
    surface = d.get("surface") or {}
    return RoE(
        target_id=str(target.get("id") or "unnamed"),
        argv=list(argv),
        sha256=str(target.get("sha256") or ""),
        classes=[str(c) for c in classes],
        surface_tools=[str(t) for t in (surface.get("tools") or [])],
        env=dict(env),
        upstream_url_keys=[str(k) for k in uk],
        mode=str(d.get("mode") or "offline"),
        budget=budget,
        kill_switch=str(d.get("kill_switch") or ""),
        authorized_by=str(d.get("authorized_by") or ""),
        expires_at=str(d.get("expires_at") or ""),
        live_approved_by=str(d.get("live_approved_by") or ""),
        live_approved_at=str(d.get("live_approved_at") or ""),
    )


def validate_for_run(roe: RoE, *, allow_live: bool = False, now: datetime | None = None) -> None:
    """Refuse the run unless the RoE is sound: signed, unexpired, target on disk matches its hash, and
    (for live) the live gate is satisfied AND explicitly allowed by the caller. Raises RoEError otherwise."""
    if not roe.authorized_by:
        raise RoEError("RoE is not signed (authorized_by is empty)")
    if roe.expired(now=now):
        raise RoEError(f"RoE expired at {roe.expires_at!r}")
    if roe.sha256:
        actual = hash_target(roe.argv)
        if actual != roe.sha256:
            raise RoEError("target on disk does not match the RoE sha256 (files changed or wrong target)")
    if roe.mode not in ("offline", "live"):
        raise RoEError(f"unknown mode {roe.mode!r}")
    if roe.mode == "live":
        if not allow_live:
            raise RoEError("live mode requires an explicit --live opt-in at launch")
        if not (roe.live_approved_by and roe.live_approved_at):
            raise RoEError("live mode requires live_approved_by and live_approved_at in the RoE")
