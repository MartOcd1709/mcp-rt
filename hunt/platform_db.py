"""Multi-tenant platform store — the enterprise data layer behind `mcp-rt serve`.

SQLAlchemy 2.0 ORM so the SAME code runs on SQLite locally and Postgres on the VPS: set
``DATABASE_URL`` (e.g. ``postgresql+psycopg://user:pw@host/db``) and nothing else changes.
Everything is scoped by ``org_id`` and gated by a hashed API token, so one deployment serves
many tenants without leaking data across them.

    from hunt.platform_db import Store
    store = Store()                      # sqlite:///mcprt_platform.db by default
    token = store.ensure_default_org()   # dev convenience: prints/returns a usable token
    org_id = store.org_for_token(token)
"""
from __future__ import annotations

import datetime
import hashlib
import os
import secrets

from sqlalchemy import ForeignKey, String, Text, UniqueConstraint, create_engine, delete, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

_DEFAULT_URL = "sqlite:///mcprt_platform.db"


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class Base(DeclarativeBase):
    pass


class Org(Base):
    __tablename__ = "orgs"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200), unique=True)
    created_at: Mapped[str] = mapped_column(String(40), default=_now)


class ApiToken(Base):
    __tablename__ = "api_tokens"
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("orgs.id"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), index=True)   # sha256, never the plaintext
    created_at: Mapped[str] = mapped_column(String(40), default=_now)


class Attestation(Base):
    __tablename__ = "attestations"
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("orgs.id"), index=True)
    public_id: Mapped[str] = mapped_column(String(32), index=True)   # unguessable public share id
    slug: Mapped[str] = mapped_column(String(80))
    target: Mapped[str] = mapped_column(Text)
    verdict: Mapped[str] = mapped_column(String(20))
    tier: Mapped[str] = mapped_column(String(20))
    change: Mapped[str] = mapped_column(String(16), default="new")   # new|regressed|fixed|unchanged vs prior scan
    envelope: Mapped[str] = mapped_column(Text)    # signed attestation JSON
    report: Mapped[str] = mapped_column(Text)      # evidence JSON
    badge: Mapped[str] = mapped_column(Text)       # badge SVG
    scanned_at: Mapped[str] = mapped_column(String(40))
    created_at: Mapped[str] = mapped_column(String(40), default=_now)
    __table_args__ = (UniqueConstraint("org_id", "slug", name="uq_org_slug"),)   # latest per server per org


class ScanRun(Base):
    """Append-only history of every scan — powers trend + rug-pull/drift detection over time."""
    __tablename__ = "scan_runs"
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("orgs.id"), index=True)
    slug: Mapped[str] = mapped_column(String(80), index=True)
    verdict: Mapped[str] = mapped_column(String(20))
    tier: Mapped[str] = mapped_column(String(20))
    change: Mapped[str] = mapped_column(String(16))
    scanned_at: Mapped[str] = mapped_column(String(40))


def _change(prev: str | None, new: str) -> str:
    """Classify a verdict transition. CLEAN->VULNERABLE is a rug-pull/drift regression."""
    if prev is None:
        return "new"
    if prev == new:
        return "unchanged"
    if new == "VULNERABLE" and prev == "CLEAN":
        return "regressed"
    if new == "CLEAN" and prev == "VULNERABLE":
        return "fixed"
    return "changed"


class Store:
    def __init__(self, url: str | None = None):
        url = url or os.getenv("DATABASE_URL") or _DEFAULT_URL
        kw = {"connect_args": {"check_same_thread": False}} if url.startswith("sqlite") else {}
        self.engine = create_engine(url, **kw)
        Base.metadata.create_all(self.engine)

    # ---- tenancy ----------------------------------------------------------------------
    def create_org(self, name: str) -> str:
        """Create an org and return a fresh plaintext API token (shown once, stored hashed)."""
        with Session(self.engine) as s:
            org = Org(name=name)
            s.add(org)
            s.flush()
            token = self._mint(s, org.id)
            s.commit()
            return token

    def ensure_default_org(self, name: str = "default") -> str:
        """Dev convenience: ensure an org exists and return a NEW usable token for it."""
        with Session(self.engine) as s:
            org = s.scalar(select(Org).where(Org.name == name))
            if org is None:
                org = Org(name=name)
                s.add(org)
                s.flush()
            token = self._mint(s, org.id)
            s.commit()
            return token

    def _mint(self, s: Session, org_id: int) -> str:
        token = secrets.token_urlsafe(24)
        s.add(ApiToken(org_id=org_id, token_hash=_hash(token)))
        return token

    def org_for_token(self, token: str) -> int | None:
        if not token:
            return None
        with Session(self.engine) as s:
            row = s.scalar(select(ApiToken).where(ApiToken.token_hash == _hash(token)))
            return row.org_id if row else None

    # ---- attestations (org-scoped) ----------------------------------------------------
    def save(self, org_id: int, *, slug: str, target: str, verdict: str, tier: str,
             envelope: str, report: str, badge: str, scanned_at: str) -> tuple[str, str]:
        """Upsert the latest attestation for (org, slug) + append history. Returns (public_id, change)."""
        public_id = secrets.token_urlsafe(12).replace("_", "").replace("-", "")[:16]
        with Session(self.engine) as s:
            prev = s.scalar(select(Attestation.verdict).where(Attestation.org_id == org_id,
                                                              Attestation.slug == slug))
            change = _change(prev, verdict)
            s.execute(delete(Attestation).where(Attestation.org_id == org_id, Attestation.slug == slug))
            s.add(Attestation(org_id=org_id, public_id=public_id, slug=slug, target=target,
                              verdict=verdict, tier=tier, change=change, envelope=envelope,
                              report=report, badge=badge, scanned_at=scanned_at))
            s.add(ScanRun(org_id=org_id, slug=slug, verdict=verdict, tier=tier, change=change,
                          scanned_at=scanned_at))
            s.commit()
        return public_id, change

    def list(self, org_id: int) -> list[Attestation]:
        with Session(self.engine) as s:
            return list(s.scalars(select(Attestation).where(Attestation.org_id == org_id)
                                   .order_by(Attestation.scanned_at.desc())))

    def get(self, org_id: int, slug: str) -> Attestation | None:
        with Session(self.engine) as s:
            return s.scalar(select(Attestation).where(Attestation.org_id == org_id,
                                                      Attestation.slug == slug))

    def get_public(self, public_id: str) -> Attestation | None:
        """Fetch by the unguessable public share id (cross-org — this is the shareable proof link)."""
        with Session(self.engine) as s:
            return s.scalar(select(Attestation).where(Attestation.public_id == public_id))

    def all_targets(self) -> list[tuple[int, str, str, str]]:
        """(org_id, slug, target, tier) for every tracked server — the monitor's rescan worklist."""
        with Session(self.engine) as s:
            return [(a.org_id, a.slug, a.target, a.tier) for a in s.scalars(select(Attestation))]

    def history(self, org_id: int, slug: str) -> list[ScanRun]:
        """Every scan of one server, newest first — the per-server trend."""
        with Session(self.engine) as s:
            return list(s.scalars(select(ScanRun).where(ScanRun.org_id == org_id, ScanRun.slug == slug)
                                  .order_by(ScanRun.id.desc())))

    def recent_changes(self, org_id: int, limit: int = 20) -> list[ScanRun]:
        """Latest scans whose verdict changed (regressions/fixes) — the monitoring feed."""
        with Session(self.engine) as s:
            return list(s.scalars(
                select(ScanRun).where(ScanRun.org_id == org_id,
                                      ScanRun.change.in_(("regressed", "fixed", "changed")))
                .order_by(ScanRun.id.desc()).limit(limit)))
