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
    envelope: Mapped[str] = mapped_column(Text)    # signed attestation JSON
    report: Mapped[str] = mapped_column(Text)      # evidence JSON
    badge: Mapped[str] = mapped_column(Text)       # badge SVG
    scanned_at: Mapped[str] = mapped_column(String(40))
    created_at: Mapped[str] = mapped_column(String(40), default=_now)
    __table_args__ = (UniqueConstraint("org_id", "slug", name="uq_org_slug"),)   # latest per server per org


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
             envelope: str, report: str, badge: str, scanned_at: str) -> str:
        """Upsert the latest attestation for (org, slug); return its public share id."""
        public_id = secrets.token_urlsafe(12).replace("_", "").replace("-", "")[:16]
        with Session(self.engine) as s:
            s.execute(delete(Attestation).where(Attestation.org_id == org_id, Attestation.slug == slug))
            s.add(Attestation(org_id=org_id, public_id=public_id, slug=slug, target=target,
                              verdict=verdict, tier=tier, envelope=envelope, report=report,
                              badge=badge, scanned_at=scanned_at))
            s.commit()
        return public_id

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
