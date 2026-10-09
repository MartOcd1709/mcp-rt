"""Multi-tenant store: org/token auth, org-scoped attestations, public share ids.

The core enterprise guarantee: a token resolves to exactly one org, and one org can never read
another's attestations. Public ids are the only cross-org lookup (the shareable proof link).
"""
from hunt.platform_db import Store


def _store(tmp_path):
    return Store(f"sqlite:///{tmp_path}/t.db")


def test_token_resolves_to_its_org(tmp_path):
    s = _store(tmp_path)
    tok = s.create_org("acme")
    org = s.org_for_token(tok)
    assert org is not None
    assert s.org_for_token("not-a-real-token") is None
    assert s.org_for_token("") is None


def test_attestations_are_org_scoped(tmp_path):
    s = _store(tmp_path)
    a = s.org_for_token(s.create_org("A"))
    b = s.org_for_token(s.create_org("B"))
    s.save(a, slug="srv", target="npx a", verdict="CLEAN", tier="basic",
           envelope="{}", report="{}", badge="<svg/>", scanned_at="t")
    assert len(s.list(a)) == 1
    assert len(s.list(b)) == 0            # B cannot see A's attestation
    assert s.get(b, "srv") is None


def test_upsert_keeps_one_latest_per_slug(tmp_path):
    s = _store(tmp_path)
    org = s.org_for_token(s.create_org("A"))
    s.save(org, slug="srv", target="npx a", verdict="CLEAN", tier="basic",
           envelope="{}", report="{}", badge="x", scanned_at="t1")
    s.save(org, slug="srv", target="npx a", verdict="VULNERABLE", tier="deep",
           envelope="{}", report="{}", badge="x", scanned_at="t2")
    rows = s.list(org)
    assert len(rows) == 1 and rows[0].verdict == "VULNERABLE"


def test_public_id_is_cross_org_lookup(tmp_path):
    s = _store(tmp_path)
    org = s.org_for_token(s.create_org("A"))
    pid = s.save(org, slug="srv", target="npx a", verdict="CLEAN", tier="basic",
                 envelope='{"ok":1}', report="{}", badge="x", scanned_at="t")
    got = s.get_public(pid)
    assert got is not None and got.verdict == "CLEAN"
    assert s.get_public("bogus") is None
