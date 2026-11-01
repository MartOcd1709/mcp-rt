"""Single-source contract for the Master Attack Taxonomy (T5 / SAM1-17): the self-check holds, the
moat is enforced (no COVERED without evidence), and no surface drifts from the matrix."""
from hunt.report import CLASS_META
from mcp_rt import taxonomy as T


def test_selfcheck_clean():
    problems = T.selfcheck()
    assert problems == [], "taxonomy self-check must be clean:\n" + "\n".join(problems)


def test_covered_requires_evidence():
    # the moat: a COVERED row without a zero-FP evidence pointer is forbidden
    for it in T.TAXONOMY:
        if it.status == T.COVERED:
            assert it.evidence.strip(), f"{it.id} COVERED without evidence"


def test_open_items_state_a_reason():
    for it in T.TAXONOMY:
        if it.status in (T.PARTIAL, T.PLANNED, T.NA):
            assert it.notes.strip(), f"{it.id} {it.status} without a reason"


def test_every_detection_class_has_a_row():
    # reconcile with reality: the engine can't have a class that's missing from the taxonomy
    mapped = {it.our_class for it in T.TAXONOMY if it.our_class}
    missing = [c for c in CLASS_META if c not in mapped]
    assert not missing, f"detection classes absent from taxonomy: {missing}"


def test_every_standard_item_accounted_for():
    # completeness denominator: each external-standard id is referenced by a row or explicitly UNMAPPED
    refs = {r for it in T.TAXONOMY for r in it.external_refs}
    for name, s in T.STANDARDS.items():
        for iid in s["items"]:
            ref = f"{name}:{iid}"
            assert ref in refs or ref in T.UNMAPPED, f"unaccounted standard item {ref}"


def test_coverage_count_matches_matrix():
    # single source: the printed number is derived, never hardcoded
    cov = T.coverage()
    assert cov["total_items"] == len(T.TAXONOMY)
    assert cov["by_status"][T.COVERED] == sum(1 for it in T.TAXONOMY if it.status == T.COVERED)


def test_external_refs_resolve():
    for it in T.TAXONOMY:
        for r in it.external_refs:
            std, _, iid = r.partition(":")
            assert std in T.STANDARDS and iid in T.STANDARDS[std]["items"], f"{it.id}: dangling ref {r}"
