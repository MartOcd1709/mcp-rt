"""Canonical stats contract: shape is stable and figures are DERIVED (never hardcoded), so the
website can't drift from the backend."""
from hunt.report import CLASS_META
from hunt.stats import SCHEMA_VERSION, stats


def test_stats_shape_and_derivation():
    s = stats()
    assert s["schema_version"] == SCHEMA_VERSION
    assert "generated_at" in s
    # class figures are derived from the live catalog, not a hardcoded number
    assert s["class_count"] == len(CLASS_META)
    assert len(s["detection_classes"]) == len(CLASS_META)
    assert {"deserialization"} <= {c["id"] for c in s["detection_classes"]}
    led = s["ledger"]
    for k in ("servers_tested", "confirmed", "clean", "inconclusive",
              "under_coordinated_disclosure", "candidates_triaged_out"):
        assert isinstance(led[k], int) and led[k] >= 0, k
    # internal consistency: confirmed targets can't exceed servers tested
    assert led["confirmed"] <= led["servers_tested"]
    # disclosure safety: never more named published findings than confirmed
    assert len(led["published_findings"]) <= led["confirmed"]
