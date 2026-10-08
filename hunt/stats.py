"""Canonical stats — the SINGLE SOURCE OF TRUTH for every number the product reports.

Derived live from the ledger (findings.db) + the detection catalog, so the website, the scorecard,
and any dashboard all read the same figures and the frontend can never drift from the backend.
Nothing downstream should hardcode a count — read `hunt/stats.json` (or call `stats()`).

Disclosure-safe: a confirmed-but-unpublished finding is COUNTED, never NAMED (coordinated disclosure).

    mcp-rt stats            # -> hunt/stats.json (+ a one-line summary)
"""
from __future__ import annotations

import datetime
import json
import sys
from pathlib import Path

from hunt.report import CLASS_META, OWASP_MCP_TOP10, TESTED_CONTROLS
from hunt.scorecard import RESEARCH_EXFILS, _gather

SCHEMA_VERSION = 1   # bump when the shape changes so the website can detect an incompatible backend


def stats() -> dict:
    """The canonical figures. Both scorecard and website build from this — no parallel counting."""
    g = _gather()
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "class_count": len(CLASS_META),
        "detection_classes": [
            {"id": cls, "title": m["title"], "severity": m["sev"], "cwe": m["cwe"], "owasp": m["owasp"]}
            for cls, m in sorted(CLASS_META.items(), key=lambda kv: kv[1]["title"])],
        "research_agent_exfils": RESEARCH_EXFILS,
        "owasp_top10": [{"id": cid, "title": t, "tested": cid in TESTED_CONTROLS}
                        for cid, t in OWASP_MCP_TOP10.items()],
        "ledger": {
            "servers_tested": g["tested"],
            "confirmed": g["confirmed"],                       # distinct targets with a real finding
            "clean": len(g["clean"]),
            "inconclusive": g["inconclusive"],
            "under_coordinated_disclosure": g["disclosing"],   # counted, NOT named
            "candidates_triaged_out": g["triaged"],            # probe-fires reviewed and rejected (zero-FP proof)
            "clean_named": g["clean"],                         # public — safe to display
            "published_findings": g["published"],              # named only once published/patched
        },
        "false_positive_policy": ("zero — every reported finding is ground-truth confirmed; unpublished "
                                  "findings are counted but never named until coordinated disclosure completes"),
    }


def main(argv=None) -> int:
    out = Path(__file__).resolve().parent / "stats.json"
    data = stats()
    out.write_text(json.dumps(data, indent=2))
    led = data["ledger"]
    print(f"stats written: {out}")
    print(f"  classes={data['class_count']}  tested={led['servers_tested']}  confirmed={led['confirmed']}  "
          f"clean={led['clean']}  inconclusive={led['inconclusive']}  triaged_out={led['candidates_triaged_out']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
