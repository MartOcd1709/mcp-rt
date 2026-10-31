"""#19 B2 resume: engine_version = hash of DETECTION-LOGIC source (R2); a sweep skips a target only when a
scan already exists at the CURRENT engine_version. No seal needed — pure DB + hashing logic."""
import shutil
from pathlib import Path

from hunt.findings_db import DB
from mcp_rt.engine_version import _SOURCES, engine_version

REPO = Path(__file__).resolve().parents[1]


def test_engine_version_is_stable():
    assert engine_version() == engine_version()


def test_engine_version_changes_when_probe_source_changes(tmp_path):
    # R2 / T7: a names+spine hash would NOT change on a logic-only edit (the #22 counterexample). Hashing the
    # SOURCE must: editing a probe's source changes engine_version.
    for rel in _SOURCES:
        dst = tmp_path / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(REPO / rel, dst)
    v1 = engine_version(tmp_path)
    assert v1 == engine_version(tmp_path)                       # deterministic
    probes = tmp_path / "hunt" / "probes.py"
    probes.write_text(probes.read_text() + "\n# a probe's classification logic changed\n")
    assert engine_version(tmp_path) != v1                        # stale results must invalidate


def test_resume_skip_is_keyed_on_name_and_engine_version(tmp_path):
    db = DB(str(tmp_path / "ledger.db"))
    tid = db.add_target(name="pkg-x", install_cmd="npx -y pkg-x", source="npm")
    db.add_scan(tid, mode="sweep", verdict="CLEAN", engine_version="eng-aaaa")
    assert db.scanned_at_engine("pkg-x", "eng-aaaa") is True     # same engine -> skip on resume
    assert db.scanned_at_engine("pkg-x", "eng-bbbb") is False    # engine changed -> re-scan
    assert db.scanned_at_engine("pkg-y", "eng-aaaa") is False    # different target
    db.close()


def test_batch_report_ranks_and_never_folds_inconclusive_into_clean(tmp_path):
    from hunt import sweep
    db = DB(str(tmp_path / "ledger.db"))
    ev = "eng-test01"
    for name, verdict, notes in [("vuln-srv", "VULNERABLE", "command_injection:run_cmd"),
                                 ("clean-srv", "CLEAN", "clean"),
                                 ("inc-srv", "INCONCLUSIVE", "[SANDBOX_UNPROVEN] seal not proven"),
                                 ("setup-srv", "SETUP_FAILED", "[BROKEN_PACKAGE] no module")]:
        tid = db.add_target(name=name, install_cmd=f"npx {name}", source="npm")
        db.add_scan(tid, mode="sweep", verdict=verdict, notes=notes, engine_version=ev)
    md = sweep.batch_report(db, ev)
    db.close()
    # VULNERABLE ranked first; INCONCLUSIVE + SETUP_FAILED present and NOT folded into clean.
    # ranking: VULNERABLE → … → INCONCLUSIVE → SETUP_FAILED → CLEAN (clean last, never above an unknown).
    assert md.index("vuln-srv") < md.index("inc-srv") < md.index("clean-srv")
    assert "INCONCLUSIVE: 1" in md and "SETUP_FAILED: 1" in md and "CLEAN: 1" in md and "VULNERABLE**: 1" in md
