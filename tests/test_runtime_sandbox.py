"""Unit 3 real sandbox: the seal is proven in a fresh namespace, the server never runs when the proof fails,
and the lab controls that must stay clean do stay clean. These start real namespaces and real servers."""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from mcp_rt.runtime import runner

REPO = Path(__file__).resolve().parents[1]
SENTINEL_SERVER = (
    "import pathlib, sys\n"
    "pathlib.Path(sys.argv[1]).write_text('started')\n"
)
PROOF_CHECKS = {"P1_own_netns", "P2_only_lo", "P3_default_route_via_lo_only", "P4_capture_rules",
                "P5_recorder_saw_every_probe", "P6_strace_witness_saw_every_probe"}


def _proof_only(tmp):
    host_ino = os.stat("/proc/self/ns/net").st_ino
    report = Path(tmp, "report.json")
    Path(tmp, "server.json").write_text("[]")
    cmd = ["unshare", "-rn", "--", sys.executable, "-I", str(runner.LAUNCHER),
           "--report", str(report), "--events", str(Path(tmp, "events.jsonl")), "--workdir", str(tmp),
           "--host-netns-ino", str(host_ino), "--port", "23456", "--server-json", str(Path(tmp, "server.json")),
           "--strace-server", str(Path(tmp, "server.strace")), "--strace-probe", str(Path(tmp, "probe.strace")),
           "--proof-only"]
    rc = subprocess.run(cmd, capture_output=True, text=True, timeout=120).returncode
    return rc, json.loads(report.read_text())


def test_seal_is_proven_in_a_fresh_namespace(tmp_path):
    rc, report = _proof_only(tmp_path)
    assert rc == 0, report
    assert report["sealed"] is True
    assert set(report["checks"]) == PROOF_CHECKS
    assert all(report["checks"].values()), report["checks"]


def test_missing_iptables_is_inconclusive_and_the_server_never_starts(tmp_path, monkeypatch):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for tool in ("unshare", "ip", "strace"):  # everything except iptables
        found = shutil.which(tool)
        if found:
            (bindir / tool).symlink_to(found)
    monkeypatch.setenv("PATH", str(bindir))
    sentinel = tmp_path / "started.flag"
    script = tmp_path / "sentinel_server.py"
    script.write_text(SENTINEL_SERVER)
    rec = runner.run_server([sys.executable, str(script), str(sentinel)], timeout=60)
    assert rec["verdict"] == "INCONCLUSIVE" and rec["method"] == "sandbox_unproven", rec
    assert not sentinel.exists(), "the server ran although the seal did not prove"


@pytest.mark.parametrize("name", [
    "benign_update_check",
    pytest.param("benign_routing", marks=pytest.mark.xfail(strict=True, reason=(
        "generic benign input is refused (unknown downstream tool), so the router's sink is never reached: "
        "INCONCLUSIVE sandbox_not_exercised. The matrix requires CLEAN. CIO ruling pending; the harness is not tuned to it.")))
])
def test_lab_controls_that_must_stay_clean_stay_clean(name):
    rec = runner.run_server([sys.executable, str(REPO / "fixtures" / "_controls" / name / "server.py")])
    assert rec["verdict"] == "CLEAN", rec
