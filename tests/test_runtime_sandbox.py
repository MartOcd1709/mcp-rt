"""Unit 3 real sandbox: the seal is proven in a fresh namespace, the server never runs when the proof fails, and the lab
targets come back as the matrix requires. These start real namespaces and real servers."""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from mcp_rt.runtime import runner
from tests.seal_capability import SEAL_REASON, can_seal

# These start real namespaces / prove the seal. Where the seal can't be built (CI runners without
# unshare -rn / CAP), skip — do not assert. Production stays fail-closed (INCONCLUSIVE) regardless.
pytestmark = pytest.mark.skipif(not can_seal(), reason=SEAL_REASON)

REPO = Path(__file__).resolve().parents[1]
SENTINEL_SERVER = (
    "import pathlib, sys\n"
    "pathlib.Path(sys.argv[1]).write_text('started')\n"
)
PROOF_CHECKS = {"P1_own_netns", "P2_only_lo", "P3_default_route_via_lo_only", "P4_capture_rules",
                "P5_recorder_saw_every_probe", "P6_strace_witness_saw_every_probe"}


def _fixture(name):
    return REPO / "fixtures" / name / "server.py"


def _control(name):
    return REPO / "fixtures" / "_controls" / name / "server.py"


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


def test_control_benign_update_check_stays_clean():
    rec = runner.run_server([sys.executable, str(_control("benign_update_check"))])
    assert rec["verdict"] == "CLEAN", rec


def test_control_benign_routing_stays_clean_when_driven_with_its_operator_input():
    rec = runner.run_server([sys.executable, str(_control("benign_routing"))],
                            hints=runner.load_hints()["benign_routing"])
    assert rec["verdict"] == "CLEAN" and rec["hinted_tools"] == ["gateway_call"], rec


def test_routers_without_operator_input_are_inconclusive_never_clean():
    for path in (_fixture("proxy_aggregator"), _control("benign_routing")):
        rec = runner.run_server([sys.executable, str(path)])
        assert (rec["verdict"], rec["method"]) == ("INCONCLUSIVE", "sandbox_not_exercised"), rec


def test_proxy_class_is_caught_when_driven_by_operator_input():
    rec = runner.run_server([sys.executable, str(_fixture("proxy_aggregator"))],
                            hints=runner.load_hints()["proxy_aggregator"])
    assert (rec["verdict"], rec["method"]) == ("VULNERABLE", "oracle"), rec
    assert rec["hinted_tools"] == ["gateway_call"], rec
