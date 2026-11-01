"""Per-scan isolation: env confinement, backend selection, and report capture (mocked).

No real containers/subprocess scans — subprocess.run and docker_available are monkeypatched.
Verifies each scan gets a confined env, the right backend is chosen, a report is parsed from
stdout, and a failed isolated scan degrades to an honest INCONCLUSIVE (never raises).
"""
import json
from types import SimpleNamespace

import hunt.sandbox as sandbox


def test_isolated_env_confines_caches(tmp_path):
    env = sandbox.isolated_env(str(tmp_path / "h"))
    assert env["HOME"] == str(tmp_path / "h")
    assert env["npm_config_cache"].startswith(env["HOME"])
    assert env["UV_CACHE_DIR"].startswith(env["HOME"]) and env["PIP_CACHE_DIR"].startswith(env["HOME"])


def test_choose_backend(monkeypatch):
    monkeypatch.setattr(sandbox, "docker_available", lambda: False)
    monkeypatch.setenv("MCPRT_SCAN_BACKEND", "docker")
    assert sandbox._choose("auto") == "subprocess"            # docker wanted but unavailable -> fallback
    monkeypatch.setattr(sandbox, "docker_available", lambda: True)
    assert sandbox._choose("auto") == "docker"
    assert sandbox._choose("subprocess") == "subprocess"      # explicit always honoured


def test_argv_shapes():
    assert sandbox._argv_subprocess("npx -y x")[-3:] == ["--target-stdio", "npx -y x", "--json"]
    dv = sandbox._argv_docker("npx -y x")
    assert dv[0] == "docker" and "--rm" in dv and dv[-1] == "--json"


def _fake_run(stdout="", returncode=0, stderr=""):
    return lambda *a, **k: SimpleNamespace(stdout=stdout, stderr=stderr, returncode=returncode)


def test_run_isolated_parses_report(monkeypatch):
    rep = {"target": "npx -y x", "verdict": "CLEAN", "findings": [], "coverage": []}
    monkeypatch.setattr(sandbox.subprocess, "run",
                        _fake_run(stdout="server banner line\n" + json.dumps(rep)))
    out = sandbox.run_isolated("npx -y x", backend="subprocess")
    assert out["verdict"] == "CLEAN" and out["target"] == "npx -y x"


def test_run_isolated_no_report_is_inconclusive(monkeypatch):
    monkeypatch.setattr(sandbox.subprocess, "run", _fake_run(stdout="boom", returncode=1, stderr="install failed"))
    out = sandbox.run_isolated("npx -y x", backend="subprocess")
    assert out["verdict"] == "INCONCLUSIVE" and "install failed" in out["note"]
