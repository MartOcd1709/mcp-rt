"""Discovery on macOS and Windows: the same code, pointed at a profile laid out the way each OS keeps it.

There is no per-platform branch in config discovery (one list of locations for every OS), so planting a macOS or a
Windows layout on Linux exercises the production path. What these tests cannot show is behaviour on real macOS or
Windows hardware; the process listing differs per OS and is pinned here by its command line only."""
import json

from hunt import discover as dc


def _plant(path, name, key="mcpServers", encoding="utf-8"):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({key: {name: {"command": "npx", "args": ["-y", name]}}}), encoding=encoding)


def test_macos_and_windows_profile_layouts_are_found(tmp_path):
    mac, win = tmp_path / "Users" / "bob", tmp_path / "Users" / "carol"
    _plant(mac / "Library/Application Support/Claude/claude_desktop_config.json", "mac-desktop")
    _plant(mac / "Library/Application Support/Code/User/mcp.json", "mac-vscode", key="servers")
    _plant(win / "AppData/Roaming/Claude/claude_desktop_config.json", "win-desktop")
    _plant(win / "AppData/Roaming/Code/User/mcp.json", "win-vscode", key="servers")
    _plant(win / ".cursor/mcp.json", "win-cursor")
    assert {s.name for s in dc.discover_configs(home=mac)} == {"mac-desktop", "mac-vscode"}
    assert {s.name for s in dc.discover_configs(home=win)} == {"win-desktop", "win-vscode", "win-cursor"}


def test_every_app_data_location_is_listed_for_all_three_systems():
    for rel in ("Claude/claude_desktop_config.json", "Code/User/mcp.json"):
        for base in (".config", "Library/Application Support", "AppData/Roaming"):
            assert f"{base}/{rel}" in dc._HOME_CONFIGS


def _plant_any(path, name):
    """A one-server config in whatever format the file's extension calls for."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.suffix == ".toml":
        path.write_text(f'[mcp_servers.{name}]\ncommand = "npx"\nargs = ["x"]\n')
    elif path.suffix in (".yaml", ".yml"):
        path.write_text(f"mcpServers:\n  - name: {name}\n    command: npx\n    args: [x]\n")
    else:
        path.write_text(json.dumps({"mcpServers": {name: {"command": "npx", "args": ["x"]}}}))


def test_every_listed_location_is_discoverable(tmp_path):
    """The table and the parser agree: a server planted at any known location comes back ("*" = any one name)."""
    for i, rel in enumerate(dc._HOME_CONFIGS):
        _plant_any(tmp_path / rel.replace("*", "p1"), f"t{i}")
    assert {s.name for s in dc.discover_configs(home=tmp_path)} == {f"t{i}" for i in range(len(dc._HOME_CONFIGS))}


def test_admin_managed_system_files_are_found_on_each_system(tmp_path):
    for i, rel in enumerate(dc._SYSTEM_CONFIGS):
        _plant_any(tmp_path / rel, f"sys{i}")
    found = dc.discover_system_configs(root=tmp_path)
    assert {s.name for s in found} == {f"sys{i}" for i in range(len(dc._SYSTEM_CONFIGS))}
    for must in ("etc/claude-code/managed-mcp.json", "Library/Application Support/ClaudeCode/managed-mcp.json",
                 "Program Files/ClaudeCode/managed-mcp.json"):
        assert must in dc._SYSTEM_CONFIGS                    # Linux, macOS, Windows
    assert dc.discover_system_configs(root=tmp_path / "empty") == []


def test_vscode_named_profiles_are_found(tmp_path):
    _plant(tmp_path / "AppData/Roaming/Code/User/profiles/-6f3a1c/mcp.json", "profile-server", key="servers")
    assert [s.name for s in dc.discover_configs(home=tmp_path)] == ["profile-server"]


def test_goose_yaml_extensions(tmp_path):
    p = tmp_path / ".config/goose/config.yaml"
    p.parent.mkdir(parents=True)
    p.write_text("extensions:\n"
                 "  github:\n    type: stdio\n    cmd: npx\n    args: [-y, gh-server]\n    envs: {GH_TOKEN: ghp_secretvalue0123456789}\n"
                 "  remote:\n    type: streamable_http\n    uri: https://example.test/mcp\n"
                 "  developer:\n    type: builtin\n    name: developer\n")
    by = {s.name: s for s in dc.discover_configs(home=tmp_path)}
    assert set(by) == {"github", "remote"}                   # the built-in is not an installed server
    assert by["github"].launch == "npx -y gh-server" and by["github"].env_keys == ["GH_TOKEN"]
    assert by["remote"].transport == "http" and by["remote"].launch == "https://example.test/mcp"
    assert "ghp_secretvalue0123456789" not in json.dumps([s.as_dict() for s in by.values()])


def test_other_spellings_of_the_same_fields(tmp_path):
    (tmp_path / ".codeium/windsurf").mkdir(parents=True)
    (tmp_path / ".codeium/windsurf/mcp_config.json").write_text(json.dumps({"mcpServers": {
        "remote-a": {"serverUrl": "https://a.example.test/sse"},
        "remote-b": {"httpUrl": "https://b.example.test/mcp"},
        "typed": {"transport": "stdio", "command": "uvx", "args": ["typed-server", 8080]},     # a word, not a wrapper
        "old-zed": {"command": {"path": "/opt/z/server", "args": ["--fast"], "env": {"Z_KEY": "v"}}},
        "argv": {"command": ["node", "srv.js"], "args": ["--x"]}}}))
    by = {s.name: s for s in dc.discover_configs(home=tmp_path)}
    assert by["remote-a"].launch.endswith("/sse") and by["remote-b"].transport == "http"
    assert by["typed"].launch == "uvx typed-server 8080"
    assert by["old-zed"].launch == "/opt/z/server --fast" and by["old-zed"].env_keys == ["Z_KEY"]
    assert by["argv"].launch == "node srv.js --x"


def test_an_unexpected_shape_is_skipped_not_fatal(tmp_path):
    (tmp_path / ".cursor").mkdir()
    (tmp_path / ".cursor/mcp.json").write_text(json.dumps({"mcp": ["not", "a", "map"], "mcpServers": "nope"}))
    (tmp_path / ".gemini").mkdir()
    (tmp_path / ".gemini/settings.json").write_text(json.dumps({"mcpServers": {"ok": {"command": "npx"},
                                                                               "bad": {"command": 7}, "worse": []}}))
    assert [s.name for s in dc.discover_configs(home=tmp_path)] == ["ok"]


def test_config_saved_with_a_byte_order_mark_parses(tmp_path):
    _plant(tmp_path / ".cursor/mcp.json", "bom-server", encoding="utf-8-sig")     # what Windows editors write
    assert [s.name for s in dc.discover_configs(home=tmp_path)] == ["bom-server"]


def test_zed_context_servers_are_read(tmp_path):
    _plant(tmp_path / ".config/zed/settings.json", "zed-server", key="context_servers")
    assert [s.name for s in dc.discover_configs(home=tmp_path)] == ["zed-server"]


def test_name_heuristic_reads_windows_command_lines():
    found = dc.processes_from_cmdlines([
        r"C:\Python312\python.exe C:\tools\weather-mcp\server.py --api-key sk-live-abcdef123456",
        r"C:\Windows\System32\svchost.exe -k netsvcs",
        r"C:\Program Files\nodejs\node.exe C:\Users\carol\AppData\Roaming\npm\node_modules\files-mcp\dist\index.js"])
    assert len(found) == 2 and all(s.source == "running process" for s in found)
    assert found[0].name == "server.py" and found[1].name == "index.js"         # no folders, either separator
    assert "sk-live-abcdef123456" not in " ".join(s.launch for s in found)


def test_macos_process_listing_never_asks_ps_for_the_environment(monkeypatch):
    """BSD ps reads -e as "print each process's environment": every variable of every process, secrets included."""
    import shutil
    import subprocess
    import sys
    seen = {}

    def fake_run(argv, **kw):
        seen["argv"] = argv
        return type("R", (), {"stdout": "uvx some-mcp-server\n"})()
    monkeypatch.setattr(shutil, "which", lambda x: "/bin/ps")
    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(sys, "platform", "darwin")
    assert [s.name for s in dc.discover_processes()] == ["some-mcp-server"]
    assert not any(a.startswith("-e") for a in seen["argv"]) and "-axww" in seen["argv"]
    monkeypatch.setattr(sys, "platform", "linux")
    dc.discover_processes()
    assert seen["argv"] == ["ps", "-eo", "args"]                                   # Linux unchanged
