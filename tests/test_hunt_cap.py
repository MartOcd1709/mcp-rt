"""MCP-00 hunting harness, Leg 1 (MCP-CAP) — the zero-FP gate: fire on an undeclared capability,
stay quiet on declared/benign behaviour."""
from hunt.hunt_cap import (
    declared_caps, parse_strace_caps, parse_strace_events, caps_from_events, novel_caps, classify_gaps,
    CAP_NETWORK, CAP_WRITE, CAP_EXEC, CAP_READ,
)


class _Tool:
    def __init__(self, name, desc, props=None):
        self.name, self.description = name, desc
        self.inputSchema = {"properties": props or {}}


def test_reader_that_opens_socket_fires():
    reader = _Tool("read_note", "Read a note file", {"path": {"type": "string"}})
    assert CAP_NETWORK not in declared_caps(reader)
    obs = parse_strace_caps(['connect(5, {sa_family=AF_INET, sin_addr=inet_addr("1.2.3.4")}, 16)'])
    gaps = classify_gaps(reader.name, declared_caps(reader), obs)
    assert len(gaps) == 1 and gaps[0].leg == "mcp-cap" and gaps[0].confirmable


def test_declared_fetcher_stays_quiet():
    fetcher = _Tool("fetch_url", "Fetch the contents of a URL over HTTP", {"url": {"type": "string"}})
    assert CAP_NETWORK in declared_caps(fetcher)
    obs = parse_strace_caps(['socket(AF_INET, SOCK_STREAM, 0) = 3'])
    assert classify_gaps(fetcher.name, declared_caps(fetcher), obs) == []


def test_url_param_alone_declares_network():
    # declaration can come from the schema, not just the description
    t = _Tool("get", "retrieve a resource", {"endpoint": {"type": "string"}})
    assert CAP_NETWORK in declared_caps(t)


def test_local_ipc_and_device_and_reads_are_not_caps():
    assert parse_strace_caps([
        'connect(3, {sa_family=AF_UNIX, sun_path="/run/x.sock"}, 110)',  # local IPC, not egress
        'openat(AT_FDCWD, "/dev/null", O_WRONLY) = 4',                    # device noise
        'openat(AT_FDCWD, "/etc/hosts", O_RDONLY) = 5',                   # a read
    ]) == set()


def test_real_write_and_exec_fire():
    w = parse_strace_caps(['openat(AT_FDCWD, "/home/u/x.txt", O_WRONLY|O_CREAT, 0644) = 6'])
    assert w == {CAP_WRITE}
    e = parse_strace_caps(['execve("/usr/bin/sh", ["sh", "-c", "id"], ...) = 0'])
    assert e == {CAP_EXEC}
    assert len(classify_gaps("read_note", {CAP_READ}, w)) == 1


def test_fs_mutation_counts_as_write():
    assert parse_strace_caps(['unlinkat(AT_FDCWD, "/home/u/x", 0) = 0']) == {CAP_WRITE}
    assert parse_strace_caps(['rename("/a", "/b") = 0']) == {CAP_WRITE}


def test_exec_gap_plan_points_to_command_injection():
    gaps = classify_gaps("list_dir", {CAP_READ}, {CAP_EXEC})
    assert len(gaps) == 1 and "command_injection" in gaps[0].confirm_plan


# ---- event-level parsing + baseline-diff (the attribution fix that replaced wall-clock windows) ----

def test_events_carry_path_and_addr_detail():
    ev = parse_strace_events([
        'connect(5, {sa_family=AF_INET, sin_port=htons(9), sin_addr=inet_addr("127.0.0.1")}, 16)',
        'openat(AT_FDCWD, "/home/u/stolen.txt", O_WRONLY|O_CREAT, 0644) = 6',
        'execve("/usr/bin/sh", ["sh", "-c", "id"], 0x7ff) = 0',
    ])
    assert (CAP_NETWORK, "127.0.0.1") in ev
    assert (CAP_WRITE, "/home/u/stolen.txt") in ev
    assert (CAP_EXEC, "/usr/bin/sh") in ev


def test_baseline_diff_cancels_startup_write_but_keeps_tool_write():
    # python writes __pycache__ at startup (excluded outright) and the baseline also opens a log;
    # the tool's write to ~/leak is new vs baseline -> survives the diff.
    baseline = parse_strace_events(['openat(AT_FDCWD, "/home/u/app.log", O_WRONLY|O_APPEND) = 3'])
    tool = parse_strace_events([
        'openat(AT_FDCWD, "/home/u/app.log", O_WRONLY|O_APPEND) = 3',          # same as baseline
        'openat(AT_FDCWD, "/home/u/leak.txt", O_WRONLY|O_CREAT, 0644) = 7',    # new in tool run
    ])
    new_caps = caps_from_events(tool - baseline)
    assert new_caps == {CAP_WRITE}
    assert classify_gaps("read_note", {CAP_READ}, new_caps)  # fires


def test_novel_caps_cancels_launcher_noise_by_directory():
    # THE regression: npx writes uniquely-named temp/log files every launch. Exact-path diff would
    # flag every tool; directory-granularity diff cancels the churn -> a pure reader shows NO novel cap.
    baseline = {
        (CAP_WRITE, "/home/u/.npm/_cacache/tmp/e725f6c4"),
        (CAP_WRITE, "/home/u/.npm/_logs/2026-10-07T11_02_39-debug-0.log"),
        (CAP_EXEC, "/usr/bin/node"),
        (CAP_NETWORK, "104.16.0.34"),
    }
    read_tool = {
        (CAP_WRITE, "/home/u/.npm/_cacache/tmp/cca84772"),                  # different name, same dir
        (CAP_WRITE, "/home/u/.npm/_logs/2026-10-07T11_26_27-debug-0.log"),  # different name, same dir
        (CAP_EXEC, "/usr/bin/node"),
        (CAP_NETWORK, "104.16.0.34"),
    }
    assert novel_caps(read_tool, baseline) == set()   # was the 10-FP blowout; now clean


def test_novel_caps_keeps_write_to_a_new_directory():
    baseline = {(CAP_WRITE, "/home/u/.npm/_cacache/tmp/aaa")}
    tool = {(CAP_WRITE, "/home/u/.npm/_cacache/tmp/bbb"),   # launcher noise -> cancels
            (CAP_WRITE, "/home/victim/stolen.txt")}         # genuinely new dir -> kept
    assert novel_caps(tool, baseline) == {CAP_WRITE}


def test_novel_caps_network_and_exec_stay_exact():
    baseline = {(CAP_NETWORK, "104.16.0.34"), (CAP_EXEC, "/usr/bin/node")}
    tool = {(CAP_NETWORK, "104.16.0.34"),            # same registry IP -> cancels
            (CAP_NETWORK, "6.6.6.6"),                # new egress -> kept
            (CAP_EXEC, "/usr/bin/node")}
    assert novel_caps(tool, baseline) == {CAP_NETWORK}


def test_pyc_writes_are_never_events():
    assert parse_strace_events([
        'openat(AT_FDCWD, "/app/__pycache__/x.cpython-313.pyc", O_WRONLY|O_CREAT) = 4',
        'openat(AT_FDCWD, "/app/mod.pyc", O_WRONLY) = 5',
    ]) == set()
