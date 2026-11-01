"""Sealed launcher. Runs INSIDE `unshare -rn`. Standard library only.

Order is the contract: recorder up -> capture rules up -> proof P1..P6 -> only then exec the server.
A proof failure writes sealed=false and exits 3; the server is never started.
stdout belongs to the server's MCP stdio channel, so nothing here writes to stdout.

Capture, and why it differs by protocol:
- TCP: REDIRECT in nat OUTPUT. SO_ORIGINAL_DST on the accepted socket gives the original destination.
- UDP: REDIRECT rewrites the destination, so the original is lost. Instead, OUTPUT marks UDP packets, a policy
  table routes them through lo, and TPROXY in PREROUTING hands them to a transparent socket. TPROXY keeps the
  original destination, which IP_RECVORIGDSTADDR returns. Verified in a throwaway namespace.
- Every route points at lo, the only interface, so nothing can leave the namespace.
"""
import argparse
import base64
import json
import os
import re
import socket
import struct
import subprocess
import sys
import threading
import time

SO_ORIGINAL_DST = 80        # netfilter: original destination of a REDIRECTed TCP socket
IP_TRANSPARENT = 19         # lets the UDP socket accept TPROXYed datagrams
IP_RECVORIGDSTADDR = 20     # the original destination of a TPROXYed UDP datagram
POLICY_TABLE = "100"
MARK = "0x1"
CAP = 64 * 1024             # bytes kept per attempt; more than this marks the attempt truncated
IDLE = 1.0                  # TCP: stop reading an attempt after this much silence
PROBE_TARGETS = [("tcp", "1.1.1.1", 80), ("tcp", "127.0.0.1", 9999), ("udp", "8.8.8.8", 53)]
PROBE_CHILD = (
    "import socket, sys\n"
    "n = sys.argv[1]\n"
    "for ip, port in (('1.1.1.1', 80), ('127.0.0.1', 9999)):\n"
    "    try:\n"
    "        s = socket.create_connection((ip, port), timeout=3)\n"
    "        s.sendall(('probe-' + n + ' ' + ip + ':' + str(port)).encode())\n"
    "        s.close()\n"
    "    except OSError:\n"
    "        pass\n"
    "u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
    "u.sendto(('probe-' + n).encode(), ('8.8.8.8', 53))\n"
    "u.close()\n"
)
_SA4 = re.compile(r'sin_port=htons\((\d+)\), sin_addr=inet_addr\("([0-9.]+)"\)')
# strace -f prefixes each line with a pid. Only attempt syscalls carry a destination. getsockname and accept carry
# a local or peer name, and counting those would invent attempts.
_ATTEMPT = re.compile(r"^(?:\d+\s+)?(?:connect|sendto|sendmsg)\(")


def strace_destinations(text):
    """(ip, port) of every IPv4 destination in a connect/sendto/sendmsg line."""
    found = set()
    for line in (text or "").splitlines():
        if _ATTEMPT.match(line):
            found.update((ip, int(port)) for port, ip in _SA4.findall(line))
    return found


def has_ipv6_attempt(text):
    """True when an attempt names an IPv6 destination. The recorder is IPv4-only, so that attempt is unobservable."""
    return any(_ATTEMPT.match(line) and "AF_INET6" in line for line in (text or "").splitlines())


_HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"PATCH ", b"OPTIONS ")


def _looks_http(buf):
    """True if the bytes begin an HTTP/1.x request line (so a plaintext 302 can be emitted). A TLS
    ClientHello (0x16 0x03 ...) is NOT http -> we cannot terminate it to emit a redirect, so the
    redirect-follow is unobservable (INCONCLUSIVE), never CLEAN."""
    return bytes(buf[:8]).startswith(_HTTP_METHODS)


class Recorder:
    """Accepts every redirected or TPROXYed attempt, records it, and forwards nothing."""

    def __init__(self, port, events_path, redirect=None):
        self.port = port
        self.events_path = events_path
        self.redirect = redirect        # #28: {sentinel_port, canary_host, canary_port, nonce} or None
        self.phase = "proof"
        self._events = []
        self._lock = threading.Lock()
        self.tcp_ready = threading.Event()
        self.udp_ready = threading.Event()

    def _r302(self):
        r = self.redirect
        loc = "http://%s:%d/%s" % (r["canary_host"], r["canary_port"], r["nonce"])
        return ("HTTP/1.1 302 Found\r\nLocation: %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                % loc).encode()

    def start(self):
        threading.Thread(target=self._tcp_accept, daemon=True).start()
        threading.Thread(target=self._udp_loop, daemon=True).start()
        if not (self.tcp_ready.wait(5) and self.udp_ready.wait(5)):
            raise RuntimeError("recorder did not bind")

    def snapshot(self):
        with self._lock:
            return list(self._events)

    def _record(self, ev):
        ev["phase"] = self.phase
        with self._lock:
            self._events.append(ev)
            with open(self.events_path, "a") as f:
                f.write(json.dumps(ev) + "\n")

    def _tcp_accept(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", self.port))
        s.listen(128)
        self.tcp_ready.set()
        while True:
            conn, _ = s.accept()
            threading.Thread(target=self._tcp_conn, args=(conn,), daemon=True).start()

    def _tcp_conn(self, conn):
        try:
            raw = conn.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
            dport = struct.unpack("!H", raw[2:4])[0]
            dip = socket.inet_ntoa(raw[4:8])
        except OSError:
            dip, dport = None, None
        buf, truncated, emitted = bytearray(), False, False
        conn.settimeout(IDLE)
        try:
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                buf.extend(chunk)
                if len(buf) > CAP:
                    truncated = True
                    break
                # SERVER-phase redirect oracle (#28): answer EXACTLY the sentinel dst with a 302 to the
                # internal canary, once a full plaintext-HTTP request head is in. Scoped by SO_ORIGINAL_DST;
                # every other dst (and a TLS ClientHello we cannot terminate) stays record-and-close.
                if (not emitted and self.phase == "server" and self.redirect
                        and dport == self.redirect["sentinel_port"]
                        and _looks_http(buf) and b"\r\n\r\n" in buf):
                    try:
                        conn.sendall(self._r302())
                    except OSError:
                        pass
                    emitted = True
                    break
        except OSError:
            pass
        finally:
            conn.close()
        self._record({"proto": "tcp", "dst": dip, "port": dport, "truncated": truncated,
                      "payload": base64.b64encode(bytes(buf[:CAP])).decode()})

    def _udp_loop(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_IP, IP_TRANSPARENT, 1)
        s.setsockopt(socket.SOL_IP, IP_RECVORIGDSTADDR, 1)
        s.bind(("0.0.0.0", self.port))
        self.udp_ready.set()
        while True:
            data, anc, _flags, _src = s.recvmsg(65536, 256)
            dip = dport = None
            for level, kind, cdata in anc:
                if level == socket.SOL_IP and kind == IP_RECVORIGDSTADDR and len(cdata) >= 8:
                    dport = struct.unpack("!H", cdata[2:4])[0]
                    dip = socket.inet_ntoa(cdata[4:8])
            self._record({"proto": "udp", "dst": dip, "port": dport, "truncated": len(data) > CAP,
                          "payload": base64.b64encode(data[:CAP]).decode()})


def _run(*args):
    return subprocess.run(list(args), capture_output=True, text=True)


def prove(rec, host_ino, port, workdir):
    """P1..P6. Every check is a boolean; the caller treats any False as unsealed."""
    checks = {}
    checks["P1_own_netns"] = os.stat("/proc/self/ns/net").st_ino != host_ino
    # /proc/net/dev is per network namespace; /sys/class/net would show the host's interfaces.
    names = [line.split(":")[0].strip() for line in open("/proc/net/dev").read().splitlines()[2:]]
    checks["P2_only_lo"] = names == ["lo"]
    routes = [line for line in _run("ip", "-4", "route", "show").stdout.splitlines() if line.strip()]
    checks["P3_default_route_via_lo_only"] = (bool(routes) and all(" dev lo" in r for r in routes)
                                              and any(r.startswith("default") for r in routes))
    added = [
        _run("iptables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-j", "REDIRECT", "--to-ports", str(port)),
        _run("iptables", "-t", "mangle", "-A", "OUTPUT", "-p", "udp", "-j", "MARK", "--set-mark", MARK),
        _run("iptables", "-t", "mangle", "-A", "PREROUTING", "-p", "udp", "-m", "mark", "--mark", f"{MARK}/{MARK}",
             "-j", "TPROXY", "--on-ip", "127.0.0.1", "--on-port", str(port), "--tproxy-mark", f"{MARK}/{MARK}"),
    ]
    nat_out = _run("iptables", "-t", "nat", "-S", "OUTPUT").stdout
    mangle_out = _run("iptables", "-t", "mangle", "-S", "OUTPUT").stdout + _run(
        "iptables", "-t", "mangle", "-S", "PREROUTING").stdout
    policy = _run("ip", "-4", "route", "show", "table", POLICY_TABLE).stdout
    checks["P4_capture_rules"] = (all(r.returncode == 0 for r in added)
                                  and f"REDIRECT --to-ports {port}" in nat_out
                                  and "MARK" in mangle_out and "TPROXY" in mangle_out
                                  and "default dev lo" in policy)
    nonce = os.urandom(6).hex()
    strace_probe = os.path.join(workdir, "probe.strace")
    subprocess.run(["strace", "-f", "-e", "trace=network", "-o", strace_probe, "--",
                    sys.executable, "-I", "-c", PROBE_CHILD, nonce], capture_output=True, timeout=60)

    def probes_seen():
        seen = set()
        for ev in rec.snapshot():
            if ev.get("phase") != "proof" or ev["dst"] is None:
                continue
            if nonce.encode() not in base64.b64decode(ev["payload"]):
                continue
            for proto, ip, pport in PROBE_TARGETS:
                if (ev["proto"], ev["dst"], ev["port"]) == (proto, ip, pport):
                    seen.add((proto, ip, pport))
        return seen

    deadline = time.time() + 15
    seen = probes_seen()
    while len(seen) < len(PROBE_TARGETS) and time.time() < deadline:
        time.sleep(0.2)
        seen = probes_seen()
    checks["P5_recorder_saw_every_probe"] = len(seen) == len(PROBE_TARGETS)
    try:
        probe_text = open(strace_probe).read()
    except OSError:
        probe_text = ""
    witnessed = strace_destinations(probe_text)
    checks["P6_strace_witness_saw_every_probe"] = (all((ip, pport) in witnessed for _, ip, pport in PROBE_TARGETS)
                                                   and not has_ipv6_attempt(probe_text))
    return checks


def main(argv=None):
    ap = argparse.ArgumentParser(prog="sandbox.py")
    ap.add_argument("--report", required=True)
    ap.add_argument("--events", required=True)
    ap.add_argument("--workdir", required=True)
    ap.add_argument("--host-netns-ino", type=int, required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--server-json", required=True)
    ap.add_argument("--strace-server", required=True)
    ap.add_argument("--strace-probe", required=True)
    ap.add_argument("--redirect")                      # #28: JSON {sentinel_port,canary_host,canary_port,nonce}
    ap.add_argument("--proof-only", action="store_true")
    args = ap.parse_args(argv)
    report = {"sealed": False, "checks": {}, "server_started": False, "server_rc": None, "error": None}

    def save():
        with open(args.report, "w") as f:
            json.dump(report, f)

    rec = None
    proc = None
    try:
        subprocess.run(["ip", "link", "set", "lo", "up"], check=True, capture_output=True)
        # Every destination routes via lo, so each attempt reaches netfilter. Without a route, connect() fails in
        # routing and the attempt is never seen. lo is the only interface, so nothing can leave.
        subprocess.run(["ip", "route", "add", "default", "dev", "lo"], check=True, capture_output=True)
        # Marked UDP (from OUTPUT) uses a policy table that also routes through lo, so TPROXY can take it.
        subprocess.run(["ip", "rule", "add", "fwmark", MARK, "lookup", POLICY_TABLE], check=True, capture_output=True)
        subprocess.run(["ip", "route", "add", "default", "dev", "lo", "table", POLICY_TABLE], check=True,
                       capture_output=True)
        rec = Recorder(args.port, args.events, redirect=json.loads(args.redirect) if args.redirect else None)
        rec.start()
        report["checks"] = prove(rec, args.host_netns_ino, args.port, args.workdir)
        report["sealed"] = bool(report["checks"]) and all(report["checks"].values())
    except Exception as exc:  # any failure to prove the seal leaves sealed=false
        report["error"] = repr(exc)[:300]
    save()
    if args.proof_only or not report["sealed"]:
        return 0 if report["sealed"] else 3
    with open(args.server_json) as f:
        server = json.load(f)
    rec.phase = "server"
    try:
        proc = subprocess.Popen(["strace", "-f", "-e", "trace=network", "-o", args.strace_server, "--", *server],
                                cwd=args.workdir, start_new_session=True)
        report["server_started"] = True
        save()
        report["server_rc"] = proc.wait()
        time.sleep(IDLE + 0.5)  # let any open attempt finish before the recorder is read
    finally:
        if proc is not None and proc.poll() is None:
            os.killpg(proc.pid, 9)
        save()
    return 0


if __name__ == "__main__":
    sys.exit(main())
