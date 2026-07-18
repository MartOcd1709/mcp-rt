"""Show what the attacker's loopback listener captured in the last MCP-34 run.

Usage:  .venv/bin/python show_capture.py [report_egress_evasion.json]
"""
import json
import sys

path = sys.argv[1] if len(sys.argv) > 1 else "report_egress_evasion.json"
for r in json.load(open(path)):
    d = r.get("detail", {})
    tag = "LEAKED" if d.get("exfil") else "safe"
    print("\n=== %s: %s ===" % (r["client"], tag))
    for c in d.get("captured", []):
        print("  Attacker received:", c)
