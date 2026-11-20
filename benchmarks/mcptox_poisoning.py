"""Benchmark hunt/poisoning.py on MCPTox (AAAI-26): real poisoned tool descriptions vs the real clean tools.

    python3 benchmarks/mcptox_poisoning.py /path/to/mcptox-dir [--split dev|test|all] [--misses FILE]

The dataset is NOT in this repo (no upstream license; fetch it yourself): MCPTox-Benchmark @ f85189f9ad12504c197c7f920ab818a40657b1fa,
response_all.json (sha256 79a90049be931c59e71446d6180b1d7f0d196d123d08a59bc155d142b5041c03) and pure_tool.json.

  positives  pure_tool.json: the 485 unique poisoned descriptions WITHOUT the "Ignore the previous instructions" prefix
             (primary, hardest) and response_all.json's 1,302 unique as-presented texts (secondary)
  negatives  every legitimate tool of the 45 real servers (descriptions + argument descriptions), parsed from each
             server's clean system prompt
  split      by SERVER with a fixed seed: tune only on `dev`, report `test` (never tuned on) as the honest number
"""
from __future__ import annotations

import argparse
import json
import random
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from hunt import poisoning  # noqa: E402

_TOOL = re.compile(r"Tool:\s*(?P<name>[^\n]+)\nDescription:(?P<body>.*?)(?=\n\s*\n\s*Tool:|\Z)", re.S)


def _split_servers(names: list[str], seed: int = 20261120) -> dict[str, str]:
    order = sorted(names)
    random.Random(seed).shuffle(order)
    half = len(order) // 2
    return {n: ("dev" if i < half else "test") for i, n in enumerate(order)}


def load(d: Path):
    ra = json.loads((d / "response_all.json").read_text())
    pure = json.loads((d / "pure_tool.json").read_text())
    servers = ra["servers"]
    split = _split_servers([s["server_name"] for s in servers.values()])
    clean = []
    for s in servers.values():
        for m in _TOOL.finditer(s.get("clean_system_promot") or ""):
            clean.append({"server": s["server_name"], "tool": m["name"].strip(), "text": m["body"].strip()})
    pure_pos = [{"server": v["server_name"], "tool": v["tool_name"], "text": v["tool_content"].strip(),
                 "paradigm": v.get("paradigm"), "risk": v.get("security risk")} for blk in pure for v in blk.values()]
    seen, as_presented = set(), []
    for s in servers.values():
        for inst in s["malicious_instance"]:
            if inst.get("wrong_data") or inst["poisoned_tool"] in seen:
                continue
            seen.add(inst["poisoned_tool"])
            m = re.match(r"Tool:\s*([^\n]+)\nDescription:(.*)", inst["poisoned_tool"], re.S)
            as_presented.append({"server": s["server_name"], "tool": (m[1] if m else "").strip(),
                                 "text": (m[2] if m else inst["poisoned_tool"]).strip(),
                                 "paradigm": inst.get("metadata", {}).get("paradigm"),
                                 "risk": inst.get("metadata", {}).get("security risk")})
    return split, clean, pure_pos, as_presented


def _score(rows, split, which):
    rows = [r for r in rows if which == "all" or split.get(r["server"]) == which]
    out = []
    for r in rows:
        hits = poisoning.scan(r["text"], purpose=r["tool"])
        out.append({**r, "kinds": sorted({h.kind for h in hits}), "high": any(h.confidence == "high" for h in hits)})
    return out


def report(name, scored, negatives=False):
    n = len(scored)
    anyhit = sum(bool(r["kinds"]) for r in scored)
    high = sum(r["high"] for r in scored)
    label = "flagged (FALSE POSITIVES)" if negatives else "caught (recall)"
    print(f"  {name:34} n={n:5}  {label}: any {anyhit:4} = {100 * anyhit / max(n, 1):5.1f}%   HIGH {high:4} = "
          f"{100 * high / max(n, 1):5.1f}%")
    return anyhit, n


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("dataset", type=Path)
    ap.add_argument("--split", choices=("dev", "test", "all"), default="all")
    ap.add_argument("--misses", type=Path, help="write missed positives (JSON) here for analysis")
    a = ap.parse_args()
    split, clean, pure_pos, as_presented = load(a.dataset)
    print(f"MCPTox @ f85189f · split={a.split} · servers dev={sum(v == 'dev' for v in split.values())} "
          f"test={sum(v == 'test' for v in split.values())}")
    sp, sa, sc = _score(pure_pos, split, a.split), _score(as_presented, split, a.split), _score(clean, split, a.split)
    tp, npos = report("poisoned, pure (primary)", sp)
    report("poisoned, as presented", sa)
    fp, nneg = report("clean real tools", sc, negatives=True)
    prec = tp / max(tp + fp, 1)
    rec = tp / max(npos, 1)
    print(f"  primary: recall {100 * rec:.1f}% · FPR {100 * fp / max(nneg, 1):.1f}% · precision {100 * prec:.1f}% · "
          f"F1 {100 * 2 * prec * rec / max(prec + rec, 1e-9):.1f}%")
    by_par, by_risk = defaultdict(lambda: [0, 0]), defaultdict(lambda: [0, 0])
    for r in sp:
        by_par[r["paradigm"]][0] += bool(r["kinds"])
        by_par[r["paradigm"]][1] += 1
        by_risk[r["risk"]][0] += bool(r["kinds"])
        by_risk[r["risk"]][1] += 1
    print("  recall by paradigm: " + ", ".join(f"{k} {c}/{t}" for k, (c, t) in sorted(by_par.items(), key=str)))
    print("  recall by risk: " + ", ".join(f"{k} {c}/{t}" for k, (c, t) in sorted(by_risk.items(), key=lambda kv: -kv[1][1])))
    print("  kinds on caught: " + ", ".join(f"{k} {n}" for k, n in Counter(k for r in sp for k in r["kinds"]).most_common()))
    fps = [r for r in sc if r["kinds"]]
    for r in fps[:12]:
        print(f"    FP {r['server']}/{r['tool']}: {r['kinds']} :: {r['text'][:110]!r}")
    if a.misses:
        a.misses.write_text(json.dumps([r for r in sp if not r["kinds"]], indent=1, ensure_ascii=False))
        print(f"  misses -> {a.misses}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
