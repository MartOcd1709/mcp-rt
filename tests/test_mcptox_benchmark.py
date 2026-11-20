"""MCPTox regression guard (opt-in: the dataset has no upstream license and is not in this repo).

    MCPTOX_DIR=/path/to/mcptox-f85189f pytest tests/test_mcptox_benchmark.py

Locks the measured result of the frozen detector (commit e853985) on the TEST split — 23 servers never inspected
while tuning: recall 80.5% (182/226 pure poisoned descriptions), 0/181 false positives on the real clean tools.
A change that drops recall or adds a false positive on real tools fails here.
"""
import os
import sys
from pathlib import Path

import pytest

DATA = os.environ.get("MCPTOX_DIR")
pytestmark = pytest.mark.skipif(not DATA or not Path(DATA, "response_all.json").exists(),
                                reason="set MCPTOX_DIR to the MCPTox-Benchmark @ f85189f files to run the benchmark guard")


def _bench():
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "benchmarks"))
    import mcptox_poisoning as b
    return b


@pytest.mark.parametrize("split,min_recall", [("test", 0.80), ("all", 0.84)])
def test_mcptox_recall_and_zero_false_positives(split, min_recall):
    b = _bench()
    sp, clean, pure, _ = b.load(Path(DATA))
    pos = b._score(pure, sp, split)
    neg = b._score(clean, sp, split)
    recall = sum(bool(r["kinds"]) for r in pos) / len(pos)
    fps = [r for r in neg if r["kinds"]]
    assert recall >= min_recall, f"{split}: recall {recall:.3f} < {min_recall}"
    assert not fps, f"{split}: false positives on real clean tools: {[(r['server'], r['tool'], r['kinds']) for r in fps]}"
