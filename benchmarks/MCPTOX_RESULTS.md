# Tool-poisoning detector on MCPTox (AAAI-26)

Dataset: MCPTox-Benchmark @ `f85189f9ad12504c197c7f920ab818a40657b1fa` (`response_all.json` sha256
`79a90049be931c59e71446d6180b1d7f0d196d123d08a59bc155d142b5041c03`). Not redistributed (no upstream license).
Harness: `benchmarks/mcptox_poisoning.py`. Detector: `hunt/poisoning.py` (deterministic, offline, no LLM).

- **Positives:** the 485 unique poisoned tool descriptions, *without* the "Ignore the previous instructions" prefix (primary), and the 1,302 as-presented texts.
- **Negatives:** every legitimate tool of the 45 real servers (362), parsed from the clean system prompts. The detector is given each tool's own listed parameters, the same for positives and negatives.
- **Split:** by server, with a fixed seed: 22 dev and 23 test. Tuning looked **only** at dev misses; **test misses have never been inspected.** The detector is committed before every test run.

| | Untuned first run (all) | Test run #1 (`e853985`) | **Test run #2 (`14c88e3`)** | All 45 servers (`14c88e3`) |
|---|---|---|---|---|
| Recall, primary | 11.3% | 80.5% | **88.9%** (HIGH 78.8%) | 91.5% (HIGH 82.5%) |
| Recall, as presented | 18.9% | 82.6% | 90.0% | 91.7% |
| False positives, clean real tools | 1 / 362 | 0 / 181 | **0 / 181** | **0 / 362** |
| Precision / F1 | 98.2% / 20.3% | 100% / 89.2% | **100% / 94.1%** | 100% / 95.6% |

Test run #2 recall by paradigm:
- explicit-trigger function hijacking: 41/44;
- implicit-trigger function hijacking: 60/61;
- parameter tampering: 100/121, up from 82/121 in run #1.

Dev was 93.9% at run #2, so the dev-to-test gap is 5 points (it was 7 at run #1).

Other precision gates on every change:
- 975 surfaces of 9 other real MCP servers: 0 hits;
- 300+ real parameter names: 0 hits;
- 40 hard negatives: 0 hits;
- own-parameter usage docs: 0 hits.

## Published reference points, same benchmark
These are other people's numbers; we did not re-run them.
- Cisco mcp-scanner YARA rules: 20.8% recall, 31.25% F1 (arXiv 2604.10534).
- A hybrid scanner: 0.592 recall on MCPTox poisoned tools (github.com/Fatimafaiq/mcp-tool-poisoning-scanner).

LLM-based tools (Snyk agent-scan, MCP-Guard) publish results on other datasets, so they are not comparable here.

## Limits
- The test split has now been *evaluated* twice. Its misses have not been inspected, but two evaluations make it slightly less pristine than a single run. A fresh benchmark would be the next independent check.
- Some misses need semantic judgment.
- Precision is measured on about 1,300 real benign surfaces; ecosystem-wide precision is not yet measured.
- Static analysis yields SUSPECTED leads. Proving that a model complies requires an agent run against a planted canary.
