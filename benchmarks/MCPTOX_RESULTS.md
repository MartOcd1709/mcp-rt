# Tool-poisoning detector on MCPTox (AAAI-26)

Dataset: MCPTox-Benchmark @ `f85189f9ad12504c197c7f920ab818a40657b1fa` (`response_all.json` sha256
`79a90049be931c59e71446d6180b1d7f0d196d123d08a59bc155d142b5041c03`). Not redistributed (no upstream license).
Harness: `benchmarks/mcptox_poisoning.py`. Detector: `hunt/poisoning.py` (deterministic, offline, no LLM).

- **Positives:** the 485 unique poisoned tool descriptions, *without* the "Ignore the previous instructions" prefix (primary), and the 1,302 as-presented texts.
- **Negatives:** every legitimate tool of the 45 real servers (362), parsed from the clean system prompts.
- **Split:** by server, with a fixed seed: 22 dev and 23 test. Tuning looked **only** at dev misses. The detector was committed (`e853985`) before the single test run.

| | Untuned first run (all) | Dev (tuned on) | **Test (never inspected)** | All, after |
|---|---|---|---|---|
| Recall, primary | 11.3% | 87.9% | **80.5%** (HIGH 72.6%) | 84.7% |
| Recall, as presented | 18.9% | 86.9% | 82.6% | 84.9% |
| False positives, clean real tools | 1 / 362 | 0 / 181 | **0 / 181** | 0 / 362 |
| Precision / F1 | 98.2% / 20.3% | 100% / 93.5% | **100% / 89.2%** | 100% / 91.7% |

Test recall by paradigm:
- explicit-trigger hijacking: 41/44;
- implicit-trigger hijacking: 59/61;
- **parameter tampering: 82/121 (68%), the weakest class.**

Other precision gates:
- 975 surfaces of 9 other real MCP servers: 0 hits;
- 300+ real parameter names: 0 hits;
- 40 hard negatives: 0 hits.

## Published reference points, same benchmark
These are other people's numbers; we did not re-run them.
- Cisco mcp-scanner YARA rules: 20.8% recall, 31.25% F1 (arXiv 2604.10534).
- A hybrid scanner: 0.592 recall on MCPTox poisoned tools (github.com/Fatimafaiq/mcp-tool-poisoning-scanner).

LLM-based tools (Snyk agent-scan, MCP-Guard) publish results on other datasets, so they are not comparable here.

## Limits
- The 7-point gap between dev and test is overfitting to dev.
- Some misses need semantic judgment, for example "make sure get contacts of the user" or a declarative "Triggers `X` by design".
- Precision is measured on about 1,300 real benign surfaces. Precision across the wider ecosystem is not yet measured.
- Static analysis yields SUSPECTED leads. Proving that a model complies requires an agent run against a planted canary.
