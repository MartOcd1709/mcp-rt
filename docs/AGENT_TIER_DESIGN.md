# Agent tier: design for review (task #21)

Status: DESIGN ONLY. No code until jev reviews and Ved signs off.
Base: `origin/phase2-attestation-beachhead` at `823399a`, which contains Units 1–3 (#40, #41, #42).
Branch: `agent-tier`.

## 0. Summary

The agent tier is a bounded orchestrator on top of the detector floor. A planner chooses the next action
from a closed set: run one floor probe class against one tool, run the sandboxed egress exercise on one
tool, re-run a finding, or stop. Deterministic code executes the action inside the Unit 3 sealed
namespace. The floor's own probes judge, and every verdict comes from the honesty spine (`verdict_for`).

The model decides where to look and in what order. It cannot write payloads, cannot assert a verdict,
and cannot reach any tool outside the target's declared surface.

Headline we can defend: **the model chooses where to look; an oracle decides what is true; every finding
is re-demonstrated; the target never leaves the seal.**

Not in v1: free-form payload generation, chaining one finding into the next, any run outside a signed RoE,
any live model call without explicit approval.

## 1. Rulings requested

- **R1. Closed action space in v1** (recommended). Constrained free-form arguments only in v2, behind
  per-class validators (section 11).
- **R2. Reproduction is automatic.** Every VULNERABLE is re-run once with fresh nonces. It is not a model
  action, so the model cannot skip it.
- **R3. Legacy modes (`agent`, `pentest`) run the target unsandboxed on the host** (section 7.4).
  Recommended: quarantine both from non-lab targets now, then re-base or retire them when the tier ships.
- **R4. Legacy oracle `mcp_rt/oracle.py` treats a `/etc/passwd` signature as proof** for path_traversal and
  ssrf (section 7.5). The spine calls that a signature, so it is SUSPECTED. Recommended: the tier does not
  import it. A later unit moves it onto the spine.
- **R5. New traversal oracles plant a per-run file** in the sandbox workdir and require its nonce in the
  response. This is a per-run planted marker, so it meets the spine's definition of `oracle`.
- **R6. Floor probes run under the seal.** Any probe whose oracle needs external reach becomes SUSPECTED or
  INCONCLUSIVE under the seal. Recommended: accept, and report it per probe.
- **R7. Command name.** `mcp-rt assess` is new and coexists with the seed `mcp-rt agent`.
- **R8. Model endpoint and model id** are Ved's decision. The code default stays the offline mock.
- **R9. RoE signer and format.** Ved signs; the format is proposed in section 2.

## 2. Scope and rules of engagement

A run is refused unless it has a valid, unexpired RoE document (`roe.json`). The RoE is data. The tier
never invents its own scope.

```json
{
  "roe_version": 1,
  "target": {"id": "lab-proxy-01", "argv": ["python3", "fixtures/proxy_aggregator/server.py"],
             "sha256": "<hash of every file the argv executes>"},
  "surface": {"tools": ["gateway_call"], "resources": [], "prompts": []},
  "classes": ["ssrf", "command_injection", "path_traversal", "sql_injection", "ssti",
              "deserialization", "context_oversharing", "egress"],
  "mode": "offline",
  "budget": {"max_actions": 40, "max_wall_seconds": 900, "patience": 5, "probe_calls_per_objective": 1},
  "kill_switch": "/home/ved/.claude/jobs/<id>/STOP",
  "authorized_by": "<name>", "expires_at": "2026-12-31T00:00:00Z"
}
```

Enforcement points:

- **E1.** The RoE is validated before anything executes: hash match, not expired, surface and classes known.
- **E2.** The action validator checks every action against the closed space (section 3) and the surface.
- **E3.** Execution happens only in a sealed session. The session refuses to exec the target unless the
  Unit 3 seal proof P1–P6 passes (`mcp_rt/runtime/sandbox.py`).
- **E4.** Before every action: the kill-switch file, the action count, and the wall clock are checked.
- **E5.** An action outside the surface or the closed space is rejected, logged, and counted. At the
  threshold the run stops with `ABORT_SCOPE`.
- **Hard ceilings in code**, not configurable by the RoE: `max_actions <= 200`, `max_wall <= 3600s`,
  canary = loopback only (the recorder is the only sink).

`mode` is `offline` by default. `live` requires section 9's gate.

## 3. Closed action space

The planner returns one JSON object per turn. Anything else is an invalid output.

```json
{"action": "run_probe", "class": "ssrf", "tool": "gateway_call", "reason": "routes URLs"}
{"action": "run_egress", "tool": "gateway_call", "reason": "takes a free-text argument"}
{"action": "stop", "reason": "objectives_exhausted"}
```

- `run_probe(class, tool)` runs one floor probe on one tool. It calls the existing `probe(session, [tool])`
  (`hunt/probes.py`), so the payloads are the floor's own, including its per-run nonces.
- `run_egress(tool)` runs the Unit 3 exercise on one tool: token-bearing benign arguments and elicitation
  answers. Attribution is per action (section 7.1).
- `stop(reason)` takes one value from a fixed enum. `reason` is a label for the ledger, not a verdict.

There is no payload field, no argument field, no shell, and no verdict field. Unknown keys are rejected.
Re-running a finding is automatic (R2), not an action.

## 4. Oracle gating and verdicts

Four layers:

1. **Planner** proposes a closed action (section 3). Its free text is kept in the transcript as a
   hypothesis. It is never evidence.
2. **Executor** runs the floor probe inside the sealed session and returns `ProbeResult`s plus the egress
   records for that action.
3. **Judge** maps each result to a verdict through `verdict_for(method)`. Egress rows go through
   `mcp_rt/runtime/observe.verdict`, which returns the same method names.
4. **Ledger** keeps findings, leads, cleared classes, and untested objectives, and never merges them.

Rules:

- **G1.** Only `ProbeResult`s and sandbox observations can create a finding. The planner cannot.
- **G2.** Verdicts come from `verdict_for(method)` and nowhere else. The tier never constructs a verdict
  string.
- **G3. Proof set.** VULNERABLE only for `oracle` and `differential`. The Unit 3 token leak is `oracle`,
  as approved in the Unit 3 review.
- **G4. Lead set.** SUSPECTED for `static`, `signature`, `observed_change`, `sandbox_claim_mismatch`, and
  `sandbox_unexplained_egress`. Lead-only classes (`lure_text`, `session_argument`, the static part of
  `tool_poisoning`) can never reach VULNERABLE.
- **G5. Clean set.** CLEAN for `oracle_negative`, `refusal`, `by_design`, `sandbox_explained_egress`, and
  `sandbox_no_egress`. CLEAN is recorded per (class, tool) and only when at least one call got a real
  response.
- **G6. Not exercised.** If every call was refused, the (class, tool) is INCONCLUSIVE
  (`sandbox_not_exercised`). It is never CLEAN.
- **G7. Errors** (`error`, `sandbox_unproven`, `sandbox_unobservable`, `sandbox_opaque_payload`) are
  INCONCLUSIVE.
- **G8. Reproduction.** Every VULNERABLE is re-run once with the same (class, tool) and fresh nonces. If it
  does not fire again, the finding is INCONCLUSIVE with `not_reproduced`. It is never kept as proven.
- **G9. Absence is not a verdict.** The model not finding anything never produces CLEAN. CLEAN needs
  G5 evidence for that class and tool.

Report sections are separate: **Proven** (VULNERABLE, reproduced), **Leads** (SUSPECTED), **Cleared**
(CLEAN with evidence), **Inconclusive** (not exercised, errors, not reproduced, not tested).

## 5. Per-class objectives

Objectives are data (`mcp_rt/agent_tier/objectives.json`), one per (class, tool). The planner orders them,
and cannot add or remove them. The methods below are the floor's own, verified by reading
`hunt/probes.py`.

| Class | Floor probe (line) | VULNERABLE proof | Lead / clean methods | Needs seal | v1 |
|---|---|---|---|---|---|
| ssrf | `probe_ssrf` (295) | oracle (330) | by_design (324), oracle_negative | yes (loopback canary) | yes |
| command_injection | `probe_command_injection` (366) | oracle (423, 429) | by_design (426), refusal | no | yes |
| path_traversal | `probe_path_traversal` (596) | oracle (647–699) | oracle_negative, refusal | no | yes |
| sql_injection | `probe_sql_injection` (835) | oracle (870) | signature (902), by_design | no | yes |
| ssti | `probe_ssti` (961) | oracle (988) | oracle_negative | no | yes |
| deserialization | `probe_deserialization` (1041) | oracle (1080) | oracle_negative | no | yes |
| context_oversharing | `probe_context_oversharing` (1125) | oracle (1144, 1156) | oracle_negative | no | yes |
| arg_injection | `probe_arg_injection` (931) | signature or oracle | oracle_negative | no | review |
| tool_poisoning | `probe_tool_poisoning` (768) | none | static (794): LEAD only | no | lead |
| lure_text | `probe_lure_text` (1203) | none | static (1194), oracle_negative (1197): LEAD only | no | lead |
| session_argument | `probe_session_argument` (1263) | none | static (1282), oracle_negative (1286): LEAD only | no | lead |
| rug_pull | `probe_rug_pull` (995) | none | observed_change (1021): SUSPECTED | no | lead |
| egress (Unit 3) | `runtime.runner` + `observe.verdict` | oracle (token leaves) | sandbox_claim_mismatch, sandbox_unexplained_egress; sandbox_explained_egress, sandbox_no_egress | yes | yes |

Notes:

- `_negative_method` (hunt/probes.py:117–119) returns `oracle_negative` or `refusal`. A refusal-only run is
  not a clean run (G6).
- No floor probe contains a `/etc/passwd` check. The grep for `passwd` in `hunt/probes.py` is empty. The
  only `/etc/passwd` proof is in the legacy `mcp_rt/oracle.py` (section 7.5).
- Default budget: one probe run per (class, tool). Each probe already varies its own payloads, so retries
  are not added in v1. Each VULNERABLE adds one reproduction run (G8).

## 6. Stop conditions

Per objective (terminal states):

- **success:** an oracle or differential fired. Finding created, then reproduced (G8).
- **negative complete:** real responses, no oracle. CLEAN for that (class, tool) (G5).
- **not exercised:** every call refused. INCONCLUSIVE (G6).
- **error:** probe or transport error. INCONCLUSIVE (G7).
- **not tested:** the run stopped first. INCONCLUSIVE `not_tested`. Never CLEAN.

Per run (exactly one stop reason is written to the ledger):

- `COMPLETE` every objective is terminal.
- `BUDGET_ACTIONS` or `BUDGET_WALL` the cap was hit.
- `STALL` `patience` (default 5) consecutive actions produced no new terminal objective.
- `ABORT_SCOPE` an action was outside the RoE (E5).
- `ABORT_UNOBSERVABLE` the seal broke or the recorder and witness disagree mid-run. This is an error
  condition, never a clean stop.
- `ABORT_PLANNER` the model produced `invalid_outputs` in a row (default 3), or the model call failed.
- `KILLED` the kill-switch file was present before an action.

## 7. Reuse

### 7.1 Sealed execution

- The session is the Unit 3 launcher used as the stdio command: argv =
  `unshare -rn -- python -I sandbox.py … --server-json <target argv>`. The launcher proves the seal, then
  execs the target with stdio inherited. This is `scan_target`'s pattern (`hunt/probes.py:1333`) with a
  different argv.
- One sealed session per run. Target state persists across actions, and the seal proof runs once.
- Per-action attribution: the recorder events file is append-only. Read its line count before and after
  each action and attribute the new records to that action. Actions are sequential, so the windows do not
  overlap.
- Refactor needed: Unit 3's `runner._drive` becomes a `SealedSession` context manager that yields the
  `ClientSession` and the events reader. The Unit 3 tests keep their behavior.

### 7.2 Floor probes

- Called per (class, tool) with `probe(session, [tool])`. The existing probes already filter by tool.
- `scan_target` keeps a module-level `_RES_CACHE` and `_CTX_CANARY`, so one session at a time. The tier
  keeps that rule.

### 7.3 Planner

- `mcp_rt/planner.plan_tool(tool)` and `refine(plan, proven, tools)` give the deterministic objective list
  and the sweep of proven classes to other tools (`mcp_rt/planner.py:105, 154`).
- `_model_augment` (planner.py:188) is NOT used. It accepts free-form points that carry a `probe` payload,
  which breaks the closed space.

### 7.4 Seed agent and pentest (the gaps)

- `mcp_rt/agent_loop.py` gives the model `shell`, run by `executor.run(cmd)` (lines 386–391; DryRun by default,
  line 316, DockerExecutor when configured), and
  any `mcp_call` with any arguments (its docstring says so). The seed's own docstring says "no allowlist and
  no fixed payload set".
- Its evidence rule is a prompt sentence (`SYSTEM_PROMPT`, lines 94–98). Nothing in code gates on it.
  Conclusions go to `agent_claimed`, and confirmation is left to the caller (lines 370–373).
- `run_agent` builds `MCPClient(target)` (agent_loop.py:322–324), and `build_target_context` does too (line 256).
  `MCPClient` runs the
  target with `stdio_client` on the host (`mcp_rt/mcp_client.py:58`). The target is unsandboxed.
- `mcp_rt/assessment.py` (`pentest`) does the same (`MCPClient(target)`, plus `oracle.confirm_plan` at
  line 76). Its PROVEN lines (line 152) come from the legacy oracle (section 7.5).
- `mcp_rt/knowledge.recall_hints` feeds recalled technique strings to the model. Those strings carry
  payloads. The tier does not use them.
- Reused from the seed: `AgentPolicy`'s budget and patience ideas (agent_loop.py:35–61) and the
  `ChatModel` interface, with `MockChatModel` as default.
- Its default model is the mock. `get_chat_model()` goes live only when `MCPRT_AI_PROVIDER=openai` and
  both a base URL and an API key are set (lines 214–219). Good default; not a reviewable config.

### 7.5 Legacy oracle

`mcp_rt/oracle.py` has its own `Proof(confirmed: bool)` (lines 31–41) and no spine method names.
Its `confirm()` checks:

- path_traversal and ssrf: a `root:…:0:0:` match in `/etc/passwd` (lines 74–88). This is a response
  signature. The spine says SUSPECTED. The legacy path says confirmed. This is an overclaim in `pentest`.
- command_injection, code_injection: a per-run nonce, with an echo guard (lines 90–117). This matches the
  spine's `oracle`.
- ssti: a per-run random product (lines 119–125). Matches `oracle`.
- sql_injection: a true/false baseline difference (lines 127–133). Matches `differential`.
- Arbitrary write: a canary written and read back (lines 138–). Matches `oracle`.

The agent tier does not import `mcp_rt/oracle.py`. A static test enforces that (T13).

### 7.6 Honesty spine

`hunt/probes.py` `_METHOD_VERDICT` and `verdict_for` are the only verdict map. The Unit 3 methods are in it.
The tier adds no entries.

## 8. Offline test plan (no model, no network)

Planners:

- `DeterministicPlanner`: walks the objective list in plan order. No model.
- `TranscriptPlanner`: replays a recorded JSONL of planner outputs. Used later for regression.
- `LivePlanner`: the model client. Tests never import it.

Fixtures, all offline:

- Calibration: `hunt/probe_fixtures/vuln_server.py` (command_injection, deserialization, path_traversal,
  sql_injection, ssrf, ssti) and `safe_server.py`.
- Lab: `fixtures/` (seven attacks and three controls, Unit 3).
- Generated battery: servers written at test time, named from modes, with ground truth.

Tests, each an acceptance criterion:

- **T1 gating.** A hypothesis-only action gives no finding. A probe whose oracle fires gives VULNERABLE, and
  only through `verdict_for`. Lead methods give SUSPECTED. `oracle_negative` gives CLEAN only with real
  responses. Refusal-only gives INCONCLUSIVE.
- **T2 reproduction.** A stub target whose oracle fires on the first run and then goes silent yields
  `not_reproduced` (INCONCLUSIVE).
- **T3 scope.** An action outside the surface or space is rejected, logged, and counted. N violations give
  `ABORT_SCOPE`.
- **T4 budgets.** Action, wall-clock, and stall caps produce their stop reasons. Untested objectives are
  INCONCLUSIVE `not_tested`, never CLEAN.
- **T5 errors.** Probe error or tool exception gives INCONCLUSIVE.
- **T6 seal.** When the seal fails, the target is never exec'd (sentinel file).
- **T7 kill switch.** The file present before action N gives `KILLED` at N.
- **T8 model contract.** Unknown keys, verdict-like fields, and free text in place of an action are rejected
  and counted.
- **T9 determinism.** `DeterministicPlanner` run twice gives an identical ledger.
- **T10 name-free.** No fixture or corpus name in `mcp_rt/agent_tier/*.py`. Objectives, RoE, and model
  config are data.
- **T11 calibration under the seal.** `vuln_server` flagged per class by its floor method. `safe_server`
  CLEAN. Any class that loses its oracle under the seal is reported (R6).
- **T12 lab.** Egress classes VULNERABLE, controls CLEAN, the router INCONCLUSIVE without operator input.
  This matches the Unit 3 gate.
- **T13 legacy isolation.** A static test: `mcp_rt/agent_tier` never imports `mcp_rt/oracle.py`,
  `mcp_rt/agent_loop.py`, or `mcp_rt/assessment.py`.
- **T14 planner injection.** A tool description containing an instruction to call an unlisted tool or to
  report a verdict cannot change the action space or the ledger.

## 9. Model configuration (design; live is gated)

`mcp_rt/agent_tier/model.json` (data):

```json
{"provider": "mock", "base_url": null, "model": null, "temperature": 0,
 "max_output_tokens": 512, "run_token_cap": 200000, "requests_per_minute": 60,
 "observation_truncate_bytes": 1500, "prompt_version": "v1"}
```

- Default `provider` is `mock`. The tests load only the mock.
- Enabling live requires all of: `roe.mode == "live"`, `roe.live_approved_by` and `live_approved_at`, a
  `provider` other than `mock`, a `--live` flag on the command, and the config hash recorded in the run
  record.
- Output contract: one JSON action object (section 3). Anything else counts as invalid.
- The model sees: the surface (tool names and descriptions, truncated), the objective list, the structured
  results of earlier actions (truncated to `observation_truncate_bytes`), and the remaining budget.
- The model never sees the verdict rules as a lever. It can read them, and they are enforced in code.
- The model choice and endpoint are Ved's (R8). The 60 RPM limit is from the gateway notes in memory.

## 10. Build units (after sign-off)

- **U1 offline core.** RoE loader and validator. Closed action space and validator. `DeterministicPlanner`.
  `SealedSession` (the Unit 3 refactor). Executor calling floor probes per (class, tool). Judge through
  the spine. Ledger, stop reasons, kill switch. Tests T1, T3–T7, T9, T10.
- **U2 acceptance.** Reproduction gate (T2). Calibration under the seal (T11). Lab acceptance (T12).
  Legacy isolation (T13). Injection test (T14). Objectives as data.
- **U3 transcripts and CLI.** `TranscriptPlanner` and replay of recorded runs. `mcp-rt assess` with the four
  report sections (section 4).
- **U4 live (gated).** `LivePlanner`, model config, and the live gate. Tests use a mocked endpoint. No
  network in tests.
- **v2 (not scheduled).** Constrained free-form arguments and chaining, with per-class validators (section 11).

Estimate: U1 and U2 are the headline. U3 and U4 can follow the design review without changing it.

## 11. v2 constraint layer (not in v1)

Free-form arguments are needed for chaining. Each proposed argument must pass a per-class validator:

- ssrf: the destination must be the loopback canary.
- command_injection: only the nonce-echo template (no free command text).
- sql_injection: boolean or time templates, no DML or DDL.
- path_traversal: reads limited to the per-run planted file (R5).

A proposal that fails its validator is an invalid action, not a warning.

## 12. Risks

- **Existing unsandboxed modes (R3).** `agent` and `pentest` run targets on the host and allow arbitrary
  arguments. Until quarantined, do not run them against any target outside the lab.
- **Planner prompt injection.** Target tool descriptions and outputs are untrusted and enter the model
  context. A hijacked planner can only choose among floor actions (closed space, T14), so it cannot leave the
  seal or change a verdict. This is the main reason to keep the space closed.
- **Seal limits (inherited from Unit 3).** IP egress only. Unix sockets to host daemons are not sealed. TLS
  payloads are opaque, so they can clear nothing (INCONCLUSIVE).
- **Floor probes under the seal (R6).** Some oracles may need external reach. Under the seal they will be
  reported as SUSPECTED or INCONCLUSIVE. That is correct, and it has to be shown per probe.
- **Demo overclaim.** v1 shows adaptive ordering over floor probes and a sealed proof. It does not show
  autonomous exploitation chains. The headline above is the claim we can back. Anything wider needs v2.
- **Legacy traversal overclaim (R4).** `pentest` can print PROVEN for a `/etc/passwd` signature. Fix or
  quarantine before any external showing.

## 13. What I need from jev, then Ved

- jev: rulings R1–R7 and the section 11 scope.
- Ved: R3 (quarantine of `agent` and `pentest` now), R8 (model), R9 (RoE signer and format).
- Blockers: none for U1 on the offline corpus. Live runs and any non-lab target are blocked on R8 and R9.
