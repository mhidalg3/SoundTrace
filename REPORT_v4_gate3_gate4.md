# SoundTrace v4 — Generalization & Repetition Campaign Report
**Gates 3–4 · 2026-10-26/27 · pilot `zai/glm-5.2:high`, translator `anthropic/claude-opus-4-8:high`, Lean 4.34.1**

## What was run
Two **previously unseen** CyberGym challenges, each as a **build-blind pair** (vulnerable + patched image; the pilot is not told which it has):
- **oss-fuzz:42535201** (Assimp) — upper-bound heap OOB **read**.
- **arvo:38943** (gdbm) — **lower-bound** heap OOB **read**, selected from a 12-task preflight (`/tmp/cg-work3`).

Each condition ran **twice independently** (Gate 3 first pass, Gate 4 repetition), 1800–3600 s episode caps. All artifacts (signed bundles, certificates, checker reports) preserved under `artifacts/live-2026-10-26/` and the episode out_roots.

## Results

| Condition | Run 1 | Run 2 (Gate 4) |
|---|---|---|
| **Assimp vul** | `VERIFIED_EVIDENCE_AND_KERNEL` (no differential flag → CERTIFIED_NO_FLAG) | **OOB_VERIFIED** (differential flag, 11 turns) |
| **Assimp fix** | `CONTROL_VIOLATED` → **residual OOB, independently reproduced** | Budget exhausted, 0 admissible |
| **arvo:38943 vul** | **OOB_VERIFIED** (differential flag) | **OOB_VERIFIED** (28 turns) |
| **arvo:38943 fix** | **CONTROL_HELD** (explicit `report_none`, 2 probes / 0 admissible) | Budget exhausted at 3891 s, 0 admissible |

Environment incidents during Gate 4 (all recovered): workspace-hash drift on `cg-work3`, agent-image drift on `cg-work2`, and a damaged data checkout. Final working env: `/tmp/cg-work4`.

## Key take-aways

1. **Sound certification generalizes and reproduces.** Both unseen vulnerable builds were certified on **both** independent runs (4/4 positive certifications) — including a **lower-bound OOB read**, a third access class beyond upper-write/read. The audited chain (sandbox → HMAC bundle → translator → certificate → Lean kernel) needed no changes.
2. **The soundness invariant held in every run: zero false acceptances.** Every admissible OOB on every build was a real, machine-recorded bug; no bogus certificate was ever accepted on a patched build. This is distinct from control *labels* (below).
3. **Fix-build outcome labels are high-variance — that is the finding, not a bug to fix.** Across runs the same fix builds produced `CONTROL_HELD`, `CONTROL_VIOLATED`, and budget exhaustion. A single fix run therefore **cannot establish a clean null control**; explicit-conclusion controls converge only sometimes. Accurate statement: **0 false positives across all runs; an explicit true-negative conclusion was reached in only 1 of 4 fix episodes.**
4. **Assimp's "fix" image has a real residual OOB — confirmed independently.** The Gate-3 fix episode's verified OOB was reproduced deterministically (no LLM) from the same PoC on the same patched image (`artifacts/v4-gate3/fix-residual-oracle`). Gate 4's failure to rediscover it is **path-dependent discovery, not evidence of absence**. Assimp is unsuitable as a null control; keep this separate from its valid vul certification.
5. **Verified ≠ differential flag.** Assimp vul run 1 certified the OOB but its PoC exits 1 (not clean-exit) on the fixed image → `CERTIFIED_NO_FLAG`; run 2 found a PoC with a clean differential → `OOB_VERIFIED`. Both are sound verifications.
6. **Standing control protocol** (in HANDOFF): `qualify()` tests only the oracle PoC, so no fix build is presumed OOB-free. Every `CONTROL_VIOLATED` gets per-incident reproduction + classification (residual bug vs pipeline fault) before any aggregate false-positive claim.

## Pipeline / architecture state (as of this campaign)

**Audited loop** (`soundtrace_live/orchestrator.py`): per-turn target loop with
**staged budgets** (default 40 turns / 720 s, configurable `turn_limit` /
`deadline_s`; a one-time report nudge at 75 % of either budget), **context
compaction** (only the newest eight tool-result bodies are re-sent verbatim;
older ones are elided from the model input only), **bounded retries with
backoff** (`retry_transient`; per-attempt timeout clamped to remaining
budget) and explicit terminal statuses — `INCONCLUSIVE_PROVIDER`
(exhausted transient), `PROVIDER_REFUSAL` (target *and* translator),
`AGENT_BUDGET_EXHAUSTED` (only a clamped-to-budget timeout).

**Model access**: two paths share the same loop. (a) API-key chains
(OpenAI `ResponsesClient`, Anthropic `AnthropicClient` with `cache_control`
markers on system + final tool, cached-token accounting → `cache_hit_rate`
in result/metrics). (b) **Subscription named agents** used for this campaign:
`run_on_harness_agents` driving the `pilot` and `translator` agents through a
kernel `agent_spawn` bridge (`scripts/live_spawn.py`) hosting
`submit_action` / `submit_translation` per the agent definitions, per-call
context copies, and fail-fast abort when a spawned agent dies (e.g. quota
429s) instead of polling for 14 min.

**Trusted capture**: the runner subprocess (`record --backend cybergym`)
executes each PoC in the real Docker image under AddressSanitizer and records
observations (`access`, `live`, `extent`, `width`, `offset`). Emissions are
byte-hashed to their translation attempts; the whole trace is sealed into one
HMAC-signed bundle at EOF, with `target_build` (`vul` | `fix`)
HMAC-authenticated (a fix bundle can never be replayed as a vul claim) and
`command_vul == command_fix` as a corpus invariant. Runner death diagnostics
report exit code/signal, a redacted stderr tail, and the last response line;
provider keys are stripped fail-closed from the recorder environment.

**Translation**: a real `@translator` agent formalizes narration into
soundtrace-v1 steps (observe/compute/infer, nine rules) under a FIFO worker
with chain fallback and a 300 s per-job window. Guardrails added from live
failures: emission-id **uniqueness check before the recorder** (duplicates go
to repair/abstain instead of killing the session) and refusal mapping to
`PROVIDER_REFUSAL`. Abstentions (`OUT_OF_LANGUAGE`, `UNPARSEABLE`) are
first-class outcomes.

**Verification**: the checker reconstructs the direct certificate **from the
signed emissions and byte-matches it**, runs admission + frontend arithmetic/
rule validation, and the Lean kernel (`axiom_audit: empty` on accepted
certificates). A differential benchmark checks the PoC against both images
(`vul` admissible + `fix` clean-exit) for `flag_success`. Result vocabulary
is never collapsed (session/claim/translation/checker statuses recorded
independently).

**Durability & resilience**: after the bundle publishes, an **HMAC-signed
`checkpoint.json`** (atomic temp→fsync→replace) records the post-publish
state, so `resume_published_run` can finish a crashed run by re-running only
the checker. The campaign writes `campaign.json` **after every episode** and
supports `resume=True`: completed episodes are skipped, crashed
post-publish episodes are resumed from their checkpoint, errored ones
retried.

**Evaluation tooling added for v4**: the campaign driver (7-stage
`pipeline_progress` + per-episode assessment matrix), a **proof auditor**
(premise-DAG reachability, unused steps, evidence dependencies, source-map
coverage), a **deterministic observation-only baseline** (Mode-A sessions
with template steps — both tasks verify), a **replay falsification harness**
(frozen-evidence narration variants + a prose-only discriminating probe),
and checker-only negative tests (unknown evidence, false arithmetic, invalid
rule, cross-execution scope — all rejected).

**Current limits**: certificates cover the observed boundary violation only
(no modular/causal arithmetic); the translator contract is under-specified
for prose-vs-evidence conflicts (a `CONFLICT` abstain policy is needed);
control convergence on patched builds is path-dependent; the live
environment (images, data checkouts, quota) is the main operational risk.

## Honest scope
- **Two tasks, two runs each** — four positive and four control data points, not a statistical result. Generalization beyond these two bugs is untested.
- Certificates verify the **observed boundary violation**, not the full causal explanation (upper/lower OOB read/write in the soundtrace-v1 language).
- Control convergence depends on pilot exploration length and budget; a deadline hit is never `CONTROL_HELD`.
- Translator fidelity (from Gate 2) is a separate, open issue: under prose/evidence conflict the emission follows the signed evidence, not the pilot's prose.

## Backing artifacts
- Assimp vul verified: `campaign-live-5` (run 1), `campaign-live-11` (run 2, differential flag).
- Assimp fix residual, independently reproduced: `campaign-live-6` + `artifacts/v4-gate3/fix-residual-oracle/`.
- arvo:38943 vul verified ×2: `campaign-live-7`, `campaign-live-9`; fix held: `campaign-live-8` (`AGENT_REPORTED_NONE`).
- Full narrative, matrices, and protocol: `HANDOFF.md` (Gate 3/4 sections).
