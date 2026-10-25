# SoundTrace — session handoff (2026-10-26)

State after the multi-provider + harness-bridge work. Read this first after a
harness restart; it captures what is proven, what is blocked, and the exact
next steps.

## Where things stand

Three integration paths now exist for running the CyberGym pipeline, all
sharing the orchestrator's verified audited loop (sandbox, HMAC bundle,
Lean checker). Pick one per run:

| Path | Entry point | Auth | Status |
|---|---|---|---|
| API keys (chains) | `run_task(..., target_chain, translator_chain)` | provider API keys | Ran the v1 campaign (12 tasks) |
| Harness completion | `run_on_harness(...)` | omp subscriptions, roles `default`/`smol`/`slow` | Live-verified: real turns + signed bundle |
| Named agents | `run_on_harness_agents(...)` | omp subscriptions, agents `pilot`/`translator` | Mechanics + scripted bundle proven; **real-model run BLOCKED** |

Full suite: 454 passed + 48 subtests. Latest pushed commit on `main`:
named-agent path (`20b1bc4`) plus this session's spawner-lifecycle +
driver-test fixes.

## Key takeaways

1. **The science result is unchanged and sound.** v1 campaign: all 12 tasks
   attempted, **0 flags / 0 certificates**. Every program was pre-qualified
   vulnerable, so 0 means *no agent demonstrated the known bug*, not clean
   code. No run reached a final report; the clearest behavioral failure is
   that **7 of 8 cohort-A agents never once probed** (submitted a candidate
   to the observation tool). Prompt v2's evidence-loop contract moved the one
   completed cohort-B run to 3 probes — the right direction, one data point.
   See `REPORT_v1_findings.md`.

2. **Provider reachability, not prompting, is the current gate.**
   - Z.ai (`glm-5.3`) and Moonshot (`kimi-k3.1`): authenticate, but the API
     accounts have **no balance** (subscriptions don't include API access).
   - Moonshot's Anthropic-compat endpoint has **no `/models` route** (404).
   - Anthropic `claude-sonnet-5` **categorically refuses** this task class
     (instant empty refusal, unmoved by research framing); `claude-sonnet-4-6`
     engages fully and is the pinned fallback.
   - Anthropic credits are now **exhausted** too (hit zero mid cohort-B).

3. **The harness bridge removes the key problem** — both bridges run on omp
   subscriptions with no API keys. But the model selection surface is narrow:
   - `completion()` accepts only `default`/`smol`/`slow` and resolves them
     from **persisted** config (session-only `modelRoles` writes are inert —
     verified by mapping `slow`→qwen and still getting Claude).
   - `completion()` rejects every other role name, including custom ones
     (`writer`, `reviewer`) and built-ins (`advisor`, `plan`).
   - Named agents ARE spawnable via the `task` tool (verified: `reviewer`
     replied in 5.6 s), but only through `task`, not `completion()`. That is
     why the named-agent path uses a spawn-per-turn client, not a role.

4. **Named-agent architecture is built and partially proven.**
   - `soundtrace_live/agents/{pilot,translator}.md`: task-specific agents,
     explicit tool allowlists (`submit_action` / `submit_translation`),
     one-shot contract in the prompt, model via `@pilot`/`@translator`.
   - `TaskAgentClient` + `run_on_harness_agents`: per turn spawns the named
     one-shot agent whose single capture-tool call becomes the model
     response; the orchestrator's audited prompt is delivered verbatim.
   - Proven: (a) a real one-shot subagent calls its kernel capture tool and
     the payload is captured; (b) scripted agent payloads drive a full
     session to a **signed HMAC bundle** with `provider: agent` in audits,
     secret scan clean.
   - **Not proven:** a real model through the composed spawner. Both attempts
     fell back to the generic `task` role (local qwen, 16k context) and
     overflowed before acting. This needs the role mapping below.

## BLOCKED — needs you, then a restart

The real-model named-agent canary is blocked on config only you can set:

1. Map the two agent roles (persisted), e.g. in config.yml `modelRoles` or
   via `task.agentModelOverrides`:
   - `@pilot      → zai/glm-5.3:high`
   - `@translator → kimi-code/k3.1-pro:high`
2. **Restart the harness** (the eval kernel resolves roles at startup; live
   overrides are ignored).
3. Verify routing with resolved-model metadata, NOT self-ID prose:
   ```python
   b = await judge_batch({'x':'ping'}, {'q':{'type':'bool','instructions':'is 1<2?'}})
   print((await b.drain(30))[0][1].answers, b.status()['model'])   # shows resolved model
   ```
   plus your omp request logs (actual provider/model per call).
4. Run the composed canary once (README "Named-agent runs" block,
   `run_on_harness_agents`, `arvo:64574`, short deadline) and confirm a
   signed bundle before any campaign.

Caveat: if `@translator`'s role has a cross-family entry in
`retry.fallbackChains`, a Kimi hiccup silently routes to Claude (and with
Anthropic credits dead, then errors). Clear that entry for a clean GLM+Kimi
cohort, or ask for the agent client to be pinned fail-closed on spawn error.

## Open engineering follow-ups (non-blocking)

- **Spawner lifecycle** (fixed in README this session): the reference
  spawner now captures the job id and `write proc://<id>/kill` on every exit
  path (capture, timeout, error), and raises a structured error instead of
  returning None. Re-confirm against the live job-ack shape after restart
  (`ack['details']['async']['jobId']`), since it was not runnable here.
- **Agent-definition drift**: `~/.omp/agent/agents/{pilot,translator}.md`
  (loaded by the harness) and `soundtrace_live/agents/*.md` (versioned) are
  byte-identical now; keep them in sync (a checksum/install check would
  prevent silent drift).
- **Transport DRY** (optional): `TaskAgentClient` could reuse
  `HarnessClient._history_text` fully (it does) and share more normalization
  so the two clients can't drift.
- **Task-mode provenance note**: task mode exposes tool calls, not raw
  per-turn model responses. The current client synthesizes the same
  `function_call` shape the orchestrator validates; audits record
  `provider: agent`. If you want stricter provenance, add a distinct
  task-action record rather than treating a tool-arg hash as a model-response
  hash.

## Advisor concerns addressed / standing

- Addressed: README spawner job-cancellation + structured empty-capture
  error; driver test now asserts client `kind` routing (action vs
  translation), not just chain labels; tracker reopened (real-model canary
  blocked, not done).
- Standing (need the restart + mapping): the composed real-model run itself;
  verifying `@pilot`/`@translator` actually resolve to GLM/Kimi via metadata;
  the fallback-chain cross-family risk.
- Rejected as outdated: advisories about import dups, NameErrors, test
  placement, the `_drive` refactor, and provider-label mismatches — all were
  already resolved in committed code (suite green).

## Restart checklist

1. Map `@pilot` / `@translator` roles (persisted) and clear any cross-family
   fallback for `@translator`.
2. Restart harness.
3. Reopen this repo; re-read this file.
4. Verify role routing via `judge_batch(...).status()['model']` + request logs.
5. Run the named-agent canary on `arvo:64574` (short deadline); confirm a
   signed bundle + clean secret scan.
6. If green, run the GLM+Kimi cohort; the three credit-blocked v1 tasks
   (arvo:65212, 65383, 67297) are the first candidates.
