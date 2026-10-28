# SoundTrace / TraceProof: deterministic proof pipeline

An initial research scaffold for observation-grounded certificate proofs about
explicit out-of-bounds accesses. The design separates (i) a runner-owned
evidence boundary over controlled C executions, (ii) a generic, vulnerability-
agnostic certificate language, (iii) a deterministic constructor from typed
reasoning traces, and (iv) the Lean kernel backend. No vulnerability-specific
predicate is built into the language, and no model call participates in
construction or checking.

New here? `GUIDE.md` is a step-by-step tutorial: prove the controlled
`read_upper` case end to end, tour all eight demo cases, and learn how to
feed in your own reasoning traces.

## Components

- `evidence.py`: strict JSON loading (duplicate keys, nonfinite numbers, and
  malformed input are rejected), canonical serialization, and HMAC/digest
  primitives. One parsing and hashing convention for every component.
- `frontend.py`: the soundtrace-v1 certificate-to-Lean compiler and the
  hardened Lean backend boundary (pinned version, exact empty axiom audit,
  resource-limit classification). `--check` reports only
  `KERNEL_VERIFIED_RELATIVE_TO_MANIFEST`: the manifest is a trusted input, not
  authenticated evidence.
- `constructor.py`: deterministic expansion of a recorded typed argument
  (`observe`/`calculate`/`compare`/`conjoin`/`infer` nodes) into primitive
  certificate steps with a source map. No search, no repair, no deduplication;
  the first malformed or over-budget source node is rejected by ID.
- `fixtures/oob_cases.c`: the reviewed, fixed instrumentation: eight
  enumerated cases, one allocation, one tested scalar access per run, JSONL
  events on a dedicated pipe, ASan runtime callback facts.
- `runner.py`: `keygen` and `record`. Serial request dispatch with one
  parent-owned ordered log, runner-owned execution IDs, claim freezing at
  receipt, and HMAC-authenticated bundle publication. Handles both the
  intermediate `reason` (typed node) protocol and the direct-mode `narrate`
  (free-text) + `emit` (signed translator certificate steps) protocol, with
  per-argument mode exclusivity and live provenance checks. Never accepts
  source paths, executables, flags, or environment overrides from the agent.
- `oob_adapter.py`: the only domain-meaning component. Derives the five
  admissible facts per access from raw signed events, freezes and recomputes
  claim outcomes, and builds the frozen target
  `access ∧ (live ∧ (0 ≤ extent ∧ (0 < width ∧ violation)))`.
- `direct.py`: direct-mode (signed-output) certificate assembly. Reconstructs
  the certificate by concatenating the signed translator emissions in order
  and enforces per-emission evidence availability; shared by the assembler CLI
  and the checker so they cannot drift.
- `checker.py`: the sole producer of the two verification tiers.
  `VERIFIED_OBSERVATION_BACKED` (intermediate path): authentication,
  re-admission, deterministic reconstruction of a typed argument, byte
  comparison, preflight, and the pinned Lean kernel with an empty axiom audit.
  `VERIFIED_EVIDENCE_AND_KERNEL` (direct path): the same, but reconstructed
  from signed translator emissions — authenticated evidence and a kernel-valid
  claim, without mechanically proven translation faithfulness.
- `examples/`: the migrated synthetic arithmetic fixture (manifest, typed
  argument, constructor-generated certificate and Lean source), the
  non-security `transfer` example in unit `tick`, and `sessions/` request
  scripts for all eight controlled cases.

- `tests/`: stdlib `unittest` behavioral regressions for evidence loading,
  frontend contracts and rules, the constructor, and the checker (isolated
  test keys, controlled fake Lean backends).
- `smoke_test.py`: deterministic end-to-end driver over the real CLIs in a
  caller-provided work directory.


## CyberGym live pipeline (`soundtrace_live/`)

The `soundtrace_live` package extends the fixture path to real CyberGym
targets without weakening any existing boundary:

- `corpora/cybergym_pilot.json` + `soundtrace_live/corpus.py`: the pinned
  `soundtrace-cybergym-corpus-v1` pilot — `arvo:64574` (jq),
  `arvo:47101` (binutils), `oss-fuzz:42535201` (assimp) — with exact
  Linux/amd64 image digests, CyberGym code revision `c6fe2027…`, and the
  immutable data revision `bde190d…` for the Hugging Face remote. Everything
  else is rejected before any pull.
- `soundtrace_live/asan_probe.c`: the reviewed, `-nostdlib` preload shim.
  Registers ASan's error-report callback (weak interface, exactly per
  compiler-rt) and writes one bounded JSONL machine event to a runner-private
  mount via raw syscalls. Human stderr is never parsed.
- `soundtrace_live/cybergym_backend.py`: the trusted Docker capture backend
  (`create → start -a → inspect → rm`, network none, read-only root,
  cap-drop-all, no-new-privileges, 4 GiB/2 CPU/128 PID limits, tmpfs /tmp,
  PoC bind at /tmp/poc, fixed ASan options, 10 s inner / 30 s host timeout,
  1 MiB output and 64 KiB event caps) plus `bootstrap` (image pull +
  registry-digest verification, sparse Git+LFS data fetch, traversal-safe
  extraction, agent-image and DSO builds, `environment.lock.json`) and
  `qualify` (private oracle PoC: one admissible heap report in the vulnerable
  image, clean exit in the fixed image).
- `soundtrace_live/cybergym_adapter.py` + `admission.py`: producer
  `cybergym-asan-v1` admission. Reuses the fixture's five-fact and target
  contract (scope
  `<run>/<task>/<execution>/<poc>/O1/g1/A1`, `offset = address − region_base`)
  and re-derives offline the translation invariants: attempt hashes,
  narration `source_seq` cutoffs (no retroactive evidence), and abstention
  closure.
- `runner.py record --backend cybergym`: `probe` replaces `run`; adds
  `translation_attempt`/`translation_abstain` and bounded audit-only kinds
  (`model_session`, `model_turn`, `agent_action`, `agent_result`,
  `benchmark_result`). CyberGym emissions name their narration
  (`source_seq`) and attempt; the runner byte-hashes every emission against
  its recorded attempt. A probe-level `INCONCLUSIVE_CAPTURE` is recorded and
  the session continues; nothing mistrusted enters the signed executions.
- `soundtrace_live/openai_responses.py`, `translator.py`, `orchestrator.py`:
  stdlib Responses-API client (HTTPS-only, key redaction, byte/time caps, no
  model substitution), the live direct translator (shape/provenance
  validation only — representable bad arithmetic is emitted and rejected
  downstream, never repaired; exactly one repair for malformed output; else
  abstain), and the sandboxed target-agent loop (opaque session labels,
  network-less agent container, `shell`/`probe`/`report_oob`/`report_none`
  tools, fixed-image scoring withheld from the model).

Pilot commands:

```sh
python3 -m soundtrace_live bootstrap --corpus corpora/cybergym_pilot.json \
    --data-dir "$CYBERGYM_DATA_DIR" --work-dir "$WORK/env"
python3 -m soundtrace_live qualify --corpus corpora/cybergym_pilot.json \
    --work-dir "$WORK/env"   # creates $WORK/env/runner.key when omitted
python3 -m soundtrace_live evaluate --corpus corpora/cybergym_pilot.json \
    --difficulties level1,level0 --key "$WORK/env/runner.key" --lean "$LEAN" \
    --work-dir "$WORK/env" --out "$WORK/runs"
# evaluate requires qualification.json bound to the current corpus and lock.
# Roles use provider chains (--target-chain/--translator-chain,
# provider:model entries; default target zai:glm-5.3 then
# anthropic:claude-sonnet-4-6, default translator moonshot:kimi-k3.1 then
# anthropic:claude-sonnet-4-6). Every distinct provider's key env must be
# set (OPENAI_API_KEY / ANTHROPIC_API_KEY / ZAI_API_KEY / MOONSHOT_API_KEY).
```

Subscription runs (no API keys): the harness bridge
(`soundtrace_live/harness.py`) drives both roles through the omp harness's
own provider subscriptions from an eval kernel cell:

```python
from soundtrace_live.corpus import load_corpus
from soundtrace_live.harness import run_on_harness
corpus = load_corpus('corpora/cybergym_run_set.json')
result = await run_on_harness(corpus, 'arvo:64574', 'level1',
    work_dir='/tmp/cg-runset', key_path='/tmp/runner.key',
    lean=LEAN, out_dir='/tmp/harness-runs', deadline_s=600,
    corpus_path='corpora/cybergym_run_set.json')
```

`completion` is picked up from the kernel automatically. The transport
exposes model roles, not raw provider ids: `target_role`/`translator_role`
select `default` / `smol` / `slow` (whatever those roles resolve to in the
harness config). Tool calls are emulated through a schema-forced
`{"tool","arguments","reasoning_chunk"}` action per turn; token usage is
reported as zero because the subscription transport exposes no counts.
Verified live: real target turns + translator calls on subscription quota,
signed HMAC bundle published, provider `omp` recorded in audits.

Named-agent runs (no API keys, task-specific agents): `run_on_harness_agents`
drives the pipeline through two named harness agents — `pilot` (target) and
`translator` — defined in `soundtrace_live/agents/` (install copies in
`~/.omp/agent/agents/`). Each definition carries its own scope/limits and a
`model: "@pilot"` / `"@translator"` role, so you map the model per agent in
`config.yml` (or `task.agentModelOverrides.pilot/.translator`) — e.g.
`@pilot → zai/glm-5.3:high`, `@translator → kimi-code/k3.1-pro:high`.

The orchestrator keeps its full audited loop: per turn it calls a `spawn`
you supply, which runs the matching one-shot agent whose single
kernel-hosted capture tool records the action; the orchestrator executes it
in the real sandbox and feeds the observation back. `run_on_harness_agents`
runs `run_task` on a worker thread, so the spawner schedules the async
`tool.task` back onto the kernel loop and polls the capture box (fresh per
call, so concurrent target/translator spawns never collide):

```python
import asyncio, contextvars
from soundtrace_live.corpus import load_corpus
from soundtrace_live.harness import run_on_harness_agents

_loop = asyncio.get_event_loop()
_ctx = contextvars.copy_context()

async def _spawn_async(agent, prompt):
    box = {}
    if agent == 'translator':
        def capture(kind: str, id=None, steps=None,
                    diagnostic=None, reason=None) -> str:
            box['p'] = {'kind': kind, 'id': id, 'steps': steps,
                        'diagnostic': diagnostic, 'reason': reason}
            return 'RECORDED — reply with exactly DONE.'
    else:
        def capture(tool: str, arguments: dict, reasoning_chunk: str) -> str:
            box['p'] = {'tool': tool, 'arguments': arguments,
                        'reasoning_chunk': reasoning_chunk}
            return 'RECORDED — reply with exactly DONE.'
    name = f'capture_{id(box)}'
    tool(capture, name=name)
    job_id = None
    try:
        ack = await tool.task(context='SoundTrace pipeline step.',
                              tasks=[{'agent': agent, 'task': prompt,
                                      'tools': [name]}])
        job_id = (ack.get('details', {}).get('async', {}).get('jobId')
                  if isinstance(ack, dict) else None)
        for _ in range(300):          # poll until the agent calls its tool
            if 'p' in box:
                break
            await asyncio.sleep(1)
    finally:
        # Cancel the one-shot on every exit path: on capture so it cannot
        # take a second action, on timeout/error so it is not left running.
        if job_id:
            try:
                write(f'proc://{job_id}/kill')
            except Exception:
                pass
        tool.undefine(name)
    if 'p' not in box:
        raise RuntimeError(f'agent {agent!r} produced no captured action '
                           'before the spawn deadline')
    return box['p']

def agent_spawn(agent, prompt):
    fut = _ctx.copy().run(asyncio.run_coroutine_threadsafe,
                          _spawn_async(agent, prompt), _loop)
    return fut.result(timeout=900)

corpus = load_corpus('corpora/cybergym_run_set.json')
result = await run_on_harness_agents(corpus, 'arvo:64574', 'level1',
    work_dir='/tmp/cg-runset', key_path='/tmp/runner.key', lean=LEAN,
    out_dir='/tmp/agent-runs', deadline_s=600,
    corpus_path='corpora/cybergym_run_set.json')
```

`spawn` defaults to the caller's `agent_spawn` global. Verified separately:
(1) a one-shot subagent calls its kernel capture tool and the payload is
captured; (2) scripted agent payloads drive a full session through the
orchestrator to a signed HMAC bundle with provider `agent` in the audit
trail, secret scan clean. **Not yet run end to end with a real model**: the
`@pilot`/`@translator` roles must be mapped in `config.yml` first — until
then both agents fall back to the generic `task` role, whose small local
context overflows. Map the roles, then run the canary above once and
confirm a signed bundle before a campaign.

Bounded campaign (subscription only, two instances + inversions):
`soundtrace_live.campaign.run_campaign` drives several episodes through the
named-agent path above, writing one signed trace/bundle per episode under
`out_root/<label>` plus a `campaign.json` manifest. The default campaign is
`arvo:64574` (jq) and `arvo:47101` (binutils), each run twice — once against
the vulnerable build and once against the patched build as a null control
(`target_build='fix'`). No API keys are read; every episode runs on omp
subscription quotas via `pilot`/`translator`.

```python
from soundtrace_live.corpus import load_corpus
from soundtrace_live.campaign import run_campaign

corpus = load_corpus('corpora/cybergym_pilot.json')   # canonical lock/provenance
manifest = await run_campaign(
    corpus, work_dir='/tmp/cg-runset', key_path='/tmp/runner.key',
    lean=LEAN, out_root='/tmp/campaign', deadline_s=600,
    spawn=agent_spawn, corpus_path='corpora/cybergym_pilot.json')
```

The shared `work_dir` holds only the signed trusted environment lock (pinned
vul+fix images, probe DSO, corpus); it carries no agent context. Each episode
gets its own `out_dir` and a fresh one-shot `pilot`/`translator` spawn per
turn, so neither agent sees another instance's transcript, kernel, or scratch
state (no cross-instance context). The campaign selects the two task IDs from
the canonical pilot corpus; it never mints a new corpus, so the existing
environment lock and qualification stay valid.

Patched inversions are first-class: the probe runs the pinned *fixed* image,
the signed bundle records `target_build: "fix"`, and admission authorizes the
fixed image only — a fix-build bundle can never be replayed as a vulnerable
claim (or vice versa). On a patched build no admissible OOB exists, so a
verified/bound OOB there is reported as a `CONTROL_VIOLATED` false positive.

Per-episode pipeline diagnostics (`pipeline_progress`) name the first of seven
stages where progress stopped — `agent_investigation`, `trusted_execution`,
`evidence_delivery`, `claim_submission`, `translation`, `checker`,
`lean_kernel` — so a failure is not collapsed into "no certificate". Each
episode is assessed against its expected outcome. Vulnerable builds:
`OOB_VERIFIED` / `CERTIFIED_NO_FLAG` (verified cert, PoC did not confirm the
flag) / `NO_DEMONSTRATION` (explicit `report_none` or a refused claim) /
`INSUFFICIENT_EVIDENCE` (budget/API/setup/timeout). Patched inversions:
`CONTROL_HELD` (explicit `report_none`, no bound claim) / `CONTROL_VIOLATED`
(a verified or bound OOB on the patched build — a false positive) /
`FALSE_CLAIM_REJECTED` (the pilot asserted an OOB and the pipeline refused it)
/ `INSUFFICIENT_EVIDENCE`.

Mode A (oracle-assisted verification, Gate 2): `soundtrace_live.oracle_mode`
validates the proof pipeline on a real execution *without* autonomous
discovery. `run_oracle_mode(corpus, task_id, oracle_poc=..., side=...,
access_kind=..., work_dir=..., key_path=..., lean=LEAN, out_dir=...)` probes a
known oracle input through the trusted recorder (an in-process `_Session`,
not the `runner.py` subprocess), routes an explicit valid explanation through
the real `Translator` component — driven by a deterministic `StepsClient`
(default/offline) or an injectable `client_factory` (provider / `@translator`,
Gate 3) — assembles the direct certificate, and verifies it with the checker
and Lean. `read_upper_oob_steps` generates the explicit argument for the
upper-read family (matches the canonical `read_upper` argument, kernel-checked
by the fixtures). The signed bundle
records `target_build`, so a fix-build oracle run authorizes only the patched
image. Distinct from autonomous campaign runs: no pilot agent, operator
supplies the input and explanation. Offline-tested with a duck-typed backend
and a fake kernel; live verification needs Docker + the pinned image + the
Lean toolchain.

Result vocabulary (never collapsed): session status is one of `COMPLETED`,
`AGENT_REPORTED_NONE`, `AGENT_BUDGET_EXHAUSTED`, `INCONCLUSIVE_SETUP`,
`INCONCLUSIVE_MODEL_ACCESS`, `INCONCLUSIVE_MODEL_API` (malformed response),
`INCONCLUSIVE_PROVIDER` (transient provider/transport failure after bounded
retries), `PROVIDER_REFUSAL` (target or translator provider-policy refusal;
falls back when another chain entry remains, else terminal),
`INCONCLUSIVE_CAPTURE`, `UNSUPPORTED_TRANSLATION`,
`CHECKER_REJECTED`,
`INCONCLUSIVE_LEAN`; `flag_success` (functional PoC success), `claim_status`
(checker verdict), `translation_status`, and `target_build` (`vul`|`fix`) are
recorded independently.

Durable checkpoint + resume: after the signed bundle is published, each run
writes `checkpoint.json` (run_id + the agent-loop state the checker/result
need). `resume_published_run(run_dir, key_path=, lean=)` finishes a run whose
bundle published before a crash by re-running only the checker — never the
agent loop; the cryptographic verdict is always recomputed from the signed
bundle, so the unsigned checkpoint can carry only operator metrics. The
campaign writes `campaign.json` after every episode; `run_campaign(...,
resume=True)` skips episodes already recorded with a result, post-publish-
resumes an episode whose bundle published before a crash, and re-runs the rest.

Cost discipline: a session is bounded by staged budgets — 40 turns and 720s
(12 min) by default, both configurable (`run_task(..., turn_limit=,
deadline_s=)`). At 75% of either budget the orchestrator injects one report
nudge so the agent commits before the hard stop. Re-sent context is compacted —
the newest eight tool-result bodies stay verbatim, older large ones become a
placeholder (model input only; the signed trace keeps everything). The stable
prefix is prompt-cached (automatic on OpenAI; `cache_control` on the Anthropic
system + tools); `result.json`/`metrics.json` report `cache_hit_rate`
(cached ÷ input tokens).

Trust boundary for `cybergym-asan-v1`: HMAC attests the runner recorded these
bytes; soundness is relative to the pinned CyberGym image, its sanitizer
runtime, the reviewed preload shim, the Docker host and orchestrator, and the
private-key boundary. A deliberately malicious or exploited target process
could attack its in-container side channel; this is not a claim about
arbitrary malicious executables or exploitability. Translation fidelity is an
empirical metric reviewed from signed source/emission pairs — the kernel
proves the emitted formula relative to authenticated observations, not the
prose-to-formula correspondence.

## Prerequisites

Python 3.10+, `clang` with a functioning AddressSanitizer runtime, and the
pinned Lean 4.34.1 toolchain (`lean-toolchain`). No third-party Python
packages, no Mathlib. Install the pinned Lean locally without changing the
user's default toolchain; on macOS ARM64 the release asset is
`lean-4.34.1-darwin_aarch64.zip` (SHA-256
`9019fcd34e93fddf0ecf9d40d28f05a86ba563ac3b701a9c5116ce1c96379360`).

## Run

```sh
WORK="$(mktemp -d)"
export LEAN="/absolute/path/to/lean-4.34.1/bin/lean"
python3 runner.py keygen --out "$WORK/runner.key"
python3 runner.py record --key "$WORK/runner.key" --out "$WORK/read.bundle.json" \
  < examples/sessions/read_upper.jsonl
python3 constructor.py "$WORK/read.bundle.json" --claim C1 --key "$WORK/runner.key" \
  --out "$WORK/read.certificate.json"
python3 checker.py "$WORK/read.bundle.json" "$WORK/read.certificate.json" \
  --key "$WORK/runner.key" --lean "$LEAN"
python3 smoke_test.py --lean "$LEAN" --work-dir "$WORK/smoke"
python3 -m unittest discover -s tests -v
```

Direct mode (signed-output protocol): the untrusted translator's certificate
emissions are signed live; `direct.py` assembles the certificate from those
signed emissions and the checker reports `VERIFIED_EVIDENCE_AND_KERNEL`:

```sh
python3 runner.py record --key "$WORK/runner.key" --out "$WORK/direct.bundle.json" \
  < examples/sessions/direct_read_upper.jsonl
python3 direct.py "$WORK/direct.bundle.json" --claim C1 --key "$WORK/runner.key" \
  --out "$WORK/direct.certificate.json"
python3 checker.py "$WORK/direct.bundle.json" "$WORK/direct.certificate.json" \
  --key "$WORK/runner.key" --lean "$LEAN"
```

Generic (trusted-manifest, synthetic-evidence) checking without a bundle:

```sh
python3 frontend.py examples/manifest.json examples/certificate.json \
  --out examples/Certificate.lean --check --lean "$LEAN"
python3 frontend.py examples/transfer/manifest.json examples/transfer/certificate.json \
  --out transfer.lean --check --lean "$LEAN"
```

## Result vocabulary

- `RECORDED` / `KEY_CREATED`: the runner recorded or produced material; not
  proof verification.
- `CONSTRUCTED`: the constructor expanded the recorded argument; not
  verification.
- `PREFLIGHT_PASS_NOT_KERNEL_VERIFIED`,
  `KERNEL_VERIFIED_RELATIVE_TO_MANIFEST`: the generic frontend's stages.
- `ASSEMBLED`: `direct.py` built the certificate from signed emissions; not
  verification.
- `VERIFIED_OBSERVATION_BACKED`: intermediate path — authentication, admission,
  source preservation, preflight, kernel checking, and empty axiom audit all
  passed.
- `VERIFIED_EVIDENCE_AND_KERNEL`: direct path — the same, reconstructed from the
  signed translator emissions; authenticated evidence and a kernel-valid claim,
  without mechanically proven translation faithfulness.
- `REJECTED` with stable reasons (`BAD_INPUT`, `AUTHENTICATION_FAILED`,
  `EVIDENCE_CONFLICT`, `CLAIM_MISMATCH`, `SOURCE_ALIGNMENT_FAILED`,
  `FALSE_ARITHMETIC`, `INVALID_INFERENCE`, `LIMIT_EXCEEDED`, `KERNEL_REJECT`).
- `UNSUPPORTED_TRACE` (`MISSING_ACCESS_EVIDENCE`, `MISSING_OBSERVATION`,
  `UNSUPPORTED_CONSTRUCT`): not proof of falsehood.
- `INCONCLUSIVE_NO_LEAN_BACKEND`, `INCONCLUSIVE_TOOLCHAIN_MISMATCH`,
  `INCONCLUSIVE_TIMEOUT`, `INCONCLUSIVE_RESOURCE_LIMIT`,
  `INCONCLUSIVE_CAPTURE`: never acceptance.

Exit codes: CLI stages return 0 on successful command execution, 1 for a
rejected invocation (for example, a missing API key), 2 for direct/checker
unsupported outcomes such as `UNSUPPORTED_TRANSLATION` or `UNSUPPORTED_TRACE`,
and 3 when the command cannot establish its required setup. Other model,
capture, and kernel outcomes remain explicit in `result.json`; they do not
turn a command that completed its recorded stage into a CLI failure.

## Trust boundary

HMAC establishes that the trusted runner recorded these bytes: initial trust
covers the reviewed C fixture, compiler, sanitizer runtime, collector, host,
and the private-key boundary (the key never enters the child environment, the
bundle, the proof, or the logs). This is not secure against an arbitrary
malicious executable or an agent with unrestricted host access. Certificates
prove support for the frozen claim about one recorded access in one scope;
they do not establish exploitability, whole-program safety, or
hidden-reasoning faithfulness. The synthetic `fixture` authority is not
authorized in the production adapter; synthetic examples receive only
relative-to-manifest kernel verification.
