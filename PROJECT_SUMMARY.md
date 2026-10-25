# SoundTrace — Project Summary

**Verifiable, evidence-grounded certificates for AI agents that claim memory-safety bugs.**

## 1. Problem and thesis

When an AI agent investigates a program and reports "there is an out-of-bounds
(OOB) read here," two very different questions are usually collapsed into one:

- **Functionality** — did the agent's search actually *trigger* the bug (e.g.
  produce a crashing input / capture the flag)?
- **Correctness** — is the agent's stated *reasoning* a sound argument that the
  access is really out of bounds, or did it guess, hallucinate a justification,
  or get the right answer for the wrong reason?

Benchmarks score the first. Almost nothing independently checks the second.
SoundTrace closes that gap. It turns an agent's explicit reasoning about a
single memory access into a **machine-checked certificate** that is accepted
only when (a) the evidence it rests on was really observed by a trusted runtime,
(b) the **proof source is captured live and authenticated** into the same signed
record — the translator's certificate emissions in direct mode, or the typed
reasoning nodes in the intermediate mode — never synthesized afterward or
silently repaired, and (c) a formal proof kernel confirms the logic with no
hidden assumptions. (The certificate itself may be assembled or reconstructed
from that signed source at any later time; it is the *source* that must be live.)

Two result tiers make the strength of each certificate explicit.
`VERIFIED_EVIDENCE_AND_KERNEL` (direct translation, iteration 1) certifies
(a)–(c). `VERIFIED_OBSERVATION_BACKED` (intermediate-language path)
additionally proves the certificate mirrors a structured argument byte for byte.
Both are deliberately narrow: they certify *one claimed access in one recorded
execution*, not whole-program safety, exploitability, or the faithfulness of any
hidden chain of thought.

## 2. The certificate language (soundtrace-v1)

The language is intentionally **domain-neutral**: generic arithmetic and
propositional logic, with memory meaning supplied only by a small reviewed
adapter. This keeps the trusted core tiny and reusable.

```
Sort     := Int | Prop
Term     := integer | declared_Int_symbol | ["add",T,T] | ["sub",T,T]
Formula  := ["atom",Prop] | ["eq",T,T] | ["lt",T,T] | ["le",T,T] | ["and",F,F]
```

Nine fixed inference rules only — `and_intro/left/right`, `eq_symm`, `eq_trans`,
`add_eq`, `sub_eq`, `lt_transport`, `le_transport`. There is no implication,
no "obviously," and no proof search: a certificate is a flat list of tiny steps,
each either an observation, a closed arithmetic fact the kernel re-checks, or
one explicit rule instance. The OOB claim is a single frozen target:

```
access ∧ (live ∧ (0 ≤ extent ∧ (0 < width ∧ violation)))
upper violation: extent < offset + width      lower violation: offset < 0
```

Everything is strictly bounded (step count, depth, integer size, serialized
bytes) and canonicalized, so identical arguments always compile to identical
proofs. This is the language the kernel checks. A higher-level, optional
**intermediate reasoning language** that compiles down to it is described in
§4.2, where it is the project's key ablation variable.

## 3. Pipeline components

| Component | Plain-language role |
|---|---|
| **Runner + C/ASan fixture** | The instrumented laboratory. Runs the real access under AddressSanitizer, records what the sanitizer *actually* observed into an ordered log, and seals it with an HMAC key kept outside the agent's reach. |
| **Evidence module** | The notary's toolkit: strict JSON parsing (duplicate keys, non-finite numbers rejected), canonical hashing, HMAC signing/verification. One convention everywhere. |
| **Adapter (OOB)** | The only place memory *meaning* lives. From signed raw events it derives exactly five facts — `access, live, offset, width, extent` — and the frozen target. A planned or blocked access yields no fact and no "safety" claim. |
| **Translator (LLM, live)** | Iteration-1 default. A resource-limited, swappable-model LLM that turns the agent's free-text reasoning into certificate steps as it is produced, under an authentic-translation prompt. Untrusted: a proposer only. |
| **Constructor** | Intermediate-language path (§4.2 ablation). Deterministically expands typed reasoning nodes into the low-level certificate. No search, no repair: a false `4+4=7` fails at that step. |
| **Frontend** | Compiles a certificate to Lean source and runs the pinned kernel, requiring an *empty axiom audit*. |
| **Checker** | The auditor: re-verifies the seal, re-derives evidence from raw events, reconstructs the certificate (from signed translator emissions in direct mode, or from the signed typed trace on the intermediate path), demands byte-equality, then runs Lean. |
| **Lean 4.34.1 kernel** | The independent referee that confirms the proof depends on no axioms. |

Four honesty invariants are enforced structurally: a *planned* access is not
evidence; recorded reasoning is never repaired; evidence cannot be cited before
it is produced; the claim is frozen at assertion and cannot be edited after.

The reference implementation is complete: ~3,400 lines of Python plus the C
fixture, 151 behavioral tests, eight controlled demo cases (upper/lower,
read/write, in-bounds, patched), and an end-to-end run producing
`VERIFIED_OBSERVATION_BACKED` with an empty axiom audit on the pinned kernel.

## 4. Proposed changes

### 4.1 Validation on CyberGym — separating correctness from functionality

We will replace the hand-built fixture-only evaluation with **CyberGym**
(real-world OSS-Fuzz–derived vulnerability tasks) as the validation benchmark.
CyberGym gives us the four quadrants we need, on genuine code:

|  | **Agent flags a vuln** | **Agent flags nothing** |
|---|---|---|
| **Genuine OOB present** | should certify (`VERIFIED_EVIDENCE_AND_KERNEL`; `VERIFIED_OBSERVATION_BACKED` on the intermediate path) | missed bug — functional failure |
| **No vuln / patched** | *false alarm* — pipeline must `REJECT`/`UNSUPPORTED` | correct abstention |

This operationalizes **correctness ⟂ functionality** as two independent axes:

- **Functionality / flag success** — did the search trigger the bug? (CyberGym's
  own signal.)
- **Correctness / certification** — is the agent's reasoning a sound,
  evidence-backed proof? (SoundTrace's signal.)

We will deliberately include both **genuine OOB instances** and
**non-vulnerability instances**, and both **good** and **poor reasoning
traces**. Poor traces (false arithmetic, forward/circular references,
unsupported claims, a read witness used for a write) must be rejected with a
specific reason; good traces over real crashes must certify. The key metric is
**false-acceptance rate** against independent ground truth — a system that
certifies a hallucinated bug is worse than useless.

*Scope note (honest):* CyberGym targets are full programs, so the adapter must
graduate from the single-allocation fixture to real ASan reports on arbitrary
heap objects (`__asan_locate_address` on real allocations, real
`heap-buffer-overflow` reports). This is the "separately reviewed adapter" the
design anticipates and is the main new engineering surface.

*Implementation status:* the graduation is implemented. Producer
`cybergym-asan-v1` (`soundtrace_live/`) captures one machine ASan callback
event per probe in pinned, locked-down CyberGym containers via a reviewed
`-nostdlib` preload shim, derives the same five facts
(`offset = address − region_base`), freezes the same target, and adds the
live direct-translation invariants (per-emission attempt hashes, narration
`source_seq` evidence cutoffs, abstention closure). The pinned pilot corpus is
`arvo:64574` (jq), `arvo:47101` (binutils), and `oss-fuzz:42535201`
(assimp) at levels 1 and 0. The target agent (`gpt-daybreak-blue-latest`,
access program `daybreak_blue`) explores extracted source in a network-less
sandbox; the translator (`gpt-5.6-luna`) converts each visible chunk live.
No live-agent experimental results are claimed in this document; see the
run artifacts for any executed pilots.

### 4.2 Translation — direct first; the intermediate language as the key ablation

**Development story.** The first iteration translates **directly** from the
target agent's free-text reasoning into the certificate language (§2), with no
intermediate. This is the simplest end-to-end path to wire into the live loop,
and it establishes the baseline we care about first: how well a bounded LLM can
emit kernel-level proof steps on its own. The structured **intermediate
language** is then introduced in a later iteration as the project's **key
ablation variable**. (The reference implementation already contains that
intermediate and its deterministic constructor; the first experimental
iteration deliberately sets it aside so the direct baseline is measured first.)

**Iteration 1 — direct translation.** A resource-limited LLM translator reads
each free-text reasoning chunk as the agent produces it and emits certificate
steps directly. Its contract:

- **Resource-limited:** a small bounded token budget, a capped number of
  emitted steps, and a fixed number of repair attempts (first-pass and repaired
  scores reported separately). A narrow translator, not an open-ended agent.
- **Specialized prompt — authentic translation:** cite *only* observations the
  runner has already delivered (by evidence ID); preserve the agent's stated
  numbers verbatim; never invent facts, soften a claim, or "repair" arithmetic;
  target the frozen claim exactly. The prompt is an **experimental control, not
  an enforcement mechanism** — faithfulness is encouraged and *measured*, while
  safety is enforced downstream.
- **Explicit abstention — narrowly scoped.** Abstention with
  `UNSUPPORTED_TRANSLATION` is reserved for input the translator *cannot
  represent*: out-of-language or unparseable reasoning, or an exhausted resource
  budget. It is **not** used for *representable bad reasoning* — a false
  `4+4=7`, an invalid inference, a forged observation value — which the
  translator must still emit faithfully so the checker and kernel reject it with
  a specific reason. Collapsing bad reasoning into abstention would turn the
  translator into a semantic verifier and hide exactly the poor-trace failures
  §4.1 measures. The three-way split: *translator failure* (abstain) vs.
  *faithfully translated but false* (emit → downstream reject) vs. *faithfully
  translated and true* (emit → certify).

**Binding live translation to the record.** Removing the intermediate also
removes the checker's deterministic reconstruction, and without a substitute
any certificate synthesized *offline after reading the whole bundle* would still
pass — leaving both "live" and "only delivered evidence" unenforced. Direct mode
therefore requires a provenance binding in the runner protocol:

1. The runner records in its **sequenced, HMAC-covered log** both each
   target-agent **free-text reasoning chunk** and each **translator certificate
   emission** (the primitive steps produced, with the evidence IDs they cite),
   each at its own log position.
2. The checker **reconstructs the certificate by concatenating the signed
   translator emissions in order** and byte-matches the submitted certificate
   against it — so an offline-synthesized certificate cannot be substituted.
3. The checker **enforces evidence availability per emission**: every evidence
   ID an emission cites must have been delivered *before that emission's* log
   position, not merely before the final claim.

This gives direct mode a new result status, **`VERIFIED_EVIDENCE_AND_KERNEL`**:
authenticated evidence, live-recorded and signed translation provenance, and a
kernel-valid proof with an empty axiom audit — but **faithfulness of the
translation to the agent's wording is not mechanically proven** (that is the
LLM's job, and we measure it). `VERIFIED_OBSERVATION_BACKED` keeps its stronger
meaning and is reserved for the intermediate path, which *does* prove the
certificate mirrors a structured argument. Soundness of the *claim* is identical
in both: the kernel rejects any false or axiom-dependent proof, and evidence
cannot be forged.

**The intermediate language (key ablation variable).** Between free text and
the certificate sits an optional, human-shaped **typed reasoning-trace
language**. A trace is an ordered list of named nodes; the order of the list is
the order of reasoning, and nodes may only refer *backward*. There are exactly
five node kinds:

| Node | Meaning | Example |
|---|---|---|
| `observe` | cite a delivered fact, asserting exactly what it says | offset is 4 (from `X1/A1.offset`) |
| `calculate` | `add`/`sub` two values, with a mandatory stated result | offset + width = 8 |
| `compare` | assert `eq`/`lt`/`le` between two values is true | extent < end (6 < 8) |
| `conjoin` | join two or more earlier facts | width>0 ∧ the violation |
| `infer` | apply one of the nine rules, with its exact conclusion | flip `offset = 4` to `4 = offset` |

Operands are integer literals or references to an earlier node that concluded
`term = literal`. The key property is the **division of labor** it enforces:
the LLM only has to produce a coarse argument at the level a person would state
it ("4 + 4 = 8, and 6 < 8"); a **deterministic constructor** then mechanically
expands each node into a fixed block of primitive kernel steps (a single
`calculate`, for instance, becomes `add_eq`, a closed arithmetic check, and
`eq_trans`), recording a source map from every kernel step back to the node that
produced it.

What the intermediate buys: **argument preservation** (the certificate is
byte-reconstructible from the signed trace, enabling
`VERIFIED_OBSERVATION_BACKED`); **node-level error localization** (a failure
names the exact node, e.g. `FALSE_ARITHMETIC at node "end"`); **determinism**
(same trace, same certificate bytes); and a clean split between *what is argued*
(LLM) and *how it is proven* (trusted, mechanical). What it costs: an extra
schema the translator must hit and an extra stage in the live loop.

**The ablation.** It isolates one question: does separating *argument* (LLM)
from *proof mechanics* (deterministic) improve coverage and faithfulness, versus
asking the LLM to emit low-level kernel steps itself? On identical admitted
evidence and the same live protocol, we compare (i) direct free-text →
certificate (**iteration 1, default**), (ii) free-text → intermediate language →
deterministic constructor, and (iii) the deterministic constructor on a
hand-authored trace (upper bound), crossed with the translator-model sweep
(§5).

### 4.3 Co-executed capture vs. decoupled capture — recommendation

First, a correction to a tempting-but-wrong framing: **"post-hoc checking" is
not inherently weak.** The reference pipeline already *records and signs the
bundle during the session, then runs the constructor and checker later*, and
that deferred path still returns `VERIFIED_OBSERVATION_BACKED`. Translation and
checking over an authenticated bundle are legitimately deferred and lose
nothing. Two steps must be kept separate:

- **(a) Evidence capture** — the runner must mediate the access and sign the
  observation *during the original execution*. This is what binds the evidence
  to its execution scope (run nonce + execution + allocation + event identity)
  and makes temporal ordering ("you cannot cite evidence that did not yet
  exist") real rather than reconstructed.
- **(b) Translation + checking** — may run at any later time over that signed
  bundle and remain fully evidence-backed. Deferring them is fine.

What actually forces a weaker outcome is a flow with **no original
runner-mediated capture**: an agent's free-text trajectory collected *outside*
the runner, with sanitizer evidence synthesized afterward by a **separate
re-run**. That re-run is a different execution (new ASLR addresses, new nonce,
new scope); the design forbids attaching it to the original argument, so it can
only reach `KERNEL_VERIFIED_RELATIVE_TO_MANIFEST` or stand as a fresh claim
about the replay. The failure mode is *missing capture*, not *deferred
checking*.

**Design commitment: the runner and the translator run live, in parallel with
the target vulnerability agent.** As the target agent searches for an OOB, its
candidate accesses execute inside the instrumented, signed runner, and its
reasoning requests interleave with the runner's observation responses in one
ordered log; the translator consumes each observation as it is delivered and
emits certificate steps in the same loop. The three run concurrently against the
same execution, so capture is co-executed with the agent's genuine search and we
certify the investigation that actually happened. Checking may still be deferred
over the resulting signed bundle (it loses nothing), but capture and translation
are live by design. The new engineering is wiring a *real* target agent — not
hand-authored sessions or externally collected trajectories — into this live
boundary. The mode we reject is **decoupled capture**: reasoning first, evidence
by replay later, because that is the one flow that cannot be evidence-backed.

Tradeoff: co-execution puts the runner (and the live translator) on the agent's
critical path and requires routing the agent's memory probes through the runner
— which is exactly what makes the evidence non-forgeable and the ordering
genuine. It does **not** require the final kernel check to be synchronous.

## 5. Tech stack

- **Core pipeline:** Python 3.10+, **standard library only** (`json`, `hmac`,
  `hashlib`, `subprocess`, `selectors`) — no third-party runtime deps, by design,
  for auditability.
- **Instrumentation:** LLVM/Apple **clang** with **AddressSanitizer**; the
  documented ASan runtime callback API (`__asan_get_report_{address,access_type,
  access_size,pc}`, `__asan_locate_address`) read live from the faulting process.
- **Proof backend:** **Lean 4.34.1**, pinned by SHA-256 and installed into a
  project-local `.tools/` dir; uses only shipped `Std`, `by decide` for closed
  arithmetic, `#print axioms` for the empty-audit gate. No Mathlib, no
  `native_decide`, no tactic search.
- **Authentication:** HMAC-SHA256 with a 32-byte key held outside the agent
  workspace.
- **Benchmark:** **CyberGym** (Docker/OSS-Fuzz harness) for real targets and
  ground-truth labels.
- **Translator (untrusted):** a resource-limited LLM behind a thin
  JSON-emitting client with a **pluggable model backend**.

**Translator model — a first-class experimental variable.** Because the
translator is untrusted (the Lean kernel is the trust anchor), the model is a
**coverage/cost lever, not a soundness lever**, so we expose it as a swappable
configuration knob and sweep it as a primary experimental axis — every model
runs behind the same client, prompt, resource limits, and evidence interface,
and is compared on identical admitted bundles:

- **Default:** **gpt-5.6-luna** — the pinned translator model used by the live
  CLI and offline harness.
- Alternative translator backends remain a configuration option, but changing
  the model is an experimental choice that does not change the proof boundary.
- **Escalation tier (optional):** a larger frontier model (e.g. **Claude
  Opus**) invoked only on first-pass failures, with first-pass and repaired
  scores kept separate.
- **Reproducible open backend:** **Qwen2.5-Coder-32B-Instruct**, so the sweep
  can be rerun without API access, consistent with the pinned-toolchain,
  stdlib-only reproducibility ethos.

Model switching is the headline knob of the translation study: holding evidence,
prompt, and limits fixed, we measure how coverage, first-pass success, and
faithfulness move across models.

## 6. Evaluation plan and metrics

- **Primary:** false-acceptance rate vs. independent ground truth; certification
  coverage of valid in-scope arguments; source-claim preservation; first-error
  localization. No-proof/timeout is always separated from "false."
- **Ablations:** the **key ablation** — intermediate language absent (direct,
  iteration 1) vs. present (§4.2); the translator-model sweep (§5); co-executed
  vs. decoupled capture (§4.3); descriptive vs. opaque identifiers;
  with/without evidence and scope locks.
- **Independence:** split by challenge family before generating any mutants;
  report per-challenge results and uncertainty, not pooled steps from correlated
  trajectories. Keep flag-success and claim-validity as independent outcomes.

## 7. Related work (positioning)

Structured-intermediate reasoning (PRoSFI), trace/context separation
(VeryTrace), NL→FOL solver verification (FoVer/Z3), and formal
certificate-checking with Lean for Datalog all inform the design; SoundTrace's
distinctive commitments are **runner-authenticated evidence**, **argument
preservation** (no silent repair), and a **kernel-checked empty-axiom audit** —
not a new theorem prover.

## 8. Risks and honest limits

Trust is **runner-relative**: initial trust covers the reviewed C fixture and
CyberGym ASan shim, compiler, sanitizer runtime, collector, host, Docker
images, pinned corpus/data revisions, and the private-key boundary. It is not
a defense against a malicious executable or an agent with unrestricted host
access. A certificate says nothing about exploitability or whole-program
safety. Real-data qualification and live runs additionally require Docker,
the pinned CyberGym data checkout, the pinned images, API access, and the
project-local Lean toolchain; missing setup is reported as inconclusive rather
than silently downgraded.

## 9. Deliverables

Implemented today: the full pipeline, **both** the intermediate (typed-trace)
and direct (signed-output) protocols, the CyberGym live adapter and
runner↔agent harness, 381 tests, eight controlled cases, and a tutorial
(`GUIDE.md`). The live path pins the corpus, CyberGym code/data revisions,
Linux/amd64 image digests, build environment, qualification records, model
access outcomes, evidence provenance, bounded capture, fixed-image benchmark,
and kernel verification. Real Docker/API/Lean qualification remains an
environment-dependent verification step; missing prerequisites are explicit
`INCONCLUSIVE_SETUP` outcomes. Evaluation reports certificate coverage,
benchmark inconclusives, claim rejections, translation abstentions, and
false-acceptance as not-applicable when the corpus has no negative tasks.
