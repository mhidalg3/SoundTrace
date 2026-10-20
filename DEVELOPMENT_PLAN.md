# Development plan: generic evidence-grounded proof language


> Implemented baseline (soundtrace-v1): the deterministic typed-trace
> constructor, runner-owned controlled-C/ASan evidence boundary with HMAC
> bundles, the nine-rule core, and the pinned Lean 4.34.1 kernel backend with
> empty axiom audits replace the originally sketched LM constructor. M0/M1
> language freeze and the M2 backend gate are covered by `tests/` and
> `smoke_test.py`; M3+ empirical work remains future work.

## Updated question

Can a compact, domain-neutral language preserve the explicit evidentiary and
logical commitments of tool-using LM agents, permit deterministic certificate
checking, and remain usable as trace length and dependency depth increase?

The language is generic; the initial empirical domain remains OOB read/write CTF
investigations. Do not claim coverage of arbitrary cybersecurity or hidden model
cognition. Concentrate effort on semantics, observation contracts, and translation
faithfulness rather than a novel theorem prover.

## Read and extract methods

1. **VeryTrace (2026)** — separate context extraction from trace translation; use
   explicit sequential dependencies and local diagnostics. Do not adopt its
   LLM-audited semantic fallback in the strict acceptance path.
   https://arxiv.org/html/2606.24124v1
2. **PRoSFI (2026)** — structured intermediates with IDs, dependencies,
   conclusions, and rule names; keep individual steps small. Reuse the interface
   idea, not the RL training pipeline in the first milestone.
   https://arxiv.org/html/2603.29500v1
3. **FoVer (TACL 2025)** — natural-language-to-FOL verification with Z3; useful
   solver-based baseline and translation-error comparator.
   https://aclanthology.org/2025.tacl-1.61/
4. **Verifying Datalog Reasoning with Lean (ITP 2025)** — existing formal
   certificate-checking infrastructure; ordered proofs avoid unnecessary search.
   https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.ITP.2025.36
5. **Evaluating the Robustness of Proof Autoformalization in Lean 4 (2026)** —
   distinguish paraphrase invariance from preservation of local numeric/symbolic
   errors; test against silent repair by the proof constructor.
   https://arxiv.org/html/2606.14867v1
6. **ProofWriter (ACL Findings 2021)** — controlled logical depth and proof labels
   for unit-level reasoning tests, not a substitute for environmental evidence.
   https://aclanthology.org/2021.findings-acl.317/
7. **Logic-LM / LINC (EMNLP 2023)** — model formalization + symbolic reasoning;
   use checker diagnostics for bounded repair, keeping first-pass scores separate.
   https://aclanthology.org/2023.findings-emnlp.248/
   https://aclanthology.org/2023.emnlp-main.313/

## Milestones and gates

### M0 — Freeze the evaluation contract

Hand-annotate 12 short fragments: four supported, four invalid, four insufficient.
Keep source claims, evidence availability, hypothesis/observation distinction,
formal targets, and failure locations separate. Choose an argument-preserving
primary evaluation and a separate post-hoc support condition. Gate: independent
reviewers agree on the labels and required premises.

### M1 — Specify language v0, then v1

For each construct define type, semantics, source contract, inference direction,
positive/negative examples, and one non-security interpretation. Start with the
included arithmetic/propositional profile. Add set/interval and event-scoping
constructs only as demanded by pilot traces. Gate: hand-written certificates cover
most in-scope supported pilot claims without task-specific shortcuts.

### M2 — Connect the Lean checker

Use explicit theorem applications and closed computation; no general proof search.
Compile the included source with the pinned toolchain, add positive/negative
backend tests, bound resources, and audit theorem dependencies. Reject source
injection and unauthorized assumptions. Gate: valid fixtures compile; malformed,
unsupported, and rule-invalid cases fail; backend absence/timeouts are inconclusive.
Do not build both a new Datalog engine and a new Lean kernel.

### M3 — Initial empirical baseline

Select approximately 40–60 reviewed fragments from a few runnable CTF tasks,
including successes, failed exploits, and incomplete diagnoses. Record model IDs,
prompts, budgets, target artifacts, runner versions, and source availability.
Compare an LM judge, direct restricted Lean, structured language -> Lean, and
post-hoc versus argument-preserving construction. Add a small fixed-rule solver
baseline with the same admitted facts. Report first attempt and at most two repair
attempts separately. Gate: end-to-end results have audited semantic alignment and
independent ground truth; compilation success alone is not a label.

### M4 — Larger and longer-horizon dataset

Provisional scale: 200–300 annotated claim/argument units from 50–80 trajectories
across 10–15 eligible challenges, subject to evidence availability. These are
planning targets, not an existing corpus. Separate raw trace length from logical
proof depth, scope changes, and distractor ratio. Begin with dependency depths
2–4, 5–8, and 9–16 where real evidence supports them. Use separately labeled
synthetic compositions to extend depth; do not pad real arguments artificially.

Split by challenge family and original artifact before generating mutants;
keep every sibling, patch, and trace from a task in the same split. Use public
EnIGMA/NYU challenges only after checking availability and instrumentation needs.
Missing runtime evidence must not be retroactively inserted into an old trace;
a fresh replay belongs to a new evidence context.

### M5 — Freeze language and test transfer

Freeze before held-out evaluation. Compare domain-specific versus generic
vocabularies; descriptive versus opaque identifiers; with/without evidence locks;
with/without scope locks; and statement-preserving versus repairing translators.
Test the same generic range reasoning on deadline/capacity fixtures. This is a
limited transfer test, not proof of universal domain independence.

## Metrics

Primary: false acceptance against independent annotated validity; certification
coverage of valid in-scope arguments; source-claim preservation; first-error
localization. Always separate no-proof/timeout from false. Secondary: token and
tool cost, translation latency, frontend latency, Lean startup and checking
latency, repair count, trace length, proof depth, and evidence distance. Keep flag
success and claim validity as independent outcomes. Report per-challenge results
and uncertainty, not only pooled steps from correlated trajectories.

## Not in the first implementation

No new search agent, arbitrary semantic entailment, automatic cybersecurity
ontology, unrestricted theorem proving, RL training, or general program safety
proof. No claim to verify hidden chain of thought. A generic `c < a + b` proof
alone is not a complete OOB diagnosis.
