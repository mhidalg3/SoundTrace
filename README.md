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
  receipt, and HMAC-authenticated bundle publication. Never accepts source
  paths, executables, flags, or environment overrides from the agent.
- `oob_adapter.py`: the only domain-meaning component. Derives the five
  admissible facts per access from raw signed events, freezes and recomputes
  claim outcomes, and builds the frozen target
  `access ∧ (live ∧ (0 ≤ extent ∧ (0 < width ∧ violation)))`.
- `checker.py`: the only producer of `VERIFIED_OBSERVATION_BACKED`:
  authentication, re-admission, deterministic reconstruction and byte
  comparison, preflight, and the pinned Lean kernel with an empty axiom audit.
- `examples/`: the migrated synthetic arithmetic fixture (manifest, typed
  argument, constructor-generated certificate and Lean source), the
  non-security `transfer` example in unit `tick`, and `sessions/` request
  scripts for all eight controlled cases.
- `tests/`: stdlib `unittest` behavioral regressions for evidence loading,
  frontend contracts and rules, the constructor, and the checker (isolated
  test keys, controlled fake Lean backends).
- `smoke_test.py`: deterministic end-to-end driver over the real CLIs in a
  caller-provided work directory.

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
- `VERIFIED_OBSERVATION_BACKED`: authentication, admission, source
  preservation, preflight, kernel checking, and empty axiom audit all passed.
- `REJECTED` with stable reasons (`BAD_INPUT`, `AUTHENTICATION_FAILED`,
  `EVIDENCE_CONFLICT`, `CLAIM_MISMATCH`, `SOURCE_ALIGNMENT_FAILED`,
  `FALSE_ARITHMETIC`, `INVALID_INFERENCE`, `LIMIT_EXCEEDED`, `KERNEL_REJECT`).
- `UNSUPPORTED_TRACE` (`MISSING_ACCESS_EVIDENCE`, `MISSING_OBSERVATION`,
  `UNSUPPORTED_CONSTRUCT`): not proof of falsehood.
- `INCONCLUSIVE_NO_LEAN_BACKEND`, `INCONCLUSIVE_TOOLCHAIN_MISMATCH`,
  `INCONCLUSIVE_TIMEOUT`, `INCONCLUSIVE_RESOURCE_LIMIT`,
  `INCONCLUSIVE_CAPTURE`: never acceptance.

Exit codes: 0 for the command's successful stage, 1 for `REJECTED`, 2 for
unsupported/inconclusive. A successfully recorded bundle exits 0 even when a
claim inside it is unsupported; constructing or checking that claim reports
its own status.

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
