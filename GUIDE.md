# SoundTrace user guide: from a controlled case to a checked certificate

This guide takes you from zero to a machine-checked proof that a specific
out-of-bounds memory access really happened, using the controlled demo cases
that ship with the tool. No prior proof-theory background is needed. At the
end you will also know how to feed in your own reasoning traces.

Everything below is run from the repository root (the `SoundTrace_starter/`
directory, which contains `runner.py`).

## 1. What this tool does, in plain words

Suppose a program reads 4 bytes at offset 4 of a 6-byte buffer. You want a
checkable answer to: *"did an out-of-bounds access actually happen, and can I
prove it?"* SoundTrace answers that in four steps:

1. **Run the access for real** in a sandboxed, instrumented program and record
   what the memory checker observed — not what anyone *claims* happened.
2. **Record your reasoning** about it as small typed steps ("I observed X",
   "4+4=8", "6 < 8", "therefore the endpoint passed the end of the buffer").
3. **Translate that reasoning automatically** into a formal certificate —
   no judgment calls, no AI, same output every time.
4. **Check the certificate with the Lean proof kernel**, the same kind of
   mathematics engine mathematicians use to verify proofs, plus a signature
   check that the evidence really came from the trusted runner.

The final success message, `VERIFIED_OBSERVATION_BACKED`, means: the evidence
was authentic, your recorded argument was preserved exactly (never silently
repaired), every logical step checked out, and the proof depends on no hidden
assumptions.

One certificate covers exactly one claimed access in one recorded run. It is
not a statement that the program is safe, exploitable, or that anything else
happened.

## 2. The pipeline, piece by piece

Think of the whole thing as a laboratory with an sealed evidence log, a
translator, and an auditor.

| Piece | File | What it is (plain words) |
|---|---|---|
| **Fixture** | `fixtures/oob_cases.c` | The laboratory experiment. A small, fixed, reviewed C program with 8 named demo cases (safe and unsafe reads/writes). It never takes code from you. |
| **Runner** | `runner.py` | The lab technician. Runs one case at a time, writes every observation into an ordered log (notebook), and seals the log with a digital signature (HMAC key). The key lives outside your workspace; without it nobody can forge a log entry. |
| **Reasoning trace** | your `.jsonl` script | Your argument, recorded line by line as requests to the technician: "run this case", "note this observation", "here is my final claim". |
| **Bundle** | `*.bundle.json` | The sealed lab notebook the runner produces: raw events, the full ordered log, and your frozen claim, all signed. |
| **Constructor** | `constructor.py` | The translator. Turns your recorded argument into a formal certificate — a chain of tiny, standard proof steps. Deterministic: same argument in, same bytes out, always. |
| **Certificate** | `*.certificate.json` | The formal proof script: which observations it uses, every arithmetic and logic step, and a map back to your original argument steps. |
| **Checker** | `checker.py` | The auditor. Re-signs nothing, trusts nothing: re-verifies the seal, re-derives the evidence from raw events, rebuilds the certificate from your recorded argument and demands byte-for-byte equality, then submits the proof to the Lean kernel and demands a clean audit. |
| **Lean kernel** | pinned 4.34.1 | The referee. An external mathematics engine that independently checks the proof and reports whether it depends on any axioms (it must depend on none). |
| **Frontend** | `frontend.py` | The compiler from certificate to Lean source. Also usable standalone with trusted synthetic data (that path reports a weaker result, `KERNEL_VERIFIED_RELATIVE_TO_MANIFEST`). |

Key honesty rules baked in:

- A planned access is not evidence. Only what the sanitizer actually reported
  (or completed) counts.
- Your recorded reasoning is never repaired. If you wrote `4+4=7`, the
  constructor fails at that step instead of fixing it.
- Evidence cannot be used before it exists. If you cite an observation the
  runner hadn't delivered yet, that step fails.
- Once you make your final claim, the argument is frozen. Nothing can be
  added afterward.

## 3. One-time setup

You need: Python 3.10+, `clang` with AddressSanitizer (standard on macOS
Xcode tools), and the pinned Lean 4.34.1 toolchain.

```sh
git clone https://github.com/mhidalg3/SoundTrace.git SoundTrace_starter
cd SoundTrace_starter

# 3a. Install Lean locally (macOS ARM64 example; pick your platform's asset
#     from the same release). Verify the digest before extracting:
mkdir -p .tools && cd .tools
curl -fL -o lean.zip \
  https://github.com/leanprover/lean4/releases/download/v4.34.1/lean-4.34.1-darwin_aarch64.zip
shasum -a 256 lean.zip
#   must be: 9019fcd34e93fddf0ecf9d40d28f05a86ba563ac3b701a9c5116ce1c96379360
unzip -q lean.zip && cd ..
export LEAN="$PWD/.tools/lean-4.34.1-darwin_aarch64/bin/lean"
"$LEAN" --version        # must print: Lean (version 4.34.1, ...)

# 3b. Make a fresh work directory for this session:
WORK="$(mktemp -d)"
```

If Lean is missing, everything still runs except the final kernel check,
which reports `INCONCLUSIVE_NO_LEAN_BACKEND` — never a fake success.

## 4. Tutorial: prove the `read_upper` case

The fixture's `read_upper` case allocates a 6-byte buffer and reads 4 bytes at
offset 4 — so the read touches bytes 4..7, two bytes past the 6-byte end.

### Step 1 — create the runner's signing key (once per session)

```sh
python3 runner.py keygen --out "$WORK/runner.key"
```

Output: `{"status": "KEY_CREATED", ...}`. The key is 32 random bytes written
with owner-only permissions; it refuses to overwrite an existing key. Keep it
private: whoever holds it can attest logs. Do not put it in the child
environment, the bundle, or git (`.gitignore` already excludes it).

### Step 2 — record a session: run, reason, claim

A session is a plain JSON-lines script you feed to the runner on stdin. Look
at `examples/sessions/read_upper.jsonl` while reading this. Three request
types exist, and order matters:

**Run the experiment** (line 1):

```json
{"kind": "run", "case": "read_upper"}
```

The runner compiles the fixed fixture once, runs the case in a fresh
subprocess, and answers with what became observable — for example (abridged):

```json
{"status": "RECORDED", "execution_id": "X1", "event_id": "A1",
 "observations": [
   {"id": "X1/A1.access", "formula": ["atom", "access"], "scope": "R<nonce>/X1/O1/g1/A1", "available_at": 2},
   {"id": "X1/A1.live",   "formula": ["atom", "live"],   ...},
   {"id": "X1/A1.extent", "formula": ["eq", "extent", 6], ...},
   {"id": "X1/A1.width",  "formula": ["eq", "width", 4],  ...},
   {"id": "X1/A1.offset", "formula": ["eq", "offset", 4], ...}]}
```

Five facts, no more: an access was attempted (and reported by the sanitizer),
the allocation was live, and the numeric extent/width/offset. `available_at: 2`
is the position in the ordered log where that evidence became available — you
may only cite it in later lines.

**Record your reasoning** (lines 2 onward). Each line is exactly this shape —
`kind`, `argument_id`, and `node`, nothing else (extra keys are rejected):

```json
{"kind": "reason", "argument_id": "C1", "node": {"id": "of", "kind": "observe", "evidence": "X1/A1.offset", "assert": ["eq", "offset", 4]}}
```

The `node` part is one of five shapes:

| Node | You are saying... | Example |
|---|---|---|
| `observe` | "I use fact X, asserting exactly what it says" | `{"id":"of","kind":"observe","evidence":"X1/A1.offset","assert":["eq","offset",4]}` |
| `calculate` | "these two known values add/subtract to this result" | `{"id":"end","kind":"calculate","operator":"add","left":{"ref":"of"},"right":{"ref":"wd"},"result":8}` |
| `compare` | "this comparison of known values is true" | `{"id":"vio","kind":"compare","relation":"lt","left":{"ref":"ex"},"right":{"ref":"end"}}` |
| `conjoin` | "these earlier facts together" | `{"id":"inner","kind":"conjoin","premises":["pw","vio"]}` |
| `infer` | "apply this named rule to these earlier steps" | `{"id":"s","kind":"infer","rule":"eq_symm","premises":["of"],"assert":["eq",4,"offset"]}` |

Operands are either an integer literal (`0`) or a reference to an earlier
node (`{"ref":"of"}`). References must point backward — you cannot cite a
step you haven't recorded yet. Every node needs a unique `id`.

The full `read_upper` argument observes all five facts, computes the access
end (`offset + width = 8`), compares (`extent < end`, i.e. 6 < 8), checks the
two sanity guards (`0 < width`, `0 ≤ extent`), and conjoins everything into
the target.

**Freeze your claim** (last line):

```json
{"kind": "claim", "argument_id": "C1", "event": "X1/A1",
 "access_kind": "read", "side": "upper", "from": "goal"}
```

- `event` names the execution/operation your claim is about.
- `side` is `"upper"` (read past the end) or `"lower"` (read before the
  start) — you must say which, it is never guessed.
- `from` names the last node of your argument (`"goal"` here).

At this moment the runner freezes the exact formal target your certificate
must prove, and the argument is closed: no more reasoning lines accepted.

### Step 3 — record the session into a signed bundle

```sh
python3 runner.py record --key "$WORK/runner.key" \
  --out "$WORK/read.bundle.json" < examples/sessions/read_upper.jsonl
```

You will see one JSON response line per request, ending with the claim
acknowledgement, and exit code 0. The bundle file now contains the sealed
log. (A blocked or rejected claim still produces a valid, signed bundle —
"the claim failed" is itself a recorded outcome.)

### Step 4 — construct the certificate

```sh
python3 constructor.py "$WORK/read.bundle.json" --claim C1 \
  --key "$WORK/runner.key" --out "$WORK/read.certificate.json"
```

Expected output:

```json
{"status": "CONSTRUCTED", "claim_id": "C1", "steps": 20, "source_nodes": 13, ...}
```

Your 13 reasoning nodes expanded into 20 primitive proof steps. `CONSTRUCTED`
means "translated successfully", **not** "verified". Open the certificate
file: `steps` holds the primitive proof (each `observe`, `compute`, or `infer`
of a standard rule), and `source_map` records which of *your* nodes produced
which steps, so nothing you said can be lost or reordered.

### Step 5 — check it (authentication + reconstruction + Lean kernel)

```sh
python3 checker.py "$WORK/read.bundle.json" "$WORK/read.certificate.json" \
  --key "$WORK/runner.key" --lean "$LEAN"
```

Expected output:

```json
{"status": "VERIFIED_OBSERVATION_BACKED", "claim_id": "C1", ...,
 "backend": {"version": "4.34.1", "axiom_audit": "empty"}, ...}
```

What the checker did before printing that: verified the bundle's signature
with the key, re-derived the five facts from the raw signed events, rebuilt
your certificate from the recorded argument and required byte-for-byte
equality, compiled the proof, and required the kernel's audit to say the
theorem depends on **no** axioms (`"empty"`). If any link fails you get a
precise rejection instead — see the status table below.

Exit codes: `0` verified, `1` rejected (something is wrong), `2`
unsupported/inconclusive (cannot decide; never counted as success).

## 5. Tour of all eight controlled cases

Run everything in one command (uses a fresh work dir, writes nothing into
the repository):

```sh
python3 smoke_test.py --lean "$LEAN" --work-dir "$(mktemp -d)/smoke"
```

The eight demo cases and what each teaches:

| Case | Situation | Outcome | Lesson |
|---|---|---|---|
| `read_upper` / `write_upper` | 4-byte access at offset 4 of 6 bytes | `VERIFIED_OBSERVATION_BACKED` | The tutorial case, for reads and writes. |
| `read_lower` / `write_lower` | access at offset −4 | `VERIFIED_OBSERVATION_BACKED` | Lower overflow proves `offset < 0` — no upper-bound claim needed. |
| `read_in_bounds` / `write_in_bounds` | access ends exactly at the buffer end | `REJECTED` / `FALSE_ARITHMETIC` | Touching the last byte exactly is legal; the comparison `16 < 12+4` is simply false, and the checker says so instead of "finding" a proof. |
| `read_patched` / `write_patched` | guard blocks the access before it happens | `UNSUPPORTED_TRACE` / `MISSING_ACCESS_EVIDENCE` | No access was attempted, so no access evidence exists. This is "cannot prove", **not** "safe" — absence of evidence is never a safety certificate. |

Record and construct work for every case; only the session script changes
(sessions for all eight ship in `examples/sessions/`). But only the four
certifiable cases produce a certificate file to check. For `*_in_bounds` the
constructor itself returns `REJECTED`/`FALSE_ARITHMETIC` and writes no
certificate; for `*_patched` the runner's claim response already says
`UNSUPPORTED_TRACE` and the constructor agrees — in both cases the outcome
*is* the answer, and there is nothing to feed the checker.

## 6. Reading the statuses (troubleshooting)

| Status / reason | Plain meaning | What to do |
|---|---|---|
| `RECORDED` | The runner logged your request. | — |
| `CONSTRUCTED` | Translation succeeded (not verification). | Continue to the checker. |
| `VERIFIED_OBSERVATION_BACKED` | Fully verified: evidence, argument, logic, kernel audit. | Done. |
| `REJECTED`/`AUTHENTICATION_FAILED` | Bundle signature wrong (altered data or wrong key). | Don't alter bundles; use the session's own key. |
| `REJECTED`/`FALSE_ARITHMETIC` | A recorded calculation/comparison is mathematically false. | Fix your argument's numbers — they are never auto-repaired. |
| `REJECTED`/`SOURCE_ALIGNMENT_FAILED` | Certificate doesn't match the recorded argument, or evidence cited too early, or bad references. | Check node order: evidence must be observed before it is cited; references point backward only. |
| `REJECTED`/`CLAIM_MISMATCH` | Claim identities don't line up (wrong event, read vs write, unknown claim). | Check the `claim` line's `event`, `access_kind`, `from`. |
| `REJECTED`/`EVIDENCE_CONFLICT` | The signed runtime events are inconsistent with each other. | Not fixable by editing the argument; the capture itself is bad. |
| `UNSUPPORTED_TRACE`/`MISSING_ACCESS_EVIDENCE` | No observed access (e.g. blocked case). | Nothing to prove; do not treat as safety. |
| `INCONCLUSIVE_NO_LEAN_BACKEND` / `INCONCLUSIVE_TOOLCHAIN_MISMATCH` | Lean missing or wrong version. | Install/point `--lean` at the pinned 4.34.1. |
| `INCONCLUSIVE_TIMEOUT` / `INCONCLUSIVE_RESOURCE_LIMIT` | Kernel ran out of time/heartbeats. | Not false — retry; keep proofs small. |
| `INCONCLUSIVE_CAPTURE` | The controlled run itself failed (timeout, output overflow). | Re-run the session; report if persistent. |

## 7. Two synthetic examples (no C involved)

`examples/manifest.json` + `examples/argument.json` prove a plain arithmetic
claim (`128 < 120 + 16`) from three synthetic observations. The transfer
example (`examples/transfer/`) proves a deadline overrun in unit `tick`
(`6 < 4 + 4`) with no memory semantics at all. Because their evidence is
authored, not captured, they get the weaker (honest) result:

```sh
python3 frontend.py examples/manifest.json examples/certificate.json \
  --out /tmp/arithmetic.lean --check --lean "$LEAN"
# -> KERNEL_VERIFIED_RELATIVE_TO_MANIFEST
```

"Relative to manifest": the proof is kernel-checked, but the observations are
trusted inputs, not authenticated facts.

## 8. Using your own reasoning traces

The controlled cases are the training wheels. The real workflow is the same
with your own agent or human analysis producing the session script — but note
the current boundary: the *evidence* side must still be one of the eight
fixture cases, because that reviewed, trusted fixture is the only thing the
runner will execute. What you bring is your own reasoning over that run.
Your trace must speak the protocol from Section 4; concretely:

1. **One run per fact source.** Every `observe` must cite an observation the
   runner delivered *earlier in the same session* (`X1/A1.…` ids from the run
   response). You cannot cite other sessions, other executions, or the
   future.
2. **Nodes in honest order.** The order of lines in your session file is the
   order of reasoning; the runner assigns log positions itself (never add a
   `seq` key — the line shape is fixed). References point backward; each
   node's conclusion is exactly what you assert — nothing is normalized or
   repaired for you.
3. **Nine logic rules only** (`infer`): and_intro, and_left, and_right,
   eq_symm, eq_trans, add_eq, sub_eq, lt_transport, le_transport. There is
   no implication and no "obviously". Arithmetic goes through `calculate` /
   `compare`, which the kernel re-checks.
4. **End at the frozen target.** Your last node must be exactly the frozen
   claim (`from` names it): `access ∧ (live ∧ (0 ≤ extent ∧ (0 < width ∧
   violation)))` with `violation` = `extent < offset+width` (upper) or
   `offset < 0` (lower). The runner freezes this at the `claim` line; you
   cannot change it afterward.
5. **Replays are new runs.** Re-running a case produces new identities and a
   new scope; you cannot retroactively attach old evidence to a new argument.


**Worked example: turning a free-text argument into session lines.** Suppose
your agent investigated the run and wrote, in prose:

> "The buffer was 6 bytes, we read 4 bytes starting at offset 4, so the read
> reached byte 8 — past the 6-byte end. The buffer was alive at the time, the
> width is positive, the extent is nonnegative, and the sanitizer did report
> the access. Hence out of bounds."

Convert each sentence, in the same order, keeping every number explicit (the
run line comes first; here `X1/A1.…` ids are abbreviated):

```jsonl
{"kind": "run", "case": "read_upper"}
{"kind": "reason", "argument_id": "C1", "node": {"id": "acc", "kind": "observe", "evidence": "X1/A1.access", "assert": ["atom", "access"]}}
{"kind": "reason", "argument_id": "C1", "node": {"id": "lv",  "kind": "observe", "evidence": "X1/A1.live",   "assert": ["atom", "live"]}}
{"kind": "reason", "argument_id": "C1", "node": {"id": "ex",  "kind": "observe", "evidence": "X1/A1.extent", "assert": ["eq", "extent", 6]}}
{"kind": "reason", "argument_id": "C1", "node": {"id": "wd",  "kind": "observe", "evidence": "X1/A1.width",  "assert": ["eq", "width", 4]}}
{"kind": "reason", "argument_id": "C1", "node": {"id": "of",  "kind": "observe", "evidence": "X1/A1.offset", "assert": ["eq", "offset", 4]}}
{"kind": "reason", "argument_id": "C1", "node": {"id": "end", "kind": "calculate", "operator": "add", "left": {"ref": "of"}, "right": {"ref": "wd"}, "result": 8}}
{"kind": "reason", "argument_id": "C1", "node": {"id": "vio", "kind": "compare", "relation": "lt", "left": {"ref": "ex"}, "right": {"ref": "end"}}}
{"kind": "reason", "argument_id": "C1", "node": {"id": "pw",  "kind": "compare", "relation": "lt", "left": 0, "right": {"ref": "wd"}}}
{"kind": "reason", "argument_id": "C1", "node": {"id": "ne",  "kind": "compare", "relation": "le", "left": 0, "right": {"ref": "ex"}}}
{"kind": "reason", "argument_id": "C1", "node": {"id": "inner", "kind": "conjoin", "premises": ["pw", "vio"]}}
{"kind": "reason", "argument_id": "C1", "node": {"id": "range", "kind": "conjoin", "premises": ["ne", "inner"]}}
{"kind": "reason", "argument_id": "C1", "node": {"id": "alive", "kind": "conjoin", "premises": ["lv", "range"]}}
{"kind": "reason", "argument_id": "C1", "node": {"id": "goal",  "kind": "conjoin", "premises": ["acc", "alive"]}}
{"kind": "claim", "argument_id": "C1", "event": "X1/A1", "access_kind": "read", "side": "upper", "from": "goal"}
```

Sanity checklist for the conversion: every prose number appears exactly once
as a literal; every "hence" became an explicit `calculate`/`compare`/`conjoin`
step; nothing was reordered to make a false step true (if the arithmetic
doesn't hold, the argument is simply rejected — rewrite the reasoning, not
the numbers).

## 9. What you can and cannot conclude

You *can* conclude: "in this signed recording, this specific access was
out-of-bounds, and this exact recorded argument proves it, machine-checked."

You *cannot* conclude: the program is safe or unsafe overall, the access is
exploitable, other accesses happened, or that any hidden reasoning (chain of
thought, unrecorded steps) was sound. Trust extends to the reviewed fixture,
compiler, sanitizer runtime, host, and the privacy of the runner key — not to
arbitrary programs.

Reference material: `LANGUAGE.md` (the certificate language),
`README.md` (commands and vocabulary), `DEVELOPMENT_PLAN.md` (research
context), `tests/` (what "correct" means, executable).
