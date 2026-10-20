# TraceProof language specification (soundtrace-v1)

## Research target

Construct explicit, observation-indexed arguments without a cybersecurity-specific
proof calculus. A search agent may propose typed reasoning; evidence admission,
certificate construction, and checking are deterministic and never invoke a model.
This scaffold handles argument preservation for a frozen claim. It does not
establish hidden-reasoning faithfulness or whole-program safety.

## Separation of responsibilities

1. **Runner / adapter:** owns the ordered request log, controlled executions,
   evidence availability positions, claim freezing, and domain meaning. Domain
   bindings live only in `oob_adapter.py`.
2. **Certificate language:** generic arithmetic/propositional deductions only.
   Units, scopes, identities, and authorities are carried, not interpreted.
3. **Constructor:** fixed template expansion of typed nodes; no search, no
   repair, no simplification.
4. **Lean backend:** checks the emitted conditional proof. Observational
   premises are authenticated hypotheses; Lean does not measure or authenticate
   the real environment.

Opaque names alone do not make a sound abstraction. The external binding
contract preserves reference identity, run/execution/allocation/event scope,
units, and claim strength. Scope strings carry the run nonce, execution ID,
allocation ID/generation, and access event ID (`<run_id>/X1/O1/g1/A1`); facts
are never joined across these identities.

## v1 syntax (implemented)

```
Sort        := Int | Prop
Term        := integer | declared_Int_symbol
             | ["add", Term, Term] | ["sub", Term, Term]
Formula     := ["atom", declared_Prop_symbol]
             | ["eq", Term, Term] | ["lt", Term, Term] | ["le", Term, Term]
             | ["and", Formula, Formula]
Step        := OBSERVE(evidence_id, admissible_observation)
             | COMPUTE(closed_arithmetic_Formula)
             | INFER(rule_id, prior_step_indices, Formula)
Certificate := profile + registry_id + frozen_claim_id + bundle_sha256
             + ordered_steps + source_map
```

The `imp` proposition and `modus_ponens` rule are removed profile-wide: with
the restricted observation contract and no assumption introduction, an
implication has no admissible origin. A manifest carries one opaque `unit`
required on every `Int` symbol; numeric literals inherit it. Manifest
`registry_id` is the SHA-256 of the canonical manifest with that field
omitted. Admissible observations are only a positive declared `Prop` atom or
`["eq", declared_Int_symbol, integer_literal]`; conflicting assignments to one
symbol in one scope are rejected and identical corroborating assignments are
permitted. Structural bounds: 1,000 expanded steps, depth 24, 1,000,000 bytes
per input and for generated output, integer magnitude 10^30, strict integer
types (booleans never qualify), exact key sets, and identifier/SHA-256 shape
rules. Generated-output budgets are enforced incrementally with bounded size
walkers that count shared substructure at every serialized occurrence and
abort before an oversized expansion is materialized.

## Typed reasoning entries (constructor input)

A recorded entry is `{"seq": n, "argument_id": ID, "node": {...}}` with the
runner-owned `seq`. Node kinds: `observe` (exact admitted formula, evidence
delivered strictly before the entry), `calculate` (`add`/`sub` with a
mandatory, never-repaired result), `compare` (`eq`/`lt`/`le` asserted true),
`conjoin` (right-associated conjunction of earlier nodes), and `infer`
(explicit use of one core rule with an exact conclusion). Operand references
must conclude an equality with a literal on its right. Every node maps to a
nonempty contiguous block of primitive steps recorded in `source_map`. A
certificate is support for the frozen claim in its recorded execution: not
exploitability, not safety, not hidden-reasoning faithfulness.

## Nine fixed inference schemas

| ID | Premises | Conclusion |
|---|---|---|
| and_intro | P; Q | P and Q |
| and_left | P and Q | P |
| and_right | P and Q | Q |
| eq_symm | a = b | b = a |
| eq_trans | a = b; b = c | a = c |
| add_eq | a = b; c = d | a + c = b + d |
| sub_eq | a = b; c = d | a − c = b − d |
| lt_transport | x = a; y = b; a < b | x < y |
| le_transport | x = a; y = b; a ≤ b | x ≤ y |

Only the supplied rule instance is checked. There is no search for an
alternative proof, no automatic correction of a bad argument, and no
free-form entailment fallback. Closed arithmetic checks become `by decide`
in generated Lean; the kernel must additionally report exactly one complete
empty axiom audit for `'certificate'`.

## Evidence contract

An observation record has an evidence ID, an admissible formula, a scope, an
available-at position (the runner response that delivered it), and an
authority label. A certificate may cite only existing records with exactly
matching formulas, permitted authority, the claim scope, availability no
later than the claim, and — in the constructor — delivery strictly before the
reasoning entry that cites it. For the OOB domain the adapter derives five
facts per matching observed access (`access`, `live`, `offset`, `width`,
`extent`) from signed raw events; a planned or blocked access yields no
access fact and no negative axiom. The exact frozen target is
`access ∧ (live ∧ (0 ≤ extent ∧ (0 < width ∧ violation)))` with
`extent < offset + width` (upper) or `offset < 0` (lower) for a positive-width
half-open access interval.

## Correctness claim

If the generated theorem passes the pinned, properly audited Lean backend,
the checker has authenticated the bundle with the external key, re-admitted
the selected claim from raw events, byte-matched the deterministic
reconstruction of the recorded argument, and obtained an argument from
authenticated hypotheses to the frozen formal target. Real-world soundness
additionally rests on the reviewed fixture, compiler, sanitizer runtime,
collector, host, and private-key boundary. No proof, backend timeout, or
missing evidence is a proof of falsehood.

## Not in this implementation

No search agent, arbitrary semantic entailment, automatic cybersecurity
ontology, unrestricted theorem proving, RL training, general program safety
proof, or claim to verify hidden chain of thought. Replaying an old trace is
a new run with a new scope; it cannot retroactively supply observations to
the original argument. Source/runtime schema variants not listed here are
unsupported until a separately reviewed adapter exists.
