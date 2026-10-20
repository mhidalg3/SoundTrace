#!/usr/bin/env python3
"""Restricted certificate-to-Lean frontend. No model calls and no arbitrary code input.

The manifest is a trusted INPUT for this compiler. `compile_certificate`
recomputes the registry digest and enforces the soundtrace-v1 structural
contract, but cannot authenticate observations environmentally; a passing
preflight is NOT a Lean-verified certificate. Use --check for the kernel
backend, which additionally requires an exact empty axiom audit. Only
`checker.py` may report observation-backed verification.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from evidence import (
    LIMIT_BYTES,
    Rejected,
    load_json,
    registry_digest,
    require,
)

LIMIT_STEPS = 1000
LIMIT_DEPTH = 24
MAX_INT = 10**30
PROFILE = 'soundtrace-v1'
LEAN_VERSION = '4.34.1'
AUDIT_LINE = "'certificate' does not depend on any axioms"
RESOURCE_LIMIT_MARKERS = (
    'maximum number of heartbeats',
    'maximum recursion depth has been reached',
)

ID_RE = re.compile(r'[A-Za-z][A-Za-z0-9_.:/-]{0,127}')
HEX64_RE = re.compile(r'[0-9a-f]{64}')


def is_index(value: Any) -> bool:
    """Strict integer test: booleans are never integer/index values."""
    return type(value) is int


def check_id(value: Any, what: str) -> str:
    require(isinstance(value, str) and ID_RE.fullmatch(value), f'invalid {what}')
    return value


def check_hex64(value: Any, what: str) -> str:
    require(isinstance(value, str) and HEX64_RE.fullmatch(value), f'invalid {what}')
    return value


def term(t: Any, symbols: dict[str, Any], depth: int = 0) -> None:
    require(depth <= LIMIT_DEPTH, 'term depth limit')
    if is_index(t):
        require(abs(t) <= MAX_INT, 'integer magnitude limit')
    elif isinstance(t, str):
        require(t in symbols and symbols[t]['sort'] == 'Int', 'undeclared integer symbol')
    else:
        require(isinstance(t, list) and len(t) == 3 and t[0] in ('add', 'sub'), 'invalid term')
        term(t[1], symbols, depth + 1)
        term(t[2], symbols, depth + 1)


def formula(p: Any, symbols: dict[str, Any], depth: int = 0) -> None:
    require(depth <= LIMIT_DEPTH, 'formula depth limit')
    require(isinstance(p, list) and p, 'invalid proposition')
    if p[0] == 'atom':
        require(len(p) == 2 and p[1] in symbols and symbols[p[1]]['sort'] == 'Prop', 'undeclared proposition')
    elif p[0] in ('eq', 'lt', 'le'):
        require(len(p) == 3, 'invalid relation arity')
        term(p[1], symbols, depth + 1)
        term(p[2], symbols, depth + 1)
    else:
        require(p[0] == 'and' and len(p) == 3, 'unsupported proposition')
        formula(p[1], symbols, depth + 1)
        formula(p[2], symbols, depth + 1)


def admissible_observation(p: Any, symbols: dict[str, Any]) -> None:
    """Observations are only positive Prop atoms or symbol=literal equalities."""
    if isinstance(p, list) and len(p) == 2 and p[0] == 'atom':
        require(p[1] in symbols and symbols[p[1]]['sort'] == 'Prop', 'undeclared proposition')
        return
    require(isinstance(p, list) and len(p) == 3 and p[0] == 'eq', 'inadmissible observation formula')
    require(isinstance(p[1], str) and p[1] in symbols and symbols[p[1]]['sort'] == 'Int',
            'observation equality must bind a declared Int symbol')
    require(is_index(p[2]) and abs(p[2]) <= MAX_INT, 'observation literal out of range')


def closed_term(t: Any) -> int:
    if is_index(t):
        require(abs(t) <= MAX_INT, 'integer magnitude limit')
        return t
    require(isinstance(t, list) and len(t) == 3 and t[0] in ('add', 'sub'), 'invalid closed term')
    a, b = closed_term(t[1]), closed_term(t[2])
    value = a + b if t[0] == 'add' else a - b
    require(abs(value) <= MAX_INT, 'computed integer magnitude limit')
    return value


def closed_truth(p: list) -> bool:
    require(p[0] in ('eq', 'lt', 'le'), 'COMPUTE only supports closed arithmetic comparisons')
    a, b = closed_term(p[1]), closed_term(p[2])
    return {'eq': a == b, 'lt': a < b, 'le': a <= b}[p[0]]

RULE_LEAN = {
    'and_intro': 'And.intro', 'and_left': 'And.left', 'and_right': 'And.right',
    'eq_symm': 'Eq.symm', 'eq_trans': 'Eq.trans',
    'add_eq': 'TraceProof.addEq', 'sub_eq': 'TraceProof.subEq',
    'lt_transport': 'TraceProof.ltTransport', 'le_transport': 'TraceProof.leTransport',
}


def rule_head(rule: str, p: list[list]) -> list:
    require(rule in RULE_LEAN, 'unknown rule')
    arities = {'and_intro': 2, 'and_left': 1, 'and_right': 1,
               'eq_symm': 1, 'eq_trans': 2,
               'add_eq': 2, 'sub_eq': 2, 'lt_transport': 3, 'le_transport': 3}
    require(isinstance(p, list) and len(p) == arities[rule], 'wrong number of premises')
    if rule == 'and_intro':
        return ['and', p[0], p[1]]
    if rule in ('and_left', 'and_right'):
        require(p[0][0] == 'and', 'conjunction required')
        return p[0][1 if rule == 'and_left' else 2]
    if rule == 'eq_symm':
        require(p[0][0] == 'eq', 'equality required')
        return ['eq', p[0][2], p[0][1]]
    if rule == 'eq_trans':
        require(p[0][0] == p[1][0] == 'eq' and p[0][2] == p[1][1], 'equality middle term mismatch')
        return ['eq', p[0][1], p[1][2]]
    if rule in ('add_eq', 'sub_eq'):
        op = 'add' if rule == 'add_eq' else 'sub'
        require(p[0][0] == p[1][0] == 'eq', 'equalities required')
        return ['eq', [op, p[0][1], p[1][1]], [op, p[0][2], p[1][2]]]
    if rule == 'lt_transport':
        require(p[0][0] == p[1][0] == 'eq' and p[2][0] == 'lt',
                'two equalities and a strict order required')
        require(p[2][1:] == [p[0][2], p[1][2]], 'order transport value mismatch')
        return ['lt', p[0][1], p[1][1]]
    require(rule == 'le_transport' and p[0][0] == p[1][0] == 'eq' and p[2][0] == 'le',
            'two equalities and a non-strict order required')
    require(p[2][1:] == [p[0][2], p[1][2]], 'order transport value mismatch')
    return ['le', p[0][1], p[1][1]]


CORE = '''import Std
namespace TraceProof
 theorem addEq {a b c d : Int} (h1 : a = b) (h2 : c = d) :
     a + c = b + d := by
   cases h1
   cases h2
   rfl
 theorem subEq {a b c d : Int} (h1 : a = b) (h2 : c = d) :
     a - c = b - d := by
   cases h1
   cases h2
   rfl
 theorem ltTransport {x a y b : Int} (hx : x = a) (hy : y = b)
     (h : a < b) : x < y := by
   cases hx
   cases hy
   exact h
 theorem leTransport {x a y b : Int} (hx : x = a) (hy : y = b)
     (h : a ≤ b) : x ≤ y := by
   cases hx
   cases hy
   exact h
end TraceProof
set_option maxHeartbeats 50000
set_option maxRecDepth 512
'''


def render_term(t: Any, names: dict[str, str]) -> str:
    if is_index(t):
        return f'({t} : Int)'
    if isinstance(t, str):
        return names[t]
    return f'({render_term(t[1], names)} {"+" if t[0] == "add" else "-"} {render_term(t[2], names)})'


def render_formula(p: list, names: dict[str, str]) -> str:
    if p[0] == 'atom':
        return names[p[1]]
    if p[0] == 'and':
        return f'({render_formula(p[1], names)} ∧ {render_formula(p[2], names)})'
    return f'({render_term(p[1], names)} { {"eq": "=", "lt": "<", "le": "≤"}[p[0]] } {render_term(p[2], names)})'


class _SizeOverflow(Exception):
    """Internal: a bounded size walk exceeded its remaining budget."""


def _utf8(text: str) -> int:
    return len(text.encode('utf-8'))


def _walk_render_formula(p: list, names: dict[str, str], budget: list[int]) -> None:
    # Exact UTF-8 byte costs mirroring render_formula; shared Python
    # substructure is counted at every serialized occurrence.
    if p[0] == 'atom':
        budget[0] -= _utf8(names[p[1]])
    elif p[0] == 'and':
        budget[0] -= 7  # '(' + ' ∧ ' + ')' with the conjunction operator in UTF-8
        _walk_render_formula(p[1], names, budget)
        _walk_render_formula(p[2], names, budget)
    else:
        budget[0] -= 7 if p[0] == 'le' else 5  # '(' + ' ≤ '/' = '/' < ' + ')'
        _walk_render_term(p[1], names, budget)
        _walk_render_term(p[2], names, budget)
    if budget[0] < 0:
        raise _SizeOverflow


def _walk_render_term(t: Any, names: dict[str, str], budget: list[int]) -> None:
    if is_index(t):
        budget[0] -= len(str(t)) + 8  # '(' + literal + ' : Int)'
    elif isinstance(t, str):
        budget[0] -= _utf8(names[t])
    else:
        budget[0] -= 5  # '(' + ' + '/' - ' + ')'
        _walk_render_term(t[1], names, budget)
        _walk_render_term(t[2], names, budget)
    if budget[0] < 0:
        raise _SizeOverflow


def render_size(prop: list, names: dict[str, str], budget: int) -> bool:
    """True iff the UTF-8 size of render_formula(prop, names) stays within budget.

    Aborts as soon as the running count exceeds the budget, so measuring an
    oversized expansion never materializes it.
    """
    remaining = [budget]
    try:
        _walk_render_formula(prop, names, remaining)
    except _SizeOverflow:
        return False
    return remaining[0] >= 0


def canonical_formula_size(prop: list, budget: int) -> bool:
    """True iff the canonical JSON size of prop stays within budget; aborts early.

    Canonical JSON is pure ASCII by contract (ensure_ascii=True), so character
    and byte counts coincide.
    """
    remaining = [budget]

    def walk_formula(p: list) -> None:
        head = p[0]
        if head == 'atom':
            remaining[0] -= 11 + len(p[1])  # '["atom",' + quoted symbol + ']'
        elif head == 'and':
            remaining[0] -= 8  # '["and",' + ']'; the operand comma is charged below
            walk_formula(p[1])
            remaining[0] -= 1
            walk_formula(p[2])
        else:
            remaining[0] -= 7  # '["eq",' + ']'; the operand comma is charged below
            walk_term(p[1])
            remaining[0] -= 1
            walk_term(p[2])
        if remaining[0] < 0:
            raise _SizeOverflow

    def walk_term(t: Any) -> None:
        if is_index(t):
            remaining[0] -= len(str(t))  # str() already includes any '-'
        elif isinstance(t, str):
            remaining[0] -= len(t) + 2
        else:
            remaining[0] -= 8
            walk_term(t[1])
            remaining[0] -= 1
            walk_term(t[2])
        if remaining[0] < 0:
            raise _SizeOverflow

    try:
        walk_formula(prop)
    except _SizeOverflow:
        return False
    return remaining[0] >= 0

def _check_keys(obj: Any, required: set, optional: set, what: str) -> None:
    require(isinstance(obj, dict), f'{what} must be an object')
    require(set(obj) <= required | optional, f'unexpected keys in {what}')
    require(required <= set(obj), f'missing keys in {what}')


def validate_manifest(manifest: Any) -> None:
    """Structural contract for every soundtrace-v1 manifest, trusted or admitted."""
    _check_keys(manifest, {'profile', 'registry_id', 'unit', 'symbols', 'records',
                           'claims', 'allowed_authorities'}, set(), 'manifest')
    require(manifest['profile'] == PROFILE, 'profile mismatch')
    check_hex64(manifest['registry_id'], 'registry_id')
    unit = manifest['unit']
    require(isinstance(unit, str) and 1 <= len(unit) <= 128 and unit.isprintable(),
            'invalid manifest unit')
    authorities = manifest['allowed_authorities']
    require(isinstance(authorities, list) and authorities, 'allowed_authorities must be a nonempty list')
    for authority in authorities:
        check_id(authority, 'authority')
    require(len(set(authorities)) == len(authorities), 'duplicate authority')
    symbols = manifest['symbols']
    require(isinstance(symbols, dict) and symbols, 'symbols must be a nonempty object')
    for name, entry in symbols.items():
        check_id(name, 'symbol name')
        require(isinstance(entry, dict) and entry.get('sort') in ('Int', 'Prop'), 'invalid symbol sort')
        if entry['sort'] == 'Int':
            _check_keys(entry, {'sort', 'scope', 'unit'}, set(), 'Int symbol')
            require(entry['unit'] == unit, 'symbol unit mismatch')
        else:
            _check_keys(entry, {'sort', 'scope'}, set(), 'Prop symbol')
        check_id(entry['scope'], 'symbol scope')
    records = manifest['records']
    require(isinstance(records, dict), 'records must be an object')
    assignments: dict[tuple[str, str], int] = {}
    for evidence_id, entry in records.items():
        check_id(evidence_id, 'evidence id')
        _check_keys(entry, {'formula', 'scope', 'available_at', 'authority'},
                    {'source_span'}, 'record entry')
        check_id(entry['scope'], 'record scope')
        require(is_index(entry['available_at']) and entry['available_at'] >= 1,
                'available_at must be a positive integer')
        check_id(entry['authority'], 'record authority')
        require(isinstance(entry.get('source_span', ''), str), 'source_span must be a string')
        admissible_observation(entry['formula'], symbols)
        if entry['formula'][0] == 'eq':
            key = (entry['scope'], entry['formula'][1])
            if key in assignments and assignments[key] != entry['formula'][2]:
                raise Rejected('conflicting assignments to the same symbol in one scope')
            assignments[key] = entry['formula'][2]
    claims = manifest['claims']
    require(isinstance(claims, dict) and claims, 'claims must be a nonempty object')
    for claim_id, entry in claims.items():
        check_id(claim_id, 'claim id')
        if 'state' in entry:
            _check_keys(entry, {'state', 'reason'}, set(), 'frozen claim outcome')
            require(entry['state'] in ('unsupported', 'rejected'), 'invalid frozen claim state')
            require(isinstance(entry['reason'], str) and entry['reason'], 'frozen reason must be a string')
            continue
        _check_keys(entry, {'scope', 'available_at', 'formula', 'from'}, {'source_span'}, 'claim entry')
        check_id(entry['scope'], 'claim scope')
        require(is_index(entry['available_at']) and entry['available_at'] >= 1,
                'claim available_at must be a positive integer')
        formula(entry['formula'], symbols)
        check_id(entry['from'], 'claim from')
        require(isinstance(entry.get('source_span', ''), str), 'source_span must be a string')
    require(registry_digest(manifest) == manifest['registry_id'], 'registry digest mismatch')


def validate_step(s: Any, symbols: dict[str, Any], index: int) -> None:
    require(isinstance(s, dict), f'step {index} must be an object')
    op = s.get('op')
    if op == 'observe':
        _check_keys(s, {'op', 'evidence', 'formula'}, set(), f'step {index}')
        check_id(s['evidence'], 'evidence id')
        admissible_observation(s['formula'], symbols)
    elif op == 'compute':
        _check_keys(s, {'op', 'formula'}, set(), f'step {index}')
        formula(s['formula'], symbols)
    elif op == 'infer':
        _check_keys(s, {'op', 'rule', 'premises', 'formula'}, set(), f'step {index}')
        require(isinstance(s['rule'], str) and s['rule'] in RULE_LEAN, 'unknown rule')
        refs = s['premises']
        require(isinstance(refs, list) and all(is_index(j) and 0 <= j < index for j in refs),
                'invalid or forward reference')
        formula(s['formula'], symbols)
    else:
        raise Rejected(f'step {index}: unsupported operation')


def validate_certificate(cert: Any, manifest: dict) -> None:
    _check_keys(cert, {'profile', 'registry_id', 'claim_id', 'bundle_sha256', 'steps',
                      'source_map'}, set(), 'certificate')
    require(cert['profile'] == PROFILE, 'profile mismatch')
    check_hex64(cert['registry_id'], 'certificate registry_id')
    check_id(cert['claim_id'], 'claim id')
    check_hex64(cert['bundle_sha256'], 'bundle_sha256')
    steps = cert['steps']
    require(isinstance(steps, list) and 0 < len(steps) <= LIMIT_STEPS, 'invalid certificate length')
    symbols = manifest['symbols']
    for i, s in enumerate(steps):
        validate_step(s, symbols, i)
    source_map = cert['source_map']
    require(isinstance(source_map, list) and source_map, 'source_map must be a nonempty list')
    seen_ids: set[str] = set()
    next_step = 0
    for entry in source_map:
        _check_keys(entry, {'source_id', 'first_step', 'last_step'}, set(), 'source_map entry')
        check_id(entry['source_id'], 'source id')
        require(entry['source_id'] not in seen_ids, 'duplicate source id in source_map')
        seen_ids.add(entry['source_id'])
        require(is_index(entry['first_step']) and is_index(entry['last_step']),
                'source_map indices must be integers')
        require(entry['first_step'] == next_step and entry['last_step'] >= entry['first_step'],
                'source_map must cover every step exactly once in order')
        next_step = entry['last_step'] + 1
    require(next_step == len(steps), 'source_map must cover every step exactly once in order')


def compile_certificate(manifest: dict, cert: dict) -> tuple[str, dict]:
    validate_manifest(manifest)
    validate_certificate(cert, manifest)
    require(cert['registry_id'] == manifest['registry_id'], 'registry mismatch')
    require(cert['claim_id'] in manifest['claims'], 'unknown frozen claim')
    target = manifest['claims'][cert['claim_id']]
    require('formula' in target, 'selected claim has no frozen formula')
    require(cert['source_map'][-1]['source_id'] == target['from'],
            'final source-map entry does not match the claim from')
    symbols, records = manifest['symbols'], manifest['records']
    scope = target['scope']
    require(all(s['scope'] == scope for s in symbols.values()), 'symbol sort/scope mismatch')
    names = {name: f'v{i}' for i, name in enumerate(sorted(symbols))}
    steps = cert['steps']
    facts: list[list] = []
    emitted: list[str] = []
    used: dict[str, str] = {}
    emitted_bytes = 0
    for i, s in enumerate(steps):
        try:
            require(len(facts) + 1 <= LIMIT_STEPS, 'expanded step limit')
            if s['op'] == 'observe':
                require(s['evidence'] in records, 'unknown evidence')
                r = records[s['evidence']]
                require(r['scope'] == scope, 'evidence scope mismatch')
                require(r['available_at'] <= target['available_at'], 'evidence occurs after claim')
                require(r['authority'] in manifest['allowed_authorities'], 'unapproved evidence authority')
                require(r['formula'] == s['formula'], 'evidence-to-proposition mismatch')
                if s['evidence'] not in used:
                    used[s['evidence']] = f'h{len(used)}'
                rhs = used[s['evidence']]
            elif s['op'] == 'compute':
                require(closed_truth(s['formula']), 'arithmetic claim is false')
                rhs = 'by decide'
            else:
                refs = s['premises']
                head = rule_head(s['rule'], [facts[j] for j in refs])
                require(head == s['formula'], 'rule conclusion does not match supplied conclusion')
                rhs = RULE_LEAN[s['rule']] + ' ' + ' '.join(f's{j}' for j in refs)
            require(render_size(s['formula'], names,
                                LIMIT_BYTES - emitted_bytes - 24 - len(rhs)),
                    'generated output byte limit')
            line = f'  have s{i} : {render_formula(s["formula"], names)} := {rhs}'
            emitted_bytes += len(line.encode('utf-8'))
            require(emitted_bytes <= LIMIT_BYTES, 'generated output byte limit')
            emitted.append(line)
            facts.append(s['formula'])
        except (Rejected, KeyError, TypeError, IndexError) as e:
            raise Rejected(f'step {i}: {e}') from e
    require(facts[-1] == target['formula'], 'last step does not establish the frozen claim')
    params = [f'({names[k]} : {v["sort"]})' for k, v in sorted(symbols.items())]
    params += [f'({h} : {render_formula(records[k]["formula"], names)})' for k, h in used.items()]
    code = CORE + '\ntheorem certificate\n    ' + '\n    '.join(params)
    code += f' : {render_formula(target["formula"], names)} := by\n'
    code += '\n'.join(emitted) + f'\n  exact s{len(facts)-1}\n\n#print axioms certificate\n'
    require(len(code.encode('utf-8')) <= LIMIT_BYTES, 'generated output byte limit')
    return code, {'status': 'PREFLIGHT_PASS_NOT_KERNEL_VERIFIED', 'steps': len(steps),
                  'evidence_used': list(used), 'scope': scope,
                  'limits': 'No semantic natural-language alignment or source authentication is performed.'}


def check_lean(code: str, lean: str, timeout: float = 10.0) -> dict:
    """Run the pinned Lean kernel on generated source; require a complete audit.

    Acceptance requires: exact toolchain version, exit 0, no sorryAx, no Lean
    errors, and exactly one complete empty-dependency axiom audit line.
    """
    executable = shutil.which(lean) if isinstance(lean, str) and lean else None
    if executable is None:
        return {'status': 'INCONCLUSIVE_NO_LEAN_BACKEND'}
    try:
        version_proc = subprocess.run([executable, '--version'], capture_output=True,
                                      text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return {'status': 'INCONCLUSIVE_TIMEOUT', 'stage': 'version check'}
    except OSError as exc:
        return {'status': 'INCONCLUSIVE_NO_LEAN_BACKEND', 'diagnostic': str(exc)}
    version_out = version_proc.stdout + version_proc.stderr
    if version_proc.returncode or not re.search(rf'version {re.escape(LEAN_VERSION)}\b', version_out):
        return {'status': 'INCONCLUSIVE_TOOLCHAIN_MISMATCH',
                'diagnostic': version_out[:500],
                'expected_version': LEAN_VERSION}
    env = {k: v for k, v in os.environ.items() if k not in ('LEAN_PATH', 'LEAN_SRC_PATH')}
    with tempfile.TemporaryDirectory(prefix='soundtrace-') as temp:
        path = Path(temp) / 'Certificate.lean'
        path.write_text(code, encoding='utf-8')
        try:
            proc = subprocess.run([executable, str(path)], capture_output=True, text=True,
                                  encoding='utf-8', errors='replace',
                                  timeout=timeout, check=False, env=env, cwd=temp)
        except subprocess.TimeoutExpired:
            return {'status': 'INCONCLUSIVE_TIMEOUT', 'backend_version': LEAN_VERSION}
        output = proc.stdout + proc.stderr
    result: dict[str, Any] = {'backend_version': LEAN_VERSION}
    if any(marker in output for marker in RESOURCE_LIMIT_MARKERS):
        return {**result, 'status': 'INCONCLUSIVE_RESOURCE_LIMIT', 'diagnostic': output[:8000]}
    audit_lines = [line.strip() for line in output.splitlines()]
    complete = sum(line == AUDIT_LINE for line in audit_lines)
    nonempty = any('depends on axioms' in line and line != AUDIT_LINE for line in audit_lines)
    if (proc.returncode or 'sorryAx' in output or ': error:' in output
            or complete != 1 or nonempty):
        return {**result, 'status': 'REJECTED', 'reason': 'KERNEL_REJECT',
                'diagnostic': output[:8000],
                'axiom_audit': 'complete' if complete == 1 else 'missing_or_incomplete'}
    # Source is generated solely from a whitelist; no user-provided Lean code is evaluated.
    return {'status': 'KERNEL_VERIFIED_RELATIVE_TO_MANIFEST', 'backend_version': LEAN_VERSION,
            'axiom_audit': output[:8000]}


def load(path: Path) -> dict:
    return load_json(path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest', type=Path)
    parser.add_argument('certificate', type=Path)
    parser.add_argument('--out', type=Path, default=Path('Certificate.lean'))
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--lean', default='lean')
    args = parser.parse_args()
    try:
        code, result = compile_certificate(load(args.manifest), load(args.certificate))
        args.out.write_text(code, encoding='utf-8')
        result['generated_lean'] = str(args.out)
        if args.check:
            result = {**result, **check_lean(code, args.lean)}
        print(json.dumps(result, indent=2))
        status = result['status']
        if status in ('PREFLIGHT_PASS_NOT_KERNEL_VERIFIED', 'KERNEL_VERIFIED_RELATIVE_TO_MANIFEST'):
            return 0
        if status == 'REJECTED':
            return 1
        return 2
    except (Rejected, KeyError, ValueError, TypeError, IndexError, OSError) as e:
        print(json.dumps({'status': 'REJECTED', 'reason': 'BAD_INPUT', 'diagnostic': str(e)}, indent=2))
        return 1


if __name__ == '__main__':
    sys.exit(main())
