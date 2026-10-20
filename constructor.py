#!/usr/bin/env python3
"""Deterministic constructor from typed reasoning entries to a certificate.

No inference search, no deduplication, no simplification, and no model calls:
each recorded node expands to a fixed contiguous block of primitive steps, in
source order, and every over-budget or malformed node is rejected at its own
source ID. The certificate is support for the frozen claim in its recorded
execution; it is not exploitability, whole-program safety, or hidden-reasoning
faithfulness.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from evidence import (
    LIMIT_BYTES,
    Rejected,
    canonical_json,
    load_json,
    mac_matches,
    require,
    sha256_hex,
)
from frontend import (
    LIMIT_STEPS,
    MAX_INT,
    PROFILE,
    RULE_LEAN,
    Rejected as FrontendRejected,
    admissible_observation,
    canonical_formula_size,
    check_hex64,
    check_id,
    closed_truth,
    compile_certificate,
    formula,
    is_index,
    render_formula,
    render_size,
    rule_head,
    validate_manifest,
)

REASON_BAD_INPUT = 'BAD_INPUT'
REASON_EVIDENCE_CONFLICT = 'EVIDENCE_CONFLICT'
REASON_CLAIM_MISMATCH = 'CLAIM_MISMATCH'
REASON_SOURCE_ALIGNMENT = 'SOURCE_ALIGNMENT_FAILED'
REASON_FALSE_ARITHMETIC = 'FALSE_ARITHMETIC'
REASON_INVALID_INFERENCE = 'INVALID_INFERENCE'
REASON_LIMIT_EXCEEDED = 'LIMIT_EXCEEDED'
REASON_MISSING_OBSERVATION = 'MISSING_OBSERVATION'
REASON_UNSUPPORTED_CONSTRUCT = 'UNSUPPORTED_CONSTRUCT'

NODE_KINDS = ('observe', 'calculate', 'compare', 'conjoin', 'infer')
RELATIONS = ('eq', 'lt', 'le')
OPERATORS = ('add', 'sub')


class ConstructionFailure(Exception):
    """Structured construction failure: status + stable reason + source node."""

    def __init__(self, status: str, reason: str, source_id: str | None = None,
                 step: int | None = None, diagnostic: str = ''):
        super().__init__(f'{status}/{reason}' + (f' at source node {source_id}' if source_id else '')
                         + (f': {diagnostic}' if diagnostic else ''))
        self.status = status
        self.reason = reason
        self.source_id = source_id
        self.step = step
        self.diagnostic = diagnostic or f'{status}/{reason}'

    def report(self) -> dict:
        out = {'status': self.status, 'reason': self.reason, 'diagnostic': self.diagnostic}
        if self.source_id is not None:
            out['source_id'] = self.source_id
        if self.step is not None:
            out['step'] = self.step
        return out


def _keys(node: dict, required: set, what: str, source_id: str) -> None:
    try:
        require(isinstance(node, dict), f'{what} must be an object')
        require(set(node) <= required | {'text'}, f'unexpected keys in {what}')
        require(required <= set(node), f'missing keys in {what}')
        require(isinstance(node.get('text', ''), str) and len(node.get('text', '')) <= 4000,
                'node text must be a bounded string')
    except Rejected as exc:
        raise ConstructionFailure('REJECTED', REASON_BAD_INPUT, source_id,
                                  diagnostic=str(exc)) from exc


class _Builder:
    """Accumulates primitive steps with incremental budgets and a source map."""

    def __init__(self, manifest: dict, target: dict):
        self.manifest = manifest
        self.symbols = manifest['symbols']
        self.records = manifest['records']
        self.target = target
        self.scope = target['scope']
        self.names = {name: f'v{i}' for i, name in enumerate(sorted(self.symbols))}
        self.used: dict[str, str] = {}
        self.steps: list[dict] = []
        self.facts: list[list] = []
        self.source_map: list[dict] = []
        self.node_fact: dict[str, list] = {}
        self.node_last: dict[str, int] = {}
        self.emitted_bytes = 0
        self.cert_bytes = 0

    def emit(self, source_id: str, step: dict, fact: list, rhs: str) -> int:
        if step.get('op') == 'observe':
            # The rendered hypothesis name is fixed by evidence first-use
            # order; compute it here so the byte budget sees the real rhs.
            if step['evidence'] not in self.used:
                self.used[step['evidence']] = f'h{len(self.used)}'
            rhs = self.used[step['evidence']]
        try:
            require(len(self.facts) + 1 <= LIMIT_STEPS, 'expanded step limit')
            # Bounded preflights run before full structural validation so that
            # measuring never materializes an oversized shared expansion.
            require(render_size(fact, self.names,
                                LIMIT_BYTES - self.emitted_bytes - 24 - len(rhs)),
                    'generated output byte limit')
            require(canonical_formula_size(fact, LIMIT_BYTES - self.cert_bytes - 256),
                    'generated output byte limit')
            formula(fact, self.symbols)
            index = len(self.steps)
            line = f'  have s{index} : {render_formula(fact, self.names)} := {rhs}'
            self.emitted_bytes += len(line.encode('utf-8'))
            self.cert_bytes += len(canonical_json(step))
            require(self.emitted_bytes <= LIMIT_BYTES and self.cert_bytes <= LIMIT_BYTES,
                    'generated output byte limit')
        except (Rejected, FrontendRejected, RecursionError) as exc:
            raise ConstructionFailure('REJECTED', REASON_LIMIT_EXCEEDED, source_id,
                                      step=len(self.steps), diagnostic=str(exc)) from exc
        if step['op'] == 'observe':
            if step['evidence'] not in self.used:
                self.used[step['evidence']] = f'h{len(self.used)}'
        self.steps.append(step)
        self.facts.append(fact)
        return index

    def operand(self, source_id: str, spec: Any) -> tuple[Any, int, int]:
        """Resolve an operand to (term, literal value, premise step index)."""
        if is_index(spec):
            try:
                require(abs(spec) <= MAX_INT, 'integer magnitude limit')
            except Rejected as exc:
                raise ConstructionFailure('REJECTED', REASON_BAD_INPUT, source_id,
                                          diagnostic=str(exc)) from exc
            index = self.emit(source_id, {'op': 'compute', 'formula': ['eq', spec, spec]},
                              ['eq', spec, spec], 'by decide')
            return spec, spec, index
        if not (isinstance(spec, dict) and set(spec) == {'ref'}):
            raise ConstructionFailure('REJECTED', REASON_BAD_INPUT, source_id,
                                      diagnostic='operand must be an integer literal or {"ref": node_id}')
        ref = spec['ref']
        if not (isinstance(ref, str) and ref in self.node_fact):
            raise ConstructionFailure('REJECTED', REASON_SOURCE_ALIGNMENT, source_id,
                                      diagnostic=f'operand reference {ref!r} is unknown, forward, self, or circular')
        fact = self.node_fact[ref]
        if not (isinstance(fact, list) and len(fact) == 3 and fact[0] == 'eq' and is_index(fact[2])):
            raise ConstructionFailure('REJECTED', REASON_SOURCE_ALIGNMENT, source_id,
                                      diagnostic='referenced node must conclude an equality with a literal on its right')
        return fact[1], fact[2], self.node_last[ref]

    def closed(self, source_id: str, prop: list) -> int:
        try:
            require(closed_truth(prop), 'arithmetic claim is false')
        except FrontendRejected as exc:
            raise ConstructionFailure('REJECTED', REASON_FALSE_ARITHMETIC, source_id,
                                      diagnostic=f'stated arithmetic {prop!r} is false') from exc
        return self.emit(source_id, {'op': 'compute', 'formula': prop}, prop, 'by decide')

    def infer(self, source_id: str, rule: str, premises: list[int], head: list) -> int:
        rhs = RULE_LEAN[rule] + ' ' + ' '.join(f's{j}' for j in premises)
        return self.emit(source_id, {'op': 'infer', 'rule': rule, 'premises': list(premises),
                                     'formula': head}, head, rhs)


def construct_certificate(manifest: dict, argument: list, *, bundle_sha256: str) -> dict:
    """Expand a recorded typed argument into its deterministic certificate."""
    # Unsuccessful frozen outcomes are decided before full manifest
    # validation: an unsupported or rejected claim carries no formula, scope,
    # symbols, or records to validate.
    peeked = manifest.get('claims') if isinstance(manifest, dict) else None
    if isinstance(peeked, dict) and len(peeked) == 1:
        peek_id, peek_target = next(iter(peeked.items()))
        if isinstance(peek_target, dict) and set(peek_target) == {'state', 'reason'}:
            if peek_target['state'] == 'unsupported':
                raise ConstructionFailure('UNSUPPORTED_TRACE', peek_target['reason'],
                                          diagnostic='frozen claim outcome is unsupported')
            raise ConstructionFailure('REJECTED', REASON_CLAIM_MISMATCH,
                                      diagnostic=f'frozen claim outcome rejected: '
                                                 f'{peek_target["reason"]}')
    try:
        validate_manifest(manifest)
    except FrontendRejected as exc:
        raise ConstructionFailure('REJECTED', REASON_BAD_INPUT, diagnostic=str(exc)) from exc
    try:
        check_hex64(bundle_sha256, 'bundle_sha256')
    except FrontendRejected as exc:
        raise ConstructionFailure('REJECTED', REASON_BAD_INPUT, diagnostic=str(exc)) from exc
    claims = manifest['claims']
    if len(claims) != 1:
        raise ConstructionFailure('REJECTED', REASON_CLAIM_MISMATCH,
                                  diagnostic='constructor manifest must contain exactly one claim')
    claim_id, target = next(iter(claims.items()))
    if 'state' in target:
        if target['state'] == 'unsupported':
            raise ConstructionFailure('UNSUPPORTED_TRACE', target['reason'],
                                      diagnostic='frozen claim outcome is unsupported')
        raise ConstructionFailure('REJECTED', REASON_CLAIM_MISMATCH,
                                  diagnostic=f'frozen claim outcome rejected: {target["reason"]}')
    try:
        require(isinstance(argument, list) and argument, 'argument must be a nonempty list')
        require(all(isinstance(entry, dict) for entry in argument),
                'every entry must be an object')
        require(all(set(entry) == {'seq', 'argument_id', 'node'} for entry in argument),
                'argument entries have exactly seq, argument_id, and node keys')
        seqs = [entry.get('seq') for entry in argument]
        require(all(is_index(s) and s >= 1 for s in seqs), 'every entry needs a positive integer seq')
        require(all(b > a for a, b in zip(seqs, seqs[1:])), 'entry seq values must strictly increase')
        if any(entry.get('argument_id') != claim_id for entry in argument):
            raise ConstructionFailure('REJECTED', REASON_CLAIM_MISMATCH,
                                      diagnostic='every argument entry must carry the selected claim/argument id')
        node_ids = [entry['node'].get('id') if isinstance(entry.get('node'), dict) else None
                    for entry in argument]
        require(all(isinstance(n, str) for n in node_ids), 'every node needs a string id')
        for node_id in node_ids:
            check_id(node_id, 'node id')
        require(len(set(node_ids)) == len(node_ids), 'node ids must be unique within an argument')
    except (Rejected, FrontendRejected, TypeError) as exc:
        raise ConstructionFailure('REJECTED', REASON_BAD_INPUT, diagnostic=str(exc)) from exc

    builder = _Builder(manifest, target)
    for entry in argument:
        node = entry['node']
        source_id = node['id']
        if not isinstance(node.get('kind'), str) or node['kind'] not in NODE_KINDS:
            raise ConstructionFailure('UNSUPPORTED_TRACE', REASON_UNSUPPORTED_CONSTRUCT, source_id,
                                      diagnostic=f'unsupported node kind {node.get("kind")!r}')
        kind = node['kind']
        try:
            if kind == 'observe':
                _expand_observe(builder, entry)
            elif kind == 'calculate':
                _expand_calculate(builder, entry)
            elif kind == 'compare':
                _expand_compare(builder, entry)
            elif kind == 'conjoin':
                _expand_conjoin(builder, entry)
            else:
                _expand_infer(builder, entry)
        except ConstructionFailure:
            raise
        except (Rejected, FrontendRejected, KeyError, TypeError, IndexError, RecursionError) as exc:
            raise ConstructionFailure('REJECTED', REASON_BAD_INPUT, source_id,
                                      diagnostic=str(exc)) from exc
        first = builder.source_map[-1]['last_step'] + 1 if builder.source_map else 0
        last = len(builder.steps) - 1
        if last < first:
            raise ConstructionFailure('REJECTED', REASON_BAD_INPUT, source_id,
                                      diagnostic='node produced no primitive steps')
        builder.source_map.append({'source_id': source_id, 'first_step': first, 'last_step': last})

    last_node_id = argument[-1]['node']['id']
    if target['from'] != last_node_id:
        raise ConstructionFailure('REJECTED', REASON_CLAIM_MISMATCH, last_node_id,
                                  diagnostic='claim from does not name the last argument node')
    if not builder.facts or builder.facts[-1] != target['formula']:
        raise ConstructionFailure('REJECTED', REASON_CLAIM_MISMATCH, last_node_id,
                                  diagnostic='last node does not establish the frozen claim')
    cert = {'profile': PROFILE, 'registry_id': manifest['registry_id'], 'claim_id': claim_id,
            'bundle_sha256': bundle_sha256, 'steps': builder.steps,
            'source_map': builder.source_map}
    try:
        require(len(canonical_json(cert)) + 1 <= LIMIT_BYTES,
                'serialized certificate byte limit')
    except (Rejected, FrontendRejected) as exc:
        raise ConstructionFailure('REJECTED', REASON_LIMIT_EXCEEDED, last_node_id,
                                  step=len(builder.steps) - 1,
                                  diagnostic=str(exc)) from exc
    # Same whole-source size check the frontend applies, so a constructed
    # certificate can never fail compile solely on its Lean-source budget.
    try:
        compile_certificate(manifest, cert)
    except FrontendRejected as exc:
        if 'byte limit' in str(exc):
            raise ConstructionFailure('REJECTED', REASON_LIMIT_EXCEEDED, last_node_id,
                                      step=len(builder.steps) - 1,
                                      diagnostic=str(exc)) from exc
    return cert


def _register(builder: _Builder, entry: dict, fact: list) -> None:
    builder.node_fact[entry['node']['id']] = fact
    builder.node_last[entry['node']['id']] = len(builder.steps) - 1


def _expand_observe(builder: _Builder, entry: dict) -> None:
    node = entry['node']
    source_id = node['id']
    _keys(node, {'id', 'kind', 'evidence', 'assert'}, 'observe node', source_id)
    evidence_id, asserted = node['evidence'], node['assert']
    try:
        check_id(evidence_id, 'evidence id')
        admissible_observation(asserted, builder.symbols)
    except FrontendRejected as exc:
        raise ConstructionFailure('REJECTED', REASON_BAD_INPUT, source_id,
                                  diagnostic=str(exc)) from exc
    if evidence_id not in builder.records:
        raise ConstructionFailure('UNSUPPORTED_TRACE', REASON_MISSING_OBSERVATION, source_id,
                                  diagnostic=f'no admitted observation {evidence_id!r}')
    record = builder.records[evidence_id]
    if record['scope'] != builder.scope:
        raise ConstructionFailure('REJECTED', REASON_EVIDENCE_CONFLICT, source_id,
                                  diagnostic='evidence scope mismatch')
    if record['authority'] not in builder.manifest['allowed_authorities']:
        raise ConstructionFailure('REJECTED', REASON_EVIDENCE_CONFLICT, source_id,
                                  diagnostic='unapproved evidence authority')
    if record['formula'] != asserted:
        raise ConstructionFailure('REJECTED', REASON_EVIDENCE_CONFLICT, source_id,
                                  diagnostic='assertion does not match admitted observation')
    if record['available_at'] >= entry['seq']:
        raise ConstructionFailure('REJECTED', REASON_SOURCE_ALIGNMENT, source_id,
                                  diagnostic='evidence delivered at or after this reasoning entry')
    index = builder.emit(source_id, {'op': 'observe', 'evidence': evidence_id,
                                     'formula': asserted}, asserted, '__observe__')
    _register(builder, entry, builder.facts[index])


def _expand_calculate(builder: _Builder, entry: dict) -> None:
    node = entry['node']
    source_id = node['id']
    _keys(node, {'id', 'kind', 'operator', 'left', 'right', 'result'}, 'calculate node', source_id)
    operator, result = node['operator'], node['result']
    if operator not in OPERATORS:
        raise ConstructionFailure('UNSUPPORTED_TRACE', REASON_UNSUPPORTED_CONSTRUCT, source_id,
                                  diagnostic=f'unsupported operator {operator!r}')
    if not is_index(result):
        raise ConstructionFailure('REJECTED', REASON_BAD_INPUT, source_id,
                                  diagnostic='calculate result must be an integer')
    tl, kl, il = builder.operand(source_id, node['left'])
    tr, kr, ir = builder.operand(source_id, node['right'])
    # Validate the supplied result against the resolved operands before any
    # arithmetic step is emitted; a wrong result is never repaired.
    try:
        require(closed_truth(['eq', [operator, kl, kr], result]),
                'arithmetic claim is false')
    except FrontendRejected as exc:
        raise ConstructionFailure('REJECTED', REASON_FALSE_ARITHMETIC, source_id,
                                  diagnostic=f'stated {kl} {operator} {kr} = {result} is false') from exc
    rule = 'add_eq' if operator == 'add' else 'sub_eq'
    joined = builder.infer(source_id, rule, [il, ir],
                           ['eq', [operator, tl, tr], [operator, kl, kr]])
    closed = builder.closed(source_id, ['eq', [operator, kl, kr], result])
    final = builder.infer(source_id, 'eq_trans', [joined, closed],
                          ['eq', [operator, tl, tr], result])
    _register(builder, entry, builder.facts[final])


def _expand_compare(builder: _Builder, entry: dict) -> None:
    node = entry['node']
    source_id = node['id']
    _keys(node, {'id', 'kind', 'relation', 'left', 'right'}, 'compare node', source_id)
    relation = node['relation']
    if relation not in RELATIONS:
        raise ConstructionFailure('UNSUPPORTED_TRACE', REASON_UNSUPPORTED_CONSTRUCT, source_id,
                                  diagnostic=f'unsupported relation {relation!r}')
    tl, kl, il = builder.operand(source_id, node['left'])
    tr, kr, ir = builder.operand(source_id, node['right'])
    if relation == 'eq':
        closed = builder.closed(source_id, ['eq', kl, kr])
        symm = builder.infer(source_id, 'eq_symm', [ir], ['eq', kr, tr])
        left = builder.infer(source_id, 'eq_trans', [il, closed], ['eq', tl, kr])
        final = builder.infer(source_id, 'eq_trans', [left, symm], ['eq', tl, tr])
    else:
        rule = 'lt_transport' if relation == 'lt' else 'le_transport'
        closed = builder.closed(source_id, [relation, kl, kr])
        final = builder.infer(source_id, rule, [il, ir, closed], [relation, tl, tr])
    _register(builder, entry, builder.facts[final])


def _expand_conjoin(builder: _Builder, entry: dict) -> None:
    node = entry['node']
    source_id = node['id']
    _keys(node, {'id', 'kind', 'premises'}, 'conjoin node', source_id)
    premises = node['premises']
    if not (isinstance(premises, list) and len(premises) >= 2
            and all(isinstance(p, str) for p in premises)):
        raise ConstructionFailure('REJECTED', REASON_BAD_INPUT, source_id,
                                  diagnostic='conjoin needs at least two premise node ids')
    for ref in premises:
        if ref not in builder.node_fact or ref == source_id:
            raise ConstructionFailure('REJECTED', REASON_SOURCE_ALIGNMENT, source_id,
                                      diagnostic=f'premise reference {ref!r} is unknown, forward, self, or circular')
    current_index = builder.node_last[premises[-1]]
    current_fact = builder.node_fact[premises[-1]]
    for ref in reversed(premises[:-1]):
        fact = builder.node_fact[ref]
        current_fact = ['and', fact, current_fact]
        current_index = builder.infer(source_id, 'and_intro',
                                      [builder.node_last[ref], current_index], current_fact)
    _register(builder, entry, builder.facts[current_index])


def _expand_infer(builder: _Builder, entry: dict) -> None:
    node = entry['node']
    source_id = node['id']
    _keys(node, {'id', 'kind', 'rule', 'premises', 'assert'}, 'infer node', source_id)
    rule, premises, asserted = node['rule'], node['premises'], node['assert']
    if not (isinstance(rule, str) and rule in RULE_LEAN):
        raise ConstructionFailure('REJECTED', REASON_INVALID_INFERENCE, source_id,
                                  diagnostic=f'unknown rule {rule!r}')
    if not (isinstance(premises, list) and premises
            and all(isinstance(p, str) for p in premises)):
        raise ConstructionFailure('REJECTED', REASON_BAD_INPUT, source_id,
                                  diagnostic='infer premises must be a nonempty list of node ids')
    for ref in premises:
        if ref not in builder.node_fact or ref == source_id:
            raise ConstructionFailure('REJECTED', REASON_SOURCE_ALIGNMENT, source_id,
                                      diagnostic=f'premise reference {ref!r} is unknown, forward, self, or circular')
    facts = [builder.node_fact[ref] for ref in premises]
    try:
        head = rule_head(rule, facts)
        require(head == asserted, 'rule conclusion does not match supplied conclusion')
    except FrontendRejected as exc:
        raise ConstructionFailure('REJECTED', REASON_INVALID_INFERENCE, source_id,
                                  diagnostic=str(exc)) from exc
    index = builder.infer(source_id, rule, [builder.node_last[ref] for ref in premises], asserted)
    _register(builder, entry, builder.facts[index])


def write_certificate(path: Path, cert: dict) -> None:
    path.write_bytes(canonical_json(cert) + b'\n')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('bundle', type=Path)
    parser.add_argument('--claim', required=True)
    parser.add_argument('--key', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    from runner import validate_bundle
    from oob_adapter import AdapterError, admit_oob
    try:
        bundle = load_json(args.bundle)
        validate_bundle(bundle)
        key = args.key.read_bytes()
        payload = bundle['payload']
        if not mac_matches(key, canonical_json(payload), bundle['hmac_sha256']):
            print(json.dumps({'status': 'REJECTED', 'reason': 'AUTHENTICATION_FAILED',
                              'diagnostic': 'bundle MAC verification failed'}, indent=2))
            return 1
        manifest, argument = admit_oob(payload, args.claim)
        cert = construct_certificate(manifest, argument,
                                     bundle_sha256=sha256_hex(canonical_json(payload)))
        write_certificate(args.out, cert)
        print(json.dumps({'status': 'CONSTRUCTED', 'claim_id': args.claim,
                          'steps': len(cert['steps']),
                          'source_nodes': len(cert['source_map']),
                          'certificate': str(args.out)}, indent=2))
        return 0
    except ConstructionFailure as failure:
        print(json.dumps(failure.report(), indent=2))
        return 1 if failure.status == 'REJECTED' else 2
    except AdapterError as exc:
        print(json.dumps({'status': exc.status, 'reason': exc.reason,
                          'diagnostic': exc.diagnostic}, indent=2))
        return 1 if exc.status == 'REJECTED' else 2
    except (Rejected, FrontendRejected, KeyError, ValueError, TypeError, IndexError, OSError) as exc:
        print(json.dumps({'status': 'REJECTED', 'reason': REASON_BAD_INPUT,
                          'diagnostic': str(exc)}, indent=2))
        return 1


if __name__ == '__main__':
    sys.exit(main())
