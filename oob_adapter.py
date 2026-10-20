"""Memory-domain adapter: controlled C/ASan executions to generic evidence.

This is the only place domain meaning enters the pipeline. It derives the five
admissible facts per access from raw signed runtime events, freezes claim
outcomes, and never turns a planned access, sanitizer prose, or an unreviewed
program's pointer arithmetic into a proof premise. The synthetic `fixture`
authority is deliberately not authorized here.
"""
from __future__ import annotations

import re
from typing import Any

from evidence import Rejected, registry_digest, require
from frontend import ID_RE, PROFILE, is_index

AUTHORITY = 'controlled-c-asan-v1'
CANONICAL_ASAN_OPTIONS = 'halt_on_error=1:abort_on_error=0:exitcode=1:detect_leaks=0:symbolize=0'
REQUIRED_DESCRIPTION = 'heap-buffer-overflow'
MAX_STDERR_CHARS = 20000

SYMBOLS = [
    ('access', 'Prop'), ('live', 'Prop'),
    ('extent', 'Int'), ('width', 'Int'), ('offset', 'Int'),
]


class AdapterError(Exception):
    """Inconsistent or non-admissible runtime facts."""

    def __init__(self, reason: str, diagnostic: str = '', status: str = 'REJECTED'):
        super().__init__(f'{status}/{reason}: {diagnostic}' if diagnostic else f'{status}/{reason}')
        self.reason = reason
        self.diagnostic = diagnostic or reason
        self.status = status


def _conflict(diagnostic: str) -> AdapterError:
    return AdapterError('EVIDENCE_CONFLICT', diagnostic)


def _is_int(value: Any) -> bool:
    return is_index(value)


def _exact_keys(obj: Any, keys: set, what: str) -> None:
    require(isinstance(obj, dict), f'{what} must be an object')
    require(set(obj) == keys, f'{what} has unexpected or missing keys')


def validate_events(events: Any) -> list[dict]:
    """Structural validation of one execution's raw event records."""
    require(isinstance(events, list) and events, 'events must be a nonempty list')
    kinds = ('alloc', 'attempt', 'asan', 'complete', 'blocked', 'free')
    for i, event in enumerate(events):
        require(isinstance(event, dict), 'event must be an object')
        require(_is_int(event.get('index')) and event['index'] == i + 1,
                'event indices must be consecutive from 1')
        kind = event.get('kind')
        require(kind in kinds, 'unknown event kind')
        if kind == 'alloc':
            _exact_keys(event, {'index', 'kind', 'object_id', 'generation', 'base',
                                'extent', 'pointer_bits', 'locator_category',
                                'locator_base', 'locator_extent'}, 'alloc event')
            require(event['object_id'] == 'O1' and event['generation'] == 1,
                    'allocation identity must be O1 generation 1')
            require(all(_is_int(event[f]) for f in
                        ('base', 'extent', 'pointer_bits', 'locator_base', 'locator_extent')),
                    'alloc numeric fields must be integers')
            require(event['locator_category'] == 'heap', 'locator category must be heap')
            require(event['locator_base'] == event['base'], 'locator base mismatch')
            require(event['locator_extent'] == event['extent'], 'locator extent mismatch')
            require(event['extent'] >= 0, 'extent must be nonnegative')
            require(event['pointer_bits'] in (32, 64), 'unsupported pointer width')
        elif kind == 'attempt':
            _exact_keys(event, {'index', 'kind', 'event_id', 'object_id', 'generation',
                                'address', 'width', 'access_kind'}, 'attempt event')
            require(event['event_id'] == 'A1' and event['object_id'] == 'O1'
                    and event['generation'] == 1, 'attempt identity mismatch')
            require(_is_int(event['address']) and _is_int(event['width']),
                    'attempt numeric fields must be integers')
            require(event['access_kind'] in ('read', 'write'), 'invalid access kind')
        elif kind == 'asan':
            _exact_keys(event, {'index', 'kind', 'event_id', 'address', 'access_kind',
                                'width', 'description', 'pc'}, 'asan event')
            require(event['event_id'] == 'A1', 'asan identity mismatch')
            require(_is_int(event['address']) and _is_int(event['width'])
                    and _is_int(event['pc']), 'asan numeric fields must be integers')
            require(event['access_kind'] in ('read', 'write'), 'invalid access kind')
            require(isinstance(event['description'], str), 'description must be a string')
        elif kind == 'complete':
            _exact_keys(event, {'index', 'kind', 'event_id'}, 'complete event')
            require(event['event_id'] == 'A1', 'complete identity mismatch')
        elif kind == 'blocked':
            _exact_keys(event, {'index', 'kind', 'event_id', 'object_id', 'generation',
                                'access_kind'}, 'blocked event')
            require(event['event_id'] == 'A1' and event['object_id'] == 'O1'
                    and event['generation'] == 1, 'blocked identity mismatch')
            require(event['access_kind'] in ('read', 'write'), 'invalid access kind')
        else:
            _exact_keys(event, {'index', 'kind', 'object_id', 'generation'}, 'free event')
            require(event['object_id'] == 'O1' and event['generation'] == 1,
                    'free identity mismatch')
    return events


def execution_facts(execution: dict, run_id: str) -> dict:
    """Classify one execution and derive its pointer facts.

    Returns the access evidence class ('asan', 'complete', or 'blocked') plus
    offset/width/extent/scope, raising EVIDENCE_CONFLICT for any inconsistent
    signed runtime data. A pre-access announcement alone is never an access.
    """
    events = validate_events(execution.get('events'))
    kinds = [e['kind'] for e in events]
    alloc = events[0]
    require(kinds[0] == 'alloc', 'first event must be alloc')
    exit_code = execution.get('exit_code')
    require(_is_int(exit_code), 'exit_code must be an integer')

    if kinds == ['alloc', 'attempt', 'asan']:
        evidence_class = 'asan'
    elif kinds == ['alloc', 'attempt', 'complete', 'free']:
        evidence_class = 'complete'
    elif kinds == ['alloc', 'blocked', 'free']:
        evidence_class = 'blocked'
    else:
        raise _conflict(f'event sequence {kinds} is not a complete sequence')

    expected_exit = 1 if evidence_class == 'asan' else 0
    require(exit_code == expected_exit,
            f'expected exit {expected_exit} for {evidence_class} sequence, got {exit_code}')
    require(execution.get('asan_options') == CANONICAL_ASAN_OPTIONS,
            'sanitizer options do not match the configured set')

    attempt = events[1] if evidence_class != 'blocked' else None
    if evidence_class == 'blocked':
        blocked = events[1]
        return {
            'class': 'blocked',
            'execution_id': execution['id'],
            'object_id': 'O1',
            'generation': 1,
            'event_id': 'A1',
            'scope': f'{run_id}/{execution["id"]}/O1/g1/A1',
            'access_kind': blocked['access_kind'],
            'pointer_bits': alloc['pointer_bits'],
        }

    bits = alloc['pointer_bits']
    limit = 1 << bits
    base, address = alloc['base'], attempt['address']
    width, extent = attempt['width'], alloc['extent']
    require(0 <= base < limit and 0 <= address < limit,
            'native addresses must fit the captured pointer width')
    require(width > 0, 'access width must be positive')
    require(extent >= 0, 'extent must be nonnegative')
    require(address + width <= limit and address + width > address,
            'native address interval would wrap')

    if evidence_class == 'asan':
        asan = events[2]
        require(asan['address'] == address and asan['access_kind'] == attempt['access_kind']
                and asan['width'] == width,
                'runtime callback does not match the attempted access')
        require(asan['description'] == REQUIRED_DESCRIPTION,
                f'sanitizer description is not {REQUIRED_DESCRIPTION}')
    # Lifetime: alloc strictly precedes the access; any free must come after
    # the access (complete sequence) and never precedes it. Address reuse can
    # never revive an old object generation.
    offset = address - base  # mathematical integers; never machine unsigned
    return {
        'class': evidence_class,
        'execution_id': execution['id'],
        'object_id': 'O1',
        'generation': 1,
        'event_id': 'A1',
        'scope': f'{run_id}/{execution["id"]}/O1/g1/A1',
        'access_kind': attempt['access_kind'],
        'pointer_bits': bits,
        'base': base,
        'address': address,
        'offset': offset,
        'width': width,
        'extent': extent,
    }


def _target_formula(side: str) -> list:
    violation = (['lt', 'extent', ['add', 'offset', 'width']] if side == 'upper'
                 else ['lt', 'offset', 0])
    return ['and', ['atom', 'access'],
            ['and', ['atom', 'live'],
             ['and', ['le', 0, 'extent'],
              ['and', ['lt', 0, 'width'], violation]]]]


def observations_for_execution(execution: dict, *, run_id: str,
                               available_at: int) -> list[dict]:
    """The five admissible facts for a matching observed access."""
    facts = execution_facts(execution, run_id)
    if facts['class'] == 'blocked':
        return []
    require(_is_int(available_at) and available_at >= 1, 'available_at must be a positive integer')
    prefix = facts['execution_id'] + '/A1.'
    scope = facts['scope']
    records = [
        {'id': prefix + 'access', 'formula': ['atom', 'access']},
        {'id': prefix + 'live', 'formula': ['atom', 'live']},
        {'id': prefix + 'extent', 'formula': ['eq', 'extent', facts['extent']]},
        {'id': prefix + 'width', 'formula': ['eq', 'width', facts['width']]},
        {'id': prefix + 'offset', 'formula': ['eq', 'offset', facts['offset']]},
    ]
    for record in records:
        record['scope'] = scope
        record['available_at'] = available_at
        record['authority'] = AUTHORITY
    return records


def _execution_response_seq(payload: dict, execution_id: str) -> int:
    for entry in payload['trace']:
        if entry['kind'] == 'response':
            body = entry['body']
            if isinstance(body, dict) and body.get('execution_id') == execution_id:
                return entry['seq']
    raise AdapterError('CLAIM_MISMATCH', f'execution {execution_id} has no delivered response')


def payload_prefix(payload: dict, seq: int) -> dict:
    """The log prefix ending at the claim's dispatch position."""
    executions = []
    for execution in payload['executions']:
        try:
            delivered = _execution_response_seq(payload, execution['id'])
        except AdapterError:
            continue
        if delivered < seq:
            executions.append(execution)
    return {'run_id': payload.get('run_id'), 'executions': executions,
            'trace': [e for e in payload['trace'] if e['seq'] <= seq]}


def freeze_claim(payload_prefix: dict, request: dict, *, seq: int) -> dict:
    """Freeze the domain binding and exact target at claim receipt."""
    try:
        _exact_keys(request, {'kind', 'argument_id', 'event', 'access_kind', 'side', 'from'},
                    'claim request')
        require(_is_int(seq) and seq >= 1, 'claim seq must be a positive integer')
        event = request['event']
        require(isinstance(event, str) and event.count('/') == 1,
                'event reference must be EXECUTION/OPERATION')
        execution_id, event_id = event.split('/')
        require(request['side'] in ('upper', 'lower'),
                'side must be explicitly upper or lower')
        require(request['access_kind'] in ('read', 'write'), 'invalid access kind')
        require(isinstance(request['from'], str) and ID_RE.fullmatch(request['from']),
                'claim from must be a node id')
    except Rejected as exc:
        raise AdapterError('BAD_INPUT', str(exc)) from exc

    execution = next((e for e in payload_prefix.get('executions', [])
                      if e.get('id') == execution_id), None)
    if execution is None:
        return {'state': 'rejected', 'reason': 'UNKNOWN_EXECUTION',
                'diagnostic': f'no execution {execution_id!r} delivered before this claim'}
    try:
        require(isinstance(payload_prefix.get('run_id'), str)
                and re.fullmatch(r'R[0-9a-f]{32}', payload_prefix['run_id']),
                'claim prefix must carry the run nonce')
        facts = execution_facts(execution, payload_prefix['run_id'])
    except Rejected as exc:
        raise _conflict(str(exc)) from exc
    if facts['event_id'] != event_id:
        return {'state': 'rejected', 'reason': 'UNKNOWN_OPERATION',
                'diagnostic': f'no operation {event_id!r} in execution {execution_id!r}'}
    if facts['access_kind'] != request['access_kind']:
        return {'state': 'rejected', 'reason': 'ACCESS_KIND_MISMATCH',
                'diagnostic': 'frozen access kind differs from the observed access'}
    if facts['class'] == 'blocked':
        return {'state': 'unsupported', 'reason': 'MISSING_ACCESS_EVIDENCE',
                'diagnostic': 'operation was blocked by the patched bounds guard'}
    return {
        'state': 'bound',
        'scope': facts['scope'],
        'binding': {'execution_id': execution_id, 'allocation_id': facts['object_id'],
                    'generation': facts['generation'], 'event_id': event_id,
                    'access_kind': facts['access_kind']},
        'formula': _target_formula(request['side']),
    }


def admit_oob(payload: dict, claim_id: str) -> tuple[dict, list]:
    """Re-derive the manifest and recorded argument for one selected claim."""
    claims = payload.get('claims')
    require(isinstance(claims, dict), 'payload claims must be an object')
    if claim_id not in claims:
        raise AdapterError('CLAIM_MISMATCH', f'no frozen claim {claim_id!r} in this bundle')
    entry = claims[claim_id]
    try:
        _exact_keys(entry, {'claim', 'available_at', 'frozen'}, 'claim record')
        _exact_keys(entry['claim'], {'kind', 'argument_id', 'event', 'access_kind',
                                     'side', 'from'}, 'claim descriptor')
        require(entry['claim']['argument_id'] == claim_id, 'claim id mismatch')
        require(_is_int(entry['available_at']) and entry['available_at'] >= 1,
                'claim available_at must be a positive integer')
    except Rejected as exc:
        raise AdapterError('CLAIM_MISMATCH', str(exc)) from exc

    argument = []
    for log_entry in payload['trace']:
        if log_entry['kind'] != 'request':
            continue
        body = log_entry['body']
        if body.get('kind') == 'reason' and body.get('argument_id') == claim_id:
            argument.append({'seq': log_entry['seq'], 'argument_id': claim_id,
                             'node': body['node']})

    frozen = entry['frozen']
    recomputed = freeze_claim(payload_prefix(payload, entry['available_at']),
                              entry['claim'], seq=entry['available_at'])
    if recomputed != frozen:
        raise AdapterError('CLAIM_MISMATCH',
                           'recorded frozen outcome does not match recomputation')

    if frozen['state'] != 'bound':
        manifest = {'profile': PROFILE,
                    'claims': {claim_id: {'state': frozen['state'],
                                          'reason': frozen['reason']}}}
        return manifest, argument

    binding = frozen['binding']
    execution = next(e for e in payload['executions'] if e['id'] == binding['execution_id'])
    available_at = _execution_response_seq(payload, binding['execution_id'])
    records = observations_for_execution(execution, run_id=payload['run_id'],
                                         available_at=available_at)
    scope = frozen['scope']
    manifest = {
        'profile': PROFILE,
        'registry_id': '',
        'unit': 'byte',
        'allowed_authorities': [AUTHORITY],
        'symbols': {name: ({'sort': 'Int', 'scope': scope, 'unit': 'byte'}
                            if sort == 'Int' else {'sort': 'Prop', 'scope': scope})
                    for name, sort in SYMBOLS},
        'records': {record['id']: {'formula': record['formula'], 'scope': record['scope'],
                                   'available_at': record['available_at'],
                                   'authority': record['authority']}
                    for record in records},
        'claims': {claim_id: {'scope': scope, 'available_at': entry['available_at'],
                              'formula': frozen['formula'],
                              'from': entry['claim']['from']}},
    }
    manifest['registry_id'] = registry_digest(manifest)
    return manifest, argument
