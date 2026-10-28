"""Memory-domain adapter: CyberGym Docker/ASan probes to generic evidence.

Producer `cybergym-asan-v1`. This adapter mirrors the fixture contract in
`oob_adapter.py` — the same five facts, the same target formula, the same
scope/binding freeze discipline — over executions captured from pinned
CyberGym images by a trusted preload shim. It never parses ASan's human
stderr, never trusts static-analysis or agent claims, and re-derives every
fact offline from the signed bundle alone.

Live-provenance extension for direct translation: every `emit` names the
narration it translates (`source_seq`) and the translation attempt that
produced it; the runner hashed the canonical emission against that attempt,
and every cited evidence record must have been delivered strictly before the
*narration*, not merely before the (possibly later) emission.
"""
from __future__ import annotations

import re
from typing import Any

from evidence import Rejected, registry_digest, require, sha256_hex, canonical_json
from frontend import ID_RE, PROFILE, is_index
from oob_adapter import AdapterError

AUTHORITY = 'cybergym-asan-v1'
BUNDLE_FORMAT = 'soundtrace-cybergym-run-v1'
CANONICAL_ASAN_OPTIONS = ('halt_on_error=1:abort_on_error=0:exitcode=1:'
                          'detect_leaks=0:symbolize=0:verify_asan_link_order=0')
REQUIRED_DESCRIPTION = 'heap-buffer-overflow'
REQUIRED_REGION_CATEGORY = 'heap'
POINTER_BITS = 64
POINTER_LIMIT = 1 << POINTER_BITS
PLATFORM = 'linux/amd64'
MAX_EXCERPT = 4096

SYMBOLS = [
    ('access', 'Prop'), ('live', 'Prop'),
    ('extent', 'Int'), ('width', 'Int'), ('offset', 'Int'),
]

EVENT_KEYS = {'index', 'kind', 'event_id', 'address', 'access_kind', 'width',
              'description', 'pc', 'region_category', 'region_base',
              'region_extent', 'pointer_bits'}
EXECUTION_KEYS = {'id', 'task_id', 'poc_sha256', 'poc_size', 'image_ref',
                  'image_digest', 'platform', 'command', 'exit_code', 'signal',
                  'oom_killed', 'timed_out', 'pointer_bits', 'asan_options',
                  'events', 'stdout_sha256', 'stdout_bytes', 'stderr_sha256',
                  'stderr_bytes', 'stdout_excerpt', 'stderr_excerpt'}
BUILD_KEYS = {'corpus_sha256', 'lock_sha256', 'probe_source_sha256',
              'probe_dso_sha256', 'docker_version', 'docker_platform',
              'agent_image_digest', 'tasks'}
ATTEMPT_OUTCOMES = ('emit', 'noop', 'invalid', 'abstain')
ABSTAIN_REASONS = ('OUT_OF_LANGUAGE', 'UNPARSEABLE', 'BUDGET_EXHAUSTED')


def _conflict(diagnostic: str) -> AdapterError:
    return AdapterError('EVIDENCE_CONFLICT', diagnostic)


def _exact_keys(obj: Any, keys: set, what: str) -> None:
    require(isinstance(obj, dict), f'{what} must be an object')
    require(set(obj) == keys, f'{what} has unexpected or missing keys')


def _hex64(value: Any, what: str) -> None:
    require(isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value),
            f'{what} must be 64 lowercase hex characters')


def _digest(value: Any, what: str) -> None:
    require(isinstance(value, str) and re.fullmatch(r'sha256:[0-9a-f]{64}', value),
            f'{what} must be sha256:<64 hex>')


# ---- structural validation -------------------------------------------

def validate_execution(execution: Any,
                       expected_task: dict[str, Any] | None = None,
                       *, build: str = 'vul') -> None:
    """Strict schema for one recorded CyberGym probe execution.

    When a pinned build task is supplied, bind the image reference and exact
    timeout-wrapped command to that task as well as validating the generic
    execution schema.
    """
    _exact_keys(execution, EXECUTION_KEYS, 'execution')
    require(isinstance(execution['id'], str)
            and re.fullmatch(r'X[0-9]+', execution['id']),
            'execution id format')
    require(isinstance(execution['task_id'], str) and execution['task_id'],
            'execution task id')
    _hex64(execution['poc_sha256'], 'poc sha256')
    require(is_index(execution['poc_size'])
            and 0 < execution['poc_size'] <= 1_048_576,
            'poc size must be an integer within the 1 MiB cap')
    require(isinstance(execution['image_ref'], str) and execution['image_ref'],
            'image reference')
    _digest(execution['image_digest'], 'image digest')
    require(execution['platform'] == PLATFORM, 'execution platform')
    require(isinstance(execution['command'], list)
            and all(isinstance(c, str) and c for c in execution['command'])
            and execution['command'], 'execution command')
    if expected_task is not None:
        require(build in ('vul', 'fix'), 'build must be vul or fix')
        require(isinstance(expected_task, dict),
                'pinned task entry must be an object')
        ref_key = 'vul_ref' if build == 'vul' else 'fix_ref'
        digest_key = 'vul_digest' if build == 'vul' else 'fix_digest'
        require(isinstance(expected_task.get(ref_key), str)
                and isinstance(expected_task.get(digest_key), str)
                and isinstance(expected_task.get('command_vul'), list)
                and expected_task['command_vul']
                and all(isinstance(part, str) and part
                        for part in expected_task['command_vul']),
                'pinned task entry is malformed')
        require(execution['image_ref'] == expected_task[ref_key],
                'execution image reference differs from the pinned task')
        require(execution['image_digest'] == expected_task[digest_key],
                'execution image digest differs from the pinned task')
        require(execution['command'] == [
            '/usr/bin/timeout', '-s', 'KILL', '10',
            *expected_task['command_vul']],
                'execution command differs from the pinned task')
    require(is_index(execution['exit_code']), 'exit code must be an integer')
    require(execution['signal'] is None or is_index(execution['execution_signal']
                                                    if False else execution['signal']),
            'signal must be null or an integer')
    require(isinstance(execution['oom_killed'], bool), 'oom_killed must be a boolean')
    require(isinstance(execution['timed_out'], bool), 'timed_out must be a boolean')
    require(is_index(execution['pointer_bits']) and execution['pointer_bits'] == POINTER_BITS,
            'pointer bits')
    require(execution['asan_options'] == CANONICAL_ASAN_OPTIONS,
            'sanitizer options do not match the configured set')
    for field in ('stdout_sha256', 'stderr_sha256'):
        _hex64(execution[field], field)
    for field in ('stdout_bytes', 'stderr_bytes'):
        require(is_index(execution[field]) and execution[field] >= 0, f'{field} must be an integer')
    for field in ('stdout_excerpt', 'stderr_excerpt'):
        require(isinstance(execution[field], str), f'{field} must be a string')
        require(len(execution[field].encode('utf-8')) <= MAX_EXCERPT,
                f'{field} exceeds the excerpt cap')
    events = execution['events']
    require(isinstance(events, list) and len(events) <= 1,
            'a recorded execution carries at most one machine event')
    if not events:
        require(execution['exit_code'] == 0 and execution['signal'] is None
                and not execution['oom_killed'] and not execution['timed_out'],
                'an eventless execution must have exited cleanly')
        return
    execution_facts({'id': execution['id'], 'task_id': execution['task_id'],
                     'poc_sha256': execution['poc_sha256'],
                     'image_digest': execution['image_digest'],
                     'exit_code': execution['exit_code'],
                     'signal': execution['signal'], 'oom_killed': execution['oom_killed'],
                     'timed_out': execution['timed_out'], 'events': events})
    require(execution['signal'] is None or is_index(execution['signal']),
            'signal must be null or an integer')

def validate_event(event: Any) -> None:
    """Exact schema of the shim's single machine event."""
    _exact_keys(event, EVENT_KEYS, 'asan event')
    require(is_index(event['index']) and event['index'] == 1, 'event index must be 1')
    require(event['kind'] == 'asan_report', 'event kind')
    require(event['event_id'] == 'A1', 'event id')
    for field in ('address', 'width', 'pc', 'region_base', 'region_extent'):
        require(is_index(event[field]), f'{field} must be an integer')
    require(event['access_kind'] in ('read', 'write'), 'access kind')
    require(isinstance(event['description'], str), 'description')
    require(isinstance(event['region_category'], str), 'region category')
    require(isinstance(event['pointer_bits'], int)
            and event['pointer_bits'] == POINTER_BITS,
            'event pointer bits')


def execution_facts(execution: dict) -> dict:
    """Classify one probe execution and derive its pointer facts.

    'asan' — exactly one admissible heap-buffer-overflow report; 'clean' —
    exit 0 with no report. Every other combination raises: a signed
    CyberGym execution may only be one of these two.
    """
    events = execution.get('events')
    require(isinstance(events, list) and len(events) <= 1, 'events must carry at most one report')
    exit_code = execution.get('exit_code')
    require(is_index(exit_code), 'exit_code must be an integer')
    signal = execution.get('signal')
    require(signal is None or is_index(signal), 'signal must be null or an integer')
    if not events:
        require(exit_code == 0 and signal is None
                and not execution.get('oom_killed') and not execution.get('timed_out'),
                'an eventless execution must have exited cleanly')
        return {'class': 'clean', 'execution_id': execution['id'],
                'task_id': execution['task_id'], 'event_id': None,
                'scope': None}
    event = events[0]
    validate_event(event)
    require(exit_code == 1, f'admissible report requires process exit 1, got {exit_code}')
    require(signal is None, f'admissible report requires no signal, got {signal}')
    require(not execution.get('oom_killed'), 'admissible report requires no OOM kill')
    require(not execution.get('timed_out'), 'admissible report requires no timeout')
    require(event['description'] == REQUIRED_DESCRIPTION,
            f"sanitizer description is not {REQUIRED_DESCRIPTION}")
    require(event['region_category'] == REQUIRED_REGION_CATEGORY,
            f"located region category is not {REQUIRED_REGION_CATEGORY}")
    address, width = event['address'], event['width']
    base, extent = event['region_base'], event['region_extent']
    require(event['pc'] > 0, 'report pc must be positive')
    require(width > 0, 'access width must be positive')
    require(extent > 0, 'region extent must be positive')
    require(0 <= base < POINTER_LIMIT and 0 <= address < POINTER_LIMIT,
            'native addresses must fit the captured pointer width')
    require(base + extent <= POINTER_LIMIT, 'region end would wrap the pointer range')
    require(address + width <= POINTER_LIMIT, 'access end would wrap the pointer range')
    offset = address - base  # mathematical integers; never machine unsigned
    return {
        'class': 'asan',
        'execution_id': execution['id'],
        'task_id': execution['task_id'],
        'poc_sha256': execution['poc_sha256'],
        'image_digest': execution['image_digest'],
        'object_id': 'O1',
        'generation': 1,
        'event_id': 'A1',
        'scope': (f"{_run_id_of(execution)}/{execution['task_id']}/{execution['id']}/"
                  f"{execution['poc_sha256']}/O1/g1/A1"),
        'access_kind': event['access_kind'],
        'pointer_bits': event['pointer_bits'],
        'base': base,
        'address': address,
        'offset': offset,
        'width': width,
        'extent': extent,
    }


_RUN_ID_KEY = '_run_id'


def _run_id_of(execution: dict) -> str:
    run_id = execution.get(_RUN_ID_KEY)
    return run_id if isinstance(run_id, str) else ''


def with_run_id(execution: dict, run_id: str) -> dict:
    """Attach the run nonce for scope derivation without polluting the record."""
    execution = dict(execution)
    execution[_RUN_ID_KEY] = run_id
    return execution


def _target_formula(side: str) -> list:
    violation = (['lt', 'extent', ['add', 'offset', 'width']] if side == 'upper'
                 else ['lt', 'offset', 0])
    return ['and', ['atom', 'access'],
            ['and', ['atom', 'live'],
             ['and', ['le', 0, 'extent'],
              ['and', ['lt', 0, 'width'], violation]]]]


def scope_for(run_id: str, facts: dict) -> str:
    return (f"{run_id}/{facts['task_id']}/{facts['execution_id']}/"
            f"{facts['poc_sha256']}/O1/g1/A1")


def scope_fits(run_id: str, task_id: str, execution_id: str,
               poc_sha256: str) -> bool:
    """True when the derived record scope fits frontend's identifier cap.

    frontend.ID_RE caps every symbol/record scope at 128 characters, so a
    long task id or a high execution number can make an otherwise valid
    heap report inadmissible. Callers must reject such tasks/executions
    up front rather than failing at kernel time.
    """
    from frontend import ID_RE
    return bool(ID_RE.fullmatch(
        f"{run_id}/{task_id}/{execution_id}/{poc_sha256}/O1/g1/A1"))


def max_execution_number(task_id: str, poc_sha256: str,
                         *, run_id_len: int = 33) -> int:
    """Largest n (bounded at 99) for which the Xn scope fits the cap."""
    run_id = 'R' + '0' * (run_id_len - 1)
    n = 0
    while n < 99 and scope_fits(run_id, task_id, f'X{n + 1}', poc_sha256):
        n += 1
    return n


def observations_for_execution(execution: dict, *, run_id: str,
                               available_at: int) -> list[dict]:
    """The five admissible facts for one admissible heap report."""
    facts = execution_facts(with_run_id(execution, run_id))
    if facts['class'] != 'asan':
        return []
    require(is_index(available_at) and available_at >= 1,
            'available_at must be a positive integer')
    prefix = facts['execution_id'] + '/A1.'
    records = [
        {'id': prefix + 'access', 'formula': ['atom', 'access']},
        {'id': prefix + 'live', 'formula': ['atom', 'live']},
        {'id': prefix + 'extent', 'formula': ['eq', 'extent', facts['extent']]},
        {'id': prefix + 'width', 'formula': ['eq', 'width', facts['width']]},
        {'id': prefix + 'offset', 'formula': ['eq', 'offset', facts['offset']]},
    ]
    for record in records:
        record['scope'] = scope_for(run_id, facts)
        record['available_at'] = available_at
        record['authority'] = AUTHORITY
    return records


# ---- trace-derived translation state ---------------------------------

def _iter_requests(payload: dict, kind: str):
    for entry in payload.get('trace', []):
        if entry.get('kind') == 'request' and isinstance(entry.get('body'), dict) \
                and entry['body'].get('kind') == kind:
            yield entry


def argument_emissions(payload: dict, argument_id: str) -> list[dict]:
    """Signed `emit` entries for one argument, in log order, with positions."""
    emissions = []
    for entry in _iter_requests(payload, 'emit'):
        body = entry['body']
        if body.get('argument_id') != argument_id:
            continue
        emissions.append({'seq': entry['seq'], 'id': body['id'], 'steps': body['steps'],
                          'attempt_id': body.get('attempt_id'),
                          'source_seq': body.get('source_seq')})
    return emissions


def argument_attempts(payload: dict, argument_id: str) -> dict[str, dict]:
    attempts = {}
    for entry in _iter_requests(payload, 'translation_attempt'):
        body = entry['body']
        if body.get('argument_id') == argument_id:
            attempts[body['attempt_id']] = {'seq': entry['seq'], **body}
    return attempts


def argument_abstentions(payload: dict, argument_id: str) -> dict[str, dict]:
    abstentions = {}
    for entry in _iter_requests(payload, 'translation_abstain'):
        body = entry['body']
        if body.get('argument_id') == argument_id:
            abstentions[body['abstain_id']] = {'seq': entry['seq'], **body}
    return abstentions


def argument_narration_seqs(payload: dict, argument_id: str) -> dict[int, str]:
    seqs = {}
    for entry in _iter_requests(payload, 'narrate'):
        body = entry['body']
        if body.get('argument_id') == argument_id:
            seqs[entry['seq']] = body.get('text', '')
    return seqs


def _execution_response_seq(payload: dict, execution_id: str) -> int:
    for entry in payload.get('trace', []):
        if entry.get('kind') == 'response':
            body = entry.get('body')
            if isinstance(body, dict) and body.get('execution_id') == execution_id:
                return entry['seq']
    raise AdapterError('CLAIM_MISMATCH', f'execution {execution_id} has no delivered response')


def _available_observations(payload: dict) -> dict[str, int]:
    """Evidence id -> delivered response position, from probe responses."""
    out: dict[str, int] = {}
    for entry in payload.get('trace', []):
        if entry.get('kind') != 'response':
            continue
        body = entry.get('body')
        if not (isinstance(body, dict) and isinstance(body.get('observations'), list)):
            continue
        for record in body['observations']:
            if isinstance(record, dict) and isinstance(record.get('id'), str):
                out[record['id']] = entry['seq']
    return out


def payload_prefix(payload: dict, seq: int) -> dict:
    """The log prefix ending at the claim's dispatch position."""
    executions = []
    for execution in payload.get('executions', []):
        try:
            delivered = _execution_response_seq(payload, execution['id'])
        except AdapterError:
            continue
        if delivered < seq:
            executions.append(execution)
    return {'run_id': payload.get('run_id'), 'executions': executions,
            'trace': [e for e in payload.get('trace', []) if e['seq'] <= seq]}


def freeze_claim(prefix: dict, request: dict, *, seq: int) -> dict:
    """Freeze the domain binding and exact target at claim receipt."""
    try:
        _exact_keys(request, {'kind', 'argument_id', 'event', 'access_kind', 'side', 'from'},
                    'claim request')
        require(is_index(seq) and seq >= 1, 'claim seq must be a positive integer')
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

    argument_id = request['argument_id']
    emissions = {e['id']: e for e in argument_emissions(prefix, argument_id)}
    abstentions = argument_abstentions(prefix, argument_id)
    if abstentions:
        return {'state': 'unsupported', 'reason': 'UNSUPPORTED_TRANSLATION',
                'diagnostic': 'argument was closed by a translation abstention'}
    if request['from'] not in emissions:
        return {'state': 'rejected', 'reason': 'UNKNOWN_SOURCE',
                'diagnostic': f'claim from {request["from"]!r} is neither a recorded '
                              f'emission nor an abstention of this argument'}
    if emissions[request['from']]['seq'] != max(e['seq'] for e in emissions.values()):
        return {'state': 'rejected', 'reason': 'FINAL_EMISSION_MISMATCH',
                'diagnostic': 'claim source must be the final emission for this argument'}

    execution = next((e for e in prefix.get('executions', [])
                      if e.get('id') == execution_id), None)
    if execution is None:
        return {'state': 'rejected', 'reason': 'UNKNOWN_EXECUTION',
                'diagnostic': f'no execution {execution_id!r} delivered before this claim'}
    try:
        require(isinstance(prefix.get('run_id'), str)
                and re.fullmatch(r'R[0-9a-f]{32}', prefix['run_id']),
                'claim prefix must carry the run nonce')
        facts = execution_facts(with_run_id(execution, prefix['run_id']))
    except Rejected as exc:
        raise _conflict(str(exc)) from exc
    if facts['class'] != 'asan':
        return {'state': 'unsupported', 'reason': 'MISSING_ACCESS_EVIDENCE',
                'diagnostic': 'probe completed without an admissible heap report'}
    if facts['event_id'] != event_id:
        return {'state': 'rejected', 'reason': 'UNKNOWN_OPERATION',
                'diagnostic': f'no operation {event_id!r} in execution {execution_id!r}'}
    if facts['access_kind'] != request['access_kind']:
        return {'state': 'rejected', 'reason': 'ACCESS_KIND_MISMATCH',
                'diagnostic': 'frozen access kind differs from the observed access'}
    return {
        'state': 'bound',
        'scope': facts['scope'],
        'binding': {'execution_id': execution_id, 'allocation_id': facts['object_id'],
                    'generation': facts['generation'], 'event_id': event_id,
                    'access_kind': facts['access_kind'],
                    'task_id': facts['task_id'], 'poc_sha256': facts['poc_sha256'],
                    'image_digest': facts['image_digest']},
        'formula': _target_formula(request['side']),
    }


# ---- emission source re-validation (offline) -------------------------

def _emission_hash(emission: dict) -> str:
    return sha256_hex(canonical_json({'id': emission['id'], 'steps': emission['steps']}))


def revalidate_emissions(payload: dict, argument_id: str) -> None:
    """Re-derive the runner's live translation invariants offline.

    Every emission must hash to its recorded attempt, translate a narration
    delivered before it, never follow an abstention, and cite only evidence
    delivered before the *narration* it translates.
    """
    attempts = argument_attempts(payload, argument_id)
    narrations = argument_narration_seqs(payload, argument_id)
    abstentions = argument_abstentions(payload, argument_id)
    available = _available_observations(payload)
    abstain_seq = min((a['seq'] for a in abstentions.values()), default=None)
    for emission in argument_emissions(payload, argument_id):
        where = f"emission {emission['id']!r}"
        if abstain_seq is not None and abstain_seq < emission['seq']:
            raise AdapterError('SOURCE_ALIGNMENT_FAILED',
                               f'{where} follows a translation abstention')
        attempt = attempts.get(emission['attempt_id'])
        if attempt is None:
            raise AdapterError('SOURCE_ALIGNMENT_FAILED',
                               f'{where} names no recorded translation attempt')
        if attempt.get('outcome') != 'emit' or attempt.get('parsed_sha256') is None:
            raise AdapterError('SOURCE_ALIGNMENT_FAILED',
                               f'{where} attempt {emission["attempt_id"]!r} did not parse')
        if attempt['parsed_sha256'] != _emission_hash(emission):
            raise AdapterError('SOURCE_ALIGNMENT_FAILED',
                               f'{where} does not byte-match its attempt hash')
        if attempt['source_seq'] != emission['source_seq']:
            raise AdapterError('SOURCE_ALIGNMENT_FAILED',
                               f'{where} source sequence differs from its attempt')
        source_seq = emission['source_seq']
        if not is_index(source_seq) or source_seq not in narrations:
            raise AdapterError('SOURCE_ALIGNMENT_FAILED',
                               f'{where} does not translate a recorded narration')
        if not source_seq < emission['seq']:
            raise AdapterError('SOURCE_ALIGNMENT_FAILED',
                               f'{where} translates a narration at or after itself')
        for step in emission['steps']:
            if isinstance(step, dict) and step.get('op') == 'observe':
                evidence = step.get('evidence')
                delivered = available.get(evidence) if isinstance(evidence, str) else None
                if delivered is None:
                    raise AdapterError('SOURCE_ALIGNMENT_FAILED',
                                       f'{where} cites unknown evidence {evidence!r}')
                if not delivered < source_seq:
                    raise AdapterError(
                        'SOURCE_ALIGNMENT_FAILED',
                        f'{where} cites evidence delivered after the narration it '
                        f'translates (no retroactive evidence)')


# ---- admission --------------------------------------------------------

def admit_cybergym(payload: dict, claim_id: str) -> tuple[dict, list]:
    """Re-derive the manifest and recorded emissions for one selected claim."""
    claims = payload.get('claims')
    require(isinstance(claims, dict), 'payload claims must be an object')
    build = payload.get('build')
    require(isinstance(build, dict) and isinstance(build.get('tasks'), dict),
            'payload build tasks must be an object')
    target_build = payload.get('target_build')
    require(target_build in ('vul', 'fix'),
            'payload target_build must be vul or fix')
    if claim_id not in claims:
        raise AdapterError('CLAIM_MISMATCH', f'no frozen claim {claim_id!r} in this bundle')
    entry = claims[claim_id]
    try:
        _exact_keys(entry, {'claim', 'available_at', 'frozen'}, 'claim record')
        _exact_keys(entry['claim'], {'kind', 'argument_id', 'event', 'access_kind',
                                     'side', 'from'}, 'claim descriptor')
        require(entry['claim']['argument_id'] == claim_id, 'claim id mismatch')
        require(is_index(entry['available_at']) and entry['available_at'] >= 1,
                'claim available_at must be a positive integer')
        for execution in payload.get('executions', []):
            task_entry = build['tasks'].get(execution.get('task_id'))
            require(task_entry is not None,
                    'execution names a task outside the build')
            validate_execution(execution, task_entry, build=target_build)
    except Rejected as exc:
        raise AdapterError('CLAIM_MISMATCH', str(exc)) from exc

    require(any(item.get('kind') == 'request'
                and item.get('seq') == entry['available_at']
                and item.get('body', {}).get('kind') == 'claim'
                and item['body'] == entry['claim']
                for item in payload['trace']),
            'frozen claim has no matching signed claim request')
    revalidate_emissions(payload, claim_id)

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
        return manifest, []

    binding = frozen['binding']
    execution = next(e for e in payload['executions'] if e['id'] == binding['execution_id'])
    if (execution['task_id'] != binding['task_id']
            or execution['poc_sha256'] != binding['poc_sha256']
            or execution['image_digest'] != binding['image_digest']):
        raise AdapterError('CLAIM_MISMATCH',
                           'frozen binding does not match the recorded execution')
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
    return manifest, []
