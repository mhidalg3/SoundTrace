"""Live direct translator: visible reasoning chunks to certificate steps.

One sequential worker per argument. Each narration is translated against the
evidence snapshot delivered before it; each parsed emission is bound to its
source through the runner-checked attempt hash. The translator may only
restate what the chunk asserts — it never repairs arithmetic, never invents
facts, and emits representable-but-wrong reasoning unchanged so downstream
rejection stays meaningful. Malformed model output gets exactly one repair
retry; exhaustion abstains UNPARSEABLE.
"""
from __future__ import annotations

import copy
import json
import os
import queue
import re
import threading
from pathlib import Path
from typing import Any, Callable

from evidence import Rejected, canonical_json, require, sha256_hex
from frontend import ID_RE, LIMIT_STEPS, RULE_LEAN, is_index

DEFAULT_MODEL = 'gpt-5.6-luna'
DEFAULT_PROMPT = Path(__file__).with_name('prompts') / 'translator_system.txt'
MAX_STEPS_PER_EMISSION = 64
MAX_OUTPUT_TOKENS = 8192
REASONING_EFFORT = 'high'
ABSTAIN_REASONS = ('OUT_OF_LANGUAGE', 'UNPARSEABLE', 'BUDGET_EXHAUSTED')
def _usage(response: dict) -> tuple[int, int]:
    from soundtrace_live.openai_responses import ApiError
    if not isinstance(response, dict) or not isinstance(response.get('usage'), dict):
        raise ApiError('MALFORMED', 'model response usage is malformed')
    values = []
    for field in ('input_tokens', 'output_tokens'):
        value = response['usage'].get(field)
        if type(value) is not int or not 0 <= value <= 1_000_000_000:
            raise ApiError('MALFORMED', 'model response usage is malformed')
        values.append(value)
    return values[0], values[1]



_NULLABLE_STRING = {'anyOf': [{'type': 'string'}, {'type': 'null'}]}

# Strict structured output must describe exactly the shapes that
# validate_emission_steps (and the runner's _check_emit_step) accept: per-op
# exact key sets, no nullable siblings, every array with items. Proposition
# and term structures are recursive, so they are expressed as $defs/$ref and
# their precise arity is enforced in Python after parsing.
_TERM_SYMBOLS = ('extent', 'width', 'offset')
_PROP_SYMBOLS = ('access', 'live', *_TERM_SYMBOLS)
_SCHEMA_DEFS = {
    'term': {
        'anyOf': [
            {'type': 'integer'},
            {'type': 'string', 'enum': list(_TERM_SYMBOLS)},
            {'type': 'array', 'items': {
                'anyOf': [
                    {'type': 'string', 'enum': ['add', 'sub']},
                    {'$ref': '#/$defs/term'},
                ]}},
        ],
    },
    'proposition': {
        'type': 'array',
        'items': {
            'anyOf': [
                {'type': 'string',
                 'enum': ['atom', 'eq', 'lt', 'le', 'and', *_PROP_SYMBOLS]},
                {'type': 'integer'},
                {'$ref': '#/$defs/term'},
                {'$ref': '#/$defs/proposition'},
            ]},
    },
}
_STEP_SCHEMA = {
    'anyOf': [
        {'type': 'object', 'additionalProperties': False,
         'required': ['op', 'evidence', 'formula'],
         'properties': {
             'op': {'type': 'string', 'enum': ['observe']},
             'evidence': {'type': 'string'},
             'formula': {'$ref': '#/$defs/proposition'}}},
        {'type': 'object', 'additionalProperties': False,
         'required': ['op', 'formula'],
         'properties': {
             'op': {'type': 'string', 'enum': ['compute']},
             'formula': {'$ref': '#/$defs/proposition'}}},
        {'type': 'object', 'additionalProperties': False,
         'required': ['op', 'rule', 'premises', 'formula'],
         'properties': {
             'op': {'type': 'string', 'enum': ['infer']},
             'rule': {'type': 'string', 'enum': sorted(RULE_LEAN)},
             'premises': {'type': 'array', 'items': {'type': 'integer'}},
             'formula': {'$ref': '#/$defs/proposition'}}},
    ],
}
OUTPUT_SCHEMA = {
    'type': 'object',
    'additionalProperties': False,
    'required': ['kind', 'id', 'steps', 'diagnostic', 'reason'],
    '$defs': _SCHEMA_DEFS,
    'properties': {
        'kind': {'type': 'string', 'enum': ['emit', 'noop', 'abstain']},
        'id': _NULLABLE_STRING,
        'steps': {'anyOf': [
            {'type': 'array', 'items': _STEP_SCHEMA,
             'maxItems': MAX_STEPS_PER_EMISSION},
            {'type': 'null'}]},
        'diagnostic': {'anyOf': [{'type': 'string', 'maxLength': 2048},
                                 {'type': 'null'}]},
        'reason': {'anyOf': [
            {'type': 'string', 'enum': list(ABSTAIN_REASONS)},
            {'type': 'null'}]},
    },
}

SYMBOL_SORTS = {'access': 'Prop', 'live': 'Prop', 'extent': 'Int',
                'width': 'Int', 'offset': 'Int'}


class TranslationBudget(Exception):
    """Step/token budget exceeded for this argument."""


def _symbols(scope: str) -> dict[str, dict]:
    return {name: ({'sort': 'Int', 'scope': scope, 'unit': 'byte'}
                   if sort == 'Int' else {'sort': 'Prop', 'scope': scope})
            for name, sort in SYMBOL_SORTS.items()}


def _term(t: Any, depth: int = 0) -> None:
    require(depth <= 24, 'term depth limit')
    if is_index(t):
        require(abs(t) <= 10 ** 30, 'integer magnitude limit')
        return
    if isinstance(t, str):
        require(t in SYMBOL_SORTS and SYMBOL_SORTS[t] == 'Int',
                'undeclared integer symbol')
        return
    require(isinstance(t, list) and len(t) == 3 and t[0] in ('add', 'sub'),
            'invalid term')
    _term(t[1], depth + 1)
    _term(t[2], depth + 1)


def _formula(p: Any, depth: int = 0) -> None:
    require(depth <= 24 and isinstance(p, list) and p, 'invalid proposition')
    if p[0] == 'atom':
        require(len(p) == 2 and p[1] in SYMBOL_SORTS, 'undeclared proposition')
    elif p[0] in ('eq', 'lt', 'le'):
        require(len(p) == 3, 'invalid relation arity')
        _term(p[1], depth + 1)
        _term(p[2], depth + 1)
    else:
        require(p[0] == 'and' and len(p) == 3, 'unsupported proposition')
        _formula(p[1], depth + 1)
        _formula(p[2], depth + 1)


def validate_emission_steps(steps: Any, *, emitted_formulas: list[list],
                            evidence: dict[str, dict], source_seq: int) -> None:
    """Shape + snapshot-provenance validation of one candidate emission.

    Deliberately NOT checked here: arithmetic truth, rule-conclusion
    correctness, and evidence-formula equality. Those are validly shaped
    emissions that must be signed and rejected downstream by the runner's
    faithful recording, the offline admission, and the kernel — repairing
    them would falsify the translation-fidelity experiment. Premise indices
    address the global prefix (already-signed steps + this emission's own
    steps), backward only; snapshot membership and narration cutoffs are
    enforced because they are provenance, not content.
    """
    require(isinstance(steps, list) and 0 < len(steps) <= MAX_STEPS_PER_EMISSION,
            f'emission must carry 1..{MAX_STEPS_PER_EMISSION} steps')
    require(len(emitted_formulas) + len(steps) <= LIMIT_STEPS,
            'argument step limit')
    facts = list(emitted_formulas)
    for index, step in enumerate(steps):
        require(isinstance(step, dict), 'step must be an object')
        op = step.get('op')
        if op == 'observe':
            require(set(step) == {'op', 'evidence', 'formula'}, 'observe step keys')
            evidence_id = step['evidence']
            require(isinstance(evidence_id, str) and ID_RE.fullmatch(evidence_id),
                    'invalid evidence id')
            record = evidence.get(evidence_id)
            require(record is not None,
                    f'cites evidence {evidence_id!r} outside the snapshot')
            require(record['available_at'] < source_seq,
                    f'cites evidence {evidence_id!r} delivered after the narration')
            _formula(step['formula'])
        elif op == 'compute':
            require(set(step) == {'op', 'formula'}, 'compute step keys')
            _formula(step['formula'])
            require(step['formula'][0] in ('eq', 'lt', 'le'),
                    'compute must be an arithmetic comparison')
        elif op == 'infer':
            require(set(step) == {'op', 'rule', 'premises', 'formula'},
                    'infer step keys')
            require(isinstance(step['rule'], str) and step['rule'] in RULE_LEAN,
                    'unknown rule')
            refs = step['premises']
            require(isinstance(refs, list)
                    and all(is_index(j) and 0 <= j < len(facts) for j in refs),
                    'premises must be backward global step indices')
            _formula(step['formula'])
        else:
            raise Rejected(f'unsupported step op {op!r}')
        facts.append(step['formula'])


class _Chunk:
    __slots__ = ('text', 'source_seq', 'evidence', 'binding', 'final')

    def __init__(self, text, source_seq, evidence, binding=None, final=False):
        self.text = text
        self.source_seq = source_seq
        self.evidence = evidence
        self.binding = binding
        self.final = final


class Translator:
    """Sequential FIFO translator for one argument ('C1')."""

    def __init__(self, recorder, client_factory: Callable[[], Any],
                 artifact_dir: Path, *, model: str = DEFAULT_MODEL,
                 provider: str | None = None,
                 prompt_path: Path | None = None,
                 remaining: Callable[[], float] | None = None):
        self.recorder = recorder
        self.client_factory = client_factory
        self._remaining = remaining
        self.artifact_dir = Path(artifact_dir)
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        self.provider = provider
        self.model = model
        self.resolved_model = model
        self.prompt_path = Path(prompt_path) if prompt_path else DEFAULT_PROMPT
        self.system_prompt = self.prompt_path.read_text(encoding='utf-8')
        self.prompt_sha256 = sha256_hex(self.system_prompt.encode('utf-8'))
        self._queue: 'queue.Queue[_Chunk | None]' = queue.Queue()
        self._lock = threading.Lock()
        self._attempt_count = 0
        self.emitted_formulas: list[list] = []   # global prefix for premises
        self.emission_ids: list[str] = []
        self.abstained = False
        self.abstain_id: str | None = None
        self.first_pass_emitted = 0
        self.repaired_emitted = 0
        self.calls = 0
        self.noops = 0

    # ---- public API ---------------------------------------------------
    def submit(self, text: str, source_seq: int, evidence: list[dict]) -> None:
        snapshot = {r['id']: {'formula': r['formula'],
                              'available_at': r['available_at']} for r in evidence}
        self._queue.put(_Chunk(text, source_seq, snapshot))

    def finalize(self, text: str, source_seq: int, evidence: list[dict],
                 binding: dict) -> str | None:
        self.drain()
        if self.abstained:
            return None
        snapshot = {r['id']: {'formula': r['formula'],
                              'available_at': r['available_at']} for r in evidence}
        chunk = _Chunk(text, source_seq, snapshot, binding=binding, final=True)
        self._translate(chunk)
        if self.abstained:
            return None
        require(self.emission_ids, 'finalization produced no emission')
        return self.emission_ids[-1]

    def drain(self) -> None:
        while True:
            try:
                chunk = self._queue.get_nowait()
            except queue.Empty:
                return
            if chunk is None:
                return
            self._translate(chunk)

    @property
    def metrics(self) -> dict:
        return {'calls': self.calls, 'first_pass_emitted': self.first_pass_emitted,
                'repaired_emitted': self.repaired_emitted, 'noops': self.noops,
                'abstained': self.abstained, 'emissions': len(self.emission_ids)}

    # ---- internals ------------------------------------------------------
    def _store_raw(self, raw: str) -> tuple[str, int]:
        data = raw.encode('utf-8')
        digest = sha256_hex(data)
        (self.artifact_dir / f'{digest}.txt').write_bytes(data)
        return digest, len(data)

    def _user_message(self, chunk: _Chunk) -> str:
        lines = ['## Reasoning chunk to translate (verbatim)',
                 chunk.text, '', '## Evidence snapshot (citable ids only)']
        for evidence_id in sorted(chunk.evidence):
            record = chunk.evidence[evidence_id]
            lines.append(f"- {evidence_id} = {json.dumps(record['formula'])}")
        if self.emitted_formulas:
            lines += ['', '## Previously signed primitive steps',
                      'Premise indices are global across this argument.']
            for index, formula in enumerate(self.emitted_formulas):
                lines.append(f"- {index}: {json.dumps(formula)}")
        if chunk.final and chunk.binding:
            b = chunk.binding
            lines += ['', '## Final emission target',
                      f"This is the FINAL chunk. The claim binds execution "
                      f"{b.get('execution_id')} event {b.get('event_id')}, access "
                      f"{b.get('access_kind')}, side {b.get('side')}. The last "
                      f"formula of your emission must be exactly the frozen target "
                      f"shape for that side.",
                      f"Symbols scope: {b.get('scope', 'the run scope')}"]
        lines.append('Respond with exactly one JSON object per the system contract.')
        return '\n'.join(lines)

    def _call_model(self, chunk: _Chunk) -> str:
        from soundtrace_live.openai_responses import ApiError
        client = self.client_factory()
        if self._remaining is not None:
            remaining = self._remaining()
            if remaining <= 0:
                raise ApiError('TIMEOUT', 'translator task deadline expired')
            if hasattr(client, '_timeout'):
                client._timeout = min(float(client._timeout), remaining)
        response = client.create(
            model=self.model,
            input_items=[{'role': 'system', 'content': self.system_prompt},
                         {'role': 'user', 'content': self._user_message(chunk)}],
            reasoning_effort=REASONING_EFFORT,
            max_output_tokens=MAX_OUTPUT_TOKENS,
            text_json_schema=OUTPUT_SCHEMA)
        if (not isinstance(response, dict)
                or not isinstance(response.get('model'), str)
                or not response['model']):
            raise ApiError('MALFORMED', 'model response model is malformed')
        output = response.get('output')
        if (not isinstance(output, list)
                or any(not isinstance(item, dict)
                       or not isinstance(item.get('type'), str)
                       for item in output)):
            raise ApiError('MALFORMED', 'model response output is malformed')
        raw_response = canonical_json(response)
        usage_in, usage_out = _usage(response)
        resolved = response['model']
        self.resolved_model = resolved
        audit = {
            'kind': 'model_turn', 'argument_id': 'C1',
            'turn': self.calls, 'role': 'translator',
            'requested_model': self.model, 'resolved_model': resolved,
            'response_sha256': sha256_hex(raw_response),
            'output_bytes': len(raw_response),
            'status': str(response.get('status', 'completed'))[:2048],
            'input_tokens': usage_in, 'output_tokens': usage_out}
        if self.provider is not None:
            audit['provider'] = self.provider
        self.recorder.audit(audit)
        self.calls += 1
        parts: list[str] = []
        for out in response.get('output') or []:
            if not isinstance(out, dict) or out.get('type') != 'message':
                continue
            content = out.get('content')
            if isinstance(content, str):
                parts.append(content)
            elif isinstance(content, list):
                for piece in content:
                    if isinstance(piece, dict) and piece.get('type') in (
                            'output_text', 'text'):
                        parts.append(str(piece.get('text', '')))
                    elif isinstance(piece, str):
                        parts.append(piece)
        if not parts:
            raise ApiError('MALFORMED', 'model response has no message text')
        return ''.join(parts)

    def _parse_output(self, raw: str, chunk: _Chunk) -> dict:
        document = json.loads(raw)
        require(isinstance(document, dict), 'output must be an object')
        kind = document.get('kind')
        require(kind in ('emit', 'noop', 'abstain'), 'output kind')
        if kind == 'emit':
            require(isinstance(document.get('id'), str)
                    and ID_RE.fullmatch(document['id']), 'emission id')
            validate_emission_steps(document['steps'],
                                    emitted_formulas=self.emitted_formulas,
                                    evidence=chunk.evidence,
                                    source_seq=chunk.source_seq)
        elif kind == 'noop':
            require(isinstance(document.get('diagnostic'), str), 'noop diagnostic')
        else:
            require(document.get('reason') in ABSTAIN_REASONS, 'abstain reason')
            require(isinstance(document.get('diagnostic'), str), 'abstain diagnostic')
        return document

    def _record_attempt(self, chunk: _Chunk, raw: str, outcome: str,
                        parsed_sha256: str | None, repair: int) -> str:
        raw_sha, raw_bytes = self._store_raw(raw)
        self._attempt_count += 1
        attempt_id = f'TA{self._attempt_count}'
        self.recorder.attempt({'kind': 'translation_attempt', 'argument_id': 'C1',
                               'attempt_id': attempt_id,
                               'source_seq': chunk.source_seq, 'model': self.model,
                               'resolved_model': self.resolved_model,
                               'raw_output_sha256': raw_sha,
                               'raw_output_bytes': raw_bytes,
                               'parsed_sha256': parsed_sha256, 'outcome': outcome,
                               'repair': repair})
        return attempt_id

    def _translate(self, chunk: _Chunk) -> None:
        if self.abstained:
            return
        repair = 0
        raw = ''
        while True:
            try:
                raw = self._call_model(chunk)
                document = self._parse_output(raw, chunk)
            except (json.JSONDecodeError, Rejected, ValueError, KeyError,
                    TypeError, IndexError) as exc:
                if repair == 0:
                    self._record_attempt(chunk, raw, 'invalid', None, 0)
                    repair = 1
                    # One repair: feed only the validation error back.
                    chunk = _Chunk(
                        chunk.text + '\n\n## Previous output was invalid\n'
                        + f'Error: {str(exc)[:1000]}\n'
                          'Respond again with exactly one valid JSON object per '
                          'the system contract.',
                        chunk.source_seq, chunk.evidence, chunk.binding, chunk.final)
                    continue
                self._record_attempt(chunk, raw, 'invalid', None, repair)
                self._abstain(chunk, 'UNPARSEABLE',
                              f'malformed output after one repair: {str(exc)[:400]}')
                return
            break
        kind = document['kind']
        if kind == 'noop':
            self._record_attempt(chunk, raw, 'noop', None, repair)
            self.noops += 1
            return
        if kind == 'abstain':
            self._record_attempt(chunk, raw, 'abstain', None, repair)
            self._abstain(chunk, document['reason'], document['diagnostic'])
            return
        steps = document['steps']
        emit_id = document['id']
        parsed = sha256_hex(canonical_json({'id': emit_id, 'steps': steps}))
        attempt_id = self._record_attempt(chunk, raw, 'emit', parsed, repair)
        response = self.recorder.emit(emit_id, steps, attempt_id, chunk.source_seq)
        require(response.get('status') == 'RECORDED',
                f"runner rejected emission: {response.get('diagnostic')}")
        for step in steps:
            self.emitted_formulas.append(step['formula'])
        self.emission_ids.append(emit_id)
        if repair == 0:
            self.first_pass_emitted += 1
        else:
            self.repaired_emitted += 1


    def _abstain(self, chunk: _Chunk, reason: str, diagnostic: str) -> None:
        abstain_id = f'AB{self._attempt_count}'
        self.recorder.abstain(abstain_id, chunk.source_seq, reason,
                              diagnostic[:4000])
        self.abstained = True
        self.abstain_id = abstain_id
