"""Mode A — oracle-assisted certificate verification (no autonomous agent).

Plan section 3 / Gate 2: validate the proof pipeline on a *real* CyberGym
execution without depending on autonomous discovery. A known oracle input is
executed through the trusted runner, an explicit valid explanation is signed
into the bundle as certificate steps, and the direct-mode certificate is
verified by the checker + Lean kernel.

This is deliberately separate from autonomous runs (Mode B, the orchestrator):

* No pilot agent, no sandbox shell loop. The oracle PoC is probed directly
  through the same trusted ``_Session`` recorder the orchestrator drives, so
  the signed bundle still attests "the runner recorded these bytes".
* The explanation is explicit and operator-supplied (or produced by
  ``read_upper_oob_steps`` for the upper-read family), not an LLM translation.
  Translator-LLM faithfulness is a separate gate.

``run_oracle_mode`` builds a real ``CybergymBackend`` (needs Docker + the
pinned image + a bootstrapped ``work_dir``) and the real Lean kernel. The core
``run_oracle_session`` / ``verify_oracle_bundle`` functions accept an injected
backend and a ``lean`` path, so the whole path is testable offline with a
duck-typed backend and a fake kernel.
"""
from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
from typing import Any

from checker import verify_certificate
from direct import assemble_direct_certificate
from evidence import Rejected, canonical_json, require, sha256_hex
from runner import _Session
from soundtrace_live.translator import Translator

ARGUMENT_ID = 'C1'
EMIT_ID = 'goal'
_ORACLE_MODEL = 'oracle-explicit-explanation'


def read_upper_oob_steps(extent: int, width: int, offset: int) -> list[dict]:
    """Deterministic valid certificate steps for an upper-side heap OOB read.

    Reproduces the Lean-verified ``read_upper`` argument structure with the
    observed integers substituted. Valid exactly when ``0 <= extent``,
    ``0 < width`` and ``extent < offset + width`` (a real upper overflow);
    these hold for any admissible upper-read ASan report. The step/premise
    skeleton is identical to the kernel-checked fixture — only the integer
    literals change — and ``read_upper_oob_steps(6, 4, 4)`` is asserted equal
    to that fixture in the tests. Non-canonical integers reuse the same proof
    skeleton; a Lean run confirms them for a specific execution.
    """
    require(isinstance(extent, int) and isinstance(width, int)
            and isinstance(offset, int)
            and not isinstance(extent, bool) and not isinstance(width, bool)
            and not isinstance(offset, bool),
            'extent/width/offset must be plain integers')
    total = offset + width
    return [
        {'op': 'observe', 'evidence': 'X1/A1.access', 'formula': ['atom', 'access']},
        {'op': 'observe', 'evidence': 'X1/A1.live', 'formula': ['atom', 'live']},
        {'op': 'observe', 'evidence': 'X1/A1.extent', 'formula': ['eq', 'extent', extent]},
        {'op': 'observe', 'evidence': 'X1/A1.width', 'formula': ['eq', 'width', width]},
        {'op': 'observe', 'evidence': 'X1/A1.offset', 'formula': ['eq', 'offset', offset]},
        {'op': 'infer', 'rule': 'add_eq', 'premises': [4, 3],
         'formula': ['eq', ['add', 'offset', 'width'], ['add', offset, width]]},
        {'op': 'compute', 'formula': ['eq', ['add', offset, width], total]},
        {'op': 'infer', 'rule': 'eq_trans', 'premises': [5, 6],
         'formula': ['eq', ['add', 'offset', 'width'], total]},
        {'op': 'compute', 'formula': ['lt', extent, total]},
        {'op': 'infer', 'rule': 'lt_transport', 'premises': [2, 7, 8],
         'formula': ['lt', 'extent', ['add', 'offset', 'width']]},
        {'op': 'compute', 'formula': ['eq', 0, 0]},
        {'op': 'compute', 'formula': ['lt', 0, width]},
        {'op': 'infer', 'rule': 'lt_transport', 'premises': [10, 3, 11],
         'formula': ['lt', 0, 'width']},
        {'op': 'compute', 'formula': ['eq', 0, 0]},
        {'op': 'compute', 'formula': ['le', 0, extent]},
        {'op': 'infer', 'rule': 'le_transport', 'premises': [13, 2, 14],
         'formula': ['le', 0, 'extent']},
        {'op': 'infer', 'rule': 'and_intro', 'premises': [12, 9],
         'formula': ['and', ['lt', 0, 'width'],
                     ['lt', 'extent', ['add', 'offset', 'width']]]},
        {'op': 'infer', 'rule': 'and_intro', 'premises': [15, 16],
         'formula': ['and', ['le', 0, 'extent'],
                     ['and', ['lt', 0, 'width'],
                      ['lt', 'extent', ['add', 'offset', 'width']]]]},
        {'op': 'infer', 'rule': 'and_intro', 'premises': [1, 17],
         'formula': ['and', ['atom', 'live'],
                     ['and', ['le', 0, 'extent'],
                      ['and', ['lt', 0, 'width'],
                       ['lt', 'extent', ['add', 'offset', 'width']]]]]},
        {'op': 'infer', 'rule': 'and_intro', 'premises': [0, 18],
         'formula': ['and', ['atom', 'access'],
                     ['and', ['atom', 'live'],
                      ['and', ['le', 0, 'extent'],
                       ['and', ['lt', 0, 'width'],
                        ['lt', 'extent', ['add', 'offset', 'width']]]]]]},
    ]


class _InProcessRunner:
    """Drives one trusted ``_Session`` in process, capturing each response.

    Mirrors the orchestrator's request protocol, minus the agent: there is no
    untrusted model to isolate, so a subprocess broker is unnecessary. The
    bundle is still signed by the recorder with the runner key.
    """

    def __init__(self, backend, key: bytes, out_path: Path,
                 target_build: str = 'vul'):
        self._session = _Session(key, out_path, backend=backend,
                                 target_build=target_build)

    def send(self, request: dict) -> dict | None:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self._session.dispatch(request)
        line = buf.getvalue().strip()
        return json.loads(line) if line else None

    def publish(self) -> int:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            return self._session.publish()


class _RecorderFacade:
    """Recorder surface (audit/probe/narrate/attempt/emit/abstain/claim) over
    the in-process _Session, matching what ``Translator`` and the oracle
    driver call."""

    def __init__(self, runner: '_InProcessRunner'):
        self._runner = runner

    def audit(self, body: dict) -> dict:
        return self._runner.send(dict(body))

    def probe(self, task_id: str, poc_sha256: str, poc_size: int,
              *, timeout: float | None = None) -> dict:
        return self._runner.send({'kind': 'probe', 'task_id': task_id,
                                  'poc_sha256': poc_sha256,
                                  'poc_size': poc_size})

    def narrate(self, text: str) -> dict:
        return self._runner.send({'kind': 'narrate',
                                  'argument_id': ARGUMENT_ID, 'text': text})

    def attempt(self, body: dict) -> dict:
        return self._runner.send(dict(body))

    def emit(self, emit_id: str, steps: list, attempt_id: str,
             source_seq: int) -> dict:
        return self._runner.send({'kind': 'emit', 'argument_id': ARGUMENT_ID,
                                  'id': emit_id, 'steps': steps,
                                  'attempt_id': attempt_id,
                                  'source_seq': source_seq})

    def abstain(self, abstain_id: str, source_seq: int, reason: str,
                diagnostic: str) -> dict:
        return self._runner.send({'kind': 'translation_abstain',
                                  'argument_id': ARGUMENT_ID,
                                  'abstain_id': abstain_id,
                                  'source_seq': source_seq, 'reason': reason,
                                  'diagnostic': diagnostic})

    def claim(self, event: str, access_kind: str, side: str,
              frm: str) -> dict:
        return self._runner.send({'kind': 'claim', 'argument_id': ARGUMENT_ID,
                                  'event': event, 'access_kind': access_kind,
                                  'side': side, 'from': frm})


class StepsClient:
    """Translator client that always emits a fixed, explicit set of steps.

    Stands in for the LLM translator when the valid explanation is supplied
    directly (Gate 2). Swap for a provider / named-``@translator`` client to
    exercise live translation (Gate 3). ``create`` returns the Responses
    shape ``Translator`` consumes; the runner still validates and signs the
    emission, so an invalid explanation is rejected exactly as a model's
    would be."""

    def __init__(self, steps: list[dict], emit_id: str = EMIT_ID,
                 model: str = _ORACLE_MODEL):
        self._doc = {'kind': 'emit', 'id': emit_id, 'steps': steps}
        self._model = model
        self._timeout = 300.0

    def create(self, *, model, input_items, reasoning_effort=None,
               max_output_tokens=None, text_json_schema=None, **_ignored):
        text = json.dumps(self._doc, separators=(',', ':'))
        return {'id': 'oracle', 'model': self._model, 'status': 'completed',
                'output': [{'type': 'message',
                            'content': [{'type': 'output_text',
                                         'text': text}]}],
                'usage': {'input_tokens': 0, 'output_tokens': 0}}


class OracleError(Exception):
    """An oracle-mode session that did not produce a signed, claimed bundle."""


def run_oracle_session(backend, key: bytes, out_path, *, task_id: str,
                       oracle_poc: bytes, steps: list[dict] | None = None,
                       client_factory=None, side: str, access_kind: str,
                       difficulty: str = 'level1',
                       explanation: str | None = None,
                       target_build: str = 'vul', artifact_dir=None) -> dict:
    """Probe the oracle PoC and run the explanation through the translator.

    The emit steps come from the translator stage: ``client_factory`` (a real
    provider / ``@translator`` client) when supplied, otherwise a
    ``StepsClient`` wrapping the explicit ``steps``. Either way the runner
    validates and signs the emission. Returns the signed bundle; raises
    ``OracleError`` if the probe is not admissible or no bound claim results.
    """
    require(side in ('upper', 'lower'), 'side must be upper or lower')
    require(access_kind in ('read', 'write'), 'access_kind must be read or write')
    require(isinstance(oracle_poc, (bytes, bytearray)) and oracle_poc,
            'oracle_poc must be nonempty bytes')
    require((steps is None) != (client_factory is None),
            'supply exactly one of steps or client_factory')
    poc = bytes(oracle_poc)
    poc_sha256 = sha256_hex(poc)
    poc_size = len(poc)
    if hasattr(backend, 'store_poc'):
        require(backend.store_poc(poc) == poc_sha256,
                'backend stored a different PoC digest')
    explanation = explanation or (
        f'Oracle input: admissible heap {access_kind} past the {side} bound; '
        'observed extent/width/offset entail the out-of-bounds access.')
    out_path = Path(out_path)
    artifact_dir = (Path(artifact_dir) if artifact_dir is not None
                    else out_path.parent / 'translator-artifacts')
    if client_factory is None:
        _steps = steps
        client_factory = lambda: StepsClient(_steps)

    runner = _InProcessRunner(backend, key, out_path, target_build)
    recorder = _RecorderFacade(runner)
    recorder.audit({'kind': 'model_session', 'argument_id': ARGUMENT_ID,
                    'session_sha256': sha256_hex(poc + b'session'),
                    'difficulty': difficulty, 'target_model': _ORACLE_MODEL,
                    'translator_model': _ORACLE_MODEL,
                    'prompt_sha256': sha256_hex(explanation.encode()),
                    'input_sha256': poc_sha256})
    probe = recorder.probe(task_id, poc_sha256, poc_size)
    if not isinstance(probe, dict) or probe.get('status') != 'RECORDED':
        raise OracleError(f'probe did not record an execution: {probe}')
    if probe.get('event_id') is None:
        raise OracleError('oracle PoC produced no admissible event '
                          '(not an out-of-bounds report on this build)')
    execution_id = probe['execution_id']
    event_id = probe['event_id']
    observations = probe['observations']
    narrate = recorder.narrate(explanation)
    source_seq = narrate['seq']
    translator = Translator(recorder, client_factory, artifact_dir,
                            model=_ORACLE_MODEL)
    binding = {'execution_id': execution_id, 'event_id': event_id,
               'access_kind': access_kind, 'side': side,
               'scope': observations[0]['scope'] if observations else ''}
    try:
        emission_id = translator.finalize(explanation, source_seq,
                                          observations, binding)
    except Exception as exc:
        raise OracleError(f'translator did not emit a valid certificate: '
                          f'{type(exc).__name__}: {exc}') from None
    if emission_id is None:
        raise OracleError('translator abstained; no certificate emitted')
    claim = recorder.claim(f'{execution_id}/{event_id}', access_kind, side,
                           emission_id)
    if not isinstance(claim, dict) or claim.get('status') != 'RECORDED':
        raise OracleError(f'claim was not accepted by the recorder: {claim}')
    code = runner.publish()
    if code != 0 or not out_path.is_file():
        raise OracleError(f'runner did not publish a bundle (exit {code})')
    return json.loads(out_path.read_text(encoding='utf-8'))


def verify_oracle_bundle(bundle: dict, *, key: bytes, lean: str,
                         timeout: float = 10.0) -> tuple[dict, dict]:
    """Assemble the direct certificate and verify it; returns (cert, report)."""
    payload = bundle['payload']
    bundle_sha256 = sha256_hex(canonical_json(payload))
    cert = assemble_direct_certificate(payload, ARGUMENT_ID,
                                       bundle_sha256=bundle_sha256)
    report = verify_certificate(bundle, cert, key=key, lean=lean,
                                timeout=timeout)
    return cert, report


def run_oracle_mode(corpus, task_id: str, *, oracle_poc: bytes,
                    work_dir, key_path, lean, out_dir,
                    side: str = 'upper', access_kind: str = 'read',
                    steps: list[dict] | None = None, client_factory=None,
                    difficulty: str = 'level1', explanation: str | None = None,
                    target_build: str = 'vul', backend=None,
                    docker: str = 'docker') -> dict:
    """End-to-end Mode-A run for one task; persists artifacts, returns a summary.

    With ``backend=None`` a real ``CybergymBackend`` is built (Docker + a
    bootstrapped ``work_dir`` required). ``steps`` defaults to
    ``read_upper_oob_steps`` for the upper-read family; supply the matching
    explicit argument for other accesses.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    key = Path(key_path).read_bytes()
    require(len(key) == 32, 'runner key must be 32 bytes')
    if steps is None and client_factory is None:
        require(side == 'upper' and access_kind == 'read',
                'the default steps generator only covers the upper-read '
                'family; supply explicit steps or a translator client_factory')
        steps = read_upper_oob_steps(6, 4, 4)
    if backend is None:
        from soundtrace_live.cybergym_backend import CybergymBackend
        backend = CybergymBackend(corpus, Path(work_dir), docker=docker)

    bundle_path = out_dir / 'bundle.json'
    summary: dict[str, Any] = {'mode': 'oracle-assisted', 'task_id': task_id,
                               'side': side, 'access_kind': access_kind,
                               'target_build': target_build}
    try:
        bundle = run_oracle_session(
            backend, key, bundle_path, task_id=task_id, oracle_poc=oracle_poc,
            steps=steps, client_factory=client_factory, side=side,
            access_kind=access_kind, difficulty=difficulty,
            explanation=explanation, target_build=target_build,
            artifact_dir=out_dir / 'translator-artifacts')
    except (OracleError, Rejected) as exc:
        summary['status'] = 'ORACLE_SESSION_FAILED'
        summary['diagnostic'] = str(exc)
        (out_dir / 'result.json').write_text(
            json.dumps(summary, indent=2) + '\n', encoding='utf-8')
        return summary

    cert, report = verify_oracle_bundle(bundle, key=key, lean=lean)
    (out_dir / 'certificate.json').write_text(
        canonical_json(cert).decode() + '\n', encoding='utf-8')
    summary['checker_status'] = report.get('status')
    summary['checker_reason'] = report.get('reason')
    summary['claim_id'] = report.get('claim_id')
    summary['run_id'] = bundle['payload']['run_id']
    summary['status'] = ('VERIFIED' if report.get('status')
                         == 'VERIFIED_EVIDENCE_AND_KERNEL' else 'NOT_VERIFIED')
    (out_dir / 'result.json').write_text(
        json.dumps(summary, indent=2) + '\n', encoding='utf-8')
    return summary
