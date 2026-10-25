"""CyberGym runner contract tests against a fake capture backend.

These were written first against the fixture-only runner (where they failed:
no probe kind, no cybergym bundle format, no translation bookkeeping) and are
retained as passing regressions. The fake backend stands in for
`soundtrace_live.cybergym_backend.CybergymBackend`: same constructor contract,
same execution-record schema, same CaptureError classification — no Docker.
"""
import io
import json
import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from evidence import Rejected, canonical_json, mac_hex, sha256_hex
from runner import _Session, validate_bundle
from soundtrace_live.corpus import load_corpus
from soundtrace_live.cybergym_backend import CaptureError
from soundtrace_live.cybergym_adapter import CANONICAL_ASAN_OPTIONS
from test_cybergym_adapter import POC, TASK, event
from test_cybergym_direct import STEPS, attempt_hash, build as build_record_stub

KEY = b'cybergym-runner-key-32-bytes-xxxx'
CORPUS = load_corpus(ROOT / 'corpora/cybergym_pilot.json')


class FakeCaptureError(CaptureError):
    def __init__(self, diagnostic):
        super().__init__('INCONCLUSIVE_CAPTURE', diagnostic)


def fake_execution(execution_id, poc_sha256=POC, exit_code=1, events=None):
    return {'id': execution_id, 'task_id': TASK, 'poc_sha256': poc_sha256,
            'poc_size': 4, 'image_ref': 'n132/arvo:368-vul@sha256:' + 'b' * 64,
            'image_digest': 'sha256:' + 'b' * 64, 'platform': 'linux/amd64',
            'command': ['/usr/bin/timeout', '-s', 'KILL', '10', '/bin/arvo'],
            'exit_code': exit_code, 'signal': None,
            'oom_killed': False, 'timed_out': False, 'pointer_bits': 64,
            'asan_options': CANONICAL_ASAN_OPTIONS,
            'events': [event()] if events is None else events,
            'stdout_sha256': 'c' * 64, 'stdout_bytes': 0,
            'stderr_sha256': 'd' * 64, 'stderr_bytes': 0,
            'stdout_excerpt': '', 'stderr_excerpt': ''}


class FakeBackend:
    """Duck-typed stand-in for CybergymBackend (no Docker)."""

    def __init__(self, script=None):
        self.corpus = CORPUS
        self.script = script or [('ok', fake_execution('X1'))]
        self.calls = []

    def validate_execution(self, execution):
        return None

    def validate_build(self, build):
        return None

    def build_record(self):
        return build_record_stub()
    def execute_probe(self, task_id, poc_sha256, execution_id, *,
                      host_timeout=30.0):
        self.calls.append((task_id, poc_sha256, execution_id))
        if not self.script:
            raise FakeCaptureError('no script left')
        tag, value = self.script.pop(0)
        if tag == 'err':
            raise FakeCaptureError(value)
        return value if tag == 'ok' else dict(value, id=execution_id)


class SessionDriver:
    """Feeds requests to a real _Session and captures emitted responses."""

    def __init__(self, backend):
        self.out = Path('/tmp/cg-test-bundle.json')
        self.session = _Session(KEY, self.out, backend=backend)
        self.responses = []
        self.exit = 0

    def send(self, request):
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.exit = self.session.dispatch(request)
        line = buf.getvalue().strip()
        self.responses.append(json.loads(line) if line else None)
        return self.responses[-1]

    def publish(self):
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = self.session.publish()
        return code, buf.getvalue()

    def bundle(self):
        return json.loads(self.out.read_text())


def drive_happy_path(backend=None, steps=None):
    steps = steps if steps is not None else [dict(s) for s in STEPS]
    driver = SessionDriver(backend or FakeBackend())
    resp = driver.send({'kind': 'model_session', 'argument_id': 'C1',
                        'session_sha256': '1' * 64, 'difficulty': 'level1',
                        'target_model': 'gpt-daybreak-blue-latest',
                        'translator_model': 'gpt-5.6-luna',
                        'prompt_sha256': '2' * 64, 'input_sha256': '3' * 64})
    probe = driver.send({'kind': 'probe', 'task_id': TASK, 'poc_sha256': POC,
                         'poc_size': 4})
    narrate = driver.send({'kind': 'narrate', 'argument_id': 'C1',
                           'text': 'final: heap read four bytes past a six-byte region'})
    attempt = driver.send({'kind': 'translation_attempt', 'argument_id': 'C1',
                           'attempt_id': 'T1', 'source_seq': narrate['seq'],
                           'model': 'gpt-5.6-luna', 'resolved_model': 'gpt-5.6-luna',
                           'raw_output_sha256': 'e' * 64, 'raw_output_bytes': 400,
                           'parsed_sha256': attempt_hash('goal', steps),
                           'outcome': 'emit', 'repair': 0})
    emit = driver.send({'kind': 'emit', 'argument_id': 'C1', 'id': 'goal',
                        'steps': steps, 'attempt_id': 'T1',
                        'source_seq': narrate['seq']})
    claim = driver.send({'kind': 'claim', 'argument_id': 'C1', 'event': 'X1/A1',
                         'access_kind': 'read', 'side': 'upper', 'from': 'goal'})
    return driver, {'session': resp, 'probe': probe, 'narrate': narrate,
                    'attempt': attempt, 'emit': emit, 'claim': claim}


class RunnerCybergymTests(unittest.TestCase):
    def test_probe_recorded_with_five_observations(self):
        driver, out = drive_happy_path()
        self.assertEqual(out['session']['status'], 'RECORDED')
        self.assertEqual(out['probe']['status'], 'RECORDED')
        self.assertEqual(out['probe']['execution_id'], 'X1')
        self.assertEqual(out['probe']['event_id'], 'A1')
        self.assertEqual([o['id'] for o in out['probe']['observations']],
                         ['X1/A1.access', 'X1/A1.live', 'X1/A1.extent',
                          'X1/A1.width', 'X1/A1.offset'])
        self.assertEqual(out['emit']['status'], 'RECORDED')
        self.assertEqual(out['claim']['status'], 'RECORDED')

    def test_full_bundle_validates_and_mac_matches(self):
        driver, _ = drive_happy_path()
        code, _ = driver.publish()
        self.assertEqual(code, 0)
        bundle = driver.bundle()
        validate_bundle(bundle)
        payload = bundle['payload']
        self.assertEqual(payload['format'], 'soundtrace-cybergym-run-v1')
        self.assertEqual(payload['producer'], 'cybergym-asan-v1')
        self.assertEqual(payload['build']['tasks'][TASK]['vul_digest'],
                         'sha256:' + 'b' * 64)
        self.assertEqual(mac_hex(KEY, canonical_json(payload)),
                         bundle['hmac_sha256'])
        frozen = payload['claims']['C1']['frozen']
        self.assertEqual(frozen['state'], 'bound')
        self.assertEqual(frozen['binding']['task_id'], TASK)
        self.assertEqual(frozen['binding']['poc_sha256'], POC)

    def test_clean_probe_records_no_observations(self):
        backend = FakeBackend(script=[('ok', fake_execution('X1', exit_code=0,
                                                            events=[]))])
        driver = SessionDriver(backend)
        resp = driver.send({'kind': 'probe', 'task_id': TASK, 'poc_sha256': POC,
                            'poc_size': 4})
        self.assertEqual(resp['status'], 'RECORDED')
        self.assertIsNone(resp['event_id'])
        self.assertEqual(resp['observations'], [])
        self.assertEqual(len(driver.session.executions), 1)

    def test_inconclusive_probe_continues_session(self):
        backend = FakeBackend(script=[('err', 'emulation failure')])
        driver = SessionDriver(backend)
        resp = driver.send({'kind': 'probe', 'task_id': TASK, 'poc_sha256': POC,
                            'poc_size': 4})
        self.assertEqual(resp['status'], 'INCONCLUSIVE_CAPTURE')
        self.assertIn('emulation failure', resp['diagnostic'])
        self.assertEqual(driver.exit, 0)  # session not aborted
        after = driver.send({'kind': 'narrate', 'argument_id': 'C1', 'text': 'still going'})
        self.assertEqual(after['status'], 'RECORDED')
        self.assertEqual(driver.session.executions, [])

    def test_unknown_task_and_bad_poc_fields_rejected(self):
        driver = SessionDriver(FakeBackend())
        for bad in ({'task_id': 'arvo:999', 'poc_sha256': POC, 'poc_size': 4},
                    {'task_id': TASK, 'poc_sha256': 'XYZ', 'poc_size': 4},
                    {'task_id': TASK, 'poc_sha256': POC, 'poc_size': -1},
                    {'task_id': TASK, 'poc_sha256': POC, 'poc_size': 1 << 21}):
            resp = driver.send({'kind': 'probe', **bad})
            self.assertEqual(resp['status'], 'REJECTED', bad)
            self.assertEqual(resp['reason'], 'BAD_INPUT')
            self.assertEqual(driver.exit, 1)
            driver = SessionDriver(FakeBackend())

    def test_run_requests_rejected_under_cybergym(self):
        driver = SessionDriver(FakeBackend())
        resp = driver.send({'kind': 'run', 'case': 'read_upper'})
        self.assertEqual((resp['status'], resp['reason']), ('REJECTED', 'BAD_INPUT'))

    def test_emit_hash_must_match_attempt(self):
        steps = [dict(s) for s in STEPS]
        driver = SessionDriver(FakeBackend())
        driver.send({'kind': 'probe', 'task_id': TASK, 'poc_sha256': POC, 'poc_size': 4})
        narrate = driver.send({'kind': 'narrate', 'argument_id': 'C1', 'text': 'x'})
        driver.send({'kind': 'translation_attempt', 'argument_id': 'C1',
                     'attempt_id': 'T1', 'source_seq': narrate['seq'],
                     'model': 'm', 'resolved_model': 'm',
                     'raw_output_sha256': 'e' * 64, 'raw_output_bytes': 1,
                     'parsed_sha256': 'f' * 64, 'outcome': 'emit', 'repair': 0})
        resp = driver.send({'kind': 'emit', 'argument_id': 'C1', 'id': 'goal',
                            'steps': steps, 'attempt_id': 'T1',
                            'source_seq': narrate['seq']})
        self.assertEqual((resp['status'], resp['reason']), ('REJECTED', 'BAD_INPUT'))
        self.assertIn('byte-match', resp['diagnostic'])

    def test_emit_requires_real_narration_source(self):
        steps = [dict(s) for s in STEPS]
        driver = SessionDriver(FakeBackend())
        driver.send({'kind': 'probe', 'task_id': TASK, 'poc_sha256': POC, 'poc_size': 4})
        driver.send({'kind': 'narrate', 'argument_id': 'C1', 'text': 'x'})
        driver.send({'kind': 'translation_attempt', 'argument_id': 'C1',
                     'attempt_id': 'T1', 'source_seq': 3,
                     'model': 'm', 'resolved_model': 'm',
                     'raw_output_sha256': 'e' * 64, 'raw_output_bytes': 1,
                     'parsed_sha256': attempt_hash('goal', steps),
                     'outcome': 'emit', 'repair': 0})
        resp = driver.send({'kind': 'emit', 'argument_id': 'C1', 'id': 'goal',
                            'steps': steps, 'attempt_id': 'T1', 'source_seq': 999})
        self.assertEqual(resp['reason'], 'BAD_INPUT')

    def test_no_retroactive_evidence_live(self):
        steps = [dict(s) for s in STEPS]
        driver = SessionDriver(FakeBackend())
        # Narration FIRST, probe after: the narration cannot cite the probe.
        narrate = driver.send({'kind': 'narrate', 'argument_id': 'C1', 'text': 'final'})
        driver.send({'kind': 'probe', 'task_id': TASK, 'poc_sha256': POC, 'poc_size': 4})
        driver.send({'kind': 'translation_attempt', 'argument_id': 'C1',
                     'attempt_id': 'T1', 'source_seq': narrate['seq'],
                     'model': 'm', 'resolved_model': 'm',
                     'raw_output_sha256': 'e' * 64, 'raw_output_bytes': 1,
                     'parsed_sha256': attempt_hash('goal', steps),
                     'outcome': 'emit', 'repair': 0})
        resp = driver.send({'kind': 'emit', 'argument_id': 'C1', 'id': 'goal',
                            'steps': steps, 'attempt_id': 'T1',
                            'source_seq': narrate['seq']})
        self.assertEqual(resp['reason'], 'BAD_INPUT')
        self.assertIn('not yet delivered', resp['diagnostic'])

    def test_abstention_closes_argument(self):
        driver, out = drive_happy_path()
        driver.session.closed_arguments.clear()  # simulate a second argument flow
        source_seq = out['narrate']['seq']
        resp = driver.send({'kind': 'translation_abstain', 'argument_id': 'C1',
                            'abstain_id': 'AB1', 'source_seq': source_seq,
                            'reason': 'OUT_OF_LANGUAGE', 'diagnostic': 'x'})
        self.assertEqual(resp['status'], 'RECORDED')
        steps = [{'op': 'compute', 'formula': ['lt', 1, 2]}]
        driver.send({'kind': 'translation_attempt', 'argument_id': 'C1',
                     'attempt_id': 'T2', 'source_seq': source_seq, 'model': 'm',
                     'resolved_model': 'm', 'raw_output_sha256': 'e' * 64,
                     'raw_output_bytes': 1,
                     'parsed_sha256': attempt_hash('late', steps),
                     'outcome': 'emit', 'repair': 0})
        resp = driver.send({'kind': 'emit', 'argument_id': 'C1', 'id': 'late',
                            'steps': steps, 'attempt_id': 'T2',
                            'source_seq': source_seq})
        self.assertEqual(resp['reason'], 'BAD_INPUT')
        self.assertIn('abstention', resp['diagnostic'])

    def test_claim_from_abstention_is_unsupported_translation(self):
        backend = FakeBackend()
        driver = SessionDriver(backend)
        driver.send({'kind': 'probe', 'task_id': TASK, 'poc_sha256': POC, 'poc_size': 4})
        narrate = driver.send({'kind': 'narrate', 'argument_id': 'C1', 'text': 'x'})
        driver.send({'kind': 'translation_abstain', 'argument_id': 'C1',
                     'abstain_id': 'AB1', 'source_seq': narrate['seq'],
                     'reason': 'UNPARSEABLE', 'diagnostic': 'gave up'})
        resp = driver.send({'kind': 'claim', 'argument_id': 'C1', 'event': 'X1/A1',
                            'access_kind': 'read', 'side': 'upper', 'from': 'AB1'})
        self.assertEqual(resp['status'], 'UNSUPPORTED_TRANSLATION')
        code, _ = driver.publish()
        self.assertEqual(code, 0)
        frozen = driver.bundle()['payload']['claims']['C1']['frozen']
        self.assertEqual((frozen['state'], frozen['reason']),
                         ('unsupported', 'UNSUPPORTED_TRANSLATION'))

    def test_audit_kinds_accepted_and_shape_checked(self):
        driver = SessionDriver(FakeBackend())
        ok = driver.send({'kind': 'agent_action', 'argument_id': 'C1',
                          'call_id': 'c1', 'tool': 'shell',
                          'input_sha256': 'a' * 64, 'input_bytes': 10})
        self.assertEqual(ok['status'], 'RECORDED')
        ok = driver.send({'kind': 'agent_result', 'argument_id': 'C1',
                          'call_id': 'c1', 'tool': 'shell',
                          'content_sha256': 'a' * 64, 'content_bytes': 10,
                          'excerpt': 'ok'})
        self.assertEqual(ok['status'], 'RECORDED')
        driver2 = SessionDriver(FakeBackend())
        bad = driver2.send({'kind': 'agent_result', 'argument_id': 'C1',
                            'call_id': 'c1', 'tool': 'probe',
                            'content_sha256': 'a' * 64, 'content_bytes': 10,
                            'excerpt': 'x' * 2000})
        self.assertEqual((bad['status'], bad['reason']), ('REJECTED', 'BAD_INPUT'))

    def test_audit_provider_fields_optional_but_shape_checked(self):
        driver = SessionDriver(FakeBackend())
        session = driver.send({'kind': 'model_session', 'argument_id': 'C1',
                               'session_sha256': '1' * 64,
                               'difficulty': 'level1',
                               'target_model': 'glm-5.3',
                               'translator_model': 'kimi-k3.1',
                               'target_provider': 'zai',
                               'translator_provider': 'moonshot',
                               'prompt_sha256': '2' * 64,
                               'input_sha256': '3' * 64})
        self.assertEqual(session['status'], 'RECORDED')
        turn = driver.send({'kind': 'model_turn', 'argument_id': 'C1',
                            'turn': 0, 'role': 'target',
                            'requested_model': 'glm-5.3',
                            'resolved_model': 'glm-5.3',
                            'response_sha256': '4' * 64,
                            'output_bytes': 10, 'status': 'completed',
                            'input_tokens': 1, 'output_tokens': 2,
                            'provider': 'zai'})
        self.assertEqual(turn['status'], 'RECORDED')
        # Records without the optional fields still pass.
        plain_session = SessionDriver(FakeBackend()).send(
            {'kind': 'model_session', 'argument_id': 'C1',
             'session_sha256': '1' * 64, 'difficulty': 'level1',
             'target_model': 'glm-5.3', 'translator_model': 'kimi-k3.1',
             'prompt_sha256': '2' * 64, 'input_sha256': '3' * 64})
        self.assertEqual(plain_session['status'], 'RECORDED')
        bad_driver = SessionDriver(FakeBackend())
        bad = bad_driver.send({'kind': 'model_turn', 'argument_id': 'C1',
                               'turn': 0, 'role': 'target',
                               'requested_model': 'glm-5.3',
                               'resolved_model': 'glm-5.3',
                               'response_sha256': '4' * 64,
                               'output_bytes': 10, 'status': 'completed',
                               'input_tokens': 1, 'output_tokens': 2,
                               'provider': 'Bad Provider'})
        self.assertEqual((bad['status'], bad['reason']),
                         ('REJECTED', 'BAD_INPUT'))

    def test_bundle_with_provider_fields_validates(self):
        driver = SessionDriver(FakeBackend())
        driver.send({'kind': 'model_session', 'argument_id': 'C1',
                     'session_sha256': '1' * 64, 'difficulty': 'level1',
                     'target_model': 'glm-5.3',
                     'translator_model': 'kimi-k3.1',
                     'target_provider': 'zai',
                     'translator_provider': 'moonshot',
                     'prompt_sha256': '2' * 64, 'input_sha256': '3' * 64})
        probe = driver.send({'kind': 'probe', 'task_id': TASK,
                             'poc_sha256': POC, 'poc_size': 4})
        narrate = driver.send({'kind': 'narrate', 'argument_id': 'C1',
                               'text': 'final: heap read four bytes past '
                                       'a six-byte region'})
        steps = [dict(s) for s in STEPS]
        driver.send({'kind': 'translation_attempt', 'argument_id': 'C1',
                     'attempt_id': 'T1', 'source_seq': narrate['seq'],
                     'model': 'kimi-k3.1', 'resolved_model': 'kimi-k3.1',
                     'raw_output_sha256': 'e' * 64, 'raw_output_bytes': 400,
                     'parsed_sha256': attempt_hash('goal', steps),
                     'outcome': 'emit', 'repair': 0})
        driver.send({'kind': 'emit', 'argument_id': 'C1', 'id': 'goal',
                     'steps': steps, 'attempt_id': 'T1',
                     'source_seq': narrate['seq']})
        driver.send({'kind': 'claim', 'argument_id': 'C1',
                     'event': 'X1/A1', 'access_kind': 'read',
                     'side': 'upper', 'from': 'goal'})
        code, output = driver.publish()
        self.assertEqual(code, 0, output)
        validate_bundle(driver.bundle())

    def test_fixture_backend_still_rejects_probe(self):
        session = _Session(KEY, Path('/tmp/cg-fixture-bundle.json'))
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = session.dispatch({'kind': 'probe', 'task_id': TASK,
                                     'poc_sha256': POC, 'poc_size': 4})
        resp = json.loads(buf.getvalue().strip())
        self.assertEqual((resp['status'], resp['reason']), ('REJECTED', 'BAD_INPUT'))
        self.assertEqual(code, 1)


class DeadlineAndScopeTests(unittest.TestCase):
    def model_session(self, driver):
        return driver.send({'kind': 'model_session', 'argument_id': 'C1',
                            'session_sha256': '1' * 64, 'difficulty': 'level1',
                            'target_model': 'gpt-daybreak-blue-latest',
                            'translator_model': 'gpt-5.6-luna',
                            'prompt_sha256': '2' * 64,
                            'input_sha256': '3' * 64})

    def test_near_deadline_probe_is_nonfatal_response(self):
        import time
        driver = SessionDriver(FakeBackend())
        self.model_session(driver)
        os.environ['SOUNDTRACE_TASK_DEADLINE'] = str(time.monotonic() + 5.0)
        try:
            resp = driver.send({'kind': 'probe', 'task_id': TASK,
                                'poc_sha256': POC, 'poc_size': 4})
        finally:
            os.environ.pop('SOUNDTRACE_TASK_DEADLINE', None)
        self.assertEqual(resp['status'], 'INCONCLUSIVE_CAPTURE')
        self.assertIn('cleanup', resp['diagnostic'])
        self.assertEqual(driver.exit, 0)
        # The session survives: a later narration still records.
        narrate = driver.send({'kind': 'narrate', 'argument_id': 'C1',
                               'text': 'the session continues'})
        self.assertEqual(narrate['status'], 'RECORDED')

    def test_invalid_deadline_rejects_setup(self):
        driver = SessionDriver(FakeBackend())
        self.model_session(driver)
        os.environ['SOUNDTRACE_TASK_DEADLINE'] = 'not-a-float'
        try:
            resp = driver.send({'kind': 'probe', 'task_id': TASK,
                                'poc_sha256': POC, 'poc_size': 4})
        finally:
            os.environ.pop('SOUNDTRACE_TASK_DEADLINE', None)
        self.assertEqual(resp['status'], 'INCONCLUSIVE_SETUP')
        self.assertEqual(resp['reason'], 'INCONCLUSIVE_SETUP')
        self.assertEqual(driver.exit, 2)

    def test_malformed_execution_is_nonfatal(self):
        bad = dict(fake_execution('X1'), stdout_excerpt='�' * 4096)
        driver = SessionDriver(FakeBackend([('ok', bad)]))
        self.model_session(driver)
        resp = driver.send({'kind': 'probe', 'task_id': TASK,
                            'poc_sha256': POC, 'poc_size': 4})
        self.assertEqual(resp['status'], 'INCONCLUSIVE_CAPTURE')
        self.assertEqual(driver.exit, 0)
        narrate = driver.send({'kind': 'narrate', 'argument_id': 'C1',
                               'text': 'still alive'})
        self.assertEqual(narrate['status'], 'RECORDED')

    def test_execution_scope_cap_is_nonfatal(self):
        # oss-fuzz:42535201 admits at most X9 under the 128-char id cap.
        script = [('ok', dict(fake_execution(f'X{i}'),
                              task_id='oss-fuzz:42535201'))
                  for i in range(1, 10)]
        driver = SessionDriver(FakeBackend(script))
        self.model_session(driver)
        for _ in range(9):
            resp = driver.send({'kind': 'probe', 'task_id': 'oss-fuzz:42535201',
                                'poc_sha256': POC, 'poc_size': 4})
            self.assertEqual(resp['status'], 'RECORDED')
        tenth = driver.send({'kind': 'probe', 'task_id': 'oss-fuzz:42535201',
                             'poc_sha256': POC, 'poc_size': 4})
        self.assertEqual(tenth['status'], 'INCONCLUSIVE_CAPTURE')
        self.assertIn('identifier cap', tenth['diagnostic'])
        self.assertEqual(driver.exit, 0)


if __name__ == '__main__':
    unittest.main()
