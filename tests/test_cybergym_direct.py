"""CyberGym direct-path regressions, parallel to tests/test_direct.py.

A signed `soundtrace-cybergym-run-v1` payload with probe/narrate/attempt/
emit/claim must assemble and verify to VERIFIED_EVIDENCE_AND_KERNEL under a
fake kernel; every forgery, retroaction, abstention, and substitution path
must land in its specific rejection class — never a traceback and never an
invented proof.
"""
import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from checker import verify_certificate
from direct import DirectError, assemble_direct_certificate
from evidence import canonical_json, mac_hex, sha256_hex
from soundtrace_live import cybergym_adapter as ca
from test_checker import fake_lean, GOOD_LEAN
from test_cybergym_adapter import DIGEST, POC, RUN_ID, TASK, event, execution

KEY = b'cybergym-direct-key-32-bytes-xxxx'
OTHER_KEY = b'cybergym-other-key-32-bytes-yyyy'

_lines = (ROOT / 'examples/sessions/direct_read_upper.jsonl').read_text().splitlines()
STEPS = [s for l in _lines if (e := json.loads(l)).get('kind') == 'emit'
         for s in e['steps']]


def attempt_hash(emit_id, steps):
    return sha256_hex(canonical_json({'id': emit_id, 'steps': steps}))


def build(task_fields=None):
    tasks = {
        TASK: dict({
            'kind': 'arvo', 'project': 'freetype2',
            'vul_ref': 'n132/arvo:368-vul@sha256:' + 'b' * 64,
            'vul_digest': DIGEST,
            'fix_ref': 'n132/arvo:368-fix@sha256:' + 'c' * 64,
            'fix_digest': 'sha256:' + 'c' * 64,
            'command_vul': ['/bin/arvo'],
            'archive_sha256': '6' * 64,
            'description_sha256': '7' * 64,
        }, **(task_fields or {})),
        'oss-fuzz:42535201': {
            'kind': 'oss-fuzz', 'project': 'assimp',
            'vul_ref': 'n132/arvo:368-vul@sha256:' + 'b' * 64,
            'vul_digest': DIGEST,
            'fix_ref': 'n132/arvo:368-fix@sha256:' + 'c' * 64,
            'fix_digest': 'sha256:' + 'c' * 64,
            'command_vul': ['/bin/arvo'],
            'archive_sha256': '8' * 64,
            'description_sha256': '9' * 64,
        },
    }
    return {'corpus_sha256': '1' * 64, 'lock_sha256': '2' * 64,
            'probe_source_sha256': '3' * 64, 'probe_dso_sha256': '4' * 64,
            'docker_version': '28.0.4', 'docker_platform': 'linux/amd64',
            'agent_image_digest': 'sha256:' + '5' * 64, 'tasks': tasks}


def make_payload(steps=None, *, side='upper', access_kind='read', frm='goal',
                 abstain=False, probe_delivered=2, execution_over=None,
                 second_execution=None, mutate_emit=None, emit_present=True,
                 evidence_task=None):
    """Trace: probe(1,2) narrate(3,4) attempt(5,6) emit(7,8) claim(9,10)."""
    steps = steps if steps is not None else copy.deepcopy(STEPS)
    ex = execution(**(execution_over or {}))
    executions = [ex]
    trace = [
        {'seq': 1, 'kind': 'request',
         'body': {'kind': 'probe', 'task_id': TASK, 'poc_sha256': POC, 'poc_size': 4}},
        {'seq': probe_delivered, 'kind': 'response', 'request_seq': 1,
         'body': {'status': 'RECORDED', 'execution_id': 'X1', 'event_id': 'A1',
                  'poc_sha256': POC,
                  'observations': [
                      {'id': 'X1/A1.access', 'formula': ['atom', 'access'],
                       'scope': 's', 'available_at': probe_delivered},
                      {'id': 'X1/A1.live', 'formula': ['atom', 'live'],
                       'scope': 's', 'available_at': probe_delivered},
                      {'id': 'X1/A1.extent', 'formula': ['eq', 'extent',
                                                         ex['events'][0]['region_extent']],
                       'scope': 's', 'available_at': probe_delivered},
                      {'id': 'X1/A1.width', 'formula': ['eq', 'width',
                                                       ex['events'][0]['width']],
                       'scope': 's', 'available_at': probe_delivered},
                      {'id': 'X1/A1.offset', 'formula': ['eq', 'offset',
                                                        ex['events'][0]['address']
                                                        - ex['events'][0]['region_base']],
                       'scope': 's', 'available_at': probe_delivered}]}},
        {'seq': 3, 'kind': 'request',
         'body': {'kind': 'narrate', 'argument_id': 'C1', 'text': 'final report'}},
        {'seq': 4, 'kind': 'response', 'request_seq': 3,
         'body': {'status': 'RECORDED', 'argument_id': 'C1', 'seq': 3}},
        {'seq': 5, 'kind': 'request',
         'body': {'kind': 'translation_attempt', 'argument_id': 'C1',
                  'attempt_id': 'T1', 'source_seq': 3, 'model': 'gpt-5.6-luna',
                  'resolved_model': 'gpt-5.6-luna', 'raw_output_sha256': 'e' * 64,
                  'raw_output_bytes': 400,
                  'parsed_sha256': attempt_hash(frm if not abstain else frm,
                                                [] if abstain else steps),
                  'outcome': 'abstain' if abstain else 'emit', 'repair': 0}},
        {'seq': 6, 'kind': 'response', 'request_seq': 5,
         'body': {'status': 'RECORDED', 'attempt_id': 'T1'}},
    ]
    if abstain:
        trace += [
            {'seq': 7, 'kind': 'request',
             'body': {'kind': 'translation_abstain', 'argument_id': 'C1',
                      'abstain_id': 'AB1', 'source_seq': 3,
                      'reason': 'OUT_OF_LANGUAGE', 'diagnostic': 'beyond the language'}},
            {'seq': 8, 'kind': 'response', 'request_seq': 7,
             'body': {'status': 'RECORDED', 'abstain_id': 'AB1'}}]
    elif emit_present:
        emit_body = {'kind': 'emit', 'argument_id': 'C1', 'id': frm,
                     'steps': steps, 'attempt_id': 'T1', 'source_seq': 3}
        if mutate_emit:
            mutate_emit(emit_body, steps)
            emit_body['steps'] = steps
        trace += [
            {'seq': 7, 'kind': 'request', 'body': emit_body},
            {'seq': 8, 'kind': 'response', 'request_seq': 7,
             'body': {'status': 'RECORDED', 'argument_id': 'C1', 'emission_id': frm,
                      'steps': len(steps), 'source_seq': 3}}]
    claim = {'kind': 'claim', 'argument_id': 'C1', 'event': 'X1/A1',
             'access_kind': access_kind, 'side': side,
             'from': 'AB1' if abstain else frm}
    prefix = {'run_id': RUN_ID, 'executions': executions,
              'trace': [e for e in trace if e['seq'] <= 9]}
    frozen = ca.freeze_claim(prefix, claim, seq=9)
    claim_status = ('RECORDED' if frozen['state'] == 'bound'
                    else ('UNSUPPORTED_TRANSLATION'
                          if frozen.get('reason') == 'UNSUPPORTED_TRANSLATION'
                          else 'UNSUPPORTED_TRACE'))
    claim_response = {'status': claim_status, 'claim_id': 'C1'}
    if claim_status != 'RECORDED':
        claim_response['reason'] = frozen['reason']
    trace += [
        {'seq': 9, 'kind': 'request', 'body': claim},
        {'seq': 10, 'kind': 'response', 'request_seq': 9,
         'body': claim_response}]
    if second_execution:
        executions.append(second_execution)
    return {'format': 'soundtrace-cybergym-run-v1', 'run_id': RUN_ID,
            'producer': 'cybergym-asan-v1', 'build': build(),
            'executions': executions, 'trace': trace,
            'claims': {'C1': {'claim': claim, 'available_at': 9, 'frozen': frozen}}}


def sign(payload, key=KEY):
    return {'payload': payload, 'hmac_sha256': mac_hex(key, canonical_json(payload))}


class CybergymDirectTests(unittest.TestCase):
    def verify(self, payload, lean='/nonexistent/lean', key=KEY):
        bundle = sign(payload, key)
        bundle_sha256 = sha256_hex(canonical_json(payload))
        cert = assemble_direct_certificate(payload, 'C1', bundle_sha256=bundle_sha256)
        return verify_certificate(bundle, cert, key=key, lean=lean), cert

    def test_certifies_evidence_and_kernel(self):
        payload = make_payload()
        with tempfile.TemporaryDirectory() as tmp:
            result, _ = self.verify(payload, lean=fake_lean(tmp, GOOD_LEAN))
        self.assertEqual(result['status'], 'VERIFIED_EVIDENCE_AND_KERNEL')
        self.assertEqual(result['evidence_class'], 'cybergym-asan-v1')
        self.assertEqual(result['claim_id'], 'C1')
        self.assertEqual(result['backend']['axiom_audit'], 'empty')
        self.assertEqual(result['steps'], 20)
        self.assertIn('pinned CyberGym image', result['trust_boundary'])

    def test_assembly_shape(self):
        payload = make_payload()
        cert = assemble_direct_certificate(
            payload, 'C1', bundle_sha256=sha256_hex(canonical_json(payload)))
        self.assertEqual(len(cert['steps']), 20)
        self.assertEqual(len(cert['source_map']), 1)
        self.assertEqual(cert['source_map'][0]['source_id'], 'goal')

    def test_false_arithmetic_rejected(self):
        steps = copy.deepcopy(STEPS)
        for s in steps:
            if s['op'] == 'compute' and s['formula'][:2] == ['lt', 6]:
                s['formula'] = ['lt', 8, 6]
        payload = make_payload(steps)
        with tempfile.TemporaryDirectory() as tmp:
            result, _ = self.verify(payload, lean=fake_lean(tmp, GOOD_LEAN))
        self.assertEqual(result['status'], 'REJECTED')
        self.assertEqual(result['reason'], 'FALSE_ARITHMETIC')

    def test_invalid_inference_rejected(self):
        steps = copy.deepcopy(STEPS)
        for s in steps:
            if s['op'] == 'infer' and s['rule'] == 'lt_transport':
                s['formula'] = ['le', 'extent', ['add', 'offset', 'width']]
                break
        payload = make_payload(steps)
        with tempfile.TemporaryDirectory() as tmp:
            result, _ = self.verify(payload, lean=fake_lean(tmp, GOOD_LEAN))
        self.assertEqual(result['status'], 'REJECTED')
        self.assertEqual(result['reason'], 'INVALID_INFERENCE')

    def test_forged_observation_value_rejected(self):
        steps = copy.deepcopy(STEPS)
        for s in steps:
            if s['op'] == 'observe' and s['evidence'].endswith('.extent'):
                s['formula'] = ['eq', 'extent', 999]
        payload = make_payload(steps)
        with tempfile.TemporaryDirectory() as tmp:
            result, _ = self.verify(payload, lean=fake_lean(tmp, GOOD_LEAN))
        self.assertEqual(result['status'], 'REJECTED')
        self.assertEqual(result['reason'], 'EVIDENCE_CONFLICT')

    def test_cross_task_evidence_rejected(self):
        other = execution(id='X2', task_id='oss-fuzz:42535201',
                          poc_sha256='9' * 64, image_digest=DIGEST,
                          events=[event(address=0x7F0000000104)])
        steps = copy.deepcopy(STEPS)
        payload = make_payload(steps, second_execution=other)
        # re-target one observe at the other execution's evidence
        mutated_steps = copy.deepcopy(steps)
        mutated_steps[0] = {
            'op': 'observe', 'evidence': 'X2/A1.access',
            'formula': ['atom', 'access']}
        for entry in payload['trace']:
            if entry['kind'] == 'request' and entry['body'].get('kind') == 'emit':
                entry['body']['steps'] = mutated_steps
                entry['body']['attempt_id'] = 'T1'
        payload['trace'][4]['body']['parsed_sha256'] = attempt_hash(
            'goal', mutated_steps)
        with self.assertRaises(DirectError) as ctx:
            assemble_direct_certificate(payload, 'C1',
                                        bundle_sha256=sha256_hex(canonical_json(payload)))
        self.assertEqual(ctx.exception.reason, 'SOURCE_ALIGNMENT_FAILED')

    def test_retroactive_evidence_rejected(self):
        # probe response delivered (seq 2)... narrated at 3: fine. Now narrate
        # BEFORE the probe: narration at 3, evidence at 4.
        payload = make_payload(probe_delivered=4)
        # renumber: probe request 1, narrate 3/4, probe response must still be
        # a response to request 1 but delivered at 5 after the narration.
        for entry in payload['trace']:
            if entry['kind'] == 'response' and entry.get('request_seq') == 1:
                entry['seq'] = 5
                for record in entry['body']['observations']:
                    record['available_at'] = 5
        payload['trace'].sort(key=lambda e: e['seq'])
        with self.assertRaises(DirectError) as ctx:
            assemble_direct_certificate(payload, 'C1',
                                        bundle_sha256=sha256_hex(canonical_json(payload)))
        self.assertEqual(ctx.exception.reason, 'SOURCE_ALIGNMENT_FAILED')

    def test_altered_event_after_signing_mac_fails(self):
        payload = make_payload()
        bundle = sign(payload, KEY)
        payload['executions'][0]['events'][0]['region_extent'] = 60
        result = verify_certificate(bundle, {'claim_id': 'C1'}, key=KEY,
                                    lean='/nonexistent/lean')
        self.assertEqual((result['status'], result['reason']),
                         ('REJECTED', 'AUTHENTICATION_FAILED'))

    def test_altered_emission_mac_fails(self):
        payload = make_payload()
        mac = sign(payload, KEY)['hmac_sha256']
        for entry in payload['trace']:
            if entry['kind'] == 'request' and entry['body'].get('kind') == 'emit':
                entry['body']['steps'][0]['formula'] = ['atom', 'live']
        bundle = {'payload': payload, 'hmac_sha256': mac}
        result = verify_certificate(bundle, {'claim_id': 'C1'}, key=KEY,
                                    lean='/nonexistent/lean')
        self.assertEqual(result['reason'], 'AUTHENTICATION_FAILED')

    def test_offline_certificate_substitution_byte_mismatch(self):
        payload = make_payload()
        bundle = sign(payload)
        cert = assemble_direct_certificate(
            payload, 'C1', bundle_sha256=sha256_hex(canonical_json(payload)))
        cert['steps'][6]['formula'] = ['eq', ['add', 4, 4], 9]
        result = verify_certificate(bundle, cert, key=KEY, lean='/nonexistent/lean')
        self.assertEqual((result['status'], result['reason']),
                         ('REJECTED', 'SOURCE_ALIGNMENT_FAILED'))

    def test_abstention_is_unsupported_translation(self):
        payload = make_payload(abstain=True)
        with self.assertRaises(DirectError) as ctx:
            assemble_direct_certificate(payload, 'C1',
                                        bundle_sha256=sha256_hex(canonical_json(payload)))
        self.assertEqual(ctx.exception.status, 'UNSUPPORTED_TRANSLATION')
        bundle = sign(payload)
        result = verify_certificate(bundle, {'claim_id': 'C1'}, key=KEY,
                                    lean='/nonexistent/lean')
        self.assertEqual(result['status'], 'UNSUPPORTED_TRANSLATION')

    def test_no_emissions_missing_observation(self):
        payload = make_payload(emit_present=False)
        payload['claims']['C1']['frozen'] = {'state': 'rejected',
                                             'reason': 'UNKNOWN_SOURCE',
                                             'diagnostic': 'x'}
        payload['trace'][-1]['body']['status'] = 'REJECTED'
        with self.assertRaises(DirectError):
            assemble_direct_certificate(payload, 'C1',
                                        bundle_sha256=sha256_hex(canonical_json(payload)))

    def test_malformed_translator_step_is_bad_input(self):
        steps = copy.deepcopy(STEPS)
        steps[5] = {'op': 'infer', 'rule': 'not_a_rule', 'premises': [0],
                    'formula': ['atom', 'access']}
        payload = make_payload(steps)
        bundle = sign(payload)
        result = verify_certificate(bundle, {'claim_id': 'C1'}, key=KEY,
                                    lean='/nonexistent/lean')
        self.assertEqual((result['status'], result['reason']),
                         ('REJECTED', 'BAD_INPUT'))

    def test_wrong_image_binding_rejected(self):
        payload = make_payload()
        payload['build']['tasks'][TASK]['vul_digest'] = 'sha256:' + 'f' * 64
        bundle = sign(payload)
        result = verify_certificate(bundle, {'claim_id': 'C1'}, key=KEY,
                                    lean='/nonexistent/lean')
        self.assertEqual((result['status'], result['reason']),
                         ('REJECTED', 'BAD_INPUT'))

    def test_fixture_format_not_confused(self):
        payload = make_payload()
        payload['format'] = 'soundtrace-run-v1'
        bundle = sign(payload)
        result = verify_certificate(bundle, {'claim_id': 'C1'}, key=KEY,
                                    lean='/nonexistent/lean')
        self.assertEqual((result['status'], result['reason']),
                         ('REJECTED', 'BAD_INPUT'))


if __name__ == '__main__':
    unittest.main()
