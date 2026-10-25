"""Behavioral regressions for the direct-mode (signed-output) protocol.

The translator is untrusted: the runner signs its emissions live, the assembler
reconstructs the certificate from those signed emissions, and the checker
byte-matches and runs the kernel. Representable bad reasoning (false
arithmetic, invalid inference) must be recorded faithfully and rejected with a
specific reason, never accepted and never crash.
"""
import copy
import json
import secrets
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from evidence import canonical_json, mac_hex, sha256_hex
from oob_adapter import freeze_claim
from direct import DirectError, assemble_direct_certificate
from checker import verify_certificate
from test_checker import KEY, asan_events, fake_lean, GOOD_LEAN

_LINES = (ROOT / 'examples/sessions/direct_read_upper.jsonl').read_text().splitlines()
EMITS = [{'id': json.loads(l)['id'], 'steps': json.loads(l)['steps']}
         for l in _LINES if json.loads(l).get('kind') == 'emit']


def sign(payload, key=KEY):
    return {'payload': payload, 'hmac_sha256': mac_hex(key, canonical_json(payload))}


def make_direct_payload(events, emits, *, side='upper', access_kind='read',
                        exit_code=1, run_id=None, case='read_upper', frm=None):
    run_id = run_id or ('R' + secrets.token_hex(16))
    trace = [{'seq': 1, 'kind': 'request', 'body': {'kind': 'run', 'case': case}},
             {'seq': 2, 'kind': 'response', 'request_seq': 1,
              'body': {'status': 'RECORDED', 'execution_id': 'X1', 'event_id': 'A1'}}]
    seq = 3
    for em in emits:
        steps = copy.deepcopy(em['steps'])  # never share mutable module state
        trace.append({'seq': seq, 'kind': 'request',
                      'body': {'kind': 'emit', 'argument_id': 'C1', 'id': em['id'],
                               'steps': steps}})
        trace.append({'seq': seq + 1, 'kind': 'response', 'request_seq': seq,
                      'body': {'status': 'RECORDED', 'argument_id': 'C1',
                               'emission_id': em['id'], 'steps': len(steps)}})
        seq += 2
    frm = frm or emits[-1]['id']
    claim = {'kind': 'claim', 'argument_id': 'C1', 'event': 'X1/A1',
             'access_kind': access_kind, 'side': side, 'from': frm}
    trace.append({'seq': seq, 'kind': 'request', 'body': claim})
    trace.append({'seq': seq + 1, 'kind': 'response', 'request_seq': seq,
                  'body': {'status': 'RECORDED', 'claim_id': 'C1'}})
    execution = {'id': 'X1', 'case': case, 'pid': 1, 'pointer_bits': 64,
                 'asan_options': 'halt_on_error=1:abort_on_error=0:exitcode=1:'
                                 'detect_leaks=0:symbolize=0',
                 'exit_code': exit_code, 'events': events, 'stderr': ''}
    frozen = freeze_claim({'run_id': run_id, 'executions': [execution], 'trace': trace},
                          claim, seq=seq)
    return {'format': 'soundtrace-run-v1', 'run_id': run_id,
            'producer': 'controlled-c-asan-v1',
            'build': {'source_sha256': '0' * 64, 'binary_sha256': '1' * 64,
                      'compiler_version': 'probe', 'flags': ['-std=c11']},
            'executions': [execution], 'trace': trace,
            'claims': {'C1': {'claim': claim, 'available_at': seq, 'frozen': frozen}}}


def mutate_emits(fn):
    emits = copy.deepcopy(EMITS)
    fn(emits)
    return emits


class AssemblyTests(unittest.TestCase):
    def test_assembles_twenty_steps_thirteen_emissions(self):
        payload = make_direct_payload(asan_events(), EMITS)
        cert = assemble_direct_certificate(payload, 'C1',
                                           bundle_sha256=sha256_hex(canonical_json(payload)))
        self.assertEqual(len(cert['steps']), 20)
        self.assertEqual(len(cert['source_map']), 13)
        self.assertEqual(cert['source_map'][-1]['source_id'], 'goal')

    def test_unknown_evidence_rejected(self):
        def corrupt(emits):
            for em in emits:
                for step in em['steps']:
                    if step.get('op') == 'observe':
                        step['evidence'] = 'X9/A1.offset'
                        return
        payload = make_direct_payload(asan_events(), mutate_emits(corrupt))
        with self.assertRaises(DirectError) as ctx:
            assemble_direct_certificate(payload, 'C1',
                                        bundle_sha256=sha256_hex(canonical_json(payload)))
        self.assertEqual(ctx.exception.reason, 'SOURCE_ALIGNMENT_FAILED')


class DirectVerifyTests(unittest.TestCase):
    def verify(self, payload, lean='/nonexistent/lean'):
        bundle = sign(payload)
        bundle_sha256 = sha256_hex(canonical_json(payload))
        cert = assemble_direct_certificate(payload, 'C1', bundle_sha256=bundle_sha256)
        return verify_certificate(bundle, cert, key=KEY, lean=lean), bundle, cert

    def test_certifies_evidence_and_kernel(self):
        payload = make_direct_payload(asan_events(), EMITS)
        with tempfile.TemporaryDirectory() as tmp:
            result, _, _ = self.verify(payload, lean=fake_lean(tmp, GOOD_LEAN))
        self.assertEqual(result['status'], 'VERIFIED_EVIDENCE_AND_KERNEL')
        self.assertEqual(result['backend']['axiom_audit'], 'empty')
        self.assertEqual(result['steps'], 20)

    def test_false_arithmetic_recorded_and_rejected(self):
        def corrupt(emits):
            for em in emits:
                for step in em['steps']:
                    if step.get('op') == 'compute' and step['formula'][0] == 'eq' \
                            and isinstance(step['formula'][1], list) \
                            and step['formula'][1][0] == 'add':
                        step['formula'][2] = step['formula'][2] + 1  # 8 -> 9
                        return
        payload = make_direct_payload(asan_events(), mutate_emits(corrupt))
        result, _, _ = self.verify(payload)
        self.assertEqual(result['status'], 'REJECTED')
        self.assertEqual(result['reason'], 'FALSE_ARITHMETIC')

    def test_invalid_inference_rejected(self):
        def corrupt(emits):
            for em in emits:
                for step in em['steps']:
                    if step.get('op') == 'infer':
                        step['formula'] = ['eq', 'extent', 'width']  # not the rule's head
                        return
        payload = make_direct_payload(asan_events(), mutate_emits(corrupt))
        result, _, _ = self.verify(payload)
        self.assertEqual(result['status'], 'REJECTED')
        self.assertEqual(result['reason'], 'INVALID_INFERENCE')

    def test_forged_observation_value_rejected(self):
        def corrupt(emits):
            for em in emits:
                for step in em['steps']:
                    if step.get('op') == 'observe' and step['formula'][0] == 'eq':
                        step['formula'][2] = 999  # claim a value never delivered
                        return
        payload = make_direct_payload(asan_events(), mutate_emits(corrupt))
        result, _, _ = self.verify(payload)
        self.assertEqual(result['status'], 'REJECTED')
        self.assertEqual(result['reason'], 'EVIDENCE_CONFLICT')

    def test_tampered_emission_fails_mac(self):
        payload = make_direct_payload(asan_events(), EMITS)
        bundle = sign(payload)
        cert = assemble_direct_certificate(payload, 'C1',
                                           bundle_sha256=sha256_hex(canonical_json(payload)))
        # Flip a step in the signed bundle without re-signing.
        for entry in bundle['payload']['trace']:
            if entry['kind'] == 'request' and entry['body'].get('kind') == 'emit':
                entry['body']['steps'][0]['op'] = 'compute'
                break
        result = verify_certificate(bundle, cert, key=KEY, lean='/nonexistent/lean')
        self.assertEqual(result['reason'], 'AUTHENTICATION_FAILED')

    def test_offline_synthesized_certificate_rejected(self):
        payload = make_direct_payload(asan_events(), EMITS)
        bundle = sign(payload)
        cert = assemble_direct_certificate(payload, 'C1',
                                           bundle_sha256=sha256_hex(canonical_json(payload)))
        # A certificate that does not match the signed emissions (a dropped step)
        # must not be substitutable, even though it is otherwise well-formed.
        forged = copy.deepcopy(cert)
        forged['steps'] = forged['steps'][:-1]
        with tempfile.TemporaryDirectory() as tmp:
            result = verify_certificate(bundle, forged, key=KEY, lean=fake_lean(tmp, GOOD_LEAN))
        self.assertEqual(result['status'], 'REJECTED')
        self.assertEqual(result['reason'], 'SOURCE_ALIGNMENT_FAILED')

    def test_mixed_mode_rejected(self):
        payload = make_direct_payload(asan_events(), EMITS)
        # Splice a reason entry for the same argument and re-sign.
        payload['trace'].insert(2, {'seq': 0, 'kind': 'request',
                                    'body': {'kind': 'reason', 'argument_id': 'C1',
                                             'node': {'id': 'x', 'kind': 'observe'}}})
        for i, entry in enumerate(payload['trace']):
            entry['seq'] = i + 1
        bundle = sign(payload)
        cert = {'claim_id': 'C1'}
        result = verify_certificate(bundle, cert, key=KEY, lean='/nonexistent/lean')
        self.assertEqual(result['status'], 'REJECTED')
        self.assertEqual(result['reason'], 'BAD_INPUT')

    def test_last_step_not_frozen_target_is_claim_mismatch(self):
        # Drop the final 'goal' emission: the last emitted step now proves
        # 'alive' (a weaker formula) rather than the frozen upper-OOB target.
        emits = EMITS[:-1]
        payload = make_direct_payload(asan_events(), emits, frm=emits[-1]['id'])
        result, _, _ = self.verify(payload)
        self.assertEqual(result['status'], 'REJECTED')
        self.assertEqual(result['reason'], 'CLAIM_MISMATCH')


class LiveRunnerTests(unittest.TestCase):
    """Subprocess tests that the real runner records faithfully and enforces
    live provenance."""

    def _keyed(self, tmp):
        key = Path(tmp) / 'k'
        subprocess.run([sys.executable, 'runner.py', 'keygen', '--out', str(key)],
                       cwd=ROOT, capture_output=True, check=True)
        return key

    def _session(self, emits):
        lines = [json.dumps({'kind': 'run', 'case': 'read_upper'})]
        for em in emits:
            lines.append(json.dumps({'kind': 'emit', 'argument_id': 'C1',
                                     'id': em['id'], 'steps': em['steps']}))
        lines.append(json.dumps({'kind': 'claim', 'argument_id': 'C1', 'event': 'X1/A1',
                                 'access_kind': 'read', 'side': 'upper',
                                 'from': emits[-1]['id']}))
        return '\n'.join(lines) + '\n'

    def test_runner_records_bad_arithmetic_then_checker_rejects(self):
        def corrupt(emits):
            for em in emits:
                for step in em['steps']:
                    if step.get('op') == 'compute' and isinstance(step['formula'][1], list) \
                            and step['formula'][1][0] == 'add':
                        step['formula'][2] += 1
                        return
        emits = mutate_emits(corrupt)
        with tempfile.TemporaryDirectory() as tmp:
            key = self._keyed(tmp)
            bundle = Path(tmp) / 'b.json'
            proc = subprocess.run([sys.executable, 'runner.py', 'record', '--key', str(key),
                                   '--out', str(bundle)], cwd=ROOT, input=self._session(emits),
                                  capture_output=True, text=True)
            # The runner records bad arithmetic faithfully and still publishes.
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertTrue(bundle.is_file())
            cert = Path(tmp) / 'c.json'
            asm = subprocess.run([sys.executable, 'direct.py', str(bundle), '--claim', 'C1',
                                  '--key', str(key), '--out', str(cert)], cwd=ROOT,
                                 capture_output=True, text=True)
            self.assertEqual(asm.returncode, 0, asm.stdout + asm.stderr)
            chk = subprocess.run([sys.executable, 'checker.py', str(bundle), str(cert),
                                  '--key', str(key), '--lean', '/nonexistent/lean'],
                                 cwd=ROOT, capture_output=True, text=True)
        report = json.loads(chk.stdout)
        self.assertEqual(report['status'], 'REJECTED')
        self.assertEqual(report['reason'], 'FALSE_ARITHMETIC')

    def test_runner_rejects_emit_before_run(self):
        session = (json.dumps({'kind': 'emit', 'argument_id': 'C1', 'id': 'e',
                               'steps': [{'op': 'observe', 'evidence': 'X1/A1.access',
                                          'formula': ['atom', 'access']}]}) + '\n')
        with tempfile.TemporaryDirectory() as tmp:
            key = self._keyed(tmp)
            bundle = Path(tmp) / 'b.json'
            proc = subprocess.run([sys.executable, 'runner.py', 'record', '--key', str(key),
                                   '--out', str(bundle)], cwd=ROOT, input=session,
                                  capture_output=True, text=True)
        self.assertNotEqual(proc.returncode, 0)
        last = json.loads(proc.stdout.strip().splitlines()[-1])
        self.assertEqual(last['status'], 'REJECTED')
        self.assertEqual(last['reason'], 'BAD_INPUT')

    def test_runner_records_narration_and_rejects_oversized(self):
        base = [json.dumps({'kind': 'run', 'case': 'read_upper'}),
                json.dumps({'kind': 'narrate', 'argument_id': 'C1', 'text': 'ok chunk'})]
        with tempfile.TemporaryDirectory() as tmp:
            key = self._keyed(tmp)
            good = subprocess.run([sys.executable, 'runner.py', 'record', '--key', str(key),
                                   '--out', str(Path(tmp) / 'g.json')], cwd=ROOT,
                                  input='\n'.join(base) + '\n', capture_output=True, text=True)
            # narration recorded (no claim here, so no bundle published, but the
            # narrate response is RECORDED and the run succeeded).
            self.assertIn('"status":"RECORDED"', good.stdout)
            huge = json.dumps({'kind': 'narrate', 'argument_id': 'C1', 'text': 'x' * 20001})
            bad = subprocess.run([sys.executable, 'runner.py', 'record', '--key', str(key),
                                  '--out', str(Path(tmp) / 'b.json')], cwd=ROOT,
                                 input=base[0] + '\n' + huge + '\n', capture_output=True, text=True)
        last = json.loads(bad.stdout.strip().splitlines()[-1])
        self.assertEqual((last['status'], last['reason']), ('REJECTED', 'BAD_INPUT'))

    def test_runner_rejects_unhashable_rule_without_traceback(self):
        # An emit infer step with a non-string (unhashable) rule must become a
        # structured BAD_INPUT, never an uncaught TypeError from `rule in dict`.
        for bad_rule in ([], {}, 7):
            step = {'op': 'infer', 'rule': bad_rule, 'premises': [],
                    'formula': ['atom', 'access']}
            session = json.dumps({'kind': 'emit', 'argument_id': 'C1', 'id': 'e',
                                  'steps': [step]}) + '\n'
            with tempfile.TemporaryDirectory() as tmp:
                key = self._keyed(tmp)
                proc = subprocess.run([sys.executable, 'runner.py', 'record', '--key', str(key),
                                       '--out', str(Path(tmp) / 'b.json')], cwd=ROOT,
                                      input=session, capture_output=True, text=True)
            self.assertNotEqual(proc.returncode, 0)
            self.assertNotIn('Traceback', proc.stderr, f'crashed on rule={bad_rule!r}')
            last = json.loads(proc.stdout.strip().splitlines()[-1])
            self.assertEqual((last['status'], last['reason']), ('REJECTED', 'BAD_INPUT'))


if __name__ == '__main__':
    unittest.main()
