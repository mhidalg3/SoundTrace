"""Behavioral regressions for observation-backed certificate verification.

Isolated test keys MAC every hand-built payload so authentication failures are
distinguishable from semantic-admission failures; fake Lean backends exercise
the kernel boundary without the real toolchain.
"""
import json
import stat
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from checker import verify_certificate
from constructor import construct_certificate
from evidence import Rejected, canonical_json, mac_hex
from oob_adapter import admit_oob

KEY = b'test-runner-key-32-bytes-xxxxxxxx'[:32]
OTHER_KEY = b'other-runner-key-32-bytes-yyyyyy'[:32]

UPPER_NODES = [
    {'id': 'acc', 'kind': 'observe', 'evidence': 'X1/A1.access', 'assert': ['atom', 'access']},
    {'id': 'lv', 'kind': 'observe', 'evidence': 'X1/A1.live', 'assert': ['atom', 'live']},
    {'id': 'ex', 'kind': 'observe', 'evidence': 'X1/A1.extent', 'assert': ['eq', 'extent', 6]},
    {'id': 'wd', 'kind': 'observe', 'evidence': 'X1/A1.width', 'assert': ['eq', 'width', 4]},
    {'id': 'of', 'kind': 'observe', 'evidence': 'X1/A1.offset', 'assert': ['eq', 'offset', 4]},
    {'id': 'end', 'kind': 'calculate', 'operator': 'add', 'left': {'ref': 'of'},
     'right': {'ref': 'wd'}, 'result': 8},
    {'id': 'vio', 'kind': 'compare', 'relation': 'lt', 'left': {'ref': 'ex'},
     'right': {'ref': 'end'}},
    {'id': 'pw', 'kind': 'compare', 'relation': 'lt', 'left': 0, 'right': {'ref': 'wd'}},
    {'id': 'ne', 'kind': 'compare', 'relation': 'le', 'left': 0, 'right': {'ref': 'ex'}},
    {'id': 'inner', 'kind': 'conjoin', 'premises': ['pw', 'vio']},
    {'id': 'range', 'kind': 'conjoin', 'premises': ['ne', 'inner']},
    {'id': 'alive', 'kind': 'conjoin', 'premises': ['lv', 'range']},
    {'id': 'goal', 'kind': 'conjoin', 'premises': ['acc', 'alive']},
]

LOWER_NODES = [
    {'id': 'acc', 'kind': 'observe', 'evidence': 'X1/A1.access', 'assert': ['atom', 'access']},
    {'id': 'lv', 'kind': 'observe', 'evidence': 'X1/A1.live', 'assert': ['atom', 'live']},
    {'id': 'ex', 'kind': 'observe', 'evidence': 'X1/A1.extent', 'assert': ['eq', 'extent', 16]},
    {'id': 'wd', 'kind': 'observe', 'evidence': 'X1/A1.width', 'assert': ['eq', 'width', 4]},
    {'id': 'of', 'kind': 'observe', 'evidence': 'X1/A1.offset', 'assert': ['eq', 'offset', -4]},
    {'id': 'neg', 'kind': 'compare', 'relation': 'lt', 'left': {'ref': 'of'}, 'right': 0},
    {'id': 'pw', 'kind': 'compare', 'relation': 'lt', 'left': 0, 'right': {'ref': 'wd'}},
    {'id': 'ne', 'kind': 'compare', 'relation': 'le', 'left': 0, 'right': {'ref': 'ex'}},
    {'id': 'inner', 'kind': 'conjoin', 'premises': ['pw', 'neg']},
    {'id': 'range', 'kind': 'conjoin', 'premises': ['ne', 'inner']},
    {'id': 'alive', 'kind': 'conjoin', 'premises': ['lv', 'range']},
    {'id': 'goal', 'kind': 'conjoin', 'premises': ['acc', 'alive']},
]


def asan_events(base=0x6020000000F0, extent=6, address=None, width=4, kind='read',
                description='heap-buffer-overflow'):
    if address is None:
        address = base + 4
    return [
        {'index': 1, 'kind': 'alloc', 'object_id': 'O1', 'generation': 1, 'base': base,
         'extent': extent, 'pointer_bits': 64, 'locator_category': 'heap',
         'locator_base': base, 'locator_extent': extent},
        {'index': 2, 'kind': 'attempt', 'event_id': 'A1', 'object_id': 'O1', 'generation': 1,
         'address': address, 'width': width, 'access_kind': kind},
        {'index': 3, 'kind': 'asan', 'event_id': 'A1', 'address': address,
         'access_kind': kind, 'width': width, 'description': description,
         'pc': 0x102AACB4C},
    ]


def complete_events(base=0x6020000000F0, extent=16, address=None, width=4, kind='read'):
    if address is None:
        address = base + 12
    return [
        {'index': 1, 'kind': 'alloc', 'object_id': 'O1', 'generation': 1, 'base': base,
         'extent': extent, 'pointer_bits': 64, 'locator_category': 'heap',
         'locator_base': base, 'locator_extent': extent},
        {'index': 2, 'kind': 'attempt', 'event_id': 'A1', 'object_id': 'O1', 'generation': 1,
         'address': address, 'width': width, 'access_kind': kind},
        {'index': 3, 'kind': 'complete', 'event_id': 'A1'},
        {'index': 4, 'kind': 'free', 'object_id': 'O1', 'generation': 1},
    ]


def blocked_events(kind='read'):
    return [
        {'index': 1, 'kind': 'alloc', 'object_id': 'O1', 'generation': 1, 'base': 0x6020000000F0,
         'extent': 6, 'pointer_bits': 64, 'locator_category': 'heap',
         'locator_base': 0x6020000000F0, 'locator_extent': 6},
        {'index': 2, 'kind': 'blocked', 'event_id': 'A1', 'object_id': 'O1', 'generation': 1,
         'access_kind': kind},
        {'index': 3, 'kind': 'free', 'object_id': 'O1', 'generation': 1},
    ]


def make_payload(events, nodes, *, side='upper', access_kind='read', exit_code=1,
                 run_id=None, case='read_upper', force_frozen=None):
    import secrets
    run_id = run_id or ('R' + secrets.token_hex(16))
    trace = [{'seq': 1, 'kind': 'request', 'body': {'kind': 'run', 'case': case}},
             {'seq': 2, 'kind': 'response', 'request_seq': 1,
              'body': {'status': 'RECORDED', 'execution_id': 'X1', 'event_id': 'A1'}}]
    seq = 3
    for node in nodes:
        node = json.loads(json.dumps(node))  # never share mutable module state
        trace.append({'seq': seq, 'kind': 'request',
                      'body': {'kind': 'reason', 'argument_id': 'C1', 'node': node}})
        trace.append({'seq': seq + 1, 'kind': 'response', 'request_seq': seq,
                      'body': {'status': 'RECORDED', 'source_id': node['id']}})
        seq += 2
    claim_request = {'kind': 'claim', 'argument_id': 'C1', 'event': 'X1/A1',
                     'access_kind': access_kind, 'side': side, 'from': nodes[-1]['id']}
    trace.append({'seq': seq, 'kind': 'request', 'body': claim_request})
    trace.append({'seq': seq + 1, 'kind': 'response', 'request_seq': seq,
                  'body': {'status': 'RECORDED', 'claim_id': 'C1'}})
    execution = {'id': 'X1', 'case': case, 'pid': 26213, 'pointer_bits': 64,
                 'asan_options': 'halt_on_error=1:abort_on_error=0:exitcode=1:'
                                 'detect_leaks=0:symbolize=0',
                 'exit_code': exit_code, 'events': events, 'stderr': ''}
    from oob_adapter import freeze_claim
    if force_frozen is not None:
        frozen = force_frozen
    else:
        frozen = freeze_claim({'run_id': run_id, 'executions': [execution], 'trace': trace},
                              claim_request, seq=seq)
    payload = {'format': 'soundtrace-run-v1', 'run_id': run_id, 'producer': 'controlled-c-asan-v1',
               'build': {'source_sha256': '0' * 64, 'binary_sha256': '1' * 64,
                         'compiler_version': 'probe', 'flags': ['-std=c11']},
               'executions': [execution], 'trace': trace,
               'claims': {'C1': {'claim': claim_request, 'available_at': seq,
                                 'frozen': frozen}}}
    return payload


def sign(payload, key=KEY):
    return {'payload': payload, 'hmac_sha256': mac_hex(key, canonical_json(payload))}


def fake_lean(tmp, body, version='Lean (version 4.34.1, aarch64-apple-darwin, Release)'):
    path = Path(tmp) / 'lean'
    path.write_text('#!/bin/sh\n'
                    f'if [ "$1" = "--version" ]; then echo "{version}"; exit 0; fi\n'
                    + body)
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return str(path)


GOOD_LEAN = "echo \"'certificate' does not depend on any axioms\"\nexit 0\n"


def build_verified(events, nodes, **payload_kwargs):
    payload = make_payload(events, nodes, **payload_kwargs)
    bundle = sign(payload)
    manifest, argument = admit_oob(payload, 'C1')
    from evidence import sha256_hex
    cert = construct_certificate(manifest, argument,
                                 bundle_sha256=sha256_hex(canonical_json(payload)))
    return bundle, cert


class PositivePathTests(unittest.TestCase):
    def test_upper_overflow_verifies_observation_backed(self):
        with tempfile.TemporaryDirectory() as tmp:
            lean = fake_lean(tmp, GOOD_LEAN)
            bundle, cert = build_verified(asan_events(), UPPER_NODES)
            result = verify_certificate(bundle, cert, key=KEY, lean=lean)
        self.assertEqual(result['status'], 'VERIFIED_OBSERVATION_BACKED')
        self.assertEqual(result['claim_id'], 'C1')
        self.assertEqual(result['backend']['axiom_audit'], 'empty')

    def test_lower_overflow_verifies_observation_backed(self):
        with tempfile.TemporaryDirectory() as tmp:
            lean = fake_lean(tmp, GOOD_LEAN)
            events = asan_events(extent=16, address=0x6020000000F0 - 4)
            bundle, cert = build_verified(events, LOWER_NODES, side='lower',
                                          case='read_lower')
            result = verify_certificate(bundle, cert, key=KEY, lean=lean)
        self.assertEqual(result['status'], 'VERIFIED_OBSERVATION_BACKED')

    def test_write_overflow_verifies(self):
        with tempfile.TemporaryDirectory() as tmp:
            lean = fake_lean(tmp, GOOD_LEAN)
            bundle, cert = build_verified(asan_events(kind='write'), UPPER_NODES,
                                          access_kind='write', case='write_upper')
            result = verify_certificate(bundle, cert, key=KEY, lean=lean)
        self.assertEqual(result['status'], 'VERIFIED_OBSERVATION_BACKED')


class AuthenticationTests(unittest.TestCase):
    def verify(self, bundle, cert, key=KEY, lean='/nonexistent/lean'):
        return verify_certificate(bundle, cert, key=key, lean=lean)

    def test_tampered_event_fails_mac(self):
        bundle, cert = build_verified(asan_events(), UPPER_NODES)
        bundle['payload']['executions'][0]['events'][2]['width'] = 8
        result = self.verify(bundle, cert)
        self.assertEqual(result['status'], 'REJECTED')
        self.assertEqual(result['reason'], 'AUTHENTICATION_FAILED')

    def test_wrong_key_fails_mac(self):
        bundle, cert = build_verified(asan_events(), UPPER_NODES)
        result = self.verify(bundle, cert, key=OTHER_KEY)
        self.assertEqual(result['reason'], 'AUTHENTICATION_FAILED')

    def test_tampered_trace_node_fails_mac(self):
        bundle, cert = build_verified(asan_events(), UPPER_NODES)
        for entry in bundle['payload']['trace']:
            if entry['kind'] == 'request' and entry['body'].get('kind') == 'reason':
                entry['body']['node']['id'] = 'sneaky'
                break
        result = self.verify(bundle, cert)
        self.assertEqual(result['reason'], 'AUTHENTICATION_FAILED')

    def test_tampered_frozen_target_fails_mac(self):
        bundle, cert = build_verified(asan_events(), UPPER_NODES)
        bundle['payload']['claims']['C1']['frozen']['formula'] = ['atom', 'access']
        result = self.verify(bundle, cert)
        self.assertEqual(result['reason'], 'AUTHENTICATION_FAILED')


class SemanticAdmissionTests(unittest.TestCase):
    """Deliberately inconsistent events, re-signed with the isolated test key.

    These payloads carry a hand-built bound outcome (only a compromised key
    holder could produce them); admission must catch the inconsistency during
    recomputation rather than trusting the recorded target.
    """

    def inconsistent(self, events, exit_code=1):
        bound = {'state': 'bound',
                 'scope': 'R' + '0' * 32 + '/X1/O1/g1/A1',
                 'binding': {'execution_id': 'X1', 'allocation_id': 'O1',
                             'generation': 1, 'event_id': 'A1', 'access_kind': 'read'},
                 'formula': ['atom', 'access']}
        payload = make_payload(events, UPPER_NODES, exit_code=exit_code,
                               force_frozen=bound)
        result = verify_certificate(sign(payload), {'claim_id': 'C1'}, key=KEY,
                                    lean='/nonexistent/lean')
        return result

    def test_callback_address_mismatch_is_evidence_conflict(self):
        events = asan_events()
        events[2]['address'] = events[1]['address'] + 8
        self.assertEqual(self.inconsistent(events)['reason'], 'EVIDENCE_CONFLICT')

    def test_wrong_description_is_evidence_conflict(self):
        events = asan_events(description='stack-buffer-overflow')
        self.assertEqual(self.inconsistent(events)['reason'], 'EVIDENCE_CONFLICT')

    def test_zero_width_rejected(self):
        self.assertEqual(self.inconsistent(asan_events(width=0))['reason'],
                         'EVIDENCE_CONFLICT')

    def test_address_wrap_rejected(self):
        base = 2**64 - 2
        events = asan_events(base=base, address=base)
        self.assertEqual(self.inconsistent(events)['reason'], 'EVIDENCE_CONFLICT')

    def test_callback_without_attempt_rejected(self):
        events = asan_events()[:1] + asan_events()[2:]
        for i, event in enumerate(events):
            event['index'] = i + 1
        self.assertEqual(self.inconsistent(events)['reason'], 'EVIDENCE_CONFLICT')

    def test_use_after_free_shape_rejected(self):
        events = [
            asan_events()[0], asan_events()[1],
            {'index': 3, 'kind': 'free', 'object_id': 'O1', 'generation': 1},
            {'index': 4, 'kind': 'complete', 'event_id': 'A1'},
        ]
        self.assertEqual(self.inconsistent(events)['reason'], 'EVIDENCE_CONFLICT')

    def test_signal_only_crash_rejected(self):
        self.assertEqual(self.inconsistent(asan_events(), exit_code=-9)['reason'],
                         'EVIDENCE_CONFLICT')

    def test_read_claim_with_write_binding_mismatch(self):
        result = verify_with_write_events_read_claim()
        self.assertEqual(result['status'], 'REJECTED')
        self.assertEqual(result['reason'], 'CLAIM_MISMATCH')

    def test_in_bounds_completed_access_rejects_false_comparison(self):
        from constructor import ConstructionFailure
        payload = make_payload(complete_events(), IN_BOUNDS_NODES, exit_code=0)
        manifest, argument = admit_oob(payload, 'C1')
        with self.assertRaises(ConstructionFailure) as ctx:
            construct_certificate(manifest, argument,
                                  bundle_sha256='ab' * 32)
        self.assertEqual(ctx.exception.reason, 'FALSE_ARITHMETIC')
        self.assertEqual(ctx.exception.source_id, 'vio')

    def test_blocked_operation_is_unsupported(self):
        from constructor import ConstructionFailure
        payload = make_payload(blocked_events(), UPPER_NODES, exit_code=0)
        manifest, argument = admit_oob(payload, 'C1')
        with self.assertRaises(ConstructionFailure) as ctx:
            construct_certificate(manifest, argument, bundle_sha256='ab' * 32)
        self.assertEqual(ctx.exception.status, 'UNSUPPORTED_TRACE')
        self.assertEqual(ctx.exception.reason, 'MISSING_ACCESS_EVIDENCE')
        result = verify_certificate(sign(payload), {'claim_id': 'C1'}, key=KEY,
                                    lean='/nonexistent/lean')
        self.assertEqual(result['status'], 'UNSUPPORTED_TRACE')
        self.assertEqual(result['reason'], 'MISSING_ACCESS_EVIDENCE')



def verify_with_write_events_read_claim():
    """A read claim frozen over write events: only the recomputed outcome can
    catch it, so force a bound record and verify the checker rejects it."""
    bound = {'state': 'bound',
             'scope': 'R' + '0' * 32 + '/X1/O1/g1/A1',
             'binding': {'execution_id': 'X1', 'allocation_id': 'O1',
                         'generation': 1, 'event_id': 'A1', 'access_kind': 'read'},
             'formula': ['atom', 'access']}
    payload = make_payload(asan_events(kind='write'), UPPER_NODES,
                           access_kind='read', case='write_upper', force_frozen=bound)
    return verify_certificate(sign(payload), {'claim_id': 'C1'}, key=KEY,
                              lean='/nonexistent/lean')


IN_BOUNDS_NODES = [
    {'id': 'acc', 'kind': 'observe', 'evidence': 'X1/A1.access', 'assert': ['atom', 'access']},
    {'id': 'lv', 'kind': 'observe', 'evidence': 'X1/A1.live', 'assert': ['atom', 'live']},
    {'id': 'ex', 'kind': 'observe', 'evidence': 'X1/A1.extent', 'assert': ['eq', 'extent', 16]},
    {'id': 'wd', 'kind': 'observe', 'evidence': 'X1/A1.width', 'assert': ['eq', 'width', 4]},
    {'id': 'of', 'kind': 'observe', 'evidence': 'X1/A1.offset', 'assert': ['eq', 'offset', 12]},
    {'id': 'end', 'kind': 'calculate', 'operator': 'add', 'left': {'ref': 'of'},
     'right': {'ref': 'wd'}, 'result': 16},
    {'id': 'vio', 'kind': 'compare', 'relation': 'lt', 'left': {'ref': 'ex'},
     'right': {'ref': 'end'}},
    {'id': 'pw', 'kind': 'compare', 'relation': 'lt', 'left': 0, 'right': {'ref': 'wd'}},
    {'id': 'ne', 'kind': 'compare', 'relation': 'le', 'left': 0, 'right': {'ref': 'ex'}},
    {'id': 'inner', 'kind': 'conjoin', 'premises': ['pw', 'vio']},
    {'id': 'range', 'kind': 'conjoin', 'premises': ['ne', 'inner']},
    {'id': 'alive', 'kind': 'conjoin', 'premises': ['lv', 'range']},
    {'id': 'goal', 'kind': 'conjoin', 'premises': ['acc', 'alive']},
]


class AlignmentTests(unittest.TestCase):
    def test_spliced_certificate_from_other_run_rejected(self):
        bundle_a, _ = build_verified(asan_events(), UPPER_NODES)
        payload_b = make_payload(asan_events(base=0x700000000000), UPPER_NODES)
        bundle_b = sign(payload_b)
        from evidence import sha256_hex
        manifest_b, argument_b = admit_oob(payload_b, 'C1')
        cert_b = construct_certificate(manifest_b, argument_b,
                                       bundle_sha256=sha256_hex(canonical_json(payload_b)))
        result = verify_certificate(bundle_a, cert_b, key=KEY, lean='/nonexistent/lean')
        self.assertEqual(result['status'], 'REJECTED')
        self.assertIn(result['reason'], ('CLAIM_MISMATCH', 'SOURCE_ALIGNMENT_FAILED'))

    def test_altered_certificate_step_rejected(self):
        bundle, cert = build_verified(asan_events(), UPPER_NODES)
        cert = json.loads(json.dumps(cert))
        for step in cert['steps']:
            if step['op'] == 'compute':
                step['formula'] = ['eq', ['add', 4, 4], 9]
                break
        result = verify_certificate(bundle, cert, key=KEY, lean='/nonexistent/lean')
        self.assertEqual(result['reason'], 'SOURCE_ALIGNMENT_FAILED')

    def test_unknown_claim_rejected(self):
        bundle, cert = build_verified(asan_events(), UPPER_NODES)
        result = verify_certificate(bundle, {'claim_id': 'C9'}, key=KEY,
                                    lean='/nonexistent/lean')
        self.assertEqual(result['status'], 'REJECTED')
        self.assertEqual(result['reason'], 'CLAIM_MISMATCH')

    def test_valid_certificate_against_wrong_argument_is_source_alignment(self):
        # Regression: the recorded argument states 4+4=7; a separately valid
        # certificate for the correct arithmetic must fail source alignment
        # against it at the checker boundary, never be accepted.
        wrong_nodes = json.loads(json.dumps(UPPER_NODES))
        wrong_nodes[5]['result'] = 7
        payload = make_payload(asan_events(), wrong_nodes)
        result = verify_certificate(sign(payload), {'claim_id': 'C1'}, key=KEY,
                                    lean='/nonexistent/lean')
        self.assertEqual(result['status'], 'REJECTED')
        self.assertEqual(result['reason'], 'SOURCE_ALIGNMENT_FAILED')
        self.assertIn('FALSE_ARITHMETIC', result['diagnostic'])
        self.assertIn('end', result['diagnostic'])

    def test_frozen_rejected_outcome_preserves_claim_mismatch(self):
        # A claim recorded against an unknown execution freezes a rejected
        # outcome; checking any certificate for it must report the frozen
        # reason, never a source-alignment or kernel verdict.
        from oob_adapter import freeze_claim
        payload = make_payload(asan_events(), UPPER_NODES)
        entry = payload['claims']['C1']
        entry['claim']['event'] = 'X9/A1'
        frozen = freeze_claim({'run_id': payload['run_id'],
                               'executions': payload['executions'],
                               'trace': payload['trace']},
                              entry['claim'], seq=entry['available_at'])
        self.assertEqual(frozen['reason'], 'UNKNOWN_EXECUTION')
        entry['frozen'] = frozen
        result = verify_certificate(sign(payload), {'claim_id': 'C1'}, key=KEY,
                                    lean='/nonexistent/lean')
        self.assertEqual(result['status'], 'REJECTED')
        self.assertEqual(result['reason'], 'CLAIM_MISMATCH')
        self.assertIn('UNKNOWN_EXECUTION', result['diagnostic'])

    def test_constructor_cli_unknown_claim_is_json_not_traceback(self):
        import subprocess
        root = Path(__file__).resolve().parent.parent
        with tempfile.TemporaryDirectory() as tmp:
            key = Path(tmp) / 'k'
            key.write_bytes(KEY)
            bundle = Path(tmp) / 'b.json'
            bundle.write_text(json.dumps(sign(make_payload(asan_events(), UPPER_NODES))))
            proc = subprocess.run(
                [sys.executable, 'constructor.py', str(bundle), '--claim', 'C9',
                 '--key', str(key), '--out', str(Path(tmp) / 'c.json')],
                cwd=root, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 1, proc.stderr)
        report = json.loads(proc.stdout)
        self.assertEqual((report['status'], report['reason']), ('REJECTED', 'CLAIM_MISMATCH'))


class BackendBoundaryTests(unittest.TestCase):
    def verify_with(self, body):
        bundle, cert = build_verified(asan_events(), UPPER_NODES)
        with tempfile.TemporaryDirectory() as tmp:
            return verify_certificate(bundle, cert, key=KEY, lean=fake_lean(tmp, body))

    def test_missing_audit_rejected(self):
        result = self.verify_with('exit 0\n')
        self.assertEqual(result['status'], 'REJECTED')
        self.assertEqual(result['reason'], 'KERNEL_REJECT')

    def test_sorry_ax_rejected(self):
        result = self.verify_with("echo \"'certificate' depends on axioms: [sorryAx]\"\nexit 0\n")
        self.assertEqual(result['reason'], 'KERNEL_REJECT')

    def test_version_mismatch_inconclusive(self):
        bundle, cert = build_verified(asan_events(), UPPER_NODES)
        with tempfile.TemporaryDirectory() as tmp:
            lean = fake_lean(tmp, GOOD_LEAN, version='Lean (version 4.35.0, aarch64)')
            result = verify_certificate(bundle, cert, key=KEY, lean=lean)
        self.assertEqual(result['status'], 'INCONCLUSIVE_TOOLCHAIN_MISMATCH')

    def test_heartbeat_inconclusive_not_false(self):
        result = self.verify_with('echo "error: maximum number of heartbeats '
                                  '(50000) has been exceeded"\nexit 1\n')
        self.assertEqual(result['status'], 'INCONCLUSIVE_RESOURCE_LIMIT')


if __name__ == '__main__':
    unittest.main()
