"""Behavioral regressions for the cybergym-asan-v1 admission adapter.

Unit-level: classification, the five facts, freeze outcomes, and the offline
re-validation of translation emissions (attempt hashes, narration cutoffs,
abstention closure). Payload-level admission is covered by the direct tests.
"""
import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from evidence import Rejected
from soundtrace_live import cybergym_adapter as ca

RUN_ID = 'R' + '0' * 32
TASK = 'arvo:64574'
POC = 'a' * 64
DIGEST = 'sha256:' + 'b' * 64


def event(**over):
    ev = {'index': 1, 'kind': 'asan_report', 'event_id': 'A1',
          'address': 0x7F0000000104, 'access_kind': 'read', 'width': 4,
          'description': 'heap-buffer-overflow', 'pc': 0x102AACB4C,
          'region_category': 'heap', 'region_base': 0x7F0000000100,
          'region_extent': 6, 'pointer_bits': 64}
    ev.update(over)
    return ev


def execution(**over):
    ex = {'id': 'X1', 'task_id': TASK, 'poc_sha256': POC, 'poc_size': 4,
          'image_ref': 'n132/arvo:368-vul@sha256:' + 'b' * 64,
          'image_digest': DIGEST, 'platform': 'linux/amd64',
          'command': ['/usr/bin/timeout', '-s', 'KILL', '10', '/bin/arvo'],
          'exit_code': 1, 'signal': None, 'oom_killed': False,
          'timed_out': False, 'pointer_bits': 64,
          'asan_options': ca.CANONICAL_ASAN_OPTIONS, 'events': [event()],
          'stdout_sha256': 'c' * 64, 'stdout_bytes': 0,
          'stderr_sha256': 'd' * 64, 'stderr_bytes': 0,
          'stdout_excerpt': '', 'stderr_excerpt': ''}
    ex.update(over)
    return ex


class ClassificationTests(unittest.TestCase):
    def facts(self, ex):
        return ca.execution_facts(ca.with_run_id(ex, RUN_ID))

    def test_admissible_report_derives_offset(self):
        facts = self.facts(execution())
        self.assertEqual(facts['class'], 'asan')
        self.assertEqual(facts['offset'], 4)
        self.assertEqual(facts['extent'], 6)
        self.assertEqual(facts['width'], 4)
        self.assertTrue(facts['scope'].endswith(f'/{TASK}/X1/{POC}/O1/g1/A1'))

    def test_clean_execution(self):
        facts = self.facts(execution(exit_code=0, events=[]))
        self.assertEqual(facts['class'], 'clean')
        self.assertEqual(ca.observations_for_execution(
            execution(exit_code=0, events=[]), run_id=RUN_ID, available_at=9), [])

    def test_non_heap_description_rejected(self):
        with self.assertRaises(Rejected):
            self.facts(execution(events=[event(description='stack-buffer-overflow')]))

    def test_non_heap_region_rejected(self):
        with self.assertRaises(Rejected):
            self.facts(execution(events=[event(region_category='global')]))

    def test_use_after_free_rejected(self):
        with self.assertRaises(Rejected):
            self.facts(execution(events=[event(description='heap-use-after-free')]))

    def test_zero_width_and_extent_and_pc_rejected(self):
        for field in ('width', 'region_extent', 'pc'):
            with self.assertRaises(Rejected):
                self.facts(execution(events=[event(**{field: 0})]))

    def test_pointer_wrap_rejected(self):
        with self.assertRaises(Rejected):
            self.facts(execution(events=[event(address=(1 << 64) - 2)]))
        with self.assertRaises(Rejected):
            self.facts(execution(events=[event(region_extent=1 << 64)]))

    def test_exit_and_signal_conditions(self):
        for over in ({'exit_code': 0}, {'exit_code': 2}, {'signal': 9},
                     {'oom_killed': True}, {'timed_out': True}):
            with self.assertRaises(Rejected):
                self.facts(execution(**over))

    def test_multiple_events_rejected(self):
        with self.assertRaises(Rejected):
            self.facts(execution(events=[event(), event()]))

    def test_eventless_nonzero_exit_rejected(self):
        with self.assertRaises(Rejected):
            self.facts(execution(exit_code=1, events=[]))

    def test_observations_five_records(self):
        records = ca.observations_for_execution(execution(), run_id=RUN_ID,
                                                available_at=7)
        self.assertEqual([r['id'] for r in records],
                         ['X1/A1.access', 'X1/A1.live', 'X1/A1.extent',
                          'X1/A1.width', 'X1/A1.offset'])
        self.assertEqual(records[2]['formula'], ['eq', 'extent', 6])
        self.assertEqual(records[4]['formula'], ['eq', 'offset', 4])
        self.assertEqual({r['authority'] for r in records}, {'cybergym-asan-v1'})
        self.assertEqual({r['available_at'] for r in records}, {7})


class ValidateExecutionTests(unittest.TestCase):
    def test_valid_passes(self):
        ca.validate_execution(execution())

    def test_every_key_mutation_rejected(self):
        mutations = [
            lambda e: e.pop('poc_size'), lambda e: e.update(extra=1),
            lambda e: e.update(poc_size=True), lambda e: e.update(poc_size=1_048_577),
            lambda e: e.update(poc_sha256='Z' * 64),
            lambda e: e.update(image_digest='sha256:' + 'Z' * 64),
            lambda e: e.update(platform='linux/arm64'),
            lambda e: e.update(command=[]),
            lambda e: e.update(signal=True),
            lambda e: e.update(oom_killed='no'),
            lambda e: e.update(asan_options=''),
            lambda e: e.update(pointer_bits=32),
            lambda e: e.update(stdout_bytes=-1),
            lambda e: e.update(stdout_excerpt='x' * 5000),
            lambda e: e.update(id='Q1'),
        ]
        for mutate in mutations:
            ex = execution()
            mutate(ex)
            with self.assertRaises(Rejected, msg=repr(mutate)):
                ca.validate_execution(ex)

    def test_clean_execution_rejects_nonzero_exit(self):
        with self.assertRaises(Rejected):
            ca.validate_execution(execution(exit_code=1, events=[]))


class BuildPinningTests(unittest.TestCase):
    """target_build selects which pinned image an execution must match;
    an execution recorded against one build is never admissible for the
    other (authorization, not mere digest provenance)."""
    TASK_ENTRY = {
        'kind': 'arvo', 'project': 'freetype2',
        'vul_ref': 'n132/arvo:368-vul@sha256:' + 'b' * 64,
        'vul_digest': DIGEST,
        'fix_ref': 'n132/arvo:368-fix@sha256:' + 'c' * 64,
        'fix_digest': 'sha256:' + 'c' * 64,
        'command_vul': ['/bin/arvo'],
        'archive_sha256': '6' * 64, 'description_sha256': '7' * 64,
    }

    def fix_execution(self, **over):
        return execution(image_ref=self.TASK_ENTRY['fix_ref'],
                         image_digest=self.TASK_ENTRY['fix_digest'], **over)

    def test_vul_execution_admitted_under_vul_build(self):
        ca.validate_execution(execution(), self.TASK_ENTRY, build='vul')

    def test_fix_execution_admitted_under_fix_build(self):
        ca.validate_execution(self.fix_execution(), self.TASK_ENTRY, build='fix')

    def test_fix_execution_rejected_under_vul_build(self):
        with self.assertRaises(Rejected):
            ca.validate_execution(self.fix_execution(), self.TASK_ENTRY,
                                  build='vul')

    def test_vul_execution_rejected_under_fix_build(self):
        with self.assertRaises(Rejected):
            ca.validate_execution(execution(), self.TASK_ENTRY, build='fix')


class FreezeTests(unittest.TestCase):
    def claim(self, frm='goal', **over):
        c = {'kind': 'claim', 'argument_id': 'C1', 'event': 'X1/A1',
             'access_kind': 'read', 'side': 'upper', 'from': frm}
        c.update(over)
        return c

    def prefix(self, executions=None, trace=None, abstain=False):
        if trace is not None:
            return {'run_id': RUN_ID,
                    'executions': executions if executions is not None else [execution()],
                    'trace': trace}
        body = ({'kind': 'translation_abstain', 'argument_id': 'C1',
                 'abstain_id': 'AB1', 'source_seq': 3, 'reason': 'OUT_OF_LANGUAGE',
                 'diagnostic': 'x'}
                if abstain else
                {'kind': 'emit', 'argument_id': 'C1', 'id': 'goal',
                 'steps': [{'op': 'compute', 'formula': ['lt', 1, 2]}],
                 'attempt_id': 'T1', 'source_seq': 3})
        return {'run_id': RUN_ID,
                'executions': executions if executions is not None else [execution()],
                'trace': [{'seq': 7, 'kind': 'request', 'body': body}]}

    def test_bound_freeze_carries_cybergym_binding(self):
        frozen = ca.freeze_claim(self.prefix(), self.claim(), seq=9)
        self.assertEqual(frozen['state'], 'bound')
        self.assertEqual(frozen['binding'],
                         {'execution_id': 'X1', 'allocation_id': 'O1', 'generation': 1,
                          'event_id': 'A1', 'access_kind': 'read', 'task_id': TASK,
                          'poc_sha256': POC, 'image_digest': DIGEST})
        self.assertEqual(frozen['formula'],
                         ['and', ['atom', 'access'],
                          ['and', ['atom', 'live'],
                           ['and', ['le', 0, 'extent'],
                            ['and', ['lt', 0, 'width'],
                             ['lt', 'extent', ['add', 'offset', 'width']]]]]])

    def test_lower_side_violation(self):
        frozen = ca.freeze_claim(self.prefix(), self.claim(side='lower'), seq=9)
        self.assertEqual(frozen['formula'][2][2][2][2], ['lt', 'offset', 0])

    def test_abstain_from_is_unsupported_translation(self):
        frozen = ca.freeze_claim(self.prefix(abstain=True), self.claim(frm='AB1'), seq=9)
        self.assertEqual((frozen['state'], frozen['reason']),
                         ('unsupported', 'UNSUPPORTED_TRANSLATION'))

    def test_unknown_from_rejected(self):
        frozen = ca.freeze_claim(self.prefix(), self.claim(frm='nope'), seq=9)
        self.assertEqual((frozen['state'], frozen['reason']),
                         ('rejected', 'UNKNOWN_SOURCE'))

    def test_unknown_execution_rejected(self):
        frozen = ca.freeze_claim(self.prefix(executions=[]), self.claim(), seq=9)
        self.assertEqual(frozen['reason'], 'UNKNOWN_EXECUTION')

    def test_clean_execution_missing_access(self):
        frozen = ca.freeze_claim(
            self.prefix(executions=[execution(exit_code=0, events=[])]),
            self.claim(), seq=9)
        self.assertEqual(frozen['reason'], 'MISSING_ACCESS_EVIDENCE')

    def test_access_kind_mismatch(self):
        frozen = ca.freeze_claim(self.prefix(), self.claim(access_kind='write'), seq=9)
        self.assertEqual(frozen['reason'], 'ACCESS_KIND_MISMATCH')

    def test_bad_request_shape(self):
        with self.assertRaises(ca.AdapterError):
            ca.freeze_claim(self.prefix(), {'kind': 'claim'}, seq=9)


class RevalidateTests(unittest.TestCase):
    def payload_with(self, *, steps=None, attempt_hash=None, source_seq=3,
                     emit_seq=7, abstain=False, evidence_available=2,
                     emit_present=True):
        steps = steps if steps is not None else [
            {'op': 'observe', 'evidence': 'X1/A1.access', 'formula': ['atom', 'access']}]
        import hashlib
        from evidence import canonical_json
        parsed = hashlib.sha256(
            canonical_json({'id': 'goal', 'steps': steps})).hexdigest()
        trace = [
            {'seq': 1, 'kind': 'request',
             'body': {'kind': 'probe', 'task_id': TASK, 'poc_sha256': POC,
                      'poc_size': 4}},
            {'seq': evidence_available, 'kind': 'response', 'request_seq': 1,
             'body': {'status': 'RECORDED', 'execution_id': 'X1', 'event_id': 'A1',
                      'observations': [{'id': 'X1/A1.access',
                                        'formula': ['atom', 'access'],
                                        'available_at': evidence_available}]}},
            {'seq': source_seq, 'kind': 'request',
             'body': {'kind': 'narrate', 'argument_id': 'C1', 'text': 'observed read'}},
            {'seq': source_seq + 1, 'kind': 'response', 'request_seq': source_seq,
             'body': {'status': 'RECORDED', 'argument_id': 'C1', 'seq': source_seq}},
            {'seq': 5, 'kind': 'request',
             'body': {'kind': 'translation_attempt', 'argument_id': 'C1',
                      'attempt_id': 'T1', 'source_seq': source_seq,
                      'model': 'gpt-5.6-luna', 'resolved_model': 'gpt-5.6-luna',
                      'raw_output_sha256': 'e' * 64, 'raw_output_bytes': 10,
                      'parsed_sha256': attempt_hash or parsed, 'outcome': 'emit',
                      'repair': 0}},
            {'seq': 6, 'kind': 'response', 'request_seq': 5,
             'body': {'status': 'RECORDED', 'attempt_id': 'T1'}},
        ]
        if abstain:
            trace += [
                {'seq': emit_seq, 'kind': 'request',
                 'body': {'kind': 'translation_abstain', 'argument_id': 'C1',
                          'abstain_id': 'AB1', 'source_seq': source_seq,
                          'reason': 'OUT_OF_LANGUAGE', 'diagnostic': 'x'}},
                {'seq': emit_seq + 1, 'kind': 'response', 'request_seq': emit_seq,
                 'body': {'status': 'RECORDED', 'abstain_id': 'AB1'}},
            ]
        if emit_present and not abstain:
            trace += [
                {'seq': emit_seq, 'kind': 'request',
                 'body': {'kind': 'emit', 'argument_id': 'C1', 'id': 'goal',
                          'steps': steps, 'attempt_id': 'T1',
                          'source_seq': source_seq}},
                {'seq': emit_seq + 1, 'kind': 'response', 'request_seq': emit_seq,
                 'body': {'status': 'RECORDED', 'argument_id': 'C1',
                          'emission_id': 'goal', 'steps': len(steps),
                          'source_seq': source_seq}},
            ]
        return {'run_id': RUN_ID, 'executions': [execution()], 'trace': trace,
                'claims': {}}

    def test_consistent_emission_passes(self):
        ca.revalidate_emissions(self.payload_with(), 'C1')

    def test_attempt_hash_mismatch_rejected(self):
        payload = self.payload_with(attempt_hash='f' * 64)
        with self.assertRaises(ca.AdapterError) as ctx:
            ca.revalidate_emissions(payload, 'C1')
        self.assertIn('byte-match', ctx.exception.diagnostic)

    def test_missing_attempt_rejected(self):
        payload = self.payload_with()
        payload['trace'][4]['body']['attempt_id'] = 'T9'
        with self.assertRaises(ca.AdapterError) as ctx:
            ca.revalidate_emissions(payload, 'C1')
        self.assertIn('no recorded translation attempt', ctx.exception.diagnostic)

    def test_source_seq_not_a_narration_rejected(self):
        payload = self.payload_with(source_seq=99)
        with self.assertRaises(ca.AdapterError):
            ca.revalidate_emissions(payload, 'C1')

    def test_retroactive_evidence_rejected(self):
        payload = self.payload_with(evidence_available=4)  # after narration at 3
        with self.assertRaises(ca.AdapterError) as ctx:
            ca.revalidate_emissions(payload, 'C1')
        self.assertIn('no retroactive evidence', ctx.exception.diagnostic)

    def test_emission_after_abstain_rejected(self):
        payload = self.payload_with(abstain=True, emit_seq=9)
        payload['trace'] += [
            {'seq': 11, 'kind': 'request',
             'body': {'kind': 'emit', 'argument_id': 'C1', 'id': 'late',
                      'steps': [{'op': 'compute', 'formula': ['lt', 1, 2]}],
                      'attempt_id': 'T1', 'source_seq': 3}},
            {'seq': 12, 'kind': 'response', 'request_seq': 11,
             'body': {'status': 'RECORDED', 'argument_id': 'C1',
                      'emission_id': 'late', 'steps': 1, 'source_seq': 3}}]
        with self.assertRaises(ca.AdapterError) as ctx:
            ca.revalidate_emissions(payload, 'C1')
        self.assertIn('abstention', ctx.exception.diagnostic)

    def test_unknown_evidence_rejected(self):
        steps = [{'op': 'observe', 'evidence': 'X2/A1.access',
                  'formula': ['atom', 'access']}]
        with self.assertRaises(ca.AdapterError):
            ca.revalidate_emissions(self.payload_with(steps=steps), 'C1')


class ScopeCapTests(unittest.TestCase):
    def test_scope_fits_boundaries(self):
        run_id = 'R' + '0' * 32
        self.assertTrue(ca.scope_fits(run_id, 'oss-fuzz:42535201', 'X9', 'a' * 64))
        self.assertFalse(ca.scope_fits(run_id, 'oss-fuzz:42535201', 'X10', 'a' * 64))
        self.assertTrue(ca.scope_fits(run_id, 'arvo:64574', 'X99', 'a' * 64))

    def test_max_execution_number(self):
        self.assertEqual(ca.max_execution_number('oss-fuzz:42535201', 'a' * 64), 9)
        self.assertEqual(ca.max_execution_number('arvo:64574', 'a' * 64), 99)
        self.assertEqual(
            ca.max_execution_number('oss-fuzz:123456789012', 'a' * 64), 0)


if __name__ == '__main__':
    unittest.main()
