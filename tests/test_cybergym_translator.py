"""Behavioral regressions for the live direct translator.

Fidelity contract: shape and provenance are validated before emission, but
arithmetic truth, rule conclusions, and evidence-formula equality are
deliberately NOT — representable bad reasoning must be signed and rejected
downstream, never repaired into correctness or abstained away.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from evidence import Rejected
from soundtrace_live.translator import (MAX_STEPS_PER_EMISSION, Translator,
                                      OUTPUT_SCHEMA, validate_emission_steps,
                                        validate_emission_steps)

STEPS = None
_lines = (ROOT / 'examples/sessions/direct_read_upper.jsonl').read_text().splitlines()
STEPS = [s for l in _lines if (e := json.loads(l)).get('kind') == 'emit'
         for s in e['steps']]

EVIDENCE = {r['id']: {'formula': r['formula'], 'available_at': 2} for r in [
    {'id': 'X1/A1.access', 'formula': ['atom', 'access']},
    {'id': 'X1/A1.live', 'formula': ['atom', 'live']},
    {'id': 'X1/A1.extent', 'formula': ['eq', 'extent', 6]},
    {'id': 'X1/A1.width', 'formula': ['eq', 'width', 4]},
    {'id': 'X1/A1.offset', 'formula': ['eq', 'offset', 4]}]}

SNAPSHOT = [{'id': k, 'formula': v['formula'], 'available_at': v['available_at']}
            for k, v in EVIDENCE.items()]


class FakeRecorder:
    def __init__(self):
        self.log = []

    def narrate(self, text):
        self.log.append(('narrate', text))
        return {'status': 'RECORDED', 'seq': len(self.log)}

    def audit(self, body):
        pass

    def attempt(self, body):
        self.log.append(('attempt', body['attempt_id'], body['outcome'],
                         body['repair'], body['parsed_sha256']))
        return {'status': 'RECORDED'}

    def emit(self, emit_id, steps, attempt_id, source_seq):
        self.log.append(('emit', emit_id, len(steps)))
        return {'status': 'RECORDED'}

    def abstain(self, abstain_id, source_seq, reason, diagnostic):
        self.log.append(('abstain', abstain_id, reason))
        return {'status': 'RECORDED'}


class ScriptedClients:
    """client_factory returning scripted create() responses, in order."""

    def __init__(self, outputs):
        self.outputs = list(outputs)
        self.requests = []

    def factory(self):
        outer = self

        class C:
            def create(self, **kw):
                outer.requests.append(kw)
                text = outer.outputs.pop(0) if outer.outputs else '{}'
                return {'output': [{'type': 'message',
                                    'content': [{'type': 'output_text',
                                                 'text': text}]}],
                        'model': 'gpt-5.6-luna',
                        'usage': {'input_tokens': 7, 'output_tokens': 3}}
        return C()


def emit_output(emit_id, steps):
    return json.dumps({'kind': 'emit', 'id': emit_id, 'steps': steps})


class ValidationTests(unittest.TestCase):
    def test_valid_twenty_steps_pass(self):
        validate_emission_steps(STEPS, emitted_formulas=[], evidence=EVIDENCE,
                                source_seq=5)

    def test_false_arithmetic_is_shape_valid(self):
        steps = json.loads(json.dumps(STEPS))
        for s in steps:
            if s['op'] == 'compute' and s['formula'][:2] == ['lt', 6]:
                s['formula'] = ['lt', 8, 6]
        validate_emission_steps(steps, emitted_formulas=[], evidence=EVIDENCE,
                                source_seq=5)

    def test_wrong_rule_conclusion_is_shape_valid(self):
        steps = json.loads(json.dumps(STEPS))
        for s in steps:
            if s['op'] == 'infer' and s['rule'] == 'lt_transport':
                s['formula'] = ['le', 'extent', ['add', 'offset', 'width']]
                break
        validate_emission_steps(steps, emitted_formulas=[], evidence=EVIDENCE,
                                source_seq=5)

    def test_evidence_formula_mismatch_is_shape_valid(self):
        steps = json.loads(json.dumps(STEPS))
        for s in steps:
            if s['op'] == 'observe' and s['evidence'].endswith('.extent'):
                s['formula'] = ['eq', 'extent', 999]
        validate_emission_steps(steps, emitted_formulas=[], evidence=EVIDENCE,
                                source_seq=5)

    def test_out_of_snapshot_evidence_rejected(self):
        steps = json.loads(json.dumps(STEPS))
        steps[0] = {'op': 'observe', 'evidence': 'X9/A1.access',
                    'formula': ['atom', 'access']}
        with self.assertRaises(Rejected):
            validate_emission_steps(steps, emitted_formulas=[], evidence=EVIDENCE,
                                    source_seq=5)

    def test_retroactive_snapshot_rejected(self):
        with self.assertRaises(Rejected):
            validate_emission_steps(STEPS, emitted_formulas=[], evidence=EVIDENCE,
                                    source_seq=1)

    def test_forward_premises_rejected(self):
        steps = [{'op': 'compute', 'formula': ['lt', 1, 2]},
                 {'op': 'infer', 'rule': 'and_intro', 'premises': [2],
                  'formula': ['and', ['lt', 1, 2], ['lt', 1, 2]]}]
        with self.assertRaises(Rejected):
            validate_emission_steps(steps, emitted_formulas=[], evidence=EVIDENCE,
                                    source_seq=5)

    def test_step_and_rule_shape_rejected(self):
        for bad in ([{'op': 'observe', 'evidence': 'X1/A1.access'}],
                    [{'op': 'mystery', 'formula': ['atom', 'access']}],
                    [{'op': 'infer', 'rule': 'not_a_rule', 'premises': [0],
                      'formula': ['atom', 'access']}],
                    [{'op': 'compute', 'formula': ['atom', 'access']}],
                    []):
            with self.assertRaises(Rejected):
                validate_emission_steps(bad, emitted_formulas=[], evidence=EVIDENCE,
                                        source_seq=5)

    def test_per_emission_limit_enforced(self):
        steps = [{'op': 'compute', 'formula': ['lt', 1, 2]}] * (MAX_STEPS_PER_EMISSION + 1)
        with self.assertRaises(Rejected):
            validate_emission_steps(steps, emitted_formulas=[], evidence=EVIDENCE,
                                    source_seq=5)

    def test_global_prefix_premises_addressable(self):
        prefix = [['lt', 1, 2]]
        steps = [{'op': 'infer', 'rule': 'and_intro', 'premises': [0, 0],
                  'formula': ['and', ['lt', 1, 2], ['lt', 1, 2]]},
                 {'op': 'infer', 'rule': 'and_left', 'premises': [1],
                  'formula': ['lt', 1, 2]}]
        validate_emission_steps(steps, emitted_formulas=prefix,
                                evidence=EVIDENCE, source_seq=5)


class TranslatorFlowTests(unittest.TestCase):
    def translate(self, outputs, chunks, finalize=None):
        with tempfile.TemporaryDirectory() as tmp:
            recorder = FakeRecorder()
            script = ScriptedClients(outputs)
            translator = Translator(recorder, script.factory, Path(tmp))
            for text, seq, ev in chunks:
                translator.submit(text, seq, ev)
            translator.drain()
            final_id = None
            if finalize is not None:
                text, seq, binding = finalize
                final_id = translator.finalize(text, seq, SNAPSHOT, binding)
            return translator, recorder, script, final_id

    def test_noop_then_emission(self):
        translator, recorder, _, _ = self.translate(
            [json.dumps({'kind': 'noop', 'diagnostic': 'exploration'}),
             emit_output('e2', STEPS)],
            [('exploring', 3, []), ('final report', 5, SNAPSHOT)])
        self.assertEqual(translator.emission_ids, ['e2'])
        self.assertEqual(translator.first_pass_emitted, 1)
        self.assertEqual(translator.noops, 1)
        self.assertEqual([l[0] for l in recorder.log],
                         ['attempt', 'attempt', 'emit'])

    def test_finalization_returns_final_id(self):
        translator, _, _, final_id = self.translate(
            [json.dumps({'kind': 'noop', 'diagnostic': 'looking around'}),
             emit_output('goal', STEPS)],
            [('first', 3, SNAPSHOT[:2])],
            finalize=('final chunk', 5,
                      {'execution_id': 'X1', 'event_id': 'A1',
                       'access_kind': 'read', 'side': 'upper', 'scope': 's'}))
        self.assertEqual(final_id, 'goal')

    def test_exactly_one_repair_for_malformed_output(self):
        translator, recorder, _, final_id = self.translate(
            ['{broken', emit_output('goal', STEPS)],
            [],
            finalize=('final', 5, {}))
        self.assertEqual(final_id, 'goal')
        self.assertEqual(translator.repaired_emitted, 1)
        self.assertEqual(translator.first_pass_emitted, 0)
        self.assertEqual([l[3] for l in recorder.log if l[0] == 'attempt'],
                         [0, 1])

    def test_exhausted_malformed_abstains_unparseable(self):
        translator, recorder, _, final_id = self.translate(
            ['{broken', 'still broken'],
            [],
            finalize=('final', 5, {}))
        self.assertIsNone(final_id)
        self.assertTrue(translator.abstained)
        self.assertEqual([l for l in recorder.log if l[0] == 'abstain'],
                         [('abstain', 'AB2', 'UNPARSEABLE')])

    def test_model_abstain_closes_argument(self):
        translator, _, _, final_id = self.translate(
            [json.dumps({'kind': 'abstain', 'reason': 'OUT_OF_LANGUAGE',
                         'diagnostic': 'beyond the grammar'})],
            [('final', 5, SNAPSHOT)])
        self.assertTrue(translator.abstained)
        self.assertEqual(translator.abstain_id, 'AB1')

    def test_false_arithmetic_emitted_not_repaired(self):
        steps = json.loads(json.dumps(STEPS))
        for s in steps:
            if s['op'] == 'compute' and s['formula'][:2] == ['lt', 6]:
                s['formula'] = ['lt', 8, 6]
        translator, recorder, _, final_id = self.translate(
            [emit_output('goal', steps)], [],
            finalize=('final', 5, {}))
        self.assertEqual(final_id, 'goal')
        self.assertEqual(translator.calls, 1)

    def test_request_shape_strict_schema_and_effort(self):
        _, _, script, _ = self.translate(
            [emit_output('goal', STEPS)], [],
            finalize=('final', 5, {}))
        request = script.requests[0]
        self.assertEqual(request['model'], 'gpt-5.6-luna')
        self.assertEqual(request['reasoning_effort'], 'high')
        self.assertEqual(request['max_output_tokens'], 8192)
        self.assertIn('properties', request['text_json_schema'])
        system = request['input_items'][0]['content']
        self.assertIn('nine rules', system)
        self.assertIn('frozen target shape', system)

    def test_raw_outputs_stored_content_addressed(self):
        with tempfile.TemporaryDirectory() as tmp:
            recorder = FakeRecorder()
            script = ScriptedClients([emit_output('goal', STEPS)])
            translator = Translator(recorder, script.factory, Path(tmp))
            translator.submit('final', 5, SNAPSHOT)
            translator.drain()
            parsed = [l[4] for l in recorder.log if l[0] == 'attempt']
            from evidence import canonical_json, sha256_hex
            self.assertEqual(parsed[0],
                             sha256_hex(canonical_json({'id': 'goal', 'steps': STEPS})))
            stored = list(Path(tmp).glob('*.txt'))
            self.assertEqual(len(stored), 1)
            self.assertEqual(stored[0].read_text(), emit_output('goal', STEPS))

    def test_attempt_binds_source_seq(self):
        with tempfile.TemporaryDirectory() as tmp:
            recorder = FakeRecorder()
            script = ScriptedClients([emit_output('goal', STEPS)])
            translator = Translator(recorder, script.factory, Path(tmp))
            translator.submit('final', 5, SNAPSHOT)
            translator.drain()
            # the runner-facing attempt body carries source_seq 5
            self.assertEqual(recorder.log[0][0], 'attempt')


class SchemaAlignmentTests(unittest.TestCase):
    """A schema-conforming response must pass step validation unchanged."""

    def test_step_variant_key_sets_match_validator(self):
        from frontend import RULE_LEAN
        variants = OUTPUT_SCHEMA['properties']['steps']['anyOf'][0]['items']['anyOf']
        expected = {'observe': {'op', 'evidence', 'formula'},
                    'compute': {'op', 'formula'},
                    'infer': {'op', 'rule', 'premises', 'formula'}}
        self.assertEqual(len(variants), 3)
        for variant in variants:
            op = variant['properties']['op']['enum'][0]
            self.assertEqual(set(variant['required']), expected[op])
            self.assertEqual(set(variant['properties']), expected[op])
            self.assertFalse(variant['additionalProperties'])
        self.assertEqual(set(variants[2]['properties']['rule']['enum']),
                         set(RULE_LEAN))

    def test_conforming_emission_passes_validation(self):
        import frontend
        steps = [
            {'op': 'observe', 'evidence': 'X1/A1.access',
             'formula': ['atom', 'access']},
            {'op': 'compute', 'formula': ['eq', ['add', 'offset', 'width'], 8]},
            {'op': 'infer', 'rule': sorted(frontend.RULE_LEAN)[0],
             'premises': [0], 'formula': ['atom', 'access']},
        ]
        validate_emission_steps(
            steps, emitted_formulas=[],
            evidence={'X1/A1.access': {'available_at': 2}}, source_seq=5)


if __name__ == '__main__':
    unittest.main()
