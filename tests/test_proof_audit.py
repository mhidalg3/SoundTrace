"""Regression tests for proof-dependency auditing (soundtrace_live.proof_audit)."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from soundtrace_live.proof_audit import audit_certificate  # noqa: E402


class ProofAuditTests(unittest.TestCase):
    def test_reachability_evidence_and_source_coverage(self):
        cert = {'steps': [
            {'op': 'observe', 'evidence': 'E/access', 'formula': ['atom', 'access']},
            {'op': 'observe', 'evidence': 'E/extent', 'formula': ['eq', 'extent', 16]},
            {'op': 'compute', 'formula': ['eq', 0, 0]},                             # unused
            {'op': 'infer', 'premises': [2], 'rule': 'x', 'formula': ['eq', 1, 1]},  # unused
            {'op': 'infer', 'premises': [0, 1], 'rule': 'and_intro',
             'formula': ['and', ['atom', 'access'], ['eq', 'extent', 16]]}],         # final
            'source_map': [
                {'source_id': 'used-src', 'first_step': 0, 'last_step': 1},
                {'source_id': 'unused-src', 'first_step': 2, 'last_step': 3},
                {'source_id': 'final-src', 'first_step': 4, 'last_step': 4}]}
        r = audit_certificate(cert)
        self.assertEqual((r['total_steps'], r['reachable_steps'],
                          r['unused_steps']), (5, 3, 2))
        self.assertTrue(r['final_claim_supported'])
        self.assertEqual(r['evidence_dependencies'], ['E/access', 'E/extent'])
        self.assertEqual(r['final_premises'], [0, 1])
        self.assertEqual(r['source_coverage'], {
            'contributing_sources': ['used-src', 'final-src'],
            'noncontributing_sources': ['unused-src']})

    def test_dangling_final_premise_is_not_supported(self):
        cert = {'steps': [
            {'op': 'observe', 'evidence': 'E', 'formula': ['atom', 'x']},
            {'op': 'infer', 'premises': [0, 7], 'rule': 'r',
             'formula': ['atom', 'y']}]}
        r = audit_certificate(cert)
        self.assertFalse(r['final_claim_supported'])
        self.assertEqual(r['dangling_premises'], [7])

    def test_malformed_premise_never_raises(self):
        cert = {'steps': [
            {'op': 'infer', 'premises': ['zero'], 'rule': 'r',
             'formula': ['atom', 'z']}]}
        r = audit_certificate(cert)
        self.assertFalse(r['final_claim_supported'])
        self.assertTrue(r['malformed_premises'])

    def test_premise_cycles_terminate(self):
        cert = {'steps': [
            {'op': 'infer', 'premises': [1], 'rule': 'r', 'formula': ['atom', 'c']},
            {'op': 'infer', 'premises': [0], 'rule': 'r', 'formula': ['atom', 'd']}]}
        r = audit_certificate(cert)
        self.assertEqual(r['reachable_steps'], 2)
        self.assertTrue(r['final_claim_supported'])

    def test_empty_certificate(self):
        r = audit_certificate({'steps': []})
        self.assertEqual(r['total_steps'], 0)
        self.assertFalse(r['final_claim_supported'])
        self.assertIsNone(r['final_step_index'])


if __name__ == '__main__':
    unittest.main()
