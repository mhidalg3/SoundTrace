"""Behavioral regressions for the soundtrace-v1 frontend contracts and rules.

Migrated from the original author-constructed smoke matrix, extended for the
new profile: strict schemas, registry digests, admissible observations, the
nine-rule core, source maps, and the hardened Lean backend boundary.
"""
import json
import stat
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from evidence import Rejected, canonical_json, registry_digest
from frontend import (MAX_INT, Rejected as FrontRejected, RULE_LEAN, check_lean,
                      compile_certificate, formula, rule_head, validate_manifest,
                      validate_certificate)

ROOT = Path(__file__).resolve().parent.parent
M = json.loads((ROOT / 'examples/manifest.json').read_text())
C = json.loads((ROOT / 'examples/certificate.json').read_text())


def rehash(manifest):
    manifest = json.loads(json.dumps(manifest))
    manifest['registry_id'] = registry_digest(manifest)
    return manifest

def compile_case(mutate=None):
    m, c = json.loads(json.dumps(M)), json.loads(json.dumps(C))
    if mutate:
        mutate(m, c)
    m = rehash(m)
    if 'registry_id' in c and c['registry_id'] == json.loads(json.dumps(C))['registry_id']:
        # Keep the certificate aligned with the mutated manifest so rejection
        # tests exercise their intended checks, not a stale digest.
        c['registry_id'] = m['registry_id']
    return compile_certificate(m, c)

def fake_lean(tmp, body, version='Lean (version 4.34.1, aarch64-apple-darwin, Release)'):
    path = Path(tmp) / 'lean'
    path.write_text('#!/bin/sh\n'
                    f'if [ "$1" = "--version" ]; then echo "{version}"; exit 0; fi\n'
                    + body)
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return str(path)


class FixtureTests(unittest.TestCase):
    def test_valid_arithmetic_chain_passes_preflight(self):
        code, report = compile_case()
        self.assertEqual(report['status'], 'PREFLIGHT_PASS_NOT_KERNEL_VERIFIED')
        self.assertEqual(report['steps'], 8)
        self.assertEqual(report['evidence_used'], ['E1', 'E2', 'E3'])

    def test_canonical_key_order_is_irrelevant(self):
        m = rehash(M)
        code_a, _ = compile_certificate(m, C)
        m2 = {k: m[k] for k in reversed(list(m))}
        m2['symbols'] = {k: m['symbols'][k] for k in reversed(list(m['symbols']))}
        code_b, _ = compile_certificate(rehash(m2), C)
        self.assertEqual(code_a, code_b)

    def test_registry_digest_depends_on_content(self):
        m = rehash(M)
        m['records']['E1']['available_at'] = 2
        self.assertNotEqual(registry_digest(m), m['registry_id'])


class ManifestContractTests(unittest.TestCase):
    def assert_rejected(self, mutate):
        with self.assertRaises(FrontRejected):
            compile_case(mutate)

    def test_registry_digest_must_recompute(self):
        m = json.loads(json.dumps(M))
        m['registry_id'] = registry_digest(m)
        m['records']['E1']['available_at'] = 2  # content changed, digest stale
        with self.assertRaises(FrontRejected):
            compile_certificate(m, C)

    def test_unknown_evidence(self):
        self.assert_rejected(lambda m, c: c['steps'][0].update(evidence='missing'))

    def test_changed_observed_value(self):
        self.assert_rejected(lambda m, c: c['steps'][0].update(formula=['eq', 'a', 121]))

    def test_cross_scope_evidence(self):
        self.assert_rejected(lambda m, c: m['records']['E1'].update(scope='ctx2'))

    def test_post_claim_evidence(self):
        self.assert_rejected(lambda m, c: m['records']['E1'].update(available_at=11))

    def test_unapproved_authority(self):
        self.assert_rejected(lambda m, c: m['records']['E1'].update(authority='agent_stdout'))

    def test_conflicting_record_assignments_rejected(self):
        def mutate(m, c):
            m['records']['E9'] = {'scope': 'ctx1', 'available_at': 2, 'authority': 'fixture',
                                  'formula': ['eq', 'a', 121]}
        self.assert_rejected(mutate)

    def test_identical_corroborating_assignment_accepted(self):
        m = json.loads(json.dumps(M))
        m['records']['E9'] = {'scope': 'ctx1', 'available_at': 2, 'authority': 'fixture',
                              'formula': ['eq', 'a', 120]}
        validate_manifest(rehash(m))


    def test_symbol_unit_must_match_manifest(self):
        self.assert_rejected(lambda m, c: m['symbols']['a'].update(unit='other'))

    def test_missing_unit_rejected(self):
        self.assert_rejected(lambda m, c: m.pop('unit'))

    def test_bool_available_at_rejected(self):
        self.assert_rejected(lambda m, c: m['records']['E1'].update(available_at=True))

    def test_unexpected_manifest_key_rejected(self):
        self.assert_rejected(lambda m, c: m.update(extra=1))

    def test_unexpected_record_key_rejected(self):
        self.assert_rejected(lambda m, c: m['records']['E1'].update(notes='x'))

    def test_inadmissible_observation_record_rejected(self):
        self.assert_rejected(lambda m, c: m['records']['E1'].update(formula=['lt', 'a', 121]))

    def test_reversed_observation_equality_rejected(self):
        self.assert_rejected(lambda m, c: m['records']['E1'].update(formula=['eq', 120, 'a']))

    def test_changed_frozen_goal(self):
        self.assert_rejected(lambda m, c: m['claims']['C1'].update(formula=['lt', 'c', 'a']))

    def test_scope_bound_symbol(self):
        self.assert_rejected(lambda m, c: m['symbols']['a'].update(scope='ctx2'))

    def test_unknown_claim(self):
        self.assert_rejected(lambda m, c: c.update(claim_id='not_in_manifest'))

    def test_cross_registry_certificate(self):
        self.assert_rejected(lambda m, c: c.update(registry_id='0' * 64))

    def test_profile_mismatch(self):
        self.assert_rejected(lambda m, c: c.update(profile='traceproof-v0'))

    def test_oversized_integer(self):
        self.assert_rejected(lambda m, c: c['steps'][4].update(
            formula=['eq', ['add', 120, 16], MAX_INT * 10]))

    def test_undeclared_symbol(self):
        self.assert_rejected(lambda m, c: c['steps'][0].update(formula=['eq', 'z', 120]))

    def test_bool_is_not_int(self):
        self.assert_rejected(lambda m, c: c['steps'][4].update(formula=['eq', True, 1]))


class CertificateContractTests(unittest.TestCase):
    def assert_rejected(self, mutate):
        with self.assertRaises(FrontRejected):
            compile_case(mutate)

    def test_unexpected_certificate_key_rejected(self):
        self.assert_rejected(lambda m, c: c.update(note='x'))

    def test_bundle_digest_must_be_hex64(self):
        self.assert_rejected(lambda m, c: c.update(bundle_sha256='zz' * 32))

    def test_source_map_hole_rejected(self):
        self.assert_rejected(lambda m, c: c['source_map'].pop(2))

    def test_source_map_duplicate_step_rejected(self):
        self.assert_rejected(
            lambda m, c: c['source_map'].insert(2, {'source_id': 'dup',
                                                    'first_step': 3, 'last_step': 3}))

    def test_source_map_overflow_rejected(self):
        self.assert_rejected(lambda m, c: c['source_map'][-1].update(last_step=99))

    def test_source_map_bool_index_rejected(self):
        self.assert_rejected(lambda m, c: c['source_map'][0].update(first_step=False))

    def test_extra_step_key_rejected(self):
        self.assert_rejected(lambda m, c: c['steps'][0].update(why='x'))

    def test_wrong_arithmetic(self):
        self.assert_rejected(lambda m, c: c['steps'][4].update(
            formula=['eq', ['add', 120, 16], 135]))

    def test_nonclosed_compute(self):
        self.assert_rejected(lambda m, c: c['steps'][4].update(
            formula=['eq', ['add', 'a', 16], 136]))

    def test_invented_rule(self):
        self.assert_rejected(lambda m, c: c['steps'][3].update(rule='looks_plausible'))

    def test_modus_ponens_rejected_profile_wide(self):
        self.assert_rejected(lambda m, c: c['steps'][3].update(rule='modus_ponens'))

    def test_wrong_premise_count(self):
        self.assert_rejected(lambda m, c: c['steps'][3].update(premises=[0]))

    def test_forward_reference(self):
        self.assert_rejected(lambda m, c: c['steps'][3].update(premises=[0, 7]))

    def test_self_reference(self):
        self.assert_rejected(lambda m, c: c['steps'][3].update(premises=[0, 3]))

    def test_premise_swapped_in_transitivity(self):
        self.assert_rejected(lambda m, c: c['steps'][5].update(premises=[4, 3]))

    def test_wrong_order_binding(self):
        self.assert_rejected(lambda m, c: c['steps'][7].update(premises=[0, 5, 6]))

    def test_unsupported_op(self):
        self.assert_rejected(lambda m, c: c['steps'][4].update(op='execute_python'))

    def test_last_step_must_establish_claim(self):
        self.assert_rejected(lambda m, c: c['steps'].insert(
            6, {'op': 'compute', 'formula': ['le', 1, 1]}))


class LanguageTests(unittest.TestCase):
    def setUp(self):
        self.symbols = {'a': {'sort': 'Int', 'scope': 's', 'unit': 'u'},
                        'b': {'sort': 'Int', 'scope': 's', 'unit': 'u'},
                        'p': {'sort': 'Prop', 'scope': 's'},
                        'q': {'sort': 'Prop', 'scope': 's'}}

    def test_implication_removed_from_language(self):
        with self.assertRaises(FrontRejected):
            formula(['imp', ['atom', 'p'], ['atom', 'q']], self.symbols)

    def test_modus_ponens_removed_from_rules(self):
        self.assertNotIn('modus_ponens', RULE_LEAN)
        with self.assertRaises(FrontRejected):
            rule_head('modus_ponens', [[['imp', ['atom', 'p'], ['atom', 'q']],
                                        ['atom', 'p']]])

    def test_deep_formula_rejected(self):
        f = ['atom', 'p']
        for _ in range(30):
            f = ['and', f, f]
        with self.assertRaises(FrontRejected):
            formula(f, self.symbols)


class RuleTableTests(unittest.TestCase):
    def test_all_nine_rule_heads(self):
        p, q = ['atom', 'p'], ['atom', 'q']
        cases = [
            ('and_intro', [p, q], ['and', p, q]),
            ('and_left', [['and', p, q]], p),
            ('and_right', [['and', p, q]], q),
            ('eq_symm', [['eq', 'a', 'b']], ['eq', 'b', 'a']),
            ('eq_trans', [['eq', 'a', 'b'], ['eq', 'b', 'c']], ['eq', 'a', 'c']),
            ('add_eq', [['eq', 'a', 1], ['eq', 'b', 2]], ['eq', ['add', 'a', 'b'], ['add', 1, 2]]),
            ('sub_eq', [['eq', 'a', 1], ['eq', 'b', 2]], ['eq', ['sub', 'a', 'b'], ['sub', 1, 2]]),
            ('lt_transport', [['eq', 'a', 1], ['eq', 'b', 2], ['lt', 1, 2]], ['lt', 'a', 'b']),
            ('le_transport', [['eq', 'a', 1], ['eq', 'b', 2], ['le', 1, 2]], ['le', 'a', 'b']),
        ]
        for name, premises, expected in cases:
            self.assertEqual(rule_head(name, premises), expected, name)

    def test_sub_eq_requires_equalities(self):
        with self.assertRaises(FrontRejected):
            rule_head('sub_eq', [['lt', 'a', 1], ['eq', 'b', 2]])

    def test_le_transport_requires_le(self):
        with self.assertRaises(FrontRejected):
            rule_head('le_transport', [['eq', 'a', 1], ['eq', 'b', 2], ['lt', 1, 2]])

    def test_transport_value_mismatch(self):
        with self.assertRaises(FrontRejected):
            rule_head('lt_transport', [['eq', 'a', 1], ['eq', 'b', 2], ['lt', 2, 1]])


class LeanBackendTests(unittest.TestCase):
    GOOD = "echo \"'certificate' does not depend on any axioms\"\nexit 0\n"

    def test_silent_zero_exit_rejected_missing_audit(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = check_lean('code', fake_lean(tmp, 'exit 0\n'), timeout=5)
        self.assertEqual(result['status'], 'REJECTED')
        self.assertEqual(result['reason'], 'KERNEL_REJECT')

    def test_nonempty_dependency_audit_rejected(self):
        body = ("echo \"'certificate' depends on axioms: [propext, Classical.choice, "
                "Quot.sound]\"\nexit 0\n")
        with tempfile.TemporaryDirectory() as tmp:
            result = check_lean('code', fake_lean(tmp, body), timeout=5)
        self.assertEqual(result['status'], 'REJECTED')
        self.assertEqual(result['reason'], 'KERNEL_REJECT')

    def test_sorry_ax_rejected(self):
        body = ("echo \"'certificate' depends on axioms: [sorryAx]\"\nexit 0\n")
        with tempfile.TemporaryDirectory() as tmp:
            result = check_lean('code', fake_lean(tmp, body), timeout=5)
        self.assertEqual(result['status'], 'REJECTED')
        self.assertEqual(result['reason'], 'KERNEL_REJECT')

    def test_error_output_rejected_even_with_audit(self):
        body = ('echo "file.lean:1:0: error: unknown identifier"\n'
                + self.GOOD + 'exit 0\n')
        with tempfile.TemporaryDirectory() as tmp:
            result = check_lean('code', fake_lean(tmp, body), timeout=5)
        self.assertEqual(result['status'], 'REJECTED')
        self.assertEqual(result['reason'], 'KERNEL_REJECT')

    def test_nonzero_exit_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = check_lean('code', fake_lean(tmp,
                "echo \"'certificate' does not depend on any axioms\"\nexit 3\n"), timeout=5)
        self.assertEqual(result['status'], 'REJECTED')
        self.assertEqual(result['reason'], 'KERNEL_REJECT')

    def test_exact_audit_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = check_lean('code', fake_lean(tmp, self.GOOD), timeout=5)
        self.assertEqual(result['status'], 'KERNEL_VERIFIED_RELATIVE_TO_MANIFEST')
        self.assertIn('does not depend on any axioms', result['axiom_audit'])

    def test_version_mismatch_inconclusive(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = fake_lean(tmp, self.GOOD, version='Lean (version 4.33.0, x86_64)')
            result = check_lean('code', path, timeout=5)
        self.assertEqual(result['status'], 'INCONCLUSIVE_TOOLCHAIN_MISMATCH')

    def test_missing_backend_inconclusive(self):
        result = check_lean('code', '/nonexistent/lean-binary', timeout=5)
        self.assertEqual(result['status'], 'INCONCLUSIVE_NO_LEAN_BACKEND')

    def test_timeout_inconclusive(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = check_lean('code', fake_lean(tmp, 'sleep 30\nexit 0\n'), timeout=0.5)
        self.assertEqual(result['status'], 'INCONCLUSIVE_TIMEOUT')

    def test_heartbeat_exhaustion_inconclusive_not_false(self):
        body = ('echo "file.lean:3:0: error: maximum number of heartbeats '
                '(50000) has been exceeded"\nexit 1\n')
        with tempfile.TemporaryDirectory() as tmp:
            result = check_lean('code', fake_lean(tmp, body), timeout=5)
        self.assertEqual(result['status'], 'INCONCLUSIVE_RESOURCE_LIMIT')

    def test_recursion_depth_inconclusive_not_false(self):
        body = ('echo "file.lean:3:0: error: maximum recursion depth has been '
                'reached"\nexit 1\n')
        with tempfile.TemporaryDirectory() as tmp:
            result = check_lean('code', fake_lean(tmp, body), timeout=5)
        self.assertEqual(result['status'], 'INCONCLUSIVE_RESOURCE_LIMIT')

    def test_lean_path_env_sanitized(self):
        # A real check_lean call must not hand import-path overrides to Lean.
        import os
        with tempfile.TemporaryDirectory() as tmp:
            seen = Path(tmp) / 'seen.txt'
            body = (f'printf "%s|%s" "$LEAN_PATH" "$LEAN_SRC_PATH" > {seen}\n' + self.GOOD)
            lean = fake_lean(tmp, body)
            saved = {k: os.environ.get(k) for k in ('LEAN_PATH', 'LEAN_SRC_PATH')}
            os.environ['LEAN_PATH'] = '/agent/controlled'
            os.environ['LEAN_SRC_PATH'] = '/agent/src'
            try:
                result = check_lean('code', lean, timeout=5)
            finally:
                for key, value in saved.items():
                    if value is None:
                        os.environ.pop(key, None)
                    else:
                        os.environ[key] = value
            self.assertEqual(result['status'], 'KERNEL_VERIFIED_RELATIVE_TO_MANIFEST')
            self.assertEqual(seen.read_text(), '|')


class SizeWalkerTests(unittest.TestCase):
    names = {'a': 'v0', 'b': 'v1', 'p': 'v0', 'q': 'v1', 'e': 'v2',
             'w': 'v3', 'o': 'v4'}

    def test_canonical_walker_exact_at_boundary(self):
        from frontend import canonical_formula_size
        props = [
            ['atom', 'p'],
            ['eq', 'a', 1],
            ['eq', -4, 0],
            ['lt', ['add', 'a', 'b'], 2],
            ['and', ['atom', 'p'], ['atom', 'q']],
            ['and', ['le', 0, 'e'],
             ['and', ['lt', 0, 'w'], ['lt', 'e', ['add', 'o', 'w']]]],
            ['eq', ['sub', ['add', 'a', 1], 'b'], ['add', 2, ['sub', 3, 4]]],
        ]
        for prop in props:
            exact = len(canonical_json(prop))
            self.assertTrue(canonical_formula_size(prop, exact), prop)
            self.assertFalse(canonical_formula_size(prop, exact - 1), prop)

    def test_render_walker_exact_at_boundary(self):
        from frontend import render_formula, render_size
        props = [
            ['eq', 'a', 1],
            ['lt', ['add', 'a', 'b'], 2],
            ['le', 0, 'e'],
            ['and', ['atom', 'p'], ['atom', 'q']],
            ['and', ['le', 0, 'e'],
             ['and', ['lt', 0, 'w'], ['lt', 'e', ['add', 'o', 'w']]]],
            ['eq', ['sub', ['add', 'a', 1], 'b'], ['add', 2, ['sub', 3, 4]]],
        ]
        for prop in props:
            exact = len(render_formula(prop, self.names).encode('utf-8'))
            self.assertTrue(render_size(prop, self.names, exact), prop)
            self.assertFalse(render_size(prop, self.names, exact - 1), prop)


class ClaimSourceBindingTests(unittest.TestCase):
    def test_final_source_map_entry_must_match_claim_from(self):
        with self.assertRaises(FrontRejected):
            compile_case(lambda m, c: c['source_map'][-1].update(source_id='other_node'))

    def test_claim_from_mismatch_on_manifest_side_rejected(self):
        with self.assertRaises(FrontRejected):
            compile_case(lambda m, c: m['claims']['C1'].update({'from': 'other_node'}))


if __name__ == '__main__':
    unittest.main()
