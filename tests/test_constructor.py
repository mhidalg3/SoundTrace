"""Behavioral regressions for the deterministic typed-trace constructor."""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from evidence import canonical_json, registry_digest, sha256_hex
from constructor import ConstructionFailure, construct_certificate

ROOT = Path(__file__).resolve().parent.parent
M = json.loads((ROOT / 'examples/manifest.json').read_text())
ARG = json.loads((ROOT / 'examples/argument.json').read_text())
FIXTURE_BUNDLE = sha256_hex(canonical_json(ARG))


def synth_manifest(symbols, records, claim_formula, claim_at=10, frm='goal',
                   scope='ctx1', unit='unit'):
    """Build a soundtrace-v1 manifest; symbols: [(name, sort)], records: [(id, formula, at)]."""
    m = {
        'profile': 'soundtrace-v1',
        'registry_id': '0' * 64,
        'unit': unit,
        'allowed_authorities': ['fixture'],
        'symbols': {name: ({'sort': 'Int', 'scope': scope, 'unit': unit} if sort == 'Int'
                           else {'sort': 'Prop', 'scope': scope})
                    for name, sort in symbols},
        'records': {rid: {'scope': scope, 'available_at': at, 'authority': 'fixture',
                          'formula': formula}
                    for rid, formula, at in records},
        'claims': {'C1': {'scope': scope, 'available_at': claim_at,
                          'formula': claim_formula, 'from': frm}},
    }
    m['registry_id'] = registry_digest(m)
    return m


def entry(seq, node):
    return {'seq': seq, 'argument_id': 'C1', 'node': node}


def observe(seq, nid, evidence, asserted):
    return entry(seq, {'id': nid, 'kind': 'observe', 'evidence': evidence, 'assert': asserted})


def calculate(seq, nid, operator, left, right, result):
    return entry(seq, {'id': nid, 'kind': 'calculate', 'operator': operator,
                       'left': left, 'right': right, 'result': result})


def compare(seq, nid, relation, left, right):
    return entry(seq, {'id': nid, 'kind': 'compare', 'relation': relation,
                       'left': left, 'right': right})


def conjoin(seq, nid, premises):
    return entry(seq, {'id': nid, 'kind': 'conjoin', 'premises': premises})


def infer(seq, nid, rule, premises, asserted):
    return entry(seq, {'id': nid, 'kind': 'infer', 'rule': rule,
                       'premises': premises, 'assert': asserted})


class FixtureExpansionTests(unittest.TestCase):
    def test_fixture_expands_to_eight_steps_five_nodes(self):
        cert = construct_certificate(M, ARG, bundle_sha256=FIXTURE_BUNDLE)
        self.assertEqual(len(cert['steps']), 8)
        self.assertEqual([e['source_id'] for e in cert['source_map']],
                         ['obs_a', 'obs_b', 'obs_c', 'sum_ab', 'cmp1'])
        self.assertEqual(cert['steps'][0]['op'], 'observe')
        self.assertEqual(cert['steps'][3]['rule'], 'add_eq')
        self.assertEqual(cert['steps'][7]['rule'], 'lt_transport')
        self.assertEqual(cert['bundle_sha256'], FIXTURE_BUNDLE)

    def test_certificate_round_trips_through_frontend_preflight(self):
        from frontend import compile_certificate
        cert = construct_certificate(M, ARG, bundle_sha256=FIXTURE_BUNDLE)
        _, report = compile_certificate(M, cert)
        self.assertEqual(report['status'], 'PREFLIGHT_PASS_NOT_KERNEL_VERIFIED')

    def test_repeated_construction_is_byte_identical(self):
        a = construct_certificate(M, ARG, bundle_sha256=FIXTURE_BUNDLE)
        b = construct_certificate(M, ARG, bundle_sha256=FIXTURE_BUNDLE)
        self.assertEqual(canonical_json(a), canonical_json(b))

    def test_reordered_json_keys_produce_identical_bytes(self):
        m2 = {k: M[k] for k in reversed(list(M))}
        m2['records'] = {k: M['records'][k] for k in reversed(list(M['records']))}
        arg2 = [{kk: v[kk] for kk in reversed(list(v))} for v in
                [{**e, 'node': {kk: e['node'][kk] for kk in reversed(list(e['node']))}}
                 for e in ARG]]
        a = construct_certificate(M, ARG, bundle_sha256=FIXTURE_BUNDLE)
        b = construct_certificate(m2, arg2, bundle_sha256=FIXTURE_BUNDLE)
        self.assertEqual(canonical_json(a), canonical_json(b))

    def test_node_text_retained_but_never_interpreted(self):
        arg = json.loads(json.dumps(ARG))
        for e in arg:
            e['node']['text'] = 'narrative claiming anything at all'
        a = construct_certificate(M, arg, bundle_sha256=FIXTURE_BUNDLE)
        b = construct_certificate(M, ARG, bundle_sha256=FIXTURE_BUNDLE)
        self.assertEqual(canonical_json(a), canonical_json(b))


def oob_target(violation):
    return ['and', ['atom', 'access'],
            ['and', ['atom', 'live'],
             ['and', ['le', 0, 'extent'],
              ['and', ['lt', 0, 'width'], violation]]]]


def oob_records(extent, width, offset, at=2):
    return [('X1/A1.access', ['atom', 'access'], at),
            ('X1/A1.live', ['atom', 'live'], at),
            ('X1/A1.extent', ['eq', 'extent', extent], at),
            ('X1/A1.width', ['eq', 'width', width], at),
            ('X1/A1.offset', ['eq', 'offset', offset], at)]


def oob_symbols():
    return [('access', 'Prop'), ('live', 'Prop'), ('extent', 'Int'),
            ('width', 'Int'), ('offset', 'Int')]


def oob_manifest(scope='RUN/X1/O1/g1/A1'):
    return synth_manifest(oob_symbols(), oob_records(6, 4, 4),
                          oob_target(['lt', 'extent', ['add', 'offset', 'width']]),
                          claim_at=30, frm='goal', scope=scope)


def oob_argument(seq_start=4, extent=6, width=4, offset=4, end_result=None):
    """Observe all five facts, assert guards, calculate the endpoint, compare the
    selected boundary, and conjoin the frozen target."""
    if end_result is None:
        end_result = offset + width
    return [
        observe(seq_start, 'acc', 'X1/A1.access', ['atom', 'access']),
        observe(seq_start + 1, 'lv', 'X1/A1.live', ['atom', 'live']),
        observe(seq_start + 2, 'ex', 'X1/A1.extent', ['eq', 'extent', extent]),
        observe(seq_start + 3, 'wd', 'X1/A1.width', ['eq', 'width', width]),
        observe(seq_start + 4, 'of', 'X1/A1.offset', ['eq', 'offset', offset]),
        calculate(seq_start + 5, 'end', 'add', {'ref': 'of'}, {'ref': 'wd'}, end_result),
        compare(seq_start + 6, 'vio', 'lt', {'ref': 'ex'}, {'ref': 'end'}),
        compare(seq_start + 7, 'pos_w', 'lt', 0, {'ref': 'wd'}),
        compare(seq_start + 8, 'nnl_e', 'le', 0, {'ref': 'ex'}),
        conjoin(seq_start + 9, 'inner', ['pos_w', 'vio']),
        conjoin(seq_start + 10, 'range', ['nnl_e', 'inner']),
        conjoin(seq_start + 11, 'alive', ['lv', 'range']),
        conjoin(seq_start + 12, 'goal', ['acc', 'alive']),
    ]


def lower_oob_argument(seq_start=4, extent=16, width=4, offset=-4):
    """Lower-overflow argument: negative-offset comparison only, no upper claim."""
    return [
        observe(seq_start, 'acc', 'X1/A1.access', ['atom', 'access']),
        observe(seq_start + 1, 'lv', 'X1/A1.live', ['atom', 'live']),
        observe(seq_start + 2, 'ex', 'X1/A1.extent', ['eq', 'extent', extent]),
        observe(seq_start + 3, 'wd', 'X1/A1.width', ['eq', 'width', width]),
        observe(seq_start + 4, 'of', 'X1/A1.offset', ['eq', 'offset', offset]),
        compare(seq_start + 5, 'neg', 'lt', {'ref': 'of'}, 0),
        compare(seq_start + 6, 'pos_w', 'lt', 0, {'ref': 'wd'}),
        compare(seq_start + 7, 'nnl_e', 'le', 0, {'ref': 'ex'}),
        conjoin(seq_start + 8, 'inner', ['pos_w', 'neg']),
        conjoin(seq_start + 9, 'range', ['nnl_e', 'inner']),
        conjoin(seq_start + 10, 'alive', ['lv', 'range']),
        conjoin(seq_start + 11, 'goal', ['acc', 'alive']),
    ]


class OOBShapedArgumentTests(unittest.TestCase):
    def test_upper_argument_constructs(self):
        cert = construct_certificate(oob_manifest(), oob_argument(), bundle_sha256='ab' * 32)
        last = cert['source_map'][-1]
        self.assertEqual(last['source_id'], 'goal')
        self.assertEqual(last['last_step'], len(cert['steps']) - 1)

    def test_lower_argument_constructs(self):
        m = synth_manifest(oob_symbols(), oob_records(16, 4, -4),
                           oob_target(['lt', 'offset', 0]), claim_at=30, frm='goal')
        cert = construct_certificate(m, lower_oob_argument(), bundle_sha256='ab' * 32)
        self.assertEqual(cert['source_map'][-1]['source_id'], 'goal')

    def test_wrong_endpoint_result_rejected_at_source_node(self):
        # The recorded '4+4=7' assertion is kept, not repaired: construction
        # fails at that node even though every observation is genuine.
        argument = oob_argument(end_result=7)
        with self.assertRaises(ConstructionFailure) as ctx:
            construct_certificate(oob_manifest(), argument, bundle_sha256='ab' * 32)
        self.assertEqual(ctx.exception.status, 'REJECTED')
        self.assertEqual(ctx.exception.reason, 'FALSE_ARITHMETIC')
        self.assertEqual(ctx.exception.source_id, 'end')

    def test_false_boundary_comparison_rejected(self):
        # in_bounds shape: extent=16, offset=12, width=4; endpoint is exactly
        # 16, so the upper OOB comparison 16 < 16 is false.
        m = synth_manifest(oob_symbols(), oob_records(16, 4, 12),
                           oob_target(['lt', 'extent', ['add', 'offset', 'width']]),
                           claim_at=30, frm='goal')
        argument = oob_argument(extent=16, width=4, offset=12, end_result=16)
        with self.assertRaises(ConstructionFailure) as ctx:
            construct_certificate(m, argument, bundle_sha256='ab' * 32)
        self.assertEqual(ctx.exception.reason, 'FALSE_ARITHMETIC')
        self.assertEqual(ctx.exception.source_id, 'vio')

    def test_missing_access_observation_is_unsupported(self):
        m = oob_manifest()
        m['records'] = {k: v for k, v in m['records'].items() if k != 'X1/A1.access'}
        m['registry_id'] = registry_digest(m)
        argument = oob_argument()
        with self.assertRaises(ConstructionFailure) as ctx:
            construct_certificate(m, argument, bundle_sha256='ab' * 32)
        self.assertEqual(ctx.exception.status, 'UNSUPPORTED_TRACE')
        self.assertEqual(ctx.exception.reason, 'MISSING_OBSERVATION')
        self.assertEqual(ctx.exception.source_id, 'acc')


class AlignmentTests(unittest.TestCase):
    def test_observation_at_or_after_its_entry_fails_temporal_alignment(self):
        # Evidence delivered at response position 9; the offset observe node is
        # recorded at request seq 8: delivery is NOT strictly before the entry.
        m = oob_manifest()
        m['records']['X1/A1.offset']['available_at'] = 9
        m['registry_id'] = registry_digest(m)
        argument = oob_argument()
        with self.assertRaises(ConstructionFailure) as ctx:
            construct_certificate(m, argument, bundle_sha256='ab' * 32)
        self.assertEqual(ctx.exception.reason, 'SOURCE_ALIGNMENT_FAILED')
        self.assertEqual(ctx.exception.source_id, 'of')

    def test_forward_reference_rejected(self):
        argument = oob_argument()
        argument[5]['node']['left'] = {'ref': 'vio'}
        with self.assertRaises(ConstructionFailure) as ctx:
            construct_certificate(oob_manifest(), argument, bundle_sha256='ab' * 32)
        self.assertEqual(ctx.exception.reason, 'SOURCE_ALIGNMENT_FAILED')
        self.assertEqual(ctx.exception.source_id, 'end')

    def test_unknown_reference_rejected(self):
        argument = oob_argument()
        argument[5]['node']['left'] = {'ref': 'nonexistent'}
        with self.assertRaises(ConstructionFailure) as ctx:
            construct_certificate(oob_manifest(), argument, bundle_sha256='ab' * 32)
        self.assertEqual(ctx.exception.reason, 'SOURCE_ALIGNMENT_FAILED')

    def test_self_reference_rejected(self):
        argument = oob_argument()
        argument[5]['node']['left'] = {'ref': 'end'}
        with self.assertRaises(ConstructionFailure) as ctx:
            construct_certificate(oob_manifest(), argument, bundle_sha256='ab' * 32)
        self.assertEqual(ctx.exception.reason, 'SOURCE_ALIGNMENT_FAILED')

    def test_circular_conjoin_rejected(self):
        argument = oob_argument()
        argument[12]['node']['premises'] = ['goal', 'goal']
        with self.assertRaises(ConstructionFailure) as ctx:
            construct_certificate(oob_manifest(), argument, bundle_sha256='ab' * 32)
        self.assertEqual(ctx.exception.reason, 'SOURCE_ALIGNMENT_FAILED')
        self.assertEqual(ctx.exception.source_id, 'goal')

    def test_referenced_node_must_end_in_literal_equality(self):
        argument = oob_argument()
        argument[6]['node']['left'] = {'ref': 'acc'}  # acc concludes an atom
        with self.assertRaises(ConstructionFailure) as ctx:
            construct_certificate(oob_manifest(), argument, bundle_sha256='ab' * 32)
        self.assertEqual(ctx.exception.reason, 'SOURCE_ALIGNMENT_FAILED')
        self.assertEqual(ctx.exception.source_id, 'vio')

    def test_claim_from_must_name_last_node(self):
        m = oob_manifest()
        m['claims']['C1']['from'] = 'alive'
        m['registry_id'] = registry_digest(m)
        with self.assertRaises(ConstructionFailure) as ctx:
            construct_certificate(m, oob_argument(), bundle_sha256='ab' * 32)
        self.assertEqual(ctx.exception.reason, 'CLAIM_MISMATCH')

    def test_final_node_must_establish_frozen_target(self):
        m = oob_manifest()
        m['claims']['C1']['formula'] = ['atom', 'access']
        m['registry_id'] = registry_digest(m)
        with self.assertRaises(ConstructionFailure) as ctx:
            construct_certificate(m, oob_argument(), bundle_sha256='ab' * 32)
        self.assertEqual(ctx.exception.reason, 'CLAIM_MISMATCH')

    def test_argument_id_must_match_claim(self):
        argument = json.loads(json.dumps(oob_argument()))
        argument[0]['argument_id'] = 'C2'
        with self.assertRaises(ConstructionFailure) as ctx:
            construct_certificate(oob_manifest(), argument, bundle_sha256='ab' * 32)
        self.assertEqual(ctx.exception.reason, 'CLAIM_MISMATCH')

    def test_non_object_entry_rejected_not_crash(self):
        argument = oob_argument()
        argument[3] = ['not', 'an', 'object']
        with self.assertRaises(ConstructionFailure) as ctx:
            construct_certificate(oob_manifest(), argument, bundle_sha256='ab' * 32)
        self.assertEqual(ctx.exception.reason, 'BAD_INPUT')


class NodeContractTests(unittest.TestCase):
    def construct(self, argument):
        return construct_certificate(oob_manifest(), argument, bundle_sha256='ab' * 32)

    def test_unsupported_node_kind(self):
        argument = oob_argument() + [entry(20, {'id': 'x', 'kind': 'introspect'})]
        with self.assertRaises(ConstructionFailure) as ctx:
            self.construct(argument)
        self.assertEqual(ctx.exception.status, 'UNSUPPORTED_TRACE')
        self.assertEqual(ctx.exception.reason, 'UNSUPPORTED_CONSTRUCT')
        self.assertEqual(ctx.exception.source_id, 'x')

    def test_unsupported_operator(self):
        argument = oob_argument()
        argument[5]['node']['operator'] = 'mul'
        with self.assertRaises(ConstructionFailure) as ctx:
            self.construct(argument)
        self.assertEqual(ctx.exception.reason, 'UNSUPPORTED_CONSTRUCT')

    def test_unsupported_relation(self):
        argument = oob_argument()
        argument[6]['node']['relation'] = 'ge'
        with self.assertRaises(ConstructionFailure) as ctx:
            self.construct(argument)
        self.assertEqual(ctx.exception.reason, 'UNSUPPORTED_CONSTRUCT')

    def test_wrong_explicit_rule_conclusion(self):
        argument = oob_argument()
        argument[6] = infer(10, 'of_symm', 'eq_symm', ['of'], ['eq', 'width', 4])
        with self.assertRaises(ConstructionFailure) as ctx:
            self.construct(argument)
        self.assertEqual(ctx.exception.reason, 'INVALID_INFERENCE')
        self.assertEqual(ctx.exception.source_id, 'of_symm')

    def test_literal_left_reference_not_silently_normalized(self):
        # of_symm concludes 4 = offset (literal on the LEFT); a calculate
        # operand must conclude an equality with a literal on the right, and
        # references are never silently normalized to fit.
        argument = oob_argument()
        symm = infer(0, 'of_symm', 'eq_symm', ['of'], ['eq', 4, 'offset'])
        slot = argument[5]['seq']
        for later in argument[5:]:
            later['seq'] += 1
        symm['seq'] = slot
        argument.insert(5, symm)  # before the calculate, after the observes
        argument[6]['node']['left'] = {'ref': 'of_symm'}
        with self.assertRaises(ConstructionFailure) as ctx:
            self.construct(argument)
        self.assertEqual(ctx.exception.reason, 'SOURCE_ALIGNMENT_FAILED')
        self.assertEqual(ctx.exception.source_id, 'end')

    def test_invented_rule_rejected(self):
        argument = oob_argument()
        argument[6] = infer(10, 'of_magic_node', 'of_magic', ['of'], ['eq', 4, 'offset'])
        with self.assertRaises(ConstructionFailure) as ctx:
            self.construct(argument)
        self.assertEqual(ctx.exception.reason, 'INVALID_INFERENCE')

    def test_bool_seq_rejected(self):
        argument = oob_argument()
        argument[0]['seq'] = True
        with self.assertRaises(ConstructionFailure) as ctx:
            self.construct(argument)
        self.assertEqual(ctx.exception.reason, 'BAD_INPUT')

    def test_non_increasing_seq_rejected(self):
        argument = oob_argument()
        argument[1]['seq'] = argument[0]['seq']
        with self.assertRaises(ConstructionFailure) as ctx:
            self.construct(argument)
        self.assertEqual(ctx.exception.reason, 'BAD_INPUT')

    def test_extra_entry_key_rejected(self):
        argument = oob_argument()
        argument[0]['annotation'] = 'trust me'
        with self.assertRaises(ConstructionFailure) as ctx:
            self.construct(argument)
        self.assertEqual(ctx.exception.reason, 'BAD_INPUT')

    def test_missing_node_key_rejected(self):
        argument = oob_argument()
        del argument[0]['node']
        with self.assertRaises(ConstructionFailure) as ctx:
            self.construct(argument)
        self.assertEqual(ctx.exception.reason, 'BAD_INPUT')

    def test_final_certificate_size_enforced_at_last_source_node(self):
        # Long source IDs inflate source_map beyond the per-step sums; the
        # complete serialized certificate must fit the byte budget.
        from unittest.mock import patch
        first_id = 'a' + 'x' * 120
        last_id = 'z' + 'x' * 120
        m = synth_manifest([('p', 'Prop'), ('q', 'Prop')],
                           [('E1', ['atom', 'p'], 1), ('E2', ['atom', 'q'], 1)],
                           ['and', ['atom', 'p'], ['atom', 'q']], claim_at=50,
                           frm=last_id)
        argument = [observe(2, first_id, 'E1', ['atom', 'p']),
                    observe(3, 'b', 'E2', ['atom', 'q']),
                    conjoin(4, last_id, [first_id, 'b'])]
        with patch('constructor.LIMIT_BYTES', 600):
            with self.assertRaises(ConstructionFailure) as ctx:
                construct_certificate(m, argument, bundle_sha256='ab' * 32)
        self.assertEqual(ctx.exception.reason, 'LIMIT_EXCEEDED')
        self.assertEqual(ctx.exception.source_id, last_id)

    def test_duplicate_node_id_rejected(self):
        argument = oob_argument()
        argument[7]['node']['id'] = argument[6]['node']['id']
        with self.assertRaises(ConstructionFailure) as ctx:
            self.construct(argument)
        self.assertEqual(ctx.exception.reason, 'BAD_INPUT')

    def test_extra_node_key_rejected(self):
        argument = oob_argument()
        argument[0]['node']['confidence'] = 0.9
        with self.assertRaises(ConstructionFailure) as ctx:
            self.construct(argument)
        self.assertEqual(ctx.exception.reason, 'BAD_INPUT')

    def test_bool_result_rejected_as_bad_input(self):
        argument = oob_argument()
        argument[5]['node']['result'] = True
        with self.assertRaises(ConstructionFailure) as ctx:
            self.construct(argument)
        self.assertEqual(ctx.exception.reason, 'BAD_INPUT')

    def test_empty_argument_rejected(self):
        with self.assertRaises(ConstructionFailure) as ctx:
            self.construct([])
        self.assertEqual(ctx.exception.reason, 'BAD_INPUT')


class LimitTests(unittest.TestCase):
    def test_repeated_doubling_hits_byte_budget_at_named_node(self):
        # Doubling conjunctions share Python substructure, but serialized size
        # doubles per level; the incremental byte budget must trip at a named
        # source node before the exponential expression is materialized. The
        # limit fires during expansion, before the (unsatisfiable) final claim
        # comparison could matter.
        m = synth_manifest([('p', 'Prop'), ('q', 'Prop')],
                           [('E1', ['atom', 'p'], 1), ('E2', ['atom', 'q'], 1)],
                           ['atom', 'p'], claim_at=1000, frm='never')
        argument = [observe(2, 'a', 'E1', ['atom', 'p']),
                    observe(3, 'b', 'E2', ['atom', 'q']),
                    conjoin(4, 'c0', ['a', 'b'])]
        seq = 5
        for level in range(1, 26):
            argument.append(conjoin(seq, f'c{level}', [f'c{level - 1}', f'c{level - 1}']))
            seq += 1
        with self.assertRaises(ConstructionFailure) as ctx:
            construct_certificate(m, argument, bundle_sha256='ab' * 32)
        self.assertEqual(ctx.exception.reason, 'LIMIT_EXCEEDED')
        self.assertRegex(ctx.exception.source_id, r'^c\d+$')
        self.assertLess(int(ctx.exception.source_id[1:]), 26)

    def test_step_expansion_limit_at_named_node(self):
        # and_intro/and_left pairs hold formula depth flat while steps grow by
        # two per pair, so the 1000-expanded-step cap is what trips.
        m = synth_manifest([('p', 'Prop'), ('q', 'Prop')],
                           [('E1', ['atom', 'p'], 1), ('E2', ['atom', 'q'], 1)],
                           ['and', ['atom', 'p'], ['atom', 'q']], claim_at=100000,
                           frm='never')
        argument = [observe(2, 'a', 'E1', ['atom', 'p']),
                    observe(3, 'b', 'E2', ['atom', 'q']),
                    conjoin(4, 'c0', ['a', 'b'])]
        seq = 5
        for i in range(600):
            argument.append(infer(seq, f'l{i}', 'and_left', [f'c{i}'], ['atom', 'p']))
            argument.append(conjoin(seq + 1, f'c{i + 1}', [f'l{i}', 'b']))
            seq += 2
        with self.assertRaises(ConstructionFailure) as ctx:
            construct_certificate(m, argument, bundle_sha256='ab' * 32)
        self.assertEqual(ctx.exception.reason, 'LIMIT_EXCEEDED')
        self.assertRegex(ctx.exception.source_id, r'^(l|c)\d+$')


class RegistryDigestTests(unittest.TestCase):
    def test_registry_digest_beginning_with_decimal_digit_accepted(self):
        # Search a non-semantic field until the computed digest starts with a
        # digit; a valid digest must not be rejected for its leading character.
        m = oob_manifest()
        found = None
        for i in range(5000):
            m['claims']['C1']['source_span'] = f'probe-{i}'
            m['registry_id'] = registry_digest(m)
            if m['registry_id'][0].isdigit():
                found = m['registry_id']
                break
        self.assertIsNotNone(found, 'a digit-leading digest exists within 5000 probes')
        cert = construct_certificate(m, oob_argument(), bundle_sha256='ab' * 32)
        self.assertEqual(cert['registry_id'], found)
        from frontend import compile_certificate
        _, report = compile_certificate(m, cert)
        self.assertEqual(report['status'], 'PREFLIGHT_PASS_NOT_KERNEL_VERIFIED')


if __name__ == '__main__':
    unittest.main()
