"""Offline tests for Mode A (oracle-assisted) certificate verification.

No Docker, no real Lean: a duck-typed backend returns the canonical
read_upper admissible execution and a fake kernel stands in for Lean. These
cover the proof-infrastructure contract (oracle execution + explicit valid
explanation -> signed bundle -> direct certificate -> checker) and its
tamper/forgery rejection, independent of autonomous discovery. The real-Lean
arithmetic-rejection path is covered by smoke_test.py (read_in_bounds).
"""
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from evidence import sha256_hex
from soundtrace_live.oracle_mode import (OracleError, read_upper_oob_steps,
                                         run_oracle_session,
                                         verify_oracle_bundle)
from test_checker import GOOD_LEAN, fake_lean
from test_cybergym_direct import STEPS
from test_cybergym_runner import KEY, TASK, FakeBackend, fake_execution

ORACLE_POC = b'\x00\x01\x02\x03'            # 4 bytes: matches fake_execution poc_size
WRONG_KEY = b'oracle-wrong-key-32-bytes-zzzzzz'


def _backend(poc=ORACLE_POC):
    return FakeBackend(script=[('ok',
                                fake_execution('X1', poc_sha256=sha256_hex(poc)))])


def _run(tmp, *, side='upper', access_kind='read', steps=None, poc=ORACLE_POC):
    out = Path(tmp) / 'bundle.json'
    return run_oracle_session(
        _backend(poc), KEY, out, task_id=TASK, oracle_poc=poc,
        steps=steps if steps is not None else read_upper_oob_steps(6, 4, 4),
        side=side, access_kind=access_kind)


class OracleStepsTests(unittest.TestCase):
    def test_generator_matches_lean_verified_fixture(self):
        # The canonical integers must reproduce the kernel-checked argument.
        self.assertEqual(read_upper_oob_steps(6, 4, 4), STEPS)

    def test_generator_tracks_observed_integers(self):
        steps = read_upper_oob_steps(10, 2, 9)   # 10 < 9 + 2
        observed = {tuple(s['formula'][:2]): s['formula'][2]
                    for s in steps if s['op'] == 'observe'
                    and s['formula'][0] == 'eq'}
        self.assertEqual(observed[('eq', 'extent')], 10)
        self.assertEqual(observed[('eq', 'width')], 2)
        self.assertEqual(observed[('eq', 'offset')], 9)


class OracleSessionTests(unittest.TestCase):
    def test_oracle_bundle_verifies(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundle = _run(tmp)
            payload = bundle['payload']
            self.assertEqual(payload['target_build'], 'vul')
            self.assertEqual(payload['producer'], 'cybergym-asan-v1')
            self.assertEqual(len(payload['executions']), 1)
            self.assertEqual(payload['claims']['C1']['frozen']['state'], 'bound')
            cert, report = verify_oracle_bundle(bundle, key=KEY,
                                                lean=fake_lean(tmp, GOOD_LEAN))
        self.assertEqual(report['status'], 'VERIFIED_EVIDENCE_AND_KERNEL')
        self.assertEqual(report['claim_id'], 'C1')
        self.assertEqual(report['backend']['axiom_audit'], 'empty')

    def test_wrong_key_is_rejected_not_verified(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundle = _run(tmp)
            _, report = verify_oracle_bundle(bundle, key=WRONG_KEY,
                                             lean=fake_lean(tmp, GOOD_LEAN))
        self.assertNotEqual(report['status'], 'VERIFIED_EVIDENCE_AND_KERNEL')

    def test_tampered_target_build_is_rejected(self):
        # Flipping the authenticated build after signing must not verify: the
        # execution was recorded against the vulnerable image, so admitting it
        # as a fix-build claim is refused end to end.
        from direct import DirectError
        with tempfile.TemporaryDirectory() as tmp:
            bundle = _run(tmp)
            bundle['payload']['target_build'] = 'fix'
            with self.assertRaises(DirectError):
                verify_oracle_bundle(bundle, key=KEY,
                                     lean=fake_lean(tmp, GOOD_LEAN))

    def test_fabricated_evidence_id_cannot_be_signed(self):
        # An observe step citing an undelivered evidence id must be refused by
        # the recorder, so no bound claim is ever produced.
        bad = read_upper_oob_steps(6, 4, 4)
        bad[0] = dict(bad[0], evidence='X1/A1.fabricated')
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(OracleError):
                _run(tmp, steps=bad)


if __name__ == '__main__':
    unittest.main()
