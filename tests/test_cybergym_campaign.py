"""Offline tests for the subscription-only campaign driver + diagnostics.

No Docker, no spawn, no API keys: the per-episode run is injected so the
loop, the 7-stage pipeline diagnostics, the null-control assessment, and the
fresh-per-episode isolation are all exercised deterministically.
"""
import asyncio
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from evidence import Rejected
from soundtrace_live import campaign as cm
from soundtrace_live.corpus import load_corpus

CORPUS = load_corpus(ROOT / 'corpora/cybergym_pilot.json')


def make_result(*, task_id='arvo:64574', difficulty='level1',
                target_build='vul', session_status='COMPLETED',
                turns=10, probe_count=1, admissible_count=1,
                evidence_ids=('X1/A1.access',), execution_id='X1',
                claim_id='C1', translation_status='EMITTED',
                checker_status='VERIFIED_EVIDENCE_AND_KERNEL',
                claim_status='BOUND', flag_success=True):
    return {
        'flag_success': flag_success, 'claim_status': claim_status,
        'translation_status': translation_status,
        'session_status': session_status, 'turns': turns,
        'probe_count': probe_count, 'admissible_count': admissible_count,
        'evidence_ids': list(evidence_ids), 'execution_id': execution_id,
        'claim_id': claim_id, 'checker_status': checker_status,
        'task_id': task_id, 'difficulty': difficulty,
        'target_build': target_build,
    }


class EpisodeTests(unittest.TestCase):
    def test_default_campaign_is_two_instances_and_inversions(self):
        eps = cm.default_episodes()
        self.assertEqual(len(eps), 4)
        self.assertEqual({e.task_id for e in eps},
                         {'arvo:64574', 'arvo:47101'})
        # Each instance appears once per build (vul + fix inversion).
        for task_id in ('arvo:64574', 'arvo:47101'):
            builds = {e.target_build for e in eps if e.task_id == task_id}
            self.assertEqual(builds, {'vul', 'fix'})
        self.assertEqual(len({e.label for e in eps}), 4)

    def test_bad_build_rejected(self):
        with self.assertRaises(Rejected):
            cm.Episode('arvo:64574', 'level1', 'patched')


class PipelineProgressTests(unittest.TestCase):
    def test_full_run_reaches_every_stage(self):
        prog = cm.pipeline_progress(make_result())
        self.assertIsNone(prog['stopped_at'])
        self.assertEqual(prog['reached'], 7)
        self.assertEqual(prog['deepest_stage'], 'lean_kernel')

    def test_explored_but_never_reported_stops_at_claim(self):
        # The v1 signal: probes + delivered evidence, but no report_oob.
        result = make_result(session_status='AGENT_BUDGET_EXHAUSTED',
                             execution_id=None, claim_id=None,
                             translation_status=None, checker_status=None,
                             claim_status=None, flag_success=None)
        prog = cm.pipeline_progress(result)
        self.assertEqual(prog['stopped_at'], 'claim_submission')
        self.assertEqual(prog['reached'], 3)
        self.assertEqual(prog['deepest_stage'], 'evidence_delivery')

    def test_patched_probe_without_admissible_stops_at_execution(self):
        result = make_result(target_build='fix',
                             session_status='AGENT_REPORTED_NONE',
                             admissible_count=0, evidence_ids=(),
                             execution_id=None, claim_id=None,
                             translation_status=None, checker_status=None,
                             claim_status=None, flag_success=None)
        prog = cm.pipeline_progress(result)
        self.assertEqual(prog['stages']['trusted_execution'],
                         'ran_no_admissible')
        self.assertEqual(prog['stopped_at'], 'trusted_execution')

    def test_setup_failure_stops_at_agent(self):
        result = make_result(session_status='INCONCLUSIVE_SETUP', turns=0,
                             probe_count=0, admissible_count=0,
                             evidence_ids=(), execution_id=None, claim_id=None,
                             translation_status=None, checker_status=None,
                             claim_status=None, flag_success=None)
        prog = cm.pipeline_progress(result)
        self.assertEqual(prog['stopped_at'], 'agent_investigation')
        self.assertEqual(prog['reached'], 0)


class AssessmentTests(unittest.TestCase):
    VUL = cm.Episode('arvo:64574', 'level1', 'vul')
    FIX = cm.Episode('arvo:64574', 'level1', 'fix')

    def test_vul_verified_is_oob_verified(self):
        a = cm.assess_episode(self.VUL, make_result())
        self.assertEqual(a['outcome'], 'OOB_VERIFIED')
        self.assertFalse(a['false_positive'])

    def test_vul_budget_is_insufficient_not_demonstration(self):
        a = cm.assess_episode(self.VUL, make_result(
            session_status='AGENT_BUDGET_EXHAUSTED', claim_status=None,
            checker_status=None, flag_success=None))
        self.assertEqual(a['outcome'], 'INSUFFICIENT_EVIDENCE')

    def test_vul_explicit_none_is_no_demonstration(self):
        a = cm.assess_episode(self.VUL, make_result(
            session_status='AGENT_REPORTED_NONE', execution_id=None,
            claim_id=None, claim_status=None, checker_status=None,
            flag_success=False))
        self.assertEqual(a['outcome'], 'NO_DEMONSTRATION')

    def test_fix_explicit_none_holds_control(self):
        a = cm.assess_episode(self.FIX, make_result(
            target_build='fix', session_status='AGENT_REPORTED_NONE',
            execution_id=None, claim_id=None, claim_status=None,
            checker_status=None, flag_success=None))
        self.assertEqual(a['outcome'], 'CONTROL_HELD')
        self.assertFalse(a['false_positive'])

    def test_fix_budget_is_insufficient_not_held(self):
        a = cm.assess_episode(self.FIX, make_result(
            target_build='fix', session_status='AGENT_BUDGET_EXHAUSTED',
            execution_id=None, claim_id=None, claim_status=None,
            checker_status=None, flag_success=None))
        self.assertEqual(a['outcome'], 'INSUFFICIENT_EVIDENCE')
        self.assertFalse(a['false_positive'])

    def test_fix_verified_oob_is_control_violation(self):
        a = cm.assess_episode(self.FIX, make_result(target_build='fix'))
        self.assertEqual(a['outcome'], 'CONTROL_VIOLATED')
        self.assertTrue(a['false_positive'])

    def test_fix_bound_claim_without_completion_is_violation(self):
        a = cm.assess_episode(self.FIX, make_result(
            target_build='fix', session_status='CHECKER_REJECTED',
            claim_status='BOUND', checker_status=None, flag_success=None))
        self.assertEqual(a['outcome'], 'CONTROL_VIOLATED')
        self.assertTrue(a['false_positive'])

    def test_fix_rejected_false_claim_is_false_claim_rejected(self):
        a = cm.assess_episode(self.FIX, make_result(
            target_build='fix', session_status='CHECKER_REJECTED',
            execution_id='X1', claim_id='C1', admissible_count=0,
            evidence_ids=(), claim_status='MISSING_ACCESS_EVIDENCE',
            checker_status=None, flag_success=None))
        self.assertEqual(a['outcome'], 'FALSE_CLAIM_REJECTED')
        self.assertFalse(a['false_positive'])

    def test_vul_rejected_claim_is_no_demonstration(self):
        a = cm.assess_episode(self.VUL, make_result(
            session_status='UNSUPPORTED_TRANSLATION', claim_status=None,
            checker_status=None, flag_success=None))
        self.assertEqual(a['outcome'], 'NO_DEMONSTRATION')


class RunCampaignTests(unittest.TestCase):
    def _run(self, run_fn, episodes=None, out_root=None, resume=False):
        return asyncio.run(cm.run_campaign(
            CORPUS, work_dir='/shared/work', key_path='/k/key',
            lean='/nonexistent/lean', out_root=out_root,
            episodes=episodes, deadline_s=123.0, spawn='SPAWN-SENTINEL',
            corpus_path='corpora/cybergym_pilot.json', run_fn=run_fn,
            resume=resume))

    def test_fresh_per_episode_dirs_and_shared_work_dir(self):
        calls = []

        async def run_fn(corpus, task_id, difficulty, **kw):
            calls.append({'task_id': task_id, 'difficulty': difficulty,
                          'work_dir': kw['work_dir'],
                          'out_dir': str(kw['out_dir']),
                          'target_build': kw['target_build'],
                          'spawn': kw['spawn'],
                          'corpus_path': kw['corpus_path']})
            none = kw['target_build'] == 'fix'
            return make_result(
                task_id=task_id, difficulty=difficulty,
                target_build=kw['target_build'],
                session_status='AGENT_REPORTED_NONE' if none else 'COMPLETED',
                execution_id=None if none else 'X1',
                claim_id=None if none else 'C1',
                claim_status=None if none else 'BOUND',
                translation_status=None if none else 'EMITTED',
                checker_status=None if none
                else 'VERIFIED_EVIDENCE_AND_KERNEL',
                admissible_count=0 if none else 1,
                evidence_ids=() if none else ('X1/A1.access',),
                flag_success=None if none else True)

        with tempfile.TemporaryDirectory() as tmp:
            manifest = self._run(run_fn, out_root=tmp)
            # Four episodes, each delivered the threaded build + spawn + corpus.
            self.assertEqual(len(calls), 4)
            self.assertEqual({c['work_dir'] for c in calls}, {'/shared/work'})
            self.assertEqual({c['spawn'] for c in calls}, {'SPAWN-SENTINEL'})
            self.assertEqual({c['corpus_path'] for c in calls},
                             {'corpora/cybergym_pilot.json'})
            # Fresh, non-colliding output directory per episode.
            out_dirs = [c['out_dir'] for c in calls]
            self.assertEqual(len(set(out_dirs)), 4)
            for ep in cm.default_episodes():
                self.assertIn(str(Path(tmp) / ep.label), out_dirs)
            # Manifest persisted and summarized.
            on_disk = json.loads((Path(tmp) / 'campaign.json').read_text())
            self.assertEqual(on_disk['schema'], cm.CAMPAIGN_SCHEMA)
            self.assertEqual(manifest['summary']['false_positives'], 0)
            self.assertEqual(manifest['summary']['outcomes'],
                             {'OOB_VERIFIED': 2, 'CONTROL_HELD': 2})

    def test_one_failing_episode_does_not_sink_the_rest(self):
        async def run_fn(corpus, task_id, difficulty, **kw):
            if task_id == 'arvo:47101':
                raise RuntimeError('spawn exploded')
            return make_result(task_id=task_id, difficulty=difficulty,
                               target_build=kw['target_build'])

        with tempfile.TemporaryDirectory() as tmp:
            manifest = self._run(run_fn, out_root=tmp)
        errored = [e for e in manifest['episodes'] if e.get('error')]
        self.assertEqual(len(errored), 2)                 # both 47101 builds
        self.assertIn('spawn exploded', errored[0]['error'])
        self.assertEqual(manifest['summary']['errors'], 2)

    def test_episode_outside_corpus_is_rejected(self):
        async def run_fn(*a, **k):      # never reached
            raise AssertionError('should not run')

        bad = [cm.Episode('arvo:3848', 'level1', 'vul')]  # not in pilot corpus
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(Rejected):
                self._run(run_fn, episodes=bad, out_root=tmp)

    def test_default_run_fn_is_subscription_named_agents(self):
        # With run_fn omitted the campaign must dispatch through the
        # subscription named-agent path (no API keys), not an injected stub.
        from unittest import mock
        calls = []

        async def fake(corpus, task_id, difficulty, **kw):
            calls.append((task_id, kw['target_build']))
            return make_result(task_id=task_id, difficulty=difficulty,
                               target_build=kw['target_build'])

        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch('soundtrace_live.harness.run_on_harness_agents',
                            fake):
                asyncio.run(cm.run_campaign(
                    CORPUS, work_dir='/w', key_path='/k',
                    lean='/nonexistent/lean', out_root=tmp, spawn='S',
                    corpus_path='corpora/cybergym_pilot.json'))
        self.assertEqual(len(calls), 4)
        self.assertEqual({b for _, b in calls}, {'vul', 'fix'})

    def test_resume_skips_completed_episodes(self):
        calls = []

        async def run_fn(corpus, task_id, difficulty, **kw):
            calls.append(task_id)
            return make_result(task_id=task_id, difficulty=difficulty,
                               target_build=kw['target_build'])
        with tempfile.TemporaryDirectory() as tmp:
            m1 = self._run(run_fn, out_root=tmp)
            self.assertEqual(len(calls), 4)

            async def boom(*a, **k):
                raise AssertionError('completed episodes must not be re-run')
            m2 = self._run(boom, out_root=tmp, resume=True)
            self.assertEqual(len(calls), 4)                  # no new runs
            self.assertEqual([e['result']['task_id'] for e in m2['episodes']],
                             [e['result']['task_id'] for e in m1['episodes']])

    def test_resume_retries_only_errored_episodes(self):
        async def run_fn(corpus, task_id, difficulty, **kw):
            if task_id == 'arvo:47101':
                raise RuntimeError('boom')
            return make_result(task_id=task_id, difficulty=difficulty,
                               target_build=kw['target_build'])
        with tempfile.TemporaryDirectory() as tmp:
            m1 = self._run(run_fn, out_root=tmp)
            self.assertEqual(
                len([e for e in m1['episodes'] if e.get('error')]), 2)
            calls = []

            async def run_fn2(corpus, task_id, difficulty, **kw):
                calls.append(task_id)
                return make_result(task_id=task_id, difficulty=difficulty,
                                   target_build=kw['target_build'])
            m2 = self._run(run_fn2, out_root=tmp, resume=True)
            self.assertEqual(sorted(calls), ['arvo:47101', 'arvo:47101'])
            self.assertFalse([e for e in m2['episodes'] if e.get('error')])

    def test_manifest_persisted_after_each_episode(self):
        seen = []

        async def run_fn(corpus, task_id, difficulty, **kw):
            path = Path(kw['out_dir']).parent / 'campaign.json'
            seen.append(len(json.loads(path.read_text())['episodes'])
                        if path.is_file() else 0)
            return make_result(task_id=task_id, difficulty=difficulty,
                               target_build=kw['target_build'])
        with tempfile.TemporaryDirectory() as tmp:
            self._run(run_fn, out_root=tmp)
        self.assertEqual(seen, [0, 1, 2, 3])

    def test_resume_post_publish_finishes_crashed_episode(self):
        from unittest import mock
        ep = cm.Episode('arvo:64574', 'level1', 'vul')
        sentinel = make_result(task_id='arvo:64574', difficulty='level1',
                               target_build='vul')

        async def boom(*a, **k):
            raise AssertionError('must post-publish resume, not re-run')
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = (Path(tmp) / ep.label / 'level1' / 'arvo:64574'
                       / 'S0-abcd')
            run_dir.mkdir(parents=True)
            (run_dir / 'bundle.json').write_text('{}')
            (run_dir / 'checkpoint.json').write_text('{}')
            with mock.patch.object(cm, 'resume_published_run',
                                   return_value=sentinel) as rp:
                m = asyncio.run(cm.run_campaign(
                    CORPUS, work_dir='/w', key_path='/k',
                    lean='/nonexistent/lean', out_root=tmp, episodes=[ep],
                    deadline_s=123.0, spawn='S',
                    corpus_path='corpora/cybergym_pilot.json',
                    run_fn=boom, resume=True))
            rp.assert_called_once()
        entry = m['episodes'][0]
        self.assertEqual(entry.get('resumed'), 'post_publish')
        self.assertEqual(entry['result']['task_id'], 'arvo:64574')

    def test_resume_ignores_foreign_run_under_episode_dir(self):
        from unittest import mock
        ep = cm.Episode('arvo:64574', 'level1', 'vul')
        foreign = make_result(task_id='arvo:47101', difficulty='level1',
                              target_build='vul')      # a different episode
        calls = []

        async def run_fn(corpus, task_id, difficulty, **kw):
            calls.append(task_id)
            return make_result(task_id=task_id, difficulty=difficulty,
                               target_build=kw['target_build'])
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = (Path(tmp) / ep.label / 'level1' / 'arvo:64574'
                       / 'S0-abcd')
            run_dir.mkdir(parents=True)
            (run_dir / 'bundle.json').write_text('{}')
            (run_dir / 'checkpoint.json').write_text('{}')
            with mock.patch.object(cm, 'resume_published_run',
                                   return_value=foreign):
                m = asyncio.run(cm.run_campaign(
                    CORPUS, work_dir='/w', key_path='/k',
                    lean='/nonexistent/lean', out_root=tmp, episodes=[ep],
                    deadline_s=123.0, spawn='S',
                    corpus_path='corpora/cybergym_pilot.json',
                    run_fn=run_fn, resume=True))
        self.assertEqual(calls, ['arvo:64574'])          # ran fresh instead
        entry = m['episodes'][0]
        self.assertNotIn('resumed', entry)               # foreign run rejected
        self.assertEqual(entry['result']['task_id'], 'arvo:64574')

    def test_campaign_manifest_uses_atomic_write(self):
        from unittest import mock

        async def run_fn(corpus, task_id, difficulty, **kw):
            return make_result(task_id=task_id, difficulty=difficulty,
                               target_build=kw['target_build'])
        with tempfile.TemporaryDirectory() as tmp:
            orig = cm._atomic_write
            with mock.patch.object(cm, '_atomic_write', wraps=orig) as aw:
                self._run(run_fn, out_root=tmp)
            wrote_manifest = [c for c in aw.call_args_list
                              if str(c.args[0]).endswith('campaign.json')]
            self.assertTrue(wrote_manifest)   # campaign.json is written atomically


if __name__ == '__main__':
    unittest.main()
