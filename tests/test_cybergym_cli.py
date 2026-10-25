"""Regression tests for live CyberGym CLI aggregation semantics."""
import contextlib
import io
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from soundtrace_live.__main__ import _claim_rejections, cmd_evaluate


class AggregateStatusTests(unittest.TestCase):
    def test_only_checker_rejection_counts(self):
        results = [
            {'session_status': 'CHECKER_REJECTED',
             'claim_status': 'UNSUPPORTED_TRACE'},
            {'session_status': 'INCONCLUSIVE_CAPTURE',
             'claim_status': 'BOUND'},
            {'session_status': 'CHECKER_REJECTED',
             'claim_status': 'REJECTED'},
        ]
        self.assertEqual(_claim_rejections(results), 1)

    def _args(self, difficulties, out):
        return SimpleNamespace(
            difficulties=difficulties, corpus='pilot.json', work_dir=str(out / 'work'),
            key=str(out / 'key'), lean='/nonexistent/lean', out=str(out),
            target_chain='openai:target', translator_chain='openai:translator')

    def _result(self):
        return {
            'task_id': 'arvo:368', 'difficulty': 'level0',
            'flag_success': False, 'claim_status': 'UNSUPPORTED_TRANSLATION',
            'translation_status': 'UNSUPPORTED_TRANSLATION',
            'first_pass_translation': None, 'session_status': 'UNSUPPORTED_TRANSLATION',
        }

    def test_empty_difficulties_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict(os.environ, {'OPENAI_API_KEY': 'test'}, clear=False):
                with patch('soundtrace_live.__main__._load') as load:
                    output = io.StringIO()
                    with contextlib.redirect_stdout(output):
                        code = cmd_evaluate(self._args('', Path(tmp)))
        self.assertEqual(code, 1)
        self.assertIn('REJECTED', output.getvalue())
        load.assert_not_called()

    def test_all_positive_evaluation_marks_false_acceptance_not_applicable(self):
        corpus = SimpleNamespace(tasks={
            'arvo:368': SimpleNamespace(vulnerability_class='heap-buffer-overflow')})
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict(os.environ, {'OPENAI_API_KEY': 'test'}, clear=False):
                with patch('soundtrace_live.__main__._load', return_value=corpus):
                    with patch('soundtrace_live.orchestrator.run_task',
                               return_value=self._result()):
                        output = io.StringIO()
                        with contextlib.redirect_stdout(output):
                            code = cmd_evaluate(self._args('level0', Path(tmp)))
            aggregate = __import__('json').loads(
                (Path(tmp) / 'aggregate.json').read_text())
        self.assertEqual(code, 0)
        self.assertIsNone(aggregate['false_acceptances'])
        self.assertEqual(aggregate['runs'], 1)

    def test_partial_setup_failure_returns_setup_status(self):
        corpus = SimpleNamespace(tasks={
            'arvo:368': SimpleNamespace(vulnerability_class='heap-buffer-overflow'),
            'oss-fuzz:42535201': SimpleNamespace(vulnerability_class='heap-buffer-overflow')})
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict(os.environ, {'OPENAI_API_KEY': 'test'}, clear=False):
                with patch('soundtrace_live.__main__._load', return_value=corpus):
                    with patch('soundtrace_live.orchestrator.run_task',
                               side_effect=[self._result(), OSError('setup')]):
                        output = io.StringIO()
                        with contextlib.redirect_stdout(output):
                            code = cmd_evaluate(self._args('level0', Path(tmp)))
        self.assertEqual(code, 3)
        self.assertIn('INCONCLUSIVE_SETUP', output.getvalue())


    def test_aggregate_counts_provider_attempts_and_fallback(self):
        corpus = SimpleNamespace(tasks={
            'arvo:368': SimpleNamespace(vulnerability_class='heap-buffer-overflow')})
        result = dict(self._result())
        result['attempts'] = [
            {'provider': 'zai', 'model': 'glm-5.3',
             'session_status': 'INCONCLUSIVE_MODEL_API',
             'diagnostic': 'HTTP 500: upstream'},
            {'provider': 'anthropic', 'model': 'claude-sonnet-4-5',
             'session_status': 'UNSUPPORTED_TRANSLATION',
             'diagnostic': None}]
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict(os.environ, {'OPENAI_API_KEY': 'test'}, clear=False):
                with patch('soundtrace_live.__main__._load',
                           return_value=corpus):
                    with patch('soundtrace_live.orchestrator.run_task',
                               return_value=result):
                        output = io.StringIO()
                        with contextlib.redirect_stdout(output):
                            code = cmd_evaluate(self._args('level0',
                                                           Path(tmp)))
            aggregate = __import__('json').loads(
                (Path(tmp) / 'aggregate.json').read_text())
        self.assertEqual(code, 0)
        self.assertEqual(aggregate['provider_attempts'], 2)
        self.assertEqual(aggregate['fallback_engaged'], 1)


    def test_task_ids_filter_and_unknown_rejection(self):
        corpus = SimpleNamespace(tasks={
            'arvo:1': SimpleNamespace(vulnerability_class='heap-buffer-overflow'),
            'arvo:2': SimpleNamespace(vulnerability_class='heap-buffer-overflow')})
        args = self._args('level0', Path('unused'))
        args.task_ids = 'arvo:2'
        with tempfile.TemporaryDirectory() as tmp:
            args.out = str(Path(tmp) / 'runs')
            with patch.dict(os.environ, {'OPENAI_API_KEY': 'test'}, clear=False):
                with patch('soundtrace_live.__main__._load',
                           return_value=corpus):
                    with patch('soundtrace_live.orchestrator.run_task',
                               return_value=self._result()) as run_task:
                        output = io.StringIO()
                        with contextlib.redirect_stdout(output):
                            code = cmd_evaluate(args)
            self.assertEqual(code, 0)
            self.assertEqual(run_task.call_count, 1)
            self.assertEqual(run_task.call_args[0][1], 'arvo:2')
        args.task_ids = 'arvo:9'
        with patch.dict(os.environ, {'OPENAI_API_KEY': 'test'}, clear=False):
            with patch('soundtrace_live.__main__._load', return_value=corpus):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    code = cmd_evaluate(args)
        self.assertEqual(code, 1)
        self.assertIn('arvo:9', output.getvalue())


if __name__ == '__main__':
    unittest.main()
