"""Tests for soundtrace_live.harness (subscription bridge, fake completion)."""
from __future__ import annotations

import asyncio
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from soundtrace_live.harness import HarnessClient, TOOL_ACTION_SCHEMA
from soundtrace_live.openai_responses import ApiError

TARGET_TOOLS = [{'type': 'function', 'name': 'shell', 'description': 'x',
                 'parameters': {'type': 'object'}}]
SCHEMA = {'type': 'object', 'additionalProperties': False,
          'required': ['kind'], 'properties': {'kind': {'type': 'string'}}}


class FakeCompletion:
    """Records calls; returns scripted plain results (bridge contract)."""

    def __init__(self, results):
        self.results = list(results)
        self.calls = []

    def __call__(self, *, prompt, model, system=None, schema=None):
        self.calls.append({'prompt': prompt, 'model': model,
                           'system': system, 'schema': schema})
        result = self.results.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


class HarnessClientTests(unittest.TestCase):
    def client(self, results, role='default'):
        self.fake = FakeCompletion(results)
        return HarnessClient(self.fake, role=role)

    def test_role_validation(self):
        with self.assertRaises(ValueError):
            HarnessClient(lambda **kw: None, role='zai/glm-5.3')

    def test_list_models_reports_role_label(self):
        self.assertEqual(self.client([]).list_models(), ['omp:default'])
        self.assertEqual(
            HarnessClient(lambda **kw: None, role='slow').list_models(),
            ['omp:slow'])

    def test_tool_action_round_trip(self):
        client = self.client([{'tool': 'shell',
                               'arguments': {'command': 'ls -la'},
                               'reasoning_chunk': 'Listing the tree.'}])
        response = client.create(
            model='omp:default',
            input_items=[
                {'role': 'system', 'content': 'system prompt'},
                {'role': 'user', 'content': 'Begin.'},
                {'type': 'function_call', 'call_id': 'c1', 'name': 'shell',
                 'arguments': json.dumps(
                     {'command': 'true', 'reasoning_chunk': 'earlier'})},
                {'type': 'function_call_output', 'call_id': 'c1',
                 'output': '{"exit_code": 0}'}],
            tools=TARGET_TOOLS)
        self.assertEqual(response['model'], 'omp:default')
        self.assertEqual(response['status'], 'completed')
        self.assertEqual(response['usage'],
                         {'input_tokens': 0, 'output_tokens': 0})
        call = response['output'][0]
        self.assertEqual(call['type'], 'function_call')
        self.assertEqual(call['name'], 'shell')
        arguments = json.loads(call['arguments'])
        self.assertEqual(arguments['command'], 'ls -la')
        self.assertEqual(arguments['reasoning_chunk'], 'Listing the tree.')
        # The transcript reached the harness with history rendered as text.
        info = self.fake.calls[0]
        self.assertIn('Begin.', info['prompt'])
        self.assertIn('[assistant action]', info['prompt'])
        self.assertIn('"command":"true"', info['prompt'])
        self.assertEqual(info['system'], 'system prompt')
        self.assertEqual(info['schema'], TOOL_ACTION_SCHEMA)
        self.assertEqual(info['model'], 'default')

    def test_structured_output_round_trip(self):
        client = self.client([{'kind': 'noop'}])
        response = client.create(
            model='omp:default',
            input_items=[{'role': 'system', 'content': 'translator prompt'},
                         {'role': 'user', 'content': '## chunk'}],
            text_json_schema=SCHEMA)
        item = response['output'][0]
        self.assertEqual(item['type'], 'message')
        self.assertEqual(json.loads(item['content'][0]['text']),
                         {'kind': 'noop'})
        self.assertEqual(self.fake.calls[0]['schema'], SCHEMA)
        self.assertEqual(self.fake.calls[0]['system'], 'translator prompt')

    def test_bare_text_turn(self):
        client = self.client(['plain reply'])
        response = client.create(model='omp:default',
                                 input_items=[{'role': 'user',
                                               'content': 'hi'}])
        self.assertEqual(response['output'][0]['content'][0]['text'],
                         'plain reply')

    def test_transport_failure_is_server_error(self):
        client = self.client([RuntimeError('kernel gone')])
        with self.assertRaises(ApiError) as ctx:
            client.create(model='omp:default',
                          input_items=[{'role': 'user', 'content': 'x'}],
                          tools=TARGET_TOOLS)
        self.assertEqual(ctx.exception.reason, 'SERVER')
        self.assertIn('kernel gone', ctx.exception.message)

    def test_malformed_action_is_malformed_error(self):
        client = self.client([{'tool': 'shell', 'arguments': 'not-a-dict',
                               'reasoning_chunk': 'x'}])
        with self.assertRaises(ApiError) as ctx:
            client.create(model='omp:default',
                          input_items=[{'role': 'user', 'content': 'x'}],
                          tools=TARGET_TOOLS)
        self.assertEqual(ctx.exception.reason, 'MALFORMED')

    def test_malformed_history_rejected(self):
        client = self.client([])
        with self.assertRaises(ApiError):
            client.create(model='omp:default',
                          input_items=[{'role': 'user', 'content': 'x'},
                                       'garbage'],
                          tools=TARGET_TOOLS)


class RunOnHarnessTests(unittest.TestCase):
    def test_resolves_completion_from_caller_globals(self):
        import soundtrace_live.harness as harness
        import soundtrace_live.orchestrator as orch

        def kernel_completion(**kwargs):
            return {'tool': 'report_none', 'arguments': {},
                    'reasoning_chunk': 'final: none'}

        ran = []

        def fake_run_task(*args, **kwargs):
            ran.append(kwargs)
            return {'session_status': 'SENTINEL'}

        saved = orch.run_task
        orch.run_task = fake_run_task
        try:
            # Call through an exec'd frame whose globals define completion,
            # exactly like a kernel cell would.
            namespace = {'completion': kernel_completion,
                         'run_on_harness': harness.run_on_harness,
                         'asyncio': asyncio}
            exec('result = asyncio.run(run_on_harness(\n'
                 '    None, "arvo:64574", "level1", work_dir="/w",\n'
                 '    key_path="/k", lean="/l", out_dir="/o"))\n',
                 namespace)
        finally:
            orch.run_task = saved
        self.assertEqual(namespace['result'], {'session_status': 'SENTINEL'})
        self.assertEqual(ran[0]['target_chain'], [('omp', 'omp:default')])
        self.assertEqual(ran[0]['translator_chain'],
                         [('omp-translator', 'omp:default')])
        self.assertIsNotNone(ran[0]['client_factory'])

    def test_explicit_completion_and_roles(self):
        import soundtrace_live.harness as harness
        import soundtrace_live.orchestrator as orch

        def kernel_completion(**kwargs):
            return {'kind': 'noop'}

        ran = []

        def fake_run_task(*args, **kwargs):
            ran.append(kwargs)
            return {'session_status': 'SENTINEL'}

        saved = orch.run_task
        orch.run_task = fake_run_task
        try:
            result = asyncio.run(harness.run_on_harness(
                None, 'arvo:64574', 'level1', work_dir='/w', key_path='/k',
                lean='/l', out_dir='/o', target_role='slow',
                translator_role='smol', completion=kernel_completion))
        finally:
            orch.run_task = saved
        self.assertEqual(result, {'session_status': 'SENTINEL'})
        self.assertEqual(ran[0]['target_chain'], [('omp', 'omp:slow')])
        self.assertEqual(ran[0]['translator_chain'],
                         [('omp-translator', 'omp:smol')])

    def test_requires_completion(self):
        import soundtrace_live.harness as harness
        with self.assertRaises(ValueError):
            asyncio.run(harness.run_on_harness(
                None, 't', 'level1', work_dir='/w', key_path='/k',
                lean='/l', out_dir='/o'))


if __name__ == '__main__':
    unittest.main()
