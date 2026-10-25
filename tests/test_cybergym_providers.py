"""Tests for soundtrace_live.providers (fake HTTP server, both auth modes)."""
from __future__ import annotations

import http.server
import json
import os
import threading
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from evidence import Rejected
from soundtrace_live.openai_responses import ApiError
from soundtrace_live.providers import (PROVIDER_CONFIG, AnthropicClient,
                                       make_client)

FAKE_KEY = 'sk-anthropic-test-DO-NOT-LEAK-0123456789abcdef'

PING_ITEMS = [{'role': 'user', 'content': [
    {'type': 'input_text', 'text': 'ping'}]}]


def _msg_response(text='ok'):
    return {'id': 'msg_1', 'model': 'resolved-x', 'type': 'message',
            'role': 'assistant',
            'content': [{'type': 'text', 'text': text}],
            'usage': {'input_tokens': 3, 'output_tokens': 2}}


class _Handler(http.server.BaseHTTPRequestHandler):
    """Records requests; responses driven by server-level attributes."""

    def finish(self):
        try:
            super().finish()
        finally:
            self.connection.close()

    def log_message(self, *args):  # silence
        pass

    def _read_body(self):
        length = int(self.headers.get('Content-Length', '0'))
        return self.rfile.read(length) if length else b''

    def _respond(self, status, payload, raw=None):
        body = raw if raw is not None else json.dumps(payload).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.server.requests.append(
            ('GET', self.path, None, dict(self.headers)))
        if self.path.split('?')[0].endswith('/models'):
            pages = self.server.models_pages
            page = pages[min(self.server.page_idx, len(pages) - 1)]
            self.server.page_idx += 1
            self._respond(200, page)
        else:
            self._respond(404, {'error': {'message': 'not found'}})

    def do_POST(self):
        body = self._read_body()
        self.server.requests.append(
            ('POST', self.path, body, dict(self.headers)))
        if self.path.endswith('/messages'):
            if self.server.statuses:
                status = self.server.statuses.pop(0)
                raw = json.dumps({'error': {'message': 'denied'}}).encode()
                if self.server.plant_key_in_error:
                    raw = json.dumps(
                        {'error': {'message': FAKE_KEY + ' leaked'}}).encode()
                self._respond(status, None, raw=raw)
            elif self.server.responses:
                self._respond(200, self.server.responses.pop(0))
            else:
                self._respond(200, _msg_response())
        else:
            self._respond(404, {'error': {'message': 'not found'}})


class _Server(http.server.HTTPServer):
    daemon_threads = False

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.requests = []          # (method, path, body, headers)
        self.responses = []
        self.statuses = []
        self.plant_key_in_error = False
        self.models_pages = [{'data': [{'id': 'glm-5.3'},
                                       {'id': 'kimi-k3.1'}]}]
        self.page_idx = 0


class ProviderClientTests(unittest.TestCase):
    def setUp(self):
        self.server = _Server(('127.0.0.1', 0), _Handler)
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       daemon=True)
        self.thread.start()
        self.base = f'http://127.0.0.1:{self.server.server_address[1]}/v1'

    def tearDown(self):
        self.server.shutdown()
        self.thread.join(timeout=2)
        self.server.server_close()

    def client(self, **kw):
        kw.setdefault('api_key', FAKE_KEY)
        kw.setdefault('base_url', self.base)
        return AnthropicClient(**kw)

    def bodies(self):
        return [json.loads(body) for _m, _p, body, _h in self.server.requests
                if _m == 'POST' and body is not None]

    # ------------------------------------------------------------ translation

    def test_system_tools_and_reasoning_translate(self):
        client = self.client(auth='bearer')
        tools = [{'type': 'function', 'name': 'shell',
                  'description': 'run', 'strict': True,
                  'parameters': {'type': 'object', 'properties': {}}}]
        thinking = {'type': 'thinking', 'thinking': 'hmm', 'signature': 'sig'}
        client.create(
            model='glm-5.3',
            input_items=[
                {'role': 'system', 'content': 'system prompt'},
                {'role': 'user', 'content': 'begin'},
                {'type': 'reasoning',
                 'encrypted_content': json.dumps(thinking)},
                {'type': 'message', 'content': [
                    {'type': 'output_text', 'text': 'working'}]},
                {'type': 'function_call', 'call_id': 'c1', 'name': 'shell',
                 'arguments': json.dumps({'command': 'ls'})},
                {'type': 'function_call_output', 'call_id': 'c1',
                 'output': '{"exit_code": 0}'},
                {'type': 'function_call_output', 'call_id': 'c2',
                 'output': '{"exit_code": 1}'},
            ],
            tools=tools, reasoning_effort='high', max_output_tokens=8192,
            include_encrypted_reasoning=True, parallel_tool_calls=False,
            extra_body={'access_programs': {'cyber': 'daybreak_blue'}})
        body = self.bodies()[-1]
        self.assertEqual(body['system'], 'system prompt')
        self.assertEqual(body['model'], 'glm-5.3')
        self.assertEqual(body['max_tokens'], 8192 + 8192)
        self.assertEqual(body['thinking'],
                         {'type': 'enabled', 'budget_tokens': 8192})
        self.assertEqual(body['tools'], [
            {'name': 'shell', 'description': 'run',
             'input_schema': {'type': 'object', 'properties': {}}}])
        # system+user -> user message; assistant-side items merge into one
        # assistant message; outputs merge into one tool_result user message.
        self.assertEqual(len(body['messages']), 3)
        self.assertEqual(body['messages'][0],
                         {'role': 'user', 'content': [
                             {'type': 'text', 'text': 'begin'}]})
        self.assertEqual(body['messages'][1], {'role': 'assistant', 'content': [
            thinking,
            {'type': 'text', 'text': 'working'},
            {'type': 'tool_use', 'id': 'c1', 'name': 'shell',
             'input': {'command': 'ls'}}]})
        self.assertEqual(body['messages'][2], {'role': 'user', 'content': [
            {'type': 'tool_result', 'tool_use_id': 'c1',
             'content': '{"exit_code": 0}'},
            {'type': 'tool_result', 'tool_use_id': 'c2',
             'content': '{"exit_code": 1}'}]})

    def test_preflight_ping_has_no_thinking(self):
        client = self.client(auth='bearer')
        client.create(model='glm-5.3', input_items=PING_ITEMS,
                      max_output_tokens=16)
        body = self.bodies()[-1]
        self.assertNotIn('thinking', body)
        self.assertEqual(body['max_tokens'], 16)
        self.assertNotIn('tools', body)

    def test_thinking_medium_budget_and_disabled(self):
        self.client(auth='bearer').create(
            model='m', input_items=PING_ITEMS, reasoning_effort='medium')
        self.assertEqual(self.bodies()[-1]['thinking'],
                         {'type': 'enabled', 'budget_tokens': 4096})
        self.client(auth='bearer', thinking=False).create(
            model='m', input_items=PING_ITEMS, reasoning_effort='high',
            max_output_tokens=4096)
        body = self.bodies()[-1]
        self.assertNotIn('thinking', body)
        self.assertEqual(body['max_tokens'], 4096)

    def test_adaptive_thinking_api_shape(self):
        client = self.client(auth='bearer', thinking_api='adaptive')
        client.create(model='claude-sonnet-5', input_items=PING_ITEMS,
                      reasoning_effort='high', max_output_tokens=8192)
        body = self.bodies()[-1]
        self.assertEqual(body['thinking'], {'type': 'adaptive'})
        self.assertEqual(body['output_config'], {'effort': 'high'})
        self.assertEqual(body['max_tokens'], 8192)

    def test_budgeted_thinking_rejects_forced_tool(self):
        client = self.client(auth='bearer')          # default: budgeted
        with self.assertRaises(ApiError) as ctx:
            client.create(model='m', input_items=PING_ITEMS,
                          reasoning_effort='high',
                          text_json_schema={'type': 'object'})
        self.assertEqual(ctx.exception.reason, 'MALFORMED')
        self.assertIn("'thinking': False", ctx.exception.message)
        # No thinking requested: forced structured output stays fine.
        self.server.responses.append({
            'id': 'msg_b', 'model': 'm', 'type': 'message',
            'content': [{'type': 'tool_use', 'id': 't', 'name': 'respond',
                         'input': {'kind': 'noop'}}],
            'usage': {'input_tokens': 1, 'output_tokens': 1}})
        response = client.create(model='m', input_items=PING_ITEMS,
                                 text_json_schema={'type': 'object'})
        self.assertEqual(response['output'][0]['type'], 'message')

    def test_tool_choice_translation(self):
        client = self.client(auth='bearer')
        client.create(model='m', input_items=PING_ITEMS,
                      tool_choice='auto',
                      tools=[{'type': 'function', 'name': 'x',
                              'parameters': {'type': 'object'}}])
        self.assertEqual(self.bodies()[-1]['tool_choice'], {'type': 'auto'})
        client.create(model='m', input_items=PING_ITEMS,
                      tool_choice={'type': 'function', 'name': 'x'})
        self.assertEqual(self.bodies()[-1]['tool_choice'],
                         {'type': 'tool', 'name': 'x'})

    # -------------------------------------------------------- normalization

    def test_response_normalization_round_trip(self):
        # Two-turn replay: normalize a full assistant turn, feed it back as
        # history, and assert the translated request keeps the shapes.
        thinking = {'type': 'thinking', 'thinking': 'plan', 'signature': 's'}
        self.server.responses.append({
            'id': 'msg_2', 'model': 'glm-5.3', 'type': 'message',
            'content': [
                dict(thinking),
                {'type': 'text', 'text': 'listing files'},
                {'type': 'tool_use', 'id': 'toolu_1', 'name': 'shell',
                 'input': {'command': 'ls'}}],
            'usage': {'input_tokens': 5, 'output_tokens': 7}})
        client = self.client(auth='bearer')
        first = client.create(model='glm-5.3', input_items=PING_ITEMS,
                              tools=[{'type': 'function', 'name': 'shell',
                                      'parameters': {'type': 'object'}}],
                              reasoning_effort='high')
        self.assertEqual(first['id'], 'msg_2')
        self.assertEqual(first['model'], 'glm-5.3')
        self.assertEqual(first['status'], 'completed')
        self.assertEqual(first['usage'],
                         {'input_tokens': 5, 'output_tokens': 7})
        self.assertEqual(first['output'], [
            {'type': 'reasoning',
             'encrypted_content': json.dumps(thinking, separators=(',', ':'))},
            {'type': 'message', 'content': [
                {'type': 'output_text', 'text': 'listing files'}]},
            {'type': 'function_call', 'call_id': 'toolu_1', 'name': 'shell',
             'arguments': json.dumps({'command': 'ls'})}])
        # Replay exactly what the orchestrator appends to its history.
        history = PING_ITEMS + [
            dict(item) for item in first['output']] + [
            {'type': 'function_call_output', 'call_id': 'toolu_1',
             'output': '{"exit_code": 0}'}]
        client.create(model='glm-5.3', input_items=history,
                      tools=[{'type': 'function', 'name': 'shell',
                              'parameters': {'type': 'object'}}],
                      reasoning_effort='high')
        body = self.bodies()[-1]
        self.assertEqual(body['messages'], [
            {'role': 'user', 'content': [
                {'type': 'text', 'text': 'ping'}]},
            {'role': 'assistant', 'content': [
                thinking,
                {'type': 'text', 'text': 'listing files'},
                {'type': 'tool_use', 'id': 'toolu_1', 'name': 'shell',
                 'input': {'command': 'ls'}}]},
            {'role': 'user', 'content': [
                {'type': 'tool_result', 'tool_use_id': 'toolu_1',
                 'content': '{"exit_code": 0}'}]}])

    def test_forced_json_schema_uses_respond_tool(self):
        schema = {'type': 'object', 'additionalProperties': False,
                  'required': ['kind'],
                  'properties': {'kind': {'type': 'string'}}}
        self.server.responses.append({
            'id': 'msg_3', 'model': 'kimi-k3.1', 'type': 'message',
            'content': [{'type': 'tool_use', 'id': 'toolu_2',
                         'name': 'respond',
                         'input': {'kind': 'noop'}}],
            'usage': {'input_tokens': 1, 'output_tokens': 1}})
        client = self.client(auth='x-api-key')
        response = client.create(model='kimi-k3.1', input_items=PING_ITEMS,
                                 text_json_schema=schema)
        body = self.bodies()[-1]
        self.assertEqual(body['tool_choice'],
                         {'type': 'tool', 'name': 'respond'})
        self.assertEqual(body['tools'][-1],
                         {'name': 'respond',
                          'description': 'Respond with the structured '
                                         'output object.',
                          'input_schema': schema})
        self.assertEqual(response['output'][0], {
            'type': 'message',
            'content': [{'type': 'output_text',
                         'text': json.dumps({'kind': 'noop'},
                                            separators=(',', ':'))}]})
        # Forced output without the respond tool call is malformed.
        self.server.responses.append({
            'id': 'msg_4', 'model': 'kimi-k3.1', 'type': 'message',
            'content': [{'type': 'text', 'text': 'nope'}],
            'usage': {'input_tokens': 1, 'output_tokens': 1}})
        with self.assertRaises(ApiError) as ctx:
            client.create(model='kimi-k3.1', input_items=PING_ITEMS,
                          text_json_schema=schema)
        self.assertEqual(ctx.exception.reason, 'MALFORMED')

    # ------------------------------------------------------------ list_models

    def test_list_models_paginates(self):
        self.server.models_pages = [
            {'data': [{'id': 'b-model'}, {'id': 'a-model'}],
             'has_more': True, 'last_id': 'a-model'},
            {'data': [{'id': 'c-model'}], 'has_more': False},
        ]
        client = self.client(auth='bearer')
        self.assertEqual(client.list_models(),
                         ['a-model', 'b-model', 'c-model'])
        model_paths = [path for _m, path, _b, _h in self.server.requests
                       if _m == 'GET']
        self.assertIn('/v1/models?limit=1000', model_paths)
        self.assertIn('/v1/models?limit=1000&after_id=a-model', model_paths)

    # ----------------------------------------------------------- failures

    def test_status_classification(self):
        for status, reason in ((401, 'AUTH'), (403, 'FORBIDDEN'),
                               (429, 'RATE_LIMIT'), (500, 'SERVER'),
                               (400, 'MALFORMED')):
            self.server.statuses.append(status)
            client = self.client(auth='bearer')
            with self.assertRaises(ApiError) as ctx:
                client.create(model='m', input_items=PING_ITEMS)
            self.assertEqual(ctx.exception.reason, reason)
            self.assertEqual(ctx.exception.status_code, status)
            self.assertNotIn(FAKE_KEY, ctx.exception.message)

    def test_key_never_leaks_into_error(self):
        self.server.plant_key_in_error = True
        self.server.statuses.append(401)
        with self.assertRaises(ApiError) as ctx:
            self.client(auth='bearer').create(model='m',
                                              input_items=PING_ITEMS)
        self.assertNotIn(FAKE_KEY, ctx.exception.message)
        self.assertIn('[REDACTED]', ctx.exception.message)

    def test_dirty_key_rejected_without_echo(self):
        dirty = FAKE_KEY + '\x07'
        with self.assertRaises(ApiError) as ctx:
            self.client(api_key=dirty, auth='bearer').create(
                model='m', input_items=PING_ITEMS)
        self.assertEqual(ctx.exception.reason, 'AUTH')
        self.assertNotIn(dirty, ctx.exception.message)

    def test_malformed_inputs(self):
        client = self.client(auth='bearer')
        for items in (
                [],
                [{'role': 'system', 'content': 'x'},
                 {'role': 'system', 'content': 'y'}],
                [{'role': 'user', 'content': 'x'}, {'bogus': True}],
                [{'role': 'user', 'content': 'x'},
                 {'type': 'function_call', 'call_id': 'c', 'name': 'n',
                  'arguments': '{not json'}],
                [{'role': 'user', 'content': 'x'},
                 {'type': 'reasoning', 'encrypted_content': '[not]'}],
                [{'role': 'user', 'content': 42}]):
            with self.assertRaises(ApiError) as ctx:
                client.create(model='m', input_items=items)
            self.assertEqual(ctx.exception.reason, 'MALFORMED')
        with self.assertRaises(ApiError) as ctx:
            client.create(model='m', input_items=PING_ITEMS,
                          tools=[{'type': 'bogus'}])
        self.assertEqual(ctx.exception.reason, 'MALFORMED')

    # ------------------------------------------------------- state + headers

    def test_auth_headers_per_mode(self):
        def sent():
            _m, _p, _b, headers = self.server.requests[-1]
            return {key.lower(): value for key, value in headers.items()}
        self.client(auth='bearer').create(model='m', input_items=PING_ITEMS)
        headers = sent()
        self.assertEqual(headers.get('authorization'), 'Bearer ' + FAKE_KEY)
        self.assertNotIn('x-api-key', headers)
        self.client(auth='x-api-key').create(model='m',
                                             input_items=PING_ITEMS)
        headers = sent()
        self.assertEqual(headers.get('x-api-key'), FAKE_KEY)
        self.assertIsNone(headers.get('authorization'))

    def test_stop_reason_mapped_into_status(self):
        for stop, status in (('refusal', 'refusal'),
                             ('max_tokens', 'incomplete'),
                             ('end_turn', 'completed')):
            self.server.responses.append({
                'id': 'msg_r', 'model': 'm', 'type': 'message',
                'stop_reason': stop,
                'content': ([{'type': 'text', 'text': 'partial'}]
                            if stop != 'refusal' else []),
                'usage': {'input_tokens': 1, 'output_tokens': 1}})
            response = self.client(auth='bearer').create(
                model='m', input_items=PING_ITEMS)
            self.assertEqual(response['status'], status)
            self.assertEqual(response['output'],
                             [] if stop == 'refusal' else [
                                 {'type': 'message', 'content': [
                                     {'type': 'output_text',
                                      'text': 'partial'}]}])

    def test_no_cross_call_state(self):
        client = self.client(auth='bearer')
        first = client.create(model='m', input_items=PING_ITEMS)
        second = client.create(model='m', input_items=PING_ITEMS)
        self.assertEqual(first['output'], second['output'])
        bodies = self.bodies()
        self.assertEqual(bodies[-2], bodies[-1])

    def test_https_enforced_off_loopback(self):
        with self.assertRaises(ValueError):
            AnthropicClient(api_key=FAKE_KEY, base_url='http://api.z.ai/v1')
        with self.assertRaises(ValueError):
            AnthropicClient(api_key=FAKE_KEY, auth='bogus')


class MakeClientTests(unittest.TestCase):
    def setUp(self):
        self._saved = {config['key_env']:
                       os.environ.get(config['key_env'])
                       for config in PROVIDER_CONFIG.values()}

    def tearDown(self):
        for name, value in self._saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value

    def _set(self, name, value='test-key'):
        os.environ[name] = value

    def test_config_resolution(self):
        self._set('OPENAI_API_KEY')
        self._set('ANTHROPIC_API_KEY')
        self._set('ZAI_API_KEY')
        self._set('MOONSHOT_API_KEY')
        openai_client = make_client('openai')
        from soundtrace_live.openai_responses import ResponsesClient
        self.assertIsInstance(openai_client, ResponsesClient)
        for provider in ('anthropic', 'zai', 'moonshot'):
            client = make_client(provider)
            self.assertIsInstance(client, AnthropicClient)
            self.assertEqual(client._base_url,
                             PROVIDER_CONFIG[provider]['base_url'])
            self.assertEqual(client._auth, PROVIDER_CONFIG[provider]['auth'])
        self.assertEqual(make_client('zai')._auth, 'bearer')
        self.assertEqual(make_client('anthropic')._auth, 'x-api-key')
        self.assertEqual(make_client('moonshot')._auth, 'x-api-key')

    def test_missing_key_env_is_auth_error(self):
        os.environ.pop('ZAI_API_KEY', None)
        with self.assertRaises(ApiError) as ctx:
            make_client('zai')
        self.assertEqual(ctx.exception.reason, 'AUTH')
        self.assertIn('ZAI_API_KEY', ctx.exception.message)

    def test_unknown_provider_rejected(self):
        with self.assertRaises(Rejected):
            make_client('nope')


if __name__ == '__main__':
    unittest.main()
