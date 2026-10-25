"""Focused tests for soundtrace_live.openai_responses (fake HTTP server)."""
from __future__ import annotations

import http.server
import json
import threading
import time
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from soundtrace_live.openai_responses import ApiError, ResponsesClient

FAKE_KEY = 'sk-test-DO-NOT-LEAK-0123456789abcdef'


class _Handler(http.server.BaseHTTPRequestHandler):
    """Records requests; behavior driven by server-level attributes."""

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

    def _respond(self, status, payload, raw=None, headers=None):
        body = raw if raw is not None else json.dumps(payload).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.server.requests.append(('GET', self.path, None,
                                     self.headers.get('Authorization')))
        if self.path.endswith('/models'):
            self._respond(200, {'data': [{'id': 'gpt-5.6-luna'},
                                         {'id': 'gpt-daybreak-blue-latest'}]})
        else:
            self._respond(404, {'error': 'not found'})

    def do_POST(self):
        body = self._read_body()
        self.server.requests.append(('POST', self.path, body,
                                     self.headers.get('Authorization')))
        if self.path.endswith('/responses'):
            status = self.server.next_status
            if self.server.plant_key_in_error:
                raw = json.dumps(
                    {'error': FAKE_KEY + ' leaked'}).encode()
                self._respond(status, None, raw=raw)
            elif self.server.raw_response is not None:
                self._respond(status, None, raw=self.server.raw_response)
            else:
                self._respond(status, {'id': 'resp_1', 'model': 'resolved-x',
                                       'output': [], 'status': 'completed'})
        else:
            self._respond(404, {'error': 'not found'})


class _Server(http.server.HTTPServer):
    daemon_threads = False

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.requests = []
        self.next_status = 200
        self.plant_key_in_error = False
        self.raw_response = None


class _SlowHandler(_Handler):
    def do_POST(self):
        self._read_body()
        time.sleep(2.0)
        self._respond(200, {'ok': True})


class _SlowServer(_Server):
    daemon_threads = False


class ClientTests(unittest.TestCase):
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
        return ResponsesClient(**kw)

    # ------------------------------------------------------------ creation

    def test_rejects_http_base_url(self):
        with self.assertRaises(ValueError):
            ResponsesClient(api_key=FAKE_KEY, base_url='http://api.openai.com/v1')

    def test_missing_key_raises_auth_at_call_time(self):
        import os
        saved = os.environ.pop('OPENAI_API_KEY', None)
        try:
            client = ResponsesClient(base_url=self.base)
            with self.assertRaises(ApiError) as ctx:
                client.list_models()
            self.assertEqual(ctx.exception.reason, 'AUTH')
        finally:
            if saved is not None:
                os.environ['OPENAI_API_KEY'] = saved

    def test_key_from_env(self):
        import os
        saved = os.environ.get('OPENAI_API_KEY')
        os.environ['OPENAI_API_KEY'] = FAKE_KEY
        try:
            client = ResponsesClient(base_url=self.base)
            self.assertEqual(client.list_models()[0], 'gpt-5.6-luna')
            _, _, _, auth = self.server.requests[-1]
            self.assertEqual(auth, 'Bearer ' + FAKE_KEY)
        finally:
            if saved is None:
                os.environ.pop('OPENAI_API_KEY', None)
            else:
                os.environ['OPENAI_API_KEY'] = saved

    # ----------------------------------------------------------- list_models

    def test_list_models(self):
        self.assertEqual(self.client().list_models(),
                         ['gpt-5.6-luna', 'gpt-daybreak-blue-latest'])
        method, path, body, auth = self.server.requests[-1]
        self.assertEqual((method, path), ('GET', '/v1/models'))
        self.assertEqual(auth, 'Bearer ' + FAKE_KEY)

    # ------------------------------------------------------------ create body

    def _create_kwargs(self):
        return dict(
            model='gpt-daybreak-blue-latest',
            input_items=[{'role': 'user', 'content': 'hi'}],
            tools=[{'type': 'function', 'name': 'shell'}],
            tool_choice='auto',
            reasoning_effort='high',
            max_output_tokens=8192,
            include_encrypted_reasoning=True,
            parallel_tool_calls=False,
            extra_body={'access_programs': {'cyber': 'daybreak_blue'}},
        )

    def test_create_request_body(self):
        resp = self.client().create(**self._create_kwargs())
        self.assertEqual(resp['model'], 'resolved-x')
        _, path, raw, _ = self.server.requests[-1]
        self.assertEqual(path, '/v1/responses')
        body = json.loads(raw)
        self.assertEqual(body['model'], 'gpt-daybreak-blue-latest')
        self.assertIs(body['store'], False)
        self.assertEqual(body['input'], [{'role': 'user', 'content': 'hi'}])
        self.assertEqual(body['tools'], [{'type': 'function', 'name': 'shell'}])
        self.assertEqual(body['tool_choice'], 'auto')
        self.assertEqual(body['reasoning'], {'effort': 'high'})
        self.assertEqual(body['max_output_tokens'], 8192)
        self.assertEqual(body['include'], ['reasoning.encrypted_content'])
        self.assertIs(body['parallel_tool_calls'], False)
        self.assertEqual(body['access_programs'],
                         {'cyber': 'daybreak_blue'})
    def test_create_preserves_responses_replay_items(self):
        client = self.client()
        prior = [
            {'type': 'reasoning', 'id': 'rs_1',
             'encrypted_content': 'opaque-reasoning'},
            {'type': 'function_call', 'id': 'fc_1', 'call_id': 'c1',
             'name': 'shell', 'arguments': '{"command":"pwd"}'},
            {'type': 'function_call_output', 'call_id': 'c1',
             'output': '{"status":"ok"}'},
        ]
        self.server.raw_response = json.dumps(
            {'id': 'resp_1', 'model': 'resolved-x', 'output': [],
             'status': 'completed'}).encode()
        client.create(model='gpt-daybreak-blue-latest',
                      input_items=[{'role': 'user', 'content': 'start'}])
        client.create(
            model='gpt-daybreak-blue-latest',
            input_items=[{'role': 'user', 'content': 'start'}, *prior])
        body = json.loads(self.server.requests[-1][2])
        self.assertEqual(body['input'][1:], prior)


    def test_create_minimal_body_has_store_false(self):
        self.client().create(model='gpt-5.6-luna', input_items=['hi'])
        body = json.loads(self.server.requests[-1][2])
        self.assertEqual(
            set(body.keys()), {'model', 'input', 'store'})
        self.assertIs(body['store'], False)

    def test_create_json_schema_nesting(self):
        schema = {'name': 'emission', 'schema': {'type': 'object'},
                  'strict': True}
        self.client().create(model='gpt-5.6-luna', input_items=['x'],
                             text_json_schema=schema)
        body = json.loads(self.server.requests[-1][2])
        self.assertEqual(body['text'], {
            'format': {'type': 'json_schema', 'name': 'emission',
                       'schema': {'type': 'object'}, 'strict': True}})

    # ---------------------------------------------------------- error mapping

    def _assert_status_reason(self, status, reason):
        self.server.next_status = status
        with self.assertRaises(ApiError) as ctx:
            self.client().create(model='m', input_items=['x'])
        self.assertEqual(ctx.exception.reason, reason)
        self.assertEqual(ctx.exception.status_code, status)


    def test_dirty_key_rejected_without_leaking_key(self):
        for dirty in ('sk-clean\n', ' sk-clean', 'sk-clean\r\n', 'sk-cl\x01ean'):
            with self.assertRaises(ApiError) as ctx:
                ResponsesClient(api_key=dirty, base_url=self.base).list_models()
            self.assertEqual(ctx.exception.reason, 'AUTH')
            self.assertNotIn('sk-cl', ctx.exception.message)
            self.assertNotIn(dirty, ctx.exception.message)

    def test_401_maps_auth(self):
        self._assert_status_reason(401, 'AUTH')

    def test_403_maps_forbidden(self):
        self._assert_status_reason(403, 'FORBIDDEN')

    def test_429_maps_rate_limit(self):
        self._assert_status_reason(429, 'RATE_LIMIT')

    def test_408_maps_timeout(self):
        self._assert_status_reason(408, 'TIMEOUT')

    def test_504_maps_timeout(self):
        self._assert_status_reason(504, 'TIMEOUT')

    def test_500_maps_server(self):
        self._assert_status_reason(500, 'SERVER')

    def test_503_maps_server(self):
        self._assert_status_reason(503, 'SERVER')

    def test_error_message_snippet_and_status(self):
        self.server.next_status = 500
        with self.assertRaises(ApiError) as ctx:
            self.client().create(model='m', input_items=['x'])
        self.assertTrue(ctx.exception.message.startswith('HTTP 500:'))
        self.assertLessEqual(len(ctx.exception.message), 260)

    def test_error_message_redacts_planted_key(self):
        self.server.next_status = 429
        self.server.plant_key_in_error = True
        with self.assertRaises(ApiError) as ctx:
            self.client().create(model='m', input_items=['x'])
        self.assertNotIn(FAKE_KEY, ctx.exception.message)
        self.assertIn('[REDACTED]', ctx.exception.message)

    # ---------------------------------------------------------------- shapes

    def test_non_json_response_maps_malformed(self):
        self.server.raw_response = b'<html>not json</html>'
        with self.assertRaises(ApiError) as ctx:
            self.client().create(model='m', input_items=['x'])
        self.assertEqual(ctx.exception.reason, 'MALFORMED')

    def test_response_byte_cap(self):
        self.server.raw_response = b'x' * 10_000
        client = ResponsesClient(api_key=FAKE_KEY, base_url=self.base,
                                 max_response_bytes=1000)
        with self.assertRaises(ApiError) as ctx:
            client.create(model='m', input_items=['x'])
        self.assertEqual(ctx.exception.reason, 'MALFORMED')

    def test_network_error(self):
        # nothing listening on this port
        client = ResponsesClient(api_key=FAKE_KEY,
                                 base_url='https://127.0.0.1:9/v1')
        with self.assertRaises(ApiError) as ctx:
            client.list_models()
        self.assertEqual(ctx.exception.reason, 'NETWORK')

    def test_timeout_maps_timeout(self):
        server = _SlowServer(('127.0.0.1', 0), _SlowHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = f'http://127.0.0.1:{server.server_address[1]}/v1'
            client = ResponsesClient(api_key=FAKE_KEY, base_url=base,
                                     timeout=0.3)
            with self.assertRaises(ApiError) as ctx:
                client.create(model='m', input_items=['x'])
            self.assertEqual(ctx.exception.reason, 'TIMEOUT')
        finally:
            server.shutdown()
            thread.join(timeout=2)
            server.server_close()

    def test_no_retry_on_error(self):
        self.server.next_status = 500
        before = len(self.server.requests)
        with self.assertRaises(ApiError):
            self.client().create(model='m', input_items=['x'])
        self.assertEqual(len(self.server.requests), before + 1)


if __name__ == '__main__':
    unittest.main()
