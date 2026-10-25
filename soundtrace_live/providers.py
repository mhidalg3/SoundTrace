"""Multi-provider model clients for the CyberGym live pipeline.

`PROVIDER_CONFIG` is the single source of truth for provider endpoints,
key environment variables, and auth header modes.  `make_client(provider)`
builds the client the orchestrator/translator already expect:

- `openai` keeps the existing `ResponsesClient` (Responses API).
- every Anthropic-compatible provider gets `AnthropicClient`, which speaks
  the Messages API (`POST {base}/messages`, `GET {base}/models`) and
  translates Responses-shaped `input_items`/outputs at the wire boundary so
  no caller changes.

Error contract is the `ApiError` from `soundtrace_live.openai_responses`
(reason in AUTH/FORBIDDEN/RATE_LIMIT/SERVER/NETWORK/TIMEOUT/MALFORMED,
`status_code` when one was received, messages redacted of the API key).
Unknown providers raise `Rejected`.

The API key is read at construction time from the provider's `key_env` (or
passed explicitly); it is never logged, never echoed in error messages, and
sent only in the configured auth header of an HTTPS request to the
configured base URL.  Plain-HTTP base URLs are rejected except for loopback
hosts, which exist solely so the offline test suite can drive this client
against a local fake server.
"""

from __future__ import annotations

import json
import os
import socket
import time
import urllib.error
import urllib.parse
import urllib.request

from evidence import Rejected
from soundtrace_live.openai_responses import ApiError, ResponsesClient

__all__ = ['PROVIDER_CONFIG', 'AnthropicClient', 'make_client']

DEFAULT_BASE_URL = 'https://api.anthropic.com/v1'
ERROR_SNIPPET_BYTES = 200
ANTHROPIC_VERSION = '2023-06-01'
# Anthropic extended-thinking budget: 'high' gets the large budget, every
# other effort level the small one.
THINKING_BUDGETS = {'high': 8192}
THINKING_BUDGET_DEFAULT = 4096
DEFAULT_MAX_TOKENS = 4096

PROVIDER_CONFIG: dict[str, dict] = {
    'openai': {
        'client': 'responses',
        'base_url': 'https://api.openai.com/v1',
        'key_env': 'OPENAI_API_KEY',
        'auth': 'bearer',
    },
    'anthropic': {
        'client': 'anthropic',
        'base_url': 'https://api.anthropic.com/v1',
        'key_env': 'ANTHROPIC_API_KEY',
        'auth': 'x-api-key',
        # Pinned by the step-5a probe: the 5-family rejects
        # thinking.type=enabled and requires adaptive + output_config.effort.
        'thinking_api': 'adaptive',
    },
    'zai': {
        'client': 'anthropic',
        'base_url': 'https://api.z.ai/api/anthropic/v1',
        'key_env': 'ZAI_API_KEY',
        'auth': 'bearer',
    },
    'moonshot': {
        'client': 'anthropic',
        'base_url': 'https://api.moonshot.ai/anthropic/v1',
        'key_env': 'MOONSHOT_API_KEY',
        'auth': 'x-api-key',
    },
}


def make_client(provider: str):
    """Build a client for `provider` from PROVIDER_CONFIG."""
    config = PROVIDER_CONFIG.get(provider)
    if config is None:
        raise Rejected(f'unknown provider {provider!r}')
    key = os.environ.get(config['key_env'])
    if not key:
        raise ApiError('AUTH', f"{config['key_env']} is not set")
    if config['client'] == 'responses':
        return ResponsesClient(api_key=key, base_url=config['base_url'])
    return AnthropicClient(api_key=key, base_url=config['base_url'],
                           auth=config['auth'],
                           thinking=config.get('thinking', True),
                           thinking_api=config.get('thinking_api',
                                                   'budgeted'))


# ------------------------------------------------------- input translation

def _malformed(detail: str) -> ApiError:
    return ApiError('MALFORMED', f'input_items: {detail}')


def _text_blocks(content) -> list[dict]:
    """Responses content (string or piece list) -> Anthropic text blocks."""
    if isinstance(content, str):
        return [{'type': 'text', 'text': content}] if content else []
    if not isinstance(content, list):
        raise _malformed('content must be a string or a list')
    blocks: list[dict] = []
    for piece in content:
        if isinstance(piece, str):
            if piece:
                blocks.append({'type': 'text', 'text': piece})
        elif isinstance(piece, dict) and piece.get('type') in (
                'input_text', 'output_text', 'text') \
                and isinstance(piece.get('text'), str):
            if piece['text']:
                blocks.append({'type': 'text', 'text': piece['text']})
        else:
            raise _malformed(f"unsupported content piece type "
                             f"{piece.get('type') if isinstance(piece, dict) else type(piece).__name__}")
    return blocks


def _thinking_block(item: dict) -> dict:
    encrypted = item.get('encrypted_content')
    if not isinstance(encrypted, str):
        raise _malformed('reasoning item has no encrypted_content string')
    try:
        block = json.loads(encrypted)
    except ValueError:
        raise _malformed('reasoning encrypted_content is not JSON') from None
    if not isinstance(block, dict) or block.get('type') not in (
            'thinking', 'redacted_thinking'):
        raise _malformed('reasoning encrypted_content is not a thinking block')
    return block


def _tool_use_block(item: dict) -> dict:
    call_id = item.get('call_id')
    name = item.get('name')
    arguments = item.get('arguments')
    if not (isinstance(call_id, str) and call_id
            and isinstance(name, str) and name
            and isinstance(arguments, str)):
        raise _malformed('function_call item is malformed')
    try:
        parsed = json.loads(arguments)
    except ValueError:
        raise _malformed('function_call arguments are not JSON') from None
    if not isinstance(parsed, dict):
        raise _malformed('function_call arguments are not an object')
    return {'type': 'tool_use', 'id': call_id, 'name': name, 'input': parsed}


def _tool_result_block(item: dict) -> dict:
    call_id = item.get('call_id')
    output = item.get('output')
    if not (isinstance(call_id, str) and call_id and isinstance(output, str)):
        raise _malformed('function_call_output item is malformed')
    return {'type': 'tool_result', 'tool_use_id': call_id, 'content': output}


def _translate_input(items: list) -> tuple[str | None, list[dict]]:
    """Responses-shaped input_items -> (system, Anthropic messages)."""
    if not isinstance(items, list) or not items:
        raise _malformed('must be a nonempty list')
    index = 0
    system: str | None = None
    first = items[0]
    if isinstance(first, dict) and first.get('role') == 'system':
        if not isinstance(first.get('content'), str):
            raise _malformed('system content must be a string')
        system = first['content']
        index = 1
    messages: list[dict] = []
    assistant: list[dict] = []
    user: list[dict] = []

    def flush() -> None:
        nonlocal assistant, user
        if assistant:
            messages.append({'role': 'assistant', 'content': assistant})
        if user:
            messages.append({'role': 'user', 'content': user})
        assistant = []
        user = []

    for item in items[index:]:
        if not isinstance(item, dict):
            raise _malformed('item is not an object')
        role = item.get('role')
        kind = item.get('type')
        if role == 'system':
            raise _malformed('system item must be first')
        if role == 'user':
            flush()
            blocks = _text_blocks(item.get('content'))
            if blocks:
                messages.append({'role': 'user', 'content': blocks})
        elif role == 'assistant' or kind == 'message':
            # History replay: Responses-shaped output items carry type
            # 'message' with no role; they are assistant-side by construction.
            if user:
                flush()
            assistant.extend(_text_blocks(item.get('content')))
        elif kind == 'reasoning':
            if user:
                flush()
            assistant.append(_thinking_block(item))
        elif kind == 'function_call':
            if user:
                flush()
            assistant.append(_tool_use_block(item))
        elif kind == 'function_call_output':
            if assistant:
                flush()
            user.append(_tool_result_block(item))
        else:
            raise _malformed(
                f"unsupported item role={role!r} type={kind!r}")
    flush()
    if not messages:
        raise _malformed('no messages after translation')
    return system, messages


def _translate_tools(tools: list) -> list[dict]:
    if not isinstance(tools, list):
        raise _malformed('tools must be a list')
    translated: list[dict] = []
    for tool in tools:
        if (not isinstance(tool, dict) or tool.get('type') != 'function'
                or not isinstance(tool.get('name'), str)
                or not isinstance(tool.get('parameters'), dict)):
            raise _malformed('tool entries must be function definitions')
        entry = {'name': tool['name'],
                 'input_schema': tool['parameters']}
        if isinstance(tool.get('description'), str):
            entry['description'] = tool['description']
        translated.append(entry)
    return translated


def _translate_tool_choice(tool_choice) -> dict:
    if tool_choice == 'auto':
        return {'type': 'auto'}
    if tool_choice == 'required':
        return {'type': 'any'}
    if (isinstance(tool_choice, dict)
            and tool_choice.get('type') == 'function'
            and isinstance(tool_choice.get('name'), str)):
        return {'type': 'tool', 'name': tool_choice['name']}
    raise _malformed(f'unsupported tool_choice {tool_choice!r}')


# ----------------------------------------------------- response conversion

def _usage_ints(usage) -> tuple[int, int]:
    if not isinstance(usage, dict):
        raise ApiError('MALFORMED', 'messages response usage is malformed')
    values = []
    for field in ('input_tokens', 'output_tokens'):
        value = usage.get(field)
        if type(value) is not int or value < 0:
            raise ApiError('MALFORMED', 'messages response usage is malformed')
        values.append(value)
    return values[0], values[1]


def _normalize_response(payload: dict, forced: bool) -> dict:
    """Messages response -> Responses-shaped dict (used by all callers)."""
    if not isinstance(payload, dict) or not isinstance(
            payload.get('content'), list):
        raise ApiError('MALFORMED', 'messages response body is malformed')
    model = payload.get('model')
    if not isinstance(model, str) or not model:
        raise ApiError('MALFORMED', 'messages response has no model string')
    usage_in, usage_out = _usage_ints(payload.get('usage'))
    output: list[dict] = []
    respond_input = None
    for block in payload['content']:
        if not isinstance(block, dict):
            raise ApiError('MALFORMED', 'messages content block is malformed')
        kind = block.get('type')
        if kind == 'text':
            text = block.get('text')
            if not isinstance(text, str):
                raise ApiError('MALFORMED', 'text block is malformed')
            if text:
                output.append({'type': 'message',
                               'content': [{'type': 'output_text',
                                            'text': text}]})
        elif kind == 'tool_use':
            call_id = block.get('id')
            name = block.get('name')
            tool_input = block.get('input')
            if not (isinstance(call_id, str) and call_id
                    and isinstance(name, str) and name
                    and isinstance(tool_input, dict)):
                raise ApiError('MALFORMED', 'tool_use block is malformed')
            if forced and name == 'respond':
                respond_input = tool_input
                continue
            output.append({'type': 'function_call', 'call_id': call_id,
                           'name': name,
                           'arguments': json.dumps(tool_input)})
        elif kind in ('thinking', 'redacted_thinking'):
            # Opaque reasoning: replayed verbatim next turn.
            output.append({'type': 'reasoning',
                           'encrypted_content': json.dumps(
                               block, separators=(',', ':'))})
        else:
            raise ApiError('MALFORMED',
                           f'unsupported content block type {kind!r}')
    if forced:
        if respond_input is None:
            raise ApiError('MALFORMED',
                           'structured output missing the forced tool call')
        output.insert(0, {'type': 'message', 'content': [
            {'type': 'output_text',
             'text': json.dumps(respond_input, separators=(',', ':'))}]})
    # Preserve wire truth: refusals and truncations must not be recorded
    # as completed turns. An empty refused turn ends the target loop's
    # no-tool-call path without retry; the signed audit keeps the status.
    stop_reason = payload.get('stop_reason')
    status = 'completed'
    if stop_reason == 'refusal':
        status = 'refusal'
    elif stop_reason == 'max_tokens':
        status = 'incomplete'
    return {'id': str(payload.get('id') or ''), 'model': model,
            'status': status, 'output': output,
            'usage': {'input_tokens': usage_in, 'output_tokens': usage_out}}


# -------------------------------------------------------------- transport

def _snippet(body: bytes, api_key: str | None) -> str:
    """First <=200 bytes of a response body, UTF-8 replaced, key-stripped."""
    text = body[:ERROR_SNIPPET_BYTES].decode('utf-8', 'replace')
    if api_key:
        text = text.replace(api_key, '[REDACTED]')
    return text


def _read_chunk(stream, deadline: float) -> bytes:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ApiError('TIMEOUT', 'response exceeded total timeout')
    current = stream
    seen: set[int] = set()
    for _ in range(6):
        if id(current) in seen:
            break
        seen.add(id(current))
        sock = getattr(current, '_sock', None)
        if sock is not None:
            sock.settimeout(remaining)
            break
        next_value = getattr(current, 'fp', None)
        if next_value is None:
            next_value = getattr(current, 'raw', None)
        if next_value is None:
            break
        current = next_value
    reader = getattr(stream, 'read1', None)
    return reader(65_536) if callable(reader) else stream.read(65_536)


def _read_limited(stream, limit: int, deadline: float | None = None
                  ) -> tuple[bytes, bool]:
    chunks: list[bytes] = []
    received = 0
    exceeded = False
    while True:
        chunk = (_read_chunk(stream, deadline) if deadline is not None
                 else stream.read(65_536))
        if not chunk:
            break
        received += len(chunk)
        if received > limit:
            exceeded = True
            remaining = limit - sum(len(part) for part in chunks)
            if remaining > 0:
                chunks.append(chunk[:remaining])
            break
        chunks.append(chunk)
    return b''.join(chunks), exceeded


def _reason_for_status(status: int) -> str:
    if status == 401:
        return 'AUTH'
    if status == 403:
        return 'FORBIDDEN'
    if status == 408 or status == 504:
        return 'TIMEOUT'
    if status == 429:
        return 'RATE_LIMIT'
    if status >= 500:
        return 'SERVER'
    return 'MALFORMED'


class AnthropicClient:
    """Strict, non-retrying client for the Anthropic Messages API.

    Presents the exact `create()` surface of `ResponsesClient`; OpenAI-only
    keyword arguments are accepted and ignored so callers stay unchanged.
    """

    def __init__(self, api_key: str | None = None,
                 base_url: str | None = None, auth: str = 'x-api-key',
                 timeout: float = 120.0,
                 max_response_bytes: int = 8_000_000,
                 thinking: bool = True,
                 thinking_api: str = 'budgeted') -> None:
        if auth not in ('x-api-key', 'bearer'):
            raise ValueError('auth must be x-api-key or bearer')
        if thinking_api not in ('budgeted', 'adaptive'):
            raise ValueError("thinking_api must be 'budgeted' or 'adaptive'")
        if base_url is None:
            base_url = os.environ.get('ANTHROPIC_BASE_URL') or DEFAULT_BASE_URL
        parsed = urllib.parse.urlparse(base_url)
        host = parsed.hostname or ''
        if parsed.scheme != 'https' and host not in (
                '127.0.0.1', 'localhost', '::1'):
            raise ValueError('base_url must be an HTTPS URL')
        self._base_url = base_url.rstrip('/')
        self._api_key = api_key
        self._auth = auth
        self._timeout = timeout
        self._max_response_bytes = max_response_bytes
        self._thinking = thinking
        self._thinking_api = thinking_api

    # ------------------------------------------------------------------ key

    def _key(self) -> str:
        key = self._api_key if self._api_key is not None \
            else os.environ.get('ANTHROPIC_API_KEY')
        if not key:
            raise ApiError('AUTH', 'missing API key: pass api_key or set '
                                   'ANTHROPIC_API_KEY')
        # Never let the raw key reach an exception message: strip surrounding
        # whitespace and reject control characters outright.
        if key != key.strip() or any(ord(c) < 32 or ord(c) == 127 for c in key):
            raise ApiError('AUTH', 'API key contains whitespace or control '
                                   'characters')
        return key

    # -------------------------------------------------------------- requests

    def _headers(self, key: str) -> dict[str, str]:
        headers = {'content-type': 'application/json',
                   'anthropic-version': ANTHROPIC_VERSION}
        if self._auth == 'bearer':
            headers['Authorization'] = 'Bearer ' + key
        else:
            headers['x-api-key'] = key
        return headers

    def _request(self, method: str, path: str,
                 body: bytes | None) -> tuple[int, bytes]:
        """Perform one HTTP request; classify and redact every failure."""
        key = self._key()
        url = self._base_url + path
        req = urllib.request.Request(url, data=body, headers=self._headers(key),
                                     method=method)
        deadline = time.monotonic() + self._timeout
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                status = resp.status
                chunks: list[bytes] = []
                received = 0
                while True:
                    chunk = _read_chunk(resp, deadline)
                    if not chunk:
                        break
                    received += len(chunk)
                    if received > self._max_response_bytes:
                        raise ApiError(
                            'MALFORMED',
                            f'response exceeded {self._max_response_bytes} '
                            'byte cap while reading')
                    chunks.append(chunk)
                return status, b''.join(chunks)
        except ApiError:
            raise
        except urllib.error.HTTPError as exc:
            try:
                status = exc.code
                try:
                    err_body, exceeded = _read_limited(
                        exc, self._max_response_bytes, deadline)
                except ApiError:
                    raise
                except Exception:            # body already drained/unavailable
                    err_body, exceeded = b'', False
                reason = _reason_for_status(status)
                suffix = (' (response body exceeded configured cap)'
                          if exceeded else '')
                raise ApiError(reason,
                               f'HTTP {status}: {_snippet(err_body, key)}{suffix}',
                               status) from None
            finally:
                exc.close()
        except urllib.error.URLError as exc:
            if isinstance(getattr(exc, 'reason', None),
                          (socket.timeout, TimeoutError)):
                raise ApiError('TIMEOUT',
                               f'request timed out after {self._timeout}s') \
                    from None
            raise ApiError('NETWORK',
                           f'connection error: {type(exc.reason).__name__}'
                           if exc.reason else 'connection error') from None
        except socket.timeout:
            raise ApiError('TIMEOUT',
                           f'request timed out after {self._timeout}s') \
                from None
        except ValueError as exc:
            # http.client rejects malformed header values quoting the raw
            # value (which embeds the key); never forward that text.
            raise ApiError('MALFORMED',
                           f'request rejected before sending: '
                           f'{type(exc).__name__}') from None
        except OSError as exc:
            raise ApiError('NETWORK',
                           f'connection error: {type(exc).__name__}') from None

    def _request_json(self, method: str, path: str,
                      body: bytes | None) -> object:
        status, raw = self._request(method, path, body)
        try:
            return json.loads(raw.decode('utf-8'))
        except (UnicodeDecodeError, ValueError):
            key = self._key()
            raise ApiError('MALFORMED',
                           f'HTTP {status}: non-JSON response: '
                           f'{_snippet(raw, key)}', status) from None

    # ------------------------------------------------------------- endpoints

    def list_models(self) -> list[str]:
        """GET {base}/models -> sorted list of model id strings."""
        ids: list[str] = []
        after: str | None = None
        for _page in range(20):
            path = '/models?limit=1000'
            if after is not None:
                path += '&after_id=' + urllib.parse.quote(after, safe='')
            payload = self._request_json('GET', path, None)
            if not isinstance(payload, dict):
                raise ApiError('MALFORMED', 'models response is not a JSON object')
            data = payload.get('data')
            if not isinstance(data, list):
                raise ApiError('MALFORMED', 'models response has no data list')
            last: str | None = None
            for entry in data:
                if not isinstance(entry, dict):
                    raise ApiError('MALFORMED', 'models entry is not an object')
                model_id = entry.get('id')
                if not isinstance(model_id, str):
                    raise ApiError('MALFORMED', 'models entry has no id string')
                ids.append(model_id)
                last = model_id
            if not payload.get('has_more') or last is None:
                break
            after = payload.get('last_id') if isinstance(
                payload.get('last_id'), str) else last
        return sorted(set(ids))

    def create(self, *, model: str, input_items: list,
               tools: list | None = None,
               tool_choice: str | dict | None = None,
               reasoning_effort: str | None = None,
               max_output_tokens: int | None = None,
               include_encrypted_reasoning: bool = False,
               text_json_schema: dict | None = None,
               parallel_tool_calls: bool | None = None,
               extra_body: dict | None = None) -> dict:
        """POST {base}/messages; returns a Responses-shaped dict."""
        del include_encrypted_reasoning, parallel_tool_calls, extra_body
        system, messages = _translate_input(input_items)
        body: dict = {'model': model,
                      'max_tokens': max_output_tokens or DEFAULT_MAX_TOKENS,
                      'messages': messages}
        if system is not None:
            body['system'] = system
        if tools is not None:
            body['tools'] = _translate_tools(tools)
        if text_json_schema is not None:
            schema = (text_json_schema.get('schema', text_json_schema)
                      if isinstance(text_json_schema, dict)
                      else text_json_schema)
            body['tools'] = list(body.get('tools', [])) + [{
                'name': 'respond',
                'description': 'Respond with the structured output object.',
                'input_schema': schema,
            }]
            body['tool_choice'] = {'type': 'tool', 'name': 'respond'}
        elif tool_choice is not None:
            body['tool_choice'] = _translate_tool_choice(tool_choice)
        if reasoning_effort is not None and self._thinking:
            if self._thinking_api == 'adaptive':
                # Wire shape verified for both the 4-6 and 5 generations
                # (step-5a probes): adaptive thinking with the effort in
                # output_config; max_tokens is plain.
                body['thinking'] = {'type': 'adaptive'}
                body['output_config'] = {'effort': reasoning_effort}
            else:
                choice = body.get('tool_choice')
                if isinstance(choice, dict) and choice.get('type') in (
                        'tool', 'any'):
                    # Unverified wire combination; make it a loud config
                    # error instead of a runtime surprise.
                    raise ApiError(
                        'MALFORMED',
                        'budgeted thinking cannot combine with a forced '
                        "tool_choice; set 'thinking': False for this "
                        'provider in PROVIDER_CONFIG')
                budget = (THINKING_BUDGETS.get(reasoning_effort,
                                               THINKING_BUDGET_DEFAULT))
                body['thinking'] = {'type': 'enabled',
                                    'budget_tokens': budget}
                body['max_tokens'] = (max_output_tokens
                                      or DEFAULT_MAX_TOKENS) + budget
        payload = self._request_json(
            'POST', '/messages', json.dumps(body).encode('utf-8'))
        if not isinstance(payload, dict):
            raise ApiError('MALFORMED', 'messages body is not a JSON object')
        return _normalize_response(payload,
                                   forced=text_json_schema is not None)
