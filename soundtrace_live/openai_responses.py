"""Minimal stdlib OpenAI Responses API client.

Only what the CyberGym live pipeline needs: `POST /v1/responses` and
`GET /v1/models`, over `urllib.request`, with strict error classification
and redaction.

Error contract (`ApiError`):
    reason in ('AUTH','FORBIDDEN','RATE_LIMIT','SERVER','NETWORK','TIMEOUT',
               'MALFORMED'); `status_code` is the HTTP status when one was
    received; `message` is the status plus a <=200-character sanitized
    snippet of the response body with any occurrence of the API key removed.

The API key is read from the constructor argument or the
`OPENAI_API_KEY` environment variable; it is never logged, never echoed in
error messages, and never sent anywhere except the `Authorization: Bearer`
header of an HTTPS request to the configured base URL.  Plain-HTTP base URLs
are rejected except for loopback hosts (`127.0.0.1`/`localhost`/`::1`),
which exist solely so the offline test suite can drive this client against a
local fake server; every non-loopback URL must be HTTPS.
"""

import json
import os
import socket
import time
import urllib.error
import urllib.parse
import urllib.request

__all__ = ['ApiError', 'ResponsesClient']

DEFAULT_BASE_URL = 'https://api.openai.com/v1'
ERROR_SNIPPET_BYTES = 200


class ApiError(Exception):
    """API call failure with a classified reason and a redacted message."""

    def __init__(self, reason: str, message: str,
                 status_code: int | None = None) -> None:
        super().__init__(message)
        self.reason = reason
        self.message = message
        self.status_code = status_code


TRANSIENT_REASONS = ('SERVER', 'RATE_LIMIT', 'NETWORK', 'TIMEOUT')
RETRY_COUNT = 2
RETRY_BASE_S = 1.0


def _sleep(seconds: float) -> None:
    """Indirection so tests can patch out real backoff sleeps."""
    time.sleep(seconds)


def retry_transient(call, *, remaining, retries=None, base=None):
    """Run ``call()``; retry a transient ``ApiError`` with bounded exponential
    backoff (capped by ``remaining()`` seconds). Re-raises on a non-transient
    reason or once retries are exhausted; the caller classifies the final
    failure into a session status."""
    retries = RETRY_COUNT if retries is None else retries
    base = RETRY_BASE_S if base is None else base
    attempt = 0
    while True:
        try:
            return call()
        except ApiError as exc:
            if exc.reason not in TRANSIENT_REASONS or attempt >= retries:
                raise
            wait = min(base * (2 ** attempt), max(0.0, remaining()))
            if wait <= 0:
                raise
            _sleep(wait)
            attempt += 1


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


class ResponsesClient:
    """Strict, non-retrying client for the OpenAI Responses API."""

    def __init__(self, api_key: str | None = None,
                 base_url: str = DEFAULT_BASE_URL,
                 timeout: float = 120.0,
                 max_response_bytes: int = 8_000_000) -> None:
        parsed = urllib.parse.urlparse(base_url)
        host = parsed.hostname or ''
        if parsed.scheme != 'https' and host not in (
                '127.0.0.1', 'localhost', '::1'):
            raise ValueError('base_url must be an HTTPS URL')
        self._base_url = base_url.rstrip('/')
        self._api_key = api_key
        self._timeout = timeout
        self._max_response_bytes = max_response_bytes

    # ------------------------------------------------------------------ key

    def _key(self) -> str:
        key = self._api_key if self._api_key is not None \
            else os.environ.get('OPENAI_API_KEY')
        if not key:
            raise ApiError('AUTH', 'missing API key: pass api_key or set '
                                   'OPENAI_API_KEY')
        # Never let the raw key reach an exception message: strip surrounding
        # whitespace and reject control characters outright.
        if key != key.strip() or any(ord(c) < 32 or ord(c) == 127 for c in key):
            raise ApiError('AUTH', 'API key contains whitespace or control '
                                   'characters')
        return key

    # -------------------------------------------------------------- requests

    def _request(self, method: str, path: str,
                 body: bytes | None) -> tuple[int, bytes]:
        """Perform one HTTP request; classify and redact every failure."""
        key = self._key()
        url = self._base_url + path
        headers = {
            'Authorization': 'Bearer ' + key,
            'Content-Type': 'application/json',
        }
        req = urllib.request.Request(url, data=body, headers=headers,
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
        """GET /v1/models -> sorted list of model id strings."""
        payload = self._request_json('GET', '/models', None)
        if not isinstance(payload, dict):
            raise ApiError('MALFORMED', 'models response is not a JSON object')
        data = payload.get('data')
        if not isinstance(data, list):
            raise ApiError('MALFORMED', 'models response has no data list')
        ids: list[str] = []
        for entry in data:
            if not isinstance(entry, dict):
                raise ApiError('MALFORMED', 'models entry is not an object')
            model_id = entry.get('id')
            if not isinstance(model_id, str):
                raise ApiError('MALFORMED', 'models entry has no id string')
            ids.append(model_id)
        return sorted(ids)

    def create(self, *, model: str, input_items: list,
               tools: list | None = None,
               tool_choice: str | dict | None = None,
               reasoning_effort: str | None = None,
               max_output_tokens: int | None = None,
               include_encrypted_reasoning: bool = False,
               text_json_schema: dict | None = None,
               parallel_tool_calls: bool | None = None,
               extra_body: dict | None = None) -> dict:
        """POST /v1/responses; returns the parsed response dict as-is."""
        body: dict = {'model': model, 'input': input_items, 'store': False}
        if tools is not None:
            body['tools'] = tools
        if tool_choice is not None:
            body['tool_choice'] = tool_choice
        if reasoning_effort is not None:
            body['reasoning'] = {'effort': reasoning_effort}
        if max_output_tokens is not None:
            body['max_output_tokens'] = max_output_tokens
        if include_encrypted_reasoning:
            body['include'] = ['reasoning.encrypted_content']
        if text_json_schema is not None:
            body['text'] = {
                'format': {
                    'type': 'json_schema',
                    'name': text_json_schema.get('name', 'response'),
                    'schema': text_json_schema.get('schema',
                                                  text_json_schema),
                    'strict': text_json_schema.get('strict', True),
                }
            }
        if parallel_tool_calls is not None:
            body['parallel_tool_calls'] = parallel_tool_calls
        if extra_body:
            for key, value in extra_body.items():
                body[key] = value
        payload = self._request_json(
            'POST', '/responses',
            json.dumps(body).encode('utf-8'))
        if not isinstance(payload, dict):
            raise ApiError('MALFORMED', 'responses body is not a JSON object')
        if not isinstance(payload.get('output'), list):
            raise ApiError('MALFORMED', 'responses body has no output list')
        return payload


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
