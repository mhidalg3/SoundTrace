"""Harness-subscription model bridge for the CyberGym live pipeline.

Runs the pipeline's model roles on the omp harness's own provider
subscriptions — no API keys. The bridge is driven from the harness eval
kernel, which exposes `completion(prompt, model, system, schema)`; the
pipeline's existing `client_factory` injection point carries clients built
here into `run_task`, so no orchestrator changes are needed.

Wire shape
----------
`HarnessClient.create()` presents the same surface as `ResponsesClient`/
`AnthropicClient`, but the transport is one stateless completion call per
turn:

- Target role (tools passed): the conversation history is rendered as a
  plain transcript and the next action is forced through a JSON schema
  (`{"tool", "arguments", "reasoning_chunk"}`). The reply is reshaped into
  a synthetic `function_call` output item; the orchestrator's existing
  argument validation (including `reasoning_chunk`) applies unchanged.
- Translator role (`text_json_schema` passed): the chunk + evidence prompt
  is sent with the translator's output schema; the parsed object is reshaped
  into the `message`/`output_text` item the translator expects.

Usage numbers are reported as zero (the subscription transport does not
expose token counts); the runner accepts zeros and the run ledger records
the role name as the resolved model.
"""

from __future__ import annotations

import json
from typing import Any, Callable

from soundtrace_live.openai_responses import ApiError

__all__ = ['HarnessClient', 'TOOL_ACTION_SCHEMA', 'run_on_harness']

# One JSON action per turn: exactly what target_loop validates afterwards.
TOOL_ACTION_SCHEMA = {
    'type': 'object',
    'additionalProperties': False,
    'required': ['tool', 'arguments', 'reasoning_chunk'],
    'properties': {
        'tool': {'type': 'string',
                 'enum': ['shell', 'probe', 'report_oob', 'report_none']},
        'arguments': {'type': 'object'},
        'reasoning_chunk': {'type': 'string'},
    },
}

_MAX_CALL_ID = 1 << 30


def _history_text(items: list) -> str:
    """Responses-shaped history -> a plain transcript for one-shot models."""
    lines: list[str] = []
    for item in items:
        if not isinstance(item, dict):
            raise ApiError('MALFORMED', 'harness bridge: bad history item')
        role = item.get('role')
        kind = item.get('type')
        if role == 'system':
            continue                      # carried separately
        if role == 'user':
            content = item.get('content')
            text = content if isinstance(content, str) else json.dumps(
                content, separators=(',', ':'))
            lines.append(f'[user]\n{text}')
        elif role == 'assistant' or kind == 'message':
            content = item.get('content')
            if isinstance(content, list):
                text = ' '.join(
                    piece.get('text', '') for piece in content
                    if isinstance(piece, dict))
            else:
                text = str(content)
            if text.strip():
                lines.append(f'[assistant]\n{text}')
        elif kind == 'function_call':
            lines.append('[assistant action]\n' + json.dumps(
                {'tool': item.get('name'),
                 'arguments': json.loads(item.get('arguments') or '{}'),
                 'reasoning_chunk': (json.loads(item.get('arguments') or '{}')
                                     .get('reasoning_chunk', ''))},
                separators=(',', ':')))
        elif kind == 'function_call_output':
            lines.append(f"[tool result {item.get('call_id')}]\n"
                         + str(item.get('output', '')))
        else:
            # reasoning items and unknown shapes carry no visible text
            continue
    return '\n\n'.join(lines)


class HarnessClient:
    """Presents the pipeline client surface over one harness completion."""

    def __init__(self, completion: Callable[..., Any], role: str = 'default',
                 label: str | None = None):
        if role not in ('default', 'smol', 'slow'):
            raise ValueError(
                "role must be 'default', 'smol' or 'slow' (the harness "
                'completion transport exposes model roles, not raw '
                'provider selectors)')
        self._completion = completion
        self._role = role
        self._label = label or f'omp:{role}'
        self._call_ids = 0
        self._timeout = 300.0     # attribute parity with call_target

    # ------------------------------------------------------------ surface

    def list_models(self) -> list[str]:
        # The harness exposes roles, not a model registry; report the role
        # so chain preflight can match it.
        return [self._label]

    def create(self, *, model: str, input_items: list,
               tools: list | None = None,
               tool_choice: str | dict | None = None,
               reasoning_effort: str | None = None,
               max_output_tokens: int | None = None,
               include_encrypted_reasoning: bool = False,
               text_json_schema: dict | None = None,
               parallel_tool_calls: bool | None = None,
               extra_body: dict | None = None) -> dict:
        del tool_choice, reasoning_effort, max_output_tokens, extra_body
        del include_encrypted_reasoning, parallel_tool_calls
        system: str | None = None
        rest = list(input_items)
        if rest and isinstance(rest[0], dict) and rest[0].get('role') == \
                'system':
            system = rest[0].get('content')
            if not isinstance(system, str):
                raise ApiError('MALFORMED',
                               'harness bridge: system content must be text')
            rest = rest[1:]
        prompt = _history_text(rest)
        if text_json_schema is not None:
            return self._structured(prompt, system, text_json_schema)
        if tools:
            return self._tool_action(prompt, system)
        # Bare text turn: no schema to enforce, ask for plain text.
        return self._text_turn(prompt, system)

    # ---------------------------------------------------------- internals

    def _call(self, prompt: str, system: str | None, schema: dict | None):
        try:
            result = self._completion(prompt=prompt, model=self._role,
                                      system=system, schema=schema)
        except ApiError:
            raise
        except Exception as exc:
            raise ApiError('SERVER',
                           f'harness completion failed: '
                           f'{type(exc).__name__}: {exc}') from None
        if hasattr(result, 'wait'):            # async handle form
            try:
                result = result.wait()
            except Exception as exc:
                raise ApiError('SERVER',
                               f'harness completion failed: '
                               f'{type(exc).__name__}: {exc}') from None
        return result

    def _tool_action(self, prompt: str, system: str | None) -> dict:
        result = self._call(prompt + '\n\nChoose exactly one next action.',
                            system, TOOL_ACTION_SCHEMA)
        if not isinstance(result, dict) \
                or not isinstance(result.get('tool'), str) \
                or not isinstance(result.get('arguments'), dict) \
                or not isinstance(result.get('reasoning_chunk'), str):
            raise ApiError('MALFORMED',
                           'harness bridge: model action was not a valid '
                           'tool call')
        arguments = dict(result['arguments'])
        arguments['reasoning_chunk'] = result['reasoning_chunk']
        self._call_ids = (self._call_ids + 1) % _MAX_CALL_ID
        call_id = f'h{self._call_ids}'
        return {'id': call_id, 'model': self._label, 'status': 'completed',
                'output': [{'type': 'function_call', 'call_id': call_id,
                            'name': result['tool'],
                            'arguments': json.dumps(arguments)}],
                'usage': {'input_tokens': 0, 'output_tokens': 0}}

    def _structured(self, prompt: str, system: str | None,
                    schema: dict) -> dict:
        result = self._call(prompt, system, schema)
        if not isinstance(result, dict):
            raise ApiError('MALFORMED',
                           'harness bridge: structured output was not an '
                           'object')
        return {'id': 'hs', 'model': self._label, 'status': 'completed',
                'output': [{'type': 'message', 'content': [
                    {'type': 'output_text',
                     'text': json.dumps(result, separators=(',', ':'))}]}],
                'usage': {'input_tokens': 0, 'output_tokens': 0}}

    def _text_turn(self, prompt: str, system: str | None) -> dict:
        result = self._call(prompt, system, None)
        text = result if isinstance(result, str) else json.dumps(result)
        return {'id': 'ht', 'model': self._label, 'status': 'completed',
                'output': ([{'type': 'message', 'content': [
                    {'type': 'output_text', 'text': text}]}] if text else []),
                'usage': {'input_tokens': 0, 'output_tokens': 0}}


def run_on_harness(corpus, task_id: str, difficulty: str, *,
                   work_dir, key_path, lean, out_dir,
                   deadline_s: float = 1200.0,
                   target_role: str = 'default',
                   translator_role: str = 'default',
                   completion: Callable[..., Any] | None = None,
                   corpus_path=None) -> Any:
    """Awaitable run_task over harness-subscription clients (no API keys).

    Call from the harness eval kernel:

        from soundtrace_live.harness import run_on_harness
        result = await run_on_harness(corpus, 'arvo:64574', 'level1',
                                      work_dir='/tmp/cg-smoke',
                                      key_path='/tmp/st-lean-smoke.xJTY/runner.key',
                                      lean=LEAN, out_dir='/tmp/harness-runs',
                                      deadline_s=600)


    `completion` defaults to the caller's global of the same name (kernel
    cells define it); resolution happens synchronously at call time because
    a coroutine body runs on the event loop, where the caller frame is gone.
    The run itself executes via asyncio.to_thread while the coroutine keeps
    the kernel loop alive for the bridge's model calls.
    """
    if completion is None:
        import sys
        frame = sys._getframe(1)
        completion = frame.f_globals.get('completion') if frame else None
    if completion is None:
        raise ValueError('pass the kernel completion callable explicitly '
                         '(or call run_on_harness directly from a kernel '
                         'cell that defines completion)')
    return _run_on_harness(corpus, task_id, difficulty,
                           work_dir=work_dir, key_path=key_path, lean=lean,
                           out_dir=out_dir, deadline_s=deadline_s,
                           target_role=target_role,
                           translator_role=translator_role,
                           completion=completion, corpus_path=corpus_path)


async def _run_on_harness(corpus, task_id: str, difficulty: str, *,
                          work_dir, key_path, lean, out_dir,
                          deadline_s: float, target_role: str,
                          translator_role: str, completion: Callable[..., Any],
                          corpus_path=None) -> Any:
    """Async driver body; `completion` is resolved by the sync wrapper."""
    import asyncio
    import contextvars
    import inspect
    from pathlib import Path
    from soundtrace_live.orchestrator import run_task
    loop = asyncio.get_event_loop()
    # asyncio.to_thread propagates this context into the run thread, but the
    # translator worker starts a raw thread without it; schedule every
    # bridge call under the captured harness context so telemetry
    # session/run/name attribution survives.
    context = contextvars.copy_context()

    async def _acall(kwargs):
        value = completion(**kwargs)
        if hasattr(value, 'wait'):
            maybe = value.wait()
            value = await maybe if inspect.isawaitable(maybe) else maybe
        elif inspect.isawaitable(value):
            value = await value
        return value

    def sync_completion(**kwargs):
        # A Context object admits one active entry; concurrent role threads
        # each get their own shallow copy of the harness context.
        ctx = context.copy()
        future = ctx.run(asyncio.run_coroutine_threadsafe, _acall(kwargs),
                         loop)
        return future.result(timeout=900)

    def client_factory(provider: str):
        role = translator_role if provider == 'omp-translator' \
            else target_role
        return HarnessClient(sync_completion, role=role)

    return await asyncio.to_thread(
        run_task, corpus, task_id, difficulty,
        work_dir=Path(work_dir), key_path=Path(key_path), lean=lean,
        out_dir=Path(out_dir),
        target_chain=[('omp', f'omp:{target_role}')],
        translator_chain=[('omp-translator', f'omp:{translator_role}')],
        client_factory=client_factory, deadline_s=deadline_s,
        corpus_path=Path(corpus_path) if corpus_path else None)
