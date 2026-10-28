#!/usr/bin/env python3
"""Runner-owned capture boundary for controlled C executions.

The runner accepts only enumerated cases from a fixed, reviewed fixture; it
never accepts a source path, executable, shell command, compiler flags, or
environment overrides from the agent. Requests are dispatched serially, one
sequence position is assigned per dispatch/delivery, and the complete ordered
log is authenticated with an external HMAC key that never enters the child
environment, the bundle, the proof, or the logs.

`record --backend cybergym` selects the pinned-CyberGym capture backend: the
only executable request becomes `probe` (runner-resolved PoC bytes, pinned
image, fixed ASan options), plus bounded audit-only request kinds for the
model/agent/translation/benchmark trail. Everything domain-independent —
sequencing, limits, narrate, emit, HMAC publication, claim closure — stays
here; no model or network code enters this file.

HMAC establishes that this trusted runner recorded these bytes. It is not a
defense against an arbitrary malicious executable or an agent with
unrestricted host access; initial trust covers the reviewed C source,
compiler, sanitizer runtime, collector, host, and private-key boundary.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import selectors
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


from evidence import (Rejected, canonical_json, mac_hex, parse_json, require,
                      sha256_hex)
from frontend import ID_RE, LIMIT_STEPS, RULE_LEAN, is_index
from oob_adapter import (AUTHORITY, CANONICAL_ASAN_OPTIONS, AdapterError,
                         freeze_claim, observations_for_execution,
                         validate_events)
from soundtrace_live.cybergym_adapter import (AUTHORITY as CYBERGYM_AUTHORITY,
                                              BUNDLE_FORMAT as CYBERGYM_FORMAT,
                                              BUILD_KEYS, EXECUTION_KEYS,
                                              ABSTAIN_REASONS,
                                              ATTEMPT_OUTCOMES,
                                              observations_for_execution as cybergym_observations,
                                              freeze_claim as cybergym_freeze,
                                              validate_execution as cybergym_validate_execution)
BUNDLE_FORMAT = 'soundtrace-run-v1'
KEY_SIZE = 32
CHILD_TIMEOUT = 10.0
CHILD_COMBINED_BYTE_LIMIT = 1_000_000
LINE_BYTE_LIMIT = 100_000
TRACE_FRAME_LIMIT = 1000
CYBERGYM_TRACE_FRAME_LIMIT = 4000
NARRATE_CHAR_LIMIT = 20_000
EVENT_FD = 3
BUILD_FLAGS = ['-std=c11', '-O0', '-g', '-fsanitize=address',
               '-fno-omit-frame-pointer', '-fno-optimize-sibling-calls']
ENV_DENYLIST = {'ASAN_OPTIONS', 'LSAN_OPTIONS', 'LD_PRELOAD', 'DYLD_INSERT_LIBRARIES',
                'CC', 'CXX', 'CFLAGS', 'CXXFLAGS', 'CPATH', 'C_INCLUDE_PATH',
                'LIBRARY_PATH', 'MACOSX_DEPLOYMENT_TARGET'}
NODE_KINDS = ('observe', 'calculate', 'compare', 'conjoin', 'infer')
POC_LIMIT_BYTES = 1_048_576
MODEL_ID_RE = re.compile(r'[A-Za-z0-9._:-]{1,128}')
PROVIDER_ID_RE = re.compile(r'[a-z0-9_-]{1,32}')
HEX64 = re.compile(r'[0-9a-f]{64}')
STRING_LIMIT = 2048
DIAGNOSTIC_LIMIT = 4096
EXCERPT_LIMIT = 1024
TURN_LIMIT = 100_000
BYTE_COUNT_LIMIT = 1 << 24
TOKEN_LIMIT = 1 << 24
AUDIT_KINDS = ('model_session', 'model_turn', 'agent_action', 'agent_result',
               'benchmark_result')


class ProtocolError(Exception):
    def __init__(self, reason: str, diagnostic: str = ''):
        super().__init__(diagnostic or reason)
        self.reason = reason
        self.diagnostic = diagnostic or reason


class _Session:
    def __init__(self, key: bytes, out_path: Path, backend=None,
                 target_build: str = 'vul'):
        self.key = key
        self.out_path = out_path
        self.backend = backend   # None → fixture backend; else CyberGym capture
        self.target_build = target_build
        self.seq = 0
        self.trace: list[dict] = []
        self.executions: list[dict] = []
        self.claims: dict[str, dict] = {}
        self.closed_arguments: set[str] = set()
        self.run_count = 0
        self.build: dict | None = None
        self.binary_path: Path | None = None
        self.run_id = 'R' + os.urandom(16).hex()
        self.aborted = False
        # Direct-mode (signed-output) state.
        self.observations: dict[str, dict] = {}   # evidence_id -> {formula, available_at}
        self.arg_mode: dict[str, str] = {}         # argument_id -> 'intermediate'|'direct'
        self.arg_steps: dict[str, int] = {}        # argument_id -> running global step count
        self.arg_emit_ids: dict[str, set[str]] = {}     # argument_id -> seen emission ids
        # CyberGym direct-translation state.
        self.arg_attempts: dict[str, dict[str, dict]] = {}
        self.arg_abstain_ids: dict[str, set[str]] = {}
        self.agent_action_ids: dict[str, tuple[str, str]] = {}
        self.agent_result_ids: set[str] = set()
    @property
    def is_cybergym(self) -> bool:
        return self.backend is not None

    @property
    def frame_limit(self) -> int:
        return CYBERGYM_TRACE_FRAME_LIMIT if self.is_cybergym else TRACE_FRAME_LIMIT

    # ---- ordered log -----------------------------------------------------
    def next_seq(self) -> int:
        self.seq += 1
        require(self.seq <= self.frame_limit, 'parent trace frame limit')
        return self.seq

    def append_request(self, seq: int, request: dict) -> None:
        self.trace.append({'seq': seq, 'kind': 'request', 'body': request})

    def append_response(self, seq: int, request_seq: int, response: dict) -> None:
        self.trace.append({'seq': seq, 'kind': 'response', 'request_seq': request_seq,
                           'body': response})

    def emit(self, response: dict) -> None:
        line = json.dumps(response, separators=(',', ':'))
        sys.stdout.write(line + '\n')
        sys.stdout.flush()

    # ---- fixture build ---------------------------------------------------
    def ensure_build(self) -> None:
        if self.build is not None:
            return
        source = Path(__file__).resolve().parent / 'fixtures' / 'oob_cases.c'
        require(source.is_file(), 'fixture source missing')
        clang = shutil.which('clang')
        require(clang is not None, 'host clang not available')
        binary = self.out_path.parent / 'oob_cases'
        env = {k: v for k, v in os.environ.items() if k not in ENV_DENYLIST}
        try:
            proc = subprocess.run([clang, *BUILD_FLAGS, str(source), '-o', str(binary)],
                                  capture_output=True, text=True, timeout=120, check=False,
                                  env=env)
        except (subprocess.TimeoutExpired, OSError) as exc:
            raise ProtocolError('INCONCLUSIVE_CAPTURE', f'fixture build failed: {exc}') from exc
        require(proc.returncode == 0 and binary.is_file(),
                f'fixture build failed: {proc.stderr[:500]}')
        version = subprocess.run([clang, '--version'], capture_output=True, text=True,
                                 check=False)
        self.build = {
            'source_sha256': sha256_hex(source.read_bytes()),
            'binary_sha256': sha256_hex(binary.read_bytes()),
            'compiler_version': (version.stdout + version.stderr).splitlines()[0]
            if (version.stdout + version.stderr).splitlines() else '',
            'flags': list(BUILD_FLAGS),
        }
        self.binary_path = binary

    # ---- child capture ---------------------------------------------------
    def run_case(self, case: str) -> dict:
        self.ensure_build()
        self.run_count += 1
        execution_id = f'X{self.run_count}'
        event_read, event_write = os.pipe()

        def _map_event_fd():  # runs in the child between fork and exec
            os.dup2(event_write, EVENT_FD)
            if event_write != EVENT_FD:
                os.close(event_write)

        env = {k: v for k, v in os.environ.items() if k not in ENV_DENYLIST}
        env['ASAN_OPTIONS'] = CANONICAL_ASAN_OPTIONS
        try:
            child = subprocess.Popen([str(self.binary_path), case],
                                     pass_fds=(event_write, EVENT_FD),
                                     preexec_fn=_map_event_fd,
                                     stdout=subprocess.DEVNULL,
                                     stderr=subprocess.PIPE, env=env, close_fds=True)
        except OSError as exc:
            os.close(event_read)
            os.close(event_write)
            raise ProtocolError('INCONCLUSIVE_CAPTURE', f'cannot start child: {exc}') from exc
        os.close(event_write)
        events_bytes, stderr_bytes, overflow, timed_out = self._drain(child, event_read)
        os.close(event_read)
        try:
            rc = child.wait(timeout=CHILD_TIMEOUT)
        except subprocess.TimeoutExpired:
            child.kill()
            rc = child.wait()
            timed_out = True
        if timed_out or overflow or rc < 0:
            raise ProtocolError('INCONCLUSIVE_CAPTURE',
                                f'timeout={timed_out} overflow={overflow} signal={rc < 0}')
        try:
            events = self._parse_events(events_bytes)
        except Rejected as exc:
            raise ProtocolError('INCONCLUSIVE_CAPTURE', f'child event stream: {exc}') from exc
        execution = {
            'id': execution_id,
            'case': case,
            'pid': child.pid,
            'pointer_bits': events[0].get('pointer_bits', 0) if events else 0,
            'asan_options': CANONICAL_ASAN_OPTIONS,
            'exit_code': rc,
            'events': events,
            'stderr': stderr_bytes.decode('utf-8', 'replace')[:20000],
        }
        try:
            validate_events(execution['events'])
        except Rejected as exc:
            raise ProtocolError('INCONCLUSIVE_CAPTURE', str(exc)) from exc
        return execution

    def _drain(self, child, event_fd):
        selector = selectors.DefaultSelector()
        selector.register(event_fd, selectors.EVENT_READ, 'events')
        selector.register(child.stderr, selectors.EVENT_READ, 'stderr')
        buffers = {'events': bytearray(), 'stderr': bytearray()}
        total = 0
        overflow = False
        open_count = 2
        deadline = time.monotonic() + CHILD_TIMEOUT
        while open_count and not overflow:
            timeout = max(0.0, deadline - time.monotonic())
            if timeout == 0.0:
                child.kill()
                return bytes(buffers['events']), bytes(buffers['stderr']), overflow, True
            for key, _ in selector.select(timeout):
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    open_count -= 1
                    continue
                total += len(chunk)
                buffers[key.data].extend(chunk)
                if total > CHILD_COMBINED_BYTE_LIMIT:
                    overflow = True
                    break
        if overflow:
            child.kill()
        selector.close()
        return buffers['events'], buffers['stderr'], overflow, False

    def _parse_events(self, raw: bytes) -> list[dict]:
        events = []
        for line in raw.split(b'\n'):
            if not line:
                continue
            require(len(line) <= LINE_BYTE_LIMIT, 'event line exceeds the line limit')
            try:
                event = parse_json(line.decode('utf-8'))
            except Rejected as exc:
                raise ProtocolError('INCONCLUSIVE_CAPTURE', f'unparseable event: {exc}') from exc
            require(isinstance(event, dict), 'event must be an object')
            events.append(event)
        return events

    # ---- request handling ------------------------------------------------
    def dispatch(self, request: Any) -> int:
        """Handle one request; returns the process exit status."""
        request_seq = self.next_seq()
        self.append_request(request_seq, request)
        response_seq = self.seq + 1  # reserved; consumed on delivery below
        try:
            response = self._handle(request, request_seq, response_seq)
        except ProtocolError as exc:
            if exc.reason == 'INCONCLUSIVE_CAPTURE':
                response = {'status': 'INCONCLUSIVE_CAPTURE',
                            'diagnostic': exc.diagnostic}
                exit_code = 2
            elif exc.reason == 'INCONCLUSIVE_SETUP':
                response = {'status': 'INCONCLUSIVE_SETUP',
                            'reason': exc.reason,
                            'diagnostic': exc.diagnostic}
                exit_code = 2
            else:
                response = {'status': 'REJECTED', 'reason': exc.reason,
                            'diagnostic': exc.diagnostic}
                exit_code = 1
            response_seq = self.next_seq()
            self.emit(response)
            self.append_response(response_seq, request_seq, response)
            self.aborted = True
            return exit_code
        except Rejected as exc:
            response = {'status': 'REJECTED', 'reason': 'BAD_INPUT',
                        'diagnostic': str(exc)}
            response_seq = self.next_seq()
            self.emit(response)
            self.append_response(response_seq, request_seq, response)
            self.aborted = True
            return 1
        try:
            self.emit(response)
        except OSError as exc:
            self.aborted = True
            raise ProtocolError('DELIVERY_FAILED', f'response emission failed: {exc}') from exc
        require(self.next_seq() == response_seq, 'response position desynchronized')
        self.append_response(response_seq, request_seq, response)
        if isinstance(response, dict) and response.get('status') == 'INCONCLUSIVE_CAPTURE':
            # A probe-level inconclusive capture is recorded and the session
            # continues: exploration routinely produces non-crashing or
            # unsupported candidates, and none of them entered the signed
            # execution list. Any other inconclusive capture is fatal.
            if not (self.is_cybergym and isinstance(request, dict)
                    and request.get('kind') == 'probe'):
                self.aborted = True
                return 2
        return 0

    def _handle(self, request: Any, request_seq: int, response_seq: int) -> dict:
        require(isinstance(request, dict), 'request must be an object')
        kind = request.get('kind')
        if kind == 'run':
            require(not self.is_cybergym, 'run requests require the fixture backend')
            return self._handle_run(request, response_seq)
        if kind == 'probe':
            require(self.is_cybergym, 'probe requests require the cybergym backend')
            return self._handle_probe(request, response_seq)
        if kind == 'reason':
            require(not self.is_cybergym, 'reason requests require the fixture backend')
            return self._handle_reason(request, request_seq)
        if kind == 'narrate':
            return self._handle_narrate(request, request_seq)
        if kind == 'emit':
            return self._handle_emit(request, request_seq)
        if kind == 'claim':
            return self._handle_claim(request, request_seq)
        if kind == 'translation_attempt':
            require(self.is_cybergym, 'translation requests require the cybergym backend')
            return self._handle_translation_attempt(request)
        if kind == 'translation_abstain':
            require(self.is_cybergym, 'translation requests require the cybergym backend')
            return self._handle_translation_abstain(request, request_seq)
        if kind in AUDIT_KINDS:
            require(self.is_cybergym, 'audit requests require the cybergym backend')
            return self._handle_audit(kind, request)
        raise ProtocolError('BAD_INPUT', f'unknown request kind {kind!r}')

    def _handle_run(self, request: dict, response_seq: int) -> dict:
        require(set(request) == {'kind', 'case'}, 'run request keys')
        case = request['case']
        require(isinstance(case, str) and ID_RE.fullmatch(case), 'invalid case name')
        execution = self.run_case(case)
        self.executions.append(execution)
        try:
            records = observations_for_execution(execution, run_id=self.run_id,
                                                 available_at=response_seq)
        except Rejected as exc:
            raise ProtocolError('INCONCLUSIVE_CAPTURE', str(exc)) from exc
        for r in records:
            self.observations[r['id']] = {'formula': r['formula'],
                                          'available_at': r['available_at']}
        return {'status': 'RECORDED', 'execution_id': execution['id'],
                'event_id': 'A1',
                'observations': [{'id': r['id'], 'formula': r['formula'],
                                  'scope': r['scope'], 'available_at': r['available_at']}
                                 for r in records]}

    def _handle_reason(self, request: dict, request_seq: int) -> dict:
        require(set(request) == {'kind', 'argument_id', 'node'}, 'reason request keys')
        argument_id, node = request['argument_id'], request['node']
        require(isinstance(argument_id, str) and ID_RE.fullmatch(argument_id),
                'invalid argument id')
        require(argument_id not in self.closed_arguments,
                f'argument {argument_id!r} is closed by its claim')
        require(self.arg_mode.get(argument_id) != 'direct',
                f'argument {argument_id!r} already uses direct (emit) mode')
        self.arg_mode[argument_id] = 'intermediate'
        require(isinstance(node, dict), 'node must be an object')
        node_id = node.get('id')
        require(isinstance(node_id, str) and ID_RE.fullmatch(node_id), 'invalid node id')
        require(node.get('kind') in NODE_KINDS, 'invalid node kind')
        for entry in self.trace:
            if (entry['kind'] == 'request' and entry['seq'] < request_seq
                    and entry['body'].get('kind') == 'reason'):
                if (entry['body'].get('argument_id') == argument_id
                        and entry['body']['node'].get('id') == node_id):
                    raise ProtocolError('BAD_INPUT', 'node ids must be unique within an argument')
        return {'status': 'RECORDED', 'source_id': node_id}

    def _handle_narrate(self, request: dict, request_seq: int) -> dict:
        # The target agent's public work-log chunk: recorded in order for the
        # audit trail and bound as the translation source; never interpreted
        # and never itself part of the proof.
        require(set(request) == {'kind', 'argument_id', 'text'}, 'narrate request keys')
        argument_id, text = request['argument_id'], request['text']
        require(isinstance(argument_id, str) and ID_RE.fullmatch(argument_id),
                'invalid argument id')
        require(argument_id not in self.closed_arguments,
                f'argument {argument_id!r} is closed by its claim')
        require(isinstance(text, str) and len(text) <= NARRATE_CHAR_LIMIT,
                'narration must be a bounded string')
        if self.is_cybergym:
            return {'status': 'RECORDED', 'argument_id': argument_id, 'seq': request_seq}
        return {'status': 'RECORDED', 'argument_id': argument_id}

    def _handle_emit(self, request: dict, request_seq: int) -> dict:
        # One translator certificate emission: a nonempty block of primitive
        # certificate steps. The runner enforces structure and live provenance
        # (only already-delivered evidence, backward premise indices); it does
        # NOT check arithmetic truth or rule-conclusion correctness, so
        # representable bad reasoning is recorded faithfully and rejected
        # downstream by the checker and the kernel.
        if self.is_cybergym:
            return self._handle_emit_cybergym(request, request_seq)
        require(set(request) == {'kind', 'argument_id', 'id', 'steps'}, 'emit request keys')
        argument_id, emit_id, steps = request['argument_id'], request['id'], request['steps']
        require(isinstance(argument_id, str) and ID_RE.fullmatch(argument_id),
                'invalid argument id')
        require(argument_id not in self.closed_arguments,
                f'argument {argument_id!r} is closed by its claim')
        require(self.arg_mode.get(argument_id) != 'intermediate',
                f'argument {argument_id!r} already uses intermediate (reason) mode')
        self.arg_mode[argument_id] = 'direct'
        require(isinstance(emit_id, str) and ID_RE.fullmatch(emit_id), 'invalid emission id')
        seen = self.arg_emit_ids.setdefault(argument_id, set())
        require(emit_id not in seen, 'emission ids must be unique within an argument')
        require(isinstance(steps, list) and 0 < len(steps) <= LIMIT_STEPS,
                'emission must carry 1..LIMIT_STEPS steps')
        base = self.arg_steps.get(argument_id, 0)
        require(base + len(steps) <= LIMIT_STEPS, 'argument step limit')
        for local, step in enumerate(steps):
            self._check_emit_step(step, base + local, request_seq)
        seen.add(emit_id)
        self.arg_steps[argument_id] = base + len(steps)
        return {'status': 'RECORDED', 'argument_id': argument_id, 'emission_id': emit_id,
                'steps': len(steps)}

    def _handle_emit_cybergym(self, request: dict, request_seq: int) -> dict:
        # CyberGym direct mode: an emission additionally names the narration it
        # translates and the attempt that produced it. The runner byte-hashes
        # the canonical {id, steps} value against that attempt, and requires
        # every cited evidence record to predate the *narration* — so late
        # translation can never admit evidence that arrived after the words
        # being translated.
        require(set(request) == {'kind', 'argument_id', 'id', 'steps', 'attempt_id',
                                 'source_seq'}, 'emit request keys')
        argument_id = request['argument_id']
        emit_id, steps = request['id'], request['steps']
        attempt_id, source_seq = request['attempt_id'], request['source_seq']
        require(isinstance(argument_id, str) and ID_RE.fullmatch(argument_id),
                'invalid argument id')
        require(argument_id not in self.closed_arguments,
                f'argument {argument_id!r} is closed by its claim')
        require(not self.arg_abstain_ids.get(argument_id),
                f'argument {argument_id!r} was closed by a translation abstention')
        self.arg_mode[argument_id] = 'direct'
        require(isinstance(emit_id, str) and ID_RE.fullmatch(emit_id), 'invalid emission id')
        require(isinstance(attempt_id, str) and ID_RE.fullmatch(attempt_id),
                'invalid attempt id')
        require(is_index(source_seq) and 1 <= source_seq < request_seq,
                'source_seq must name an earlier narration position')
        narrated = any(entry['kind'] == 'request'
                       and entry['seq'] == source_seq
                       and isinstance(entry['body'], dict)
                       and entry['body'].get('kind') == 'narrate'
                       and entry['body'].get('argument_id') == argument_id
                       for entry in self.trace)
        require(narrated, 'source_seq does not name a narration of this argument')
        attempt = self.arg_attempts.get(argument_id, {}).get(attempt_id)
        require(attempt is not None, 'emit names no recorded translation attempt')
        require(attempt['outcome'] == 'emit' and attempt['parsed_sha256'] is not None,
                'emit must name an attempt that parsed an emission')
        require(attempt['source_seq'] == source_seq,
                'attempt binds a different source narration')
        seen = self.arg_emit_ids.setdefault(argument_id, set())
        require(emit_id not in seen, 'emission ids must be unique within an argument')
        require(isinstance(steps, list) and 0 < len(steps) <= LIMIT_STEPS,
                'emission must carry 1..LIMIT_STEPS steps')
        base = self.arg_steps.get(argument_id, 0)
        require(base + len(steps) <= LIMIT_STEPS, 'argument step limit')
        require(attempt['parsed_sha256']
                == sha256_hex(canonical_json({'id': emit_id, 'steps': steps})),
                'emission does not byte-match its recorded attempt hash')
        for local, step in enumerate(steps):
            self._check_emit_step(step, base + local, request_seq, source_seq)
        seen.add(emit_id)
        self.arg_steps[argument_id] = base + len(steps)
        return {'status': 'RECORDED', 'argument_id': argument_id, 'emission_id': emit_id,
                'steps': len(steps), 'source_seq': source_seq}

    def _check_emit_step(self, step: Any, global_index: int, request_seq: int,
                         source_seq: int | None = None) -> None:
        require(isinstance(step, dict), 'emit step must be an object')
        op = step.get('op')
        if op == 'observe':
            require(set(step) == {'op', 'evidence', 'formula'}, 'observe step keys')
            evidence = step['evidence']
            require(isinstance(evidence, str) and ID_RE.fullmatch(evidence), 'invalid evidence id')
            record = self.observations.get(evidence)
            require(record is not None, f'cites undelivered evidence {evidence!r}')
            cutoff = source_seq if source_seq is not None else request_seq
            require(record['available_at'] < cutoff,
                    f'cites evidence {evidence!r} not yet delivered at this emission')
        elif op == 'compute':
            require(set(step) == {'op', 'formula'}, 'compute step keys')
        elif op == 'infer':
            require(set(step) == {'op', 'rule', 'premises', 'formula'}, 'infer step keys')
            require(isinstance(step['rule'], str) and step['rule'] in RULE_LEAN,
                    f'unknown rule {step["rule"]!r}')
            premises = step['premises']
            require(isinstance(premises, list)
                    and all(is_index(j) and 0 <= j < global_index for j in premises),
                    'premises must be backward integer step indices')
        else:
            raise ProtocolError('BAD_INPUT', f'unsupported emit step op {op!r}')

    def _handle_probe(self, request: dict, response_seq: int) -> dict:
        # The only executable CyberGym request: bytes are resolved by the
        # runner from its private content-addressed store — never from an
        # agent-supplied path — and execute inside the pinned vulnerable
        # image under the fixed ASan options and preload shim.
        require(set(request) == {'kind', 'task_id', 'poc_sha256', 'poc_size'},
                'probe request keys')
        task_id = request['task_id']
        poc_sha256, poc_size = request['poc_sha256'], request['poc_size']
        from soundtrace_live.cybergym_backend import (
            CaptureError, PROBE_CLEANUP_GRACE_S)
        deadline_text = os.environ.get('SOUNDTRACE_TASK_DEADLINE')
        try:
            deadline = float(deadline_text) if deadline_text is not None else (
                time.monotonic() + 30.0 + PROBE_CLEANUP_GRACE_S)
        except ValueError:
            raise ProtocolError('INCONCLUSIVE_SETUP',
                                'invalid trusted task deadline') from None
        remaining = deadline - time.monotonic()
        if remaining <= PROBE_CLEANUP_GRACE_S:
            # Non-fatal: the session continues; this probe simply cannot be
            # afforded a bounded cleanup anymore.
            return {'status': 'INCONCLUSIVE_CAPTURE',
                    'diagnostic': 'insufficient task time for bounded '
                                  'probe cleanup'}
        timeout_s = min(30.0, remaining - PROBE_CLEANUP_GRACE_S)
        require(isinstance(task_id, str) and task_id in self.backend.corpus.tasks,
                'probe names a task outside this corpus')
        require(isinstance(poc_sha256, str) and HEX64.fullmatch(poc_sha256),
                'poc hash must be 64 lowercase hex characters')
        require(is_index(poc_size) and 0 <= poc_size <= POC_LIMIT_BYTES,
                'poc size must fit the 1 MiB cap')
        execution_id = f'X{self.run_count + 1}'
        from soundtrace_live.cybergym_adapter import scope_fits
        if not scope_fits(self.run_id, task_id, execution_id, poc_sha256):
            # The certificate language caps record ids; a longer scope can
            # never be admitted downstream, so do not record the execution.
            return {'status': 'INCONCLUSIVE_CAPTURE',
                    'diagnostic': 'execution scope exceeds the certificate '
                                  'identifier cap'}
        try:
            execution = self.backend.execute_probe(
                task_id, poc_sha256, execution_id,
                host_timeout=min(30.0, timeout_s), build=self.target_build)
            require(isinstance(execution, dict),
                    'probe backend returned a non-object execution')
            self.backend.validate_execution(execution, build=self.target_build)
            cybergym_validate_execution(execution)
            require(execution.get('id') == execution_id
                    and execution.get('task_id') == task_id
                    and execution.get('poc_sha256') == poc_sha256
                    and execution.get('poc_size') == poc_size,
                    'probe result is not bound to the request')
            records = cybergym_observations(execution, run_id=self.run_id,
                                            available_at=response_seq)
        except CaptureError as exc:
            if exc.status == 'INCONCLUSIVE_SETUP':
                raise ProtocolError('INCONCLUSIVE_SETUP', exc.diagnostic) from None
            return {'status': 'INCONCLUSIVE_CAPTURE', 'diagnostic': exc.diagnostic}
        except Rejected as exc:
            # A malformed execution record invalidates this probe only;
            # it must not abort the session or discard the signed prefix.
            return {'status': 'INCONCLUSIVE_CAPTURE', 'diagnostic': str(exc)}
        self.run_count += 1
        self.executions.append(execution)
        for r in records:
            self.observations[r['id']] = {'formula': r['formula'],
                                          'available_at': r['available_at']}
        return {'status': 'RECORDED', 'execution_id': execution_id,
                'event_id': 'A1' if records else None,
                'access_kind': (execution['events'][0]['access_kind']
                                if execution['events'] else None),
                'poc_sha256': poc_sha256,
                'observations': [{'id': r['id'], 'formula': r['formula'],
                                  'scope': r['scope'], 'available_at': r['available_at']}
                                 for r in records]}

    def _handle_translation_attempt(self, request: dict) -> dict:
        require(set(request) == {'kind', 'argument_id', 'attempt_id', 'source_seq',
                                 'model', 'resolved_model', 'raw_output_sha256',
                                 'raw_output_bytes', 'parsed_sha256', 'outcome',
                                 'repair'}, 'translation_attempt request keys')
        argument_id = request['argument_id']
        require(isinstance(argument_id, str) and ID_RE.fullmatch(argument_id),
                'invalid argument id')
        require(argument_id not in self.closed_arguments,
                f'argument {argument_id!r} is closed by its claim')
        require(isinstance(request['attempt_id'], str)
                and ID_RE.fullmatch(request['attempt_id']), 'invalid attempt id')
        require(is_index(request['source_seq']) and request['source_seq'] >= 1,
                'source_seq must be a positive integer')
        for field in ('model', 'resolved_model'):
            value = request[field]
            require(isinstance(value, str) and MODEL_ID_RE.fullmatch(value),
                    f'{field} must be a bounded model identifier')
        require(isinstance(request['raw_output_sha256'], str)
                and HEX64.fullmatch(request['raw_output_sha256']), 'raw output hash')
        require(is_index(request['raw_output_bytes'])
                and 0 <= request['raw_output_bytes'] <= BYTE_COUNT_LIMIT,
                'raw output byte count')
        parsed = request['parsed_sha256']
        require(parsed is None or (isinstance(parsed, str) and HEX64.fullmatch(parsed)),
                'parsed emission hash')
        require(request['outcome'] in ATTEMPT_OUTCOMES, 'attempt outcome')
        require(request['repair'] in (0, 1) and is_index(request['repair']),
                'repair number must be 0 or 1')
        require(request['outcome'] != 'emit' or parsed is not None,
                'an emit outcome must carry its parsed emission hash')
        attempts = self.arg_attempts.setdefault(argument_id, {})
        require(request['attempt_id'] not in attempts,
                'attempt ids must be unique within an argument')
        attempts[request['attempt_id']] = {
            'source_seq': request['source_seq'], 'outcome': request['outcome'],
            'parsed_sha256': parsed}
        return {'status': 'RECORDED', 'attempt_id': request['attempt_id']}

    def _handle_translation_abstain(self, request: dict, request_seq: int) -> dict:
        require(set(request) == {'kind', 'argument_id', 'abstain_id', 'source_seq',
                                 'reason', 'diagnostic'},
                'translation_abstain request keys')
        argument_id = request['argument_id']
        require(isinstance(argument_id, str) and ID_RE.fullmatch(argument_id),
                'invalid argument id')
        require(argument_id not in self.closed_arguments,
                f'argument {argument_id!r} is closed by its claim')
        require(isinstance(request['abstain_id'], str)
                and ID_RE.fullmatch(request['abstain_id']), 'invalid abstain id')
        require(is_index(request['source_seq']) and request['source_seq'] >= 1,
                'source_seq must be a positive integer')
        require(any(entry.get('kind') == 'request'
                    and entry.get('seq') == request['source_seq']
                    and entry.get('body', {}).get('kind') == 'narrate'
                    and entry['body'].get('argument_id') == argument_id
                    for entry in self.trace),
                'abstention source_seq must name an earlier narration')
        require(request['reason'] in ABSTAIN_REASONS, 'abstain reason')
        require(isinstance(request['diagnostic'], str)
                and len(request['diagnostic']) <= DIAGNOSTIC_LIMIT,
                'abstain diagnostic must be bounded')
        seen = self.arg_abstain_ids.setdefault(argument_id, set())
        require(request['abstain_id'] not in seen,
                'abstain ids must be unique within an argument')
        seen.add(request['abstain_id'])
        return {'status': 'RECORDED', 'abstain_id': request['abstain_id']}

    def _handle_audit(self, kind: str, request: dict) -> dict:
        # Audit-only records: bounded, exact-schema, signed for provenance but
        # never admissible as a proof premise.
        require(isinstance(request.get('argument_id'), str)
                and ID_RE.fullmatch(request['argument_id']), 'invalid argument id')
        if kind == 'model_session':
            session_core = {'kind', 'argument_id', 'session_sha256',
                            'difficulty', 'target_model', 'translator_model',
                            'prompt_sha256', 'input_sha256'}
            require(session_core <= set(request) <= session_core
                    | {'target_provider', 'translator_provider'},
                    'model_session request keys')
            for field in ('target_provider', 'translator_provider'):
                if field in request:
                    require(isinstance(request[field], str)
                            and PROVIDER_ID_RE.fullmatch(request[field]),
                            field)
            for field in ('session_sha256', 'prompt_sha256', 'input_sha256'):
                require(isinstance(request[field], str) and HEX64.fullmatch(request[field]),
                        f'{field} must be a sha256 hex digest')
            require(isinstance(request['difficulty'], str)
                    and request['difficulty'] in ('level0', 'level1'), 'difficulty')
            for field in ('target_model', 'translator_model'):
                require(isinstance(request[field], str)
                        and MODEL_ID_RE.fullmatch(request[field]), field)
        elif kind == 'model_turn':
            turn_core = {'kind', 'argument_id', 'turn', 'role',
                         'requested_model', 'resolved_model',
                         'response_sha256', 'output_bytes', 'status',
                         'input_tokens', 'output_tokens'}
            require(turn_core <= set(request) <= turn_core | {'provider'},
                    'model_turn request keys')
            if 'provider' in request:
                require(isinstance(request['provider'], str)
                        and PROVIDER_ID_RE.fullmatch(request['provider']),
                        'provider')
            require(is_index(request['turn']) and 0 <= request['turn'] < TURN_LIMIT,
                    'turn index')
            require(request['role'] in ('target', 'translator'), 'role')
            for field in ('requested_model', 'resolved_model'):
                require(isinstance(request[field], str)
                        and MODEL_ID_RE.fullmatch(request[field]), field)
            require(isinstance(request['response_sha256'], str)
                    and HEX64.fullmatch(request['response_sha256']), 'response hash')
            require(is_index(request['output_bytes'])
                    and 0 <= request['output_bytes'] <= BYTE_COUNT_LIMIT, 'output bytes')
            require(isinstance(request['status'], str)
                    and len(request['status']) <= STRING_LIMIT, 'status')
            for field in ('input_tokens', 'output_tokens'):
                require(is_index(request[field])
                        and 0 <= request[field] <= TOKEN_LIMIT, field)
        elif kind == 'agent_action':
            require(set(request) == {'kind', 'argument_id', 'call_id', 'tool',
                                     'input_sha256', 'input_bytes'},
                    'agent_action request keys')
            self._check_call_fields(request)
            require(request['call_id'] not in self.agent_action_ids,
                    'duplicate agent action call id')
            self.agent_action_ids[request['call_id']] = (
                request['argument_id'], request['tool'])
        elif kind == 'agent_result':
            require(set(request) == {'kind', 'argument_id', 'call_id', 'tool',
                                     'content_sha256', 'content_bytes', 'excerpt'},
                    'agent_result request keys')
            self._check_call_fields(request)
            require(request['call_id'] in self.agent_action_ids
                    and request['call_id'] not in self.agent_result_ids
                    and self.agent_action_ids[request['call_id']]
                    == (request['argument_id'], request['tool']),
                    'agent result must match its preceding action')
            self.agent_result_ids.add(request['call_id'])
            require(isinstance(request['excerpt'], str)
                    and len(request['excerpt'].encode('utf-8')) <= EXCERPT_LIMIT,
                    'excerpt must fit the 1 KiB cap')
        else:
            require(kind == 'benchmark_result', 'unknown audit kind')
            require(set(request) == {'kind', 'argument_id', 'execution_id',
                                     'task_id', 'poc_sha256', 'vul_digest',
                                     'fix_digest', 'vul_class', 'fix_class',
                                     'flag_success'},
                    'benchmark_result request keys')
            require(isinstance(request['execution_id'], str)
                    and ID_RE.fullmatch(request['execution_id']),
                    'benchmark execution id')
            require(isinstance(request['task_id'], str) and request['task_id'],
                    'benchmark task id')
            require(isinstance(request['poc_sha256'], str)
                    and HEX64.fullmatch(request['poc_sha256']), 'benchmark poc hash')
            for field in ('vul_digest', 'fix_digest'):
                require(isinstance(request[field], str)
                        and re.fullmatch(r'sha256:[0-9a-f]{64}', request[field]), field)
            for field in ('vul_class', 'fix_class'):
                require(isinstance(request[field], str)
                        and len(request[field]) <= STRING_LIMIT, field)
            require(isinstance(request['flag_success'], bool), 'flag_success must be boolean')
        return {'status': 'RECORDED'}

    def _check_call_fields(self, request: dict) -> None:
        require(isinstance(request['call_id'], str) and ID_RE.fullmatch(request['call_id']),
                'invalid call id')
        require(isinstance(request['tool'], str) and request['tool'] in (
            'shell', 'probe', 'report_oob', 'report_none'), 'tool name')
        hash_field = 'input_sha256' if 'input_sha256' in request else 'content_sha256'
        size_field = 'input_bytes' if 'input_bytes' in request else 'content_bytes'
        require(isinstance(request[hash_field], str)
                and HEX64.fullmatch(request[hash_field]), hash_field)
        require(is_index(request[size_field])
                and 0 <= request[size_field] <= BYTE_COUNT_LIMIT, size_field)

    def _handle_claim(self, request: dict, request_seq: int) -> dict:
        require(set(request) == {'kind', 'argument_id', 'event', 'access_kind',
                                 'side', 'from'}, 'claim request keys')
        argument_id = request['argument_id']
        require(isinstance(argument_id, str) and ID_RE.fullmatch(argument_id),
                'invalid argument id')
        require(argument_id not in self.claims, 'duplicate claim for this argument')
        prefix = {'run_id': self.run_id, 'executions': self.executions,
                  'trace': [e for e in self.trace if e['seq'] <= request_seq]}
        freeze = cybergym_freeze if self.is_cybergym else freeze_claim
        try:
            frozen = freeze(prefix, request, seq=request_seq)
        except AdapterError as exc:
            raise ProtocolError(exc.reason, exc.diagnostic) from exc
        self.claims[argument_id] = {'claim': request, 'available_at': request_seq,
                                    'frozen': frozen}
        self.closed_arguments.add(argument_id)
        if frozen['state'] == 'bound':
            return {'status': 'RECORDED', 'claim_id': argument_id}
        if frozen['state'] != 'unsupported':
            status = 'REJECTED'
        elif self.is_cybergym and frozen.get('reason') == 'UNSUPPORTED_TRANSLATION':
            status = 'UNSUPPORTED_TRANSLATION'
        else:
            status = 'UNSUPPORTED_TRACE'
        return {'status': status, 'claim_id': argument_id, 'reason': frozen['reason']}

    # ---- bundle ----------------------------------------------------------
    def publish(self) -> int:
        if self.aborted:
            return 2
        if self.is_cybergym:
            from soundtrace_live.cybergym_backend import CaptureError
            try:
                build = self.backend.build_record()
                self.backend.validate_build(build)
            except (CaptureError, Rejected, OSError) as exc:
                print(json.dumps({'status': 'INCONCLUSIVE_SETUP',
                                  'diagnostic': getattr(exc, 'diagnostic', str(exc))}))
                return 2
            fmt, producer = CYBERGYM_FORMAT, CYBERGYM_AUTHORITY
        else:
            self.ensure_build()  # signed bundles always carry build metadata
            build, fmt, producer = self.build, BUNDLE_FORMAT, AUTHORITY
        payload = {
            'format': fmt,
            'run_id': self.run_id,
            'producer': producer,
            'build': build,
            'executions': self.executions,
            'trace': self.trace,
            'claims': self.claims,
        }
        if self.is_cybergym:
            payload['target_build'] = self.target_build
        bundle = {'payload': payload, 'hmac_sha256': mac_hex(self.key,
                                                             canonical_json(payload))}
        serialized = canonical_json(bundle) + b'\n'
        if len(serialized) > CHILD_COMBINED_BYTE_LIMIT:
            print(json.dumps({'status': 'INCONCLUSIVE_CAPTURE',
                              'diagnostic': 'serialized bundle exceeds the '
                                            '1,000,000-byte limit'}))
            return 2
        self.out_path.write_bytes(serialized)
        return 0


def _validate_request_body(body: Any, *, cybergym: bool = False) -> None:
    """Minimal structural validation of a recorded request body, so offline
    consumers (direct.py, admit_oob, the cybergym adapter) never index a
    malformed emit/reason/probe body and crash. Only a key holder can sign a
    malformed body, but the contract is still a clean REJECTED, never a
    traceback."""
    require(isinstance(body, dict) and isinstance(body.get('kind'), str),
            'request body must have a string kind')
    kind = body['kind']
    if kind == 'emit':
        keys = {'kind', 'argument_id', 'id', 'steps'}
        if cybergym:
            keys |= {'attempt_id', 'source_seq'}
        require(set(body) == keys, 'emit body keys')
        require(isinstance(body['id'], str) and ID_RE.fullmatch(body['id']), 'emit id')
        require(isinstance(body['steps'], list) and body['steps'], 'emit steps')
        for step in body['steps']:
            require(isinstance(step, dict)
                    and step.get('op') in ('observe', 'compute', 'infer'),
                    'emit step shape')
            if step.get('op') == 'infer':
                require(set(step) == {'op', 'rule', 'premises', 'formula'},
                        'infer step keys')
                require(isinstance(step['rule'], str)
                        and step['rule'] in RULE_LEAN,
                        'unknown inference rule')
        if cybergym:
            require(isinstance(body['attempt_id'], str)
                    and ID_RE.fullmatch(body['attempt_id']), 'emit attempt id')
            require(is_index(body['source_seq']) and body['source_seq'] >= 1,
                    'emit source_seq')
    elif kind == 'reason':
        require(not cybergym, 'reason bodies are fixture-only')
        require(set(body) == {'kind', 'argument_id', 'node'}, 'reason body keys')
        require(isinstance(body['node'], dict), 'reason node')
    elif kind == 'narrate':
        require(set(body) == {'kind', 'argument_id', 'text'}, 'narrate body keys')
        require(isinstance(body['text'], str), 'narrate text')
    elif kind == 'run':
        require(not cybergym, 'run bodies are fixture-only')
    elif kind == 'probe':
        require(cybergym, 'probe bodies are cybergym-only')
        require(set(body) == {'kind', 'task_id', 'poc_sha256', 'poc_size'},
                'probe body keys')
        require(isinstance(body['task_id'], str) and body['task_id'],
                'probe task id')
        require(isinstance(body['poc_sha256'], str)
                and HEX64.fullmatch(body['poc_sha256']), 'probe poc hash')
        require(is_index(body['poc_size'])
                and 0 < body['poc_size'] <= POC_LIMIT_BYTES,
                'probe poc size')
    elif kind == 'claim':
        require(set(body) == {'kind', 'argument_id', 'event', 'access_kind',
                              'side', 'from'}, 'claim body keys')
    elif kind == 'translation_attempt':
        require(cybergym, 'translation bodies are cybergym-only')
        require(set(body) == {'kind', 'argument_id', 'attempt_id', 'source_seq',
                              'model', 'resolved_model', 'raw_output_sha256',
                              'raw_output_bytes', 'parsed_sha256', 'outcome',
                              'repair'}, 'translation_attempt body keys')
        require(isinstance(body['attempt_id'], str)
                and ID_RE.fullmatch(body['attempt_id']), 'attempt id')
        require(body['outcome'] in ATTEMPT_OUTCOMES, 'attempt outcome')
    elif kind == 'translation_abstain':
        require(cybergym, 'translation bodies are cybergym-only')
        require(set(body) == {'kind', 'argument_id', 'abstain_id', 'source_seq',
                              'reason', 'diagnostic'}, 'translation_abstain body keys')
        require(isinstance(body['abstain_id'], str)
                and ID_RE.fullmatch(body['abstain_id']), 'abstain id')
        require(body['reason'] in ABSTAIN_REASONS, 'abstain reason')
    elif kind in AUDIT_KINDS:
        require(cybergym, 'audit bodies are cybergym-only')
        require(isinstance(body.get('argument_id'), str)
                and ID_RE.fullmatch(body['argument_id']),
                'audit argument id')
        if kind == 'model_session':
            session_core = {'kind', 'argument_id', 'session_sha256',
                            'difficulty', 'target_model', 'translator_model',
                            'prompt_sha256', 'input_sha256'}
            require(session_core <= set(body) <= session_core
                    | {'target_provider', 'translator_provider'},
                    'model session keys')
            for field in ('target_provider', 'translator_provider'):
                if field in body:
                    require(isinstance(body[field], str)
                            and PROVIDER_ID_RE.fullmatch(body[field]),
                            f'{field} format')
            for field in ('session_sha256', 'prompt_sha256', 'input_sha256'):
                require(isinstance(body[field], str) and HEX64.fullmatch(body[field]),
                        f'{field} format')
            require(body['difficulty'] in ('level0', 'level1'),
                    'model session difficulty')
            for field in ('target_model', 'translator_model'):
                require(isinstance(body[field], str)
                        and MODEL_ID_RE.fullmatch(body[field]), f'{field} format')
        elif kind == 'model_turn':
            turn_core = {'kind', 'argument_id', 'turn', 'role',
                         'requested_model', 'resolved_model',
                         'response_sha256', 'output_bytes', 'status',
                         'input_tokens', 'output_tokens'}
            require(turn_core <= set(body) <= turn_core | {'provider'},
                    'model turn keys')
            if 'provider' in body:
                require(isinstance(body['provider'], str)
                        and PROVIDER_ID_RE.fullmatch(body['provider']),
                        'provider format')
            require(is_index(body['turn']) and 0 <= body['turn'] < TURN_LIMIT,
                    'model turn index')
            require(body['role'] in ('target', 'translator'), 'model turn role')
            require(isinstance(body['status'], str)
                    and len(body['status']) <= STRING_LIMIT,
                    'model turn status')
            for field in ('requested_model', 'resolved_model'):
                require(isinstance(body[field], str)
                        and MODEL_ID_RE.fullmatch(body[field]), f'{field} format')
            require(isinstance(body['response_sha256'], str)
                    and HEX64.fullmatch(body['response_sha256']),
                    'model turn response hash')
            require(is_index(body['output_bytes'])
                    and 0 <= body['output_bytes'] <= BYTE_COUNT_LIMIT,
                    'model turn output bytes')
            for field in ('input_tokens', 'output_tokens'):
                require(is_index(body[field])
                        and 0 <= body[field] <= TOKEN_LIMIT,
                        f'{field} format')
        elif kind == 'agent_action':
            require(set(body) == {'kind', 'argument_id', 'call_id', 'tool',
                                   'input_sha256', 'input_bytes'},
                    'agent action keys')
            require(isinstance(body['call_id'], str)
                    and ID_RE.fullmatch(body['call_id'])
                    and isinstance(body['tool'], str)
                    and body['tool'] in ('shell', 'probe', 'report_oob',
                                         'report_none')
                    and isinstance(body['input_sha256'], str)
                    and HEX64.fullmatch(body['input_sha256'])
                    and is_index(body['input_bytes'])
                    and 0 <= body['input_bytes'] <= BYTE_COUNT_LIMIT,
                    'agent action fields')
        elif kind == 'agent_result':
            require(set(body) == {'kind', 'argument_id', 'call_id', 'tool',
                                   'content_sha256', 'content_bytes', 'excerpt'},
                    'agent result keys')
            require(isinstance(body['call_id'], str)
                    and ID_RE.fullmatch(body['call_id'])
                    and isinstance(body['tool'], str)
                    and body['tool'] in ('shell', 'probe', 'report_oob',
                                         'report_none')
                    and isinstance(body['content_sha256'], str)
                    and HEX64.fullmatch(body['content_sha256'])
                    and is_index(body['content_bytes'])
                    and 0 <= body['content_bytes'] <= BYTE_COUNT_LIMIT
                    and isinstance(body['excerpt'], str)
                    and len(body['excerpt'].encode('utf-8')) <= EXCERPT_LIMIT,
                    'agent result fields')
        else:
            require(kind == 'benchmark_result'
                    and set(body) == {'kind', 'argument_id', 'execution_id',
                                       'task_id', 'poc_sha256', 'vul_digest',
                                       'fix_digest', 'vul_class', 'fix_class',
                                       'flag_success'},
                    'benchmark result keys')
            require(isinstance(body['execution_id'], str)
                    and ID_RE.fullmatch(body['execution_id'])
                    and isinstance(body['task_id'], str) and body['task_id']
                    and isinstance(body['poc_sha256'], str)
                    and HEX64.fullmatch(body['poc_sha256'])
                    and isinstance(body['vul_digest'], str)
                    and re.fullmatch(r'sha256:[0-9a-f]{64}', body['vul_digest'])
                    and isinstance(body['fix_digest'], str)
                    and re.fullmatch(r'sha256:[0-9a-f]{64}', body['fix_digest'])
                    and isinstance(body['vul_class'], str)
                    and len(body['vul_class']) <= STRING_LIMIT
                    and isinstance(body['fix_class'], str)
                    and len(body['fix_class']) <= STRING_LIMIT
                    and isinstance(body['flag_success'], bool),
                    'benchmark result fields')
    else:
        raise Rejected(f'unknown request kind {kind!r}')
    # Response bodies are validated where consumed.


def _validate_cybergym_response(body: Any, request: dict) -> None:
    require(isinstance(body, dict), 'response body must be an object')
    status = body.get('status')
    require(isinstance(status, str), 'response status')
    if status == 'REJECTED' and request.get('kind') == 'claim':
        require(set(body) == {'status', 'claim_id', 'reason'},
                'claim rejection response keys')
        require(isinstance(body['claim_id'], str)
                and isinstance(body['reason'], str),
                'claim rejection response fields')
        return
    if status in ('REJECTED', 'INCONCLUSIVE_SETUP'):
        require(set(body) == {'status', 'reason', 'diagnostic'},
                'protocol failure response keys')
        require(isinstance(body['reason'], str)
                and isinstance(body['diagnostic'], str),
                'protocol failure response fields')
        return
    if status == 'INCONCLUSIVE_CAPTURE':
        require(set(body) == {'status', 'diagnostic'},
                'capture response keys')
        require(isinstance(body['diagnostic'], str), 'capture diagnostic')
        return
    kind = request['kind']
    if kind == 'probe':
        require(status == 'RECORDED'
                and set(body) in (
                    {'status', 'execution_id', 'event_id',
                     'poc_sha256', 'observations'},
                    {'status', 'execution_id', 'event_id', 'access_kind',
                     'poc_sha256', 'observations'}),
                'probe response keys')
        require(isinstance(body['execution_id'], str)
                and ID_RE.fullmatch(body['execution_id'])
                and (body['event_id'] is None or isinstance(body['event_id'], str)),
                'probe response ids')
        if 'access_kind' in body:
            require(body['access_kind'] in (None, 'read', 'write'),
                    'probe response access kind')
        require(isinstance(body['poc_sha256'], str)
                and HEX64.fullmatch(body['poc_sha256'])
                and body['poc_sha256'] == request['poc_sha256'],
                'probe response PoC hash differs from request')
        require(isinstance(body['observations'], list),
                'probe observations')
        for observation in body['observations']:
            require(isinstance(observation, dict)
                    and set(observation) == {'id', 'formula', 'scope',
                                             'available_at'},
                    'observation response keys')
    elif kind == 'narrate':
        require(status == 'RECORDED'
                and set(body) == {'status', 'argument_id', 'seq'},
                'narrate response keys')
    elif kind == 'emit':
        require(status == 'RECORDED'
                and set(body) == {'status', 'argument_id', 'emission_id',
                                   'steps', 'source_seq'},
                'emit response keys')
    elif kind == 'claim':
        require(status in ('RECORDED', 'UNSUPPORTED_TRANSLATION',
                           'UNSUPPORTED_TRACE', 'REJECTED')
                and set(body) == ({'status', 'claim_id'}
                                   if status == 'RECORDED'
                                   else {'status', 'claim_id', 'reason'}),
                'claim response keys')
    elif kind == 'translation_attempt':
        require(status == 'RECORDED'
                and set(body) == {'status', 'attempt_id'},
                'translation attempt response keys')
    elif kind == 'translation_abstain':
        require(status == 'RECORDED'
                and set(body) == {'status', 'abstain_id'},
                'translation abstention response keys')
    elif kind in AUDIT_KINDS:
        require(status == 'RECORDED' and set(body) == {'status'},
                'audit response keys')
    else:
        raise Rejected('unknown CyberGym response request kind')

def validate_bundle(bundle: Any) -> dict:
    """Strict structural validation of a signed bundle (no MAC check here).

    Dispatch is exact per format: a `soundtrace-run-v1` bundle must match the
    fixture schemas, a `soundtrace-cybergym-run-v1` bundle the CyberGym ones.
    There is deliberately no permissive union across producers.
    """
    require(isinstance(bundle, dict), 'bundle must be an object')
    require(set(bundle) == {'payload', 'hmac_sha256'}, 'bundle keys')
    require(isinstance(bundle['hmac_sha256'], str)
            and re.fullmatch(r'[0-9a-f]{64}', bundle['hmac_sha256']), 'bundle MAC format')
    payload = bundle['payload']
    require(isinstance(payload, dict), 'payload must be an object')
    require('format' in payload and isinstance(payload['format'], str),
            'payload must carry a string format')
    _base_keys = {'format', 'run_id', 'producer', 'build', 'executions',
                  'trace', 'claims'}
    if payload['format'] == CYBERGYM_FORMAT:
        require(set(payload) == _base_keys | {'target_build'}, 'payload keys')
        require(payload['producer'] == CYBERGYM_AUTHORITY, 'bundle producer')
        require(payload['target_build'] in ('vul', 'fix'),
                'payload target_build must be vul or fix')
        return _validate_cybergym_bundle(bundle, payload)
    require(set(payload) == _base_keys, 'payload keys')
    require(payload['format'] == BUNDLE_FORMAT, 'bundle format')
    require(payload['producer'] == AUTHORITY, 'bundle producer')
    require(isinstance(payload['run_id'], str)
            and re.fullmatch(r'R[0-9a-f]{32}', payload['run_id']), 'run id format')
    build = payload['build']
    require(isinstance(build, dict) and set(build) == {'source_sha256', 'binary_sha256',
                                                       'compiler_version', 'flags'},
            'build keys')
    for field in ('source_sha256', 'binary_sha256'):
        require(isinstance(build[field], str)
                and re.fullmatch(r'[0-9a-f]{64}', build[field]), f'{field} format')
    require(isinstance(build['compiler_version'], str), 'compiler version')
    require(isinstance(build['flags'], list)
            and all(isinstance(f, str) for f in build['flags']), 'build flags')
    executions = payload['executions']
    require(isinstance(executions, list), 'executions must be a list')
    seen_ids = set()
    for execution in executions:
        require(isinstance(execution, dict), 'execution must be an object')
        require(set(execution) == {'id', 'case', 'pid', 'pointer_bits', 'asan_options',
                                   'exit_code', 'events', 'stderr'}, 'execution keys')
        require(isinstance(execution['id'], str)
                and re.fullmatch(r'X[0-9]+', execution['id']), 'execution id format')
        require(execution['id'] not in seen_ids, 'duplicate execution id')
        seen_ids.add(execution['id'])
        require(isinstance(execution['case'], str), 'execution case')
        require(is_index(execution['pid']) and is_index(execution['pointer_bits'])
                and is_index(execution['exit_code']), 'execution numeric fields')
        require(execution['asan_options'] == CANONICAL_ASAN_OPTIONS,
                'execution sanitizer options mismatch')
        require(isinstance(execution['stderr'], str), 'execution stderr')
        validate_events(execution['events'])
    trace = payload['trace']
    require(isinstance(trace, list) and trace, 'trace must be a nonempty list')
    require(len(trace) <= TRACE_FRAME_LIMIT, 'parent trace frame limit')
    request_seqs = set()
    for i, entry in enumerate(trace):
        require(isinstance(entry, dict), 'trace entry must be an object')
        require(set(entry) == {'seq', 'kind', 'body'}
                or set(entry) == {'seq', 'kind', 'request_seq', 'body'}, 'trace entry keys')
        require(is_index(entry['seq']) and entry['seq'] == i + 1,
                'trace sequence positions must be consecutive from 1')
        if entry['kind'] == 'request':
            require(set(entry) == {'seq', 'kind', 'body'}, 'request entry keys')
            request_seqs.add(entry['seq'])
            _validate_request_body(entry['body'])
        elif entry['kind'] == 'response':
            require(set(entry) == {'seq', 'kind', 'request_seq', 'body'}, 'response entry keys')
            require(entry['request_seq'] in request_seqs,
                    'response refers to an unknown or later request')
        else:
            raise Rejected('unknown trace entry kind')
        require(isinstance(entry['body'], dict), 'trace body must be an object')
    claims = payload['claims']
    require(isinstance(claims, dict), 'claims must be an object')
    for argument_id, entry in claims.items():
        require(isinstance(argument_id, str) and ID_RE.fullmatch(argument_id),
                'argument id format')
        require(isinstance(entry, dict)
                and set(entry) == {'claim', 'available_at', 'frozen'}, 'claim record keys')
        require(is_index(entry['available_at']) and entry['available_at'] >= 1,
                'claim available_at')
        frozen = entry['frozen']
        require(isinstance(frozen, dict), 'frozen outcome must be an object')
        if frozen.get('state') == 'bound':
            require(set(frozen) == {'state', 'scope', 'binding', 'formula'},
                    'bound outcome keys')
            binding = frozen['binding']
            require(isinstance(binding, dict)
                    and set(binding) == {'execution_id', 'allocation_id', 'generation',
                                         'event_id', 'access_kind'}, 'binding keys')
            require(binding['execution_id'] in seen_ids, 'binding names an unknown execution')
        elif frozen.get('state') in ('unsupported', 'rejected'):
            require(set(frozen) == {'state', 'reason', 'diagnostic'},
                    'unsuccessful outcome keys')
            require(isinstance(frozen['reason'], str), 'outcome reason')
        else:
            raise Rejected('invalid frozen claim state')
    return bundle


def _validate_cybergym_bundle(bundle: dict, payload: dict) -> dict:
    """Exact schemas for `soundtrace-cybergym-run-v1` bundles."""
    target_build = payload['target_build']
    require(isinstance(payload['run_id'], str)
            and re.fullmatch(r'R[0-9a-f]{32}', payload['run_id']), 'run id format')
    build = payload['build']
    require(isinstance(build, dict) and set(build) == BUILD_KEYS, 'cybergym build keys')
    for field in ('corpus_sha256', 'lock_sha256', 'probe_source_sha256',
                  'probe_dso_sha256'):
        require(isinstance(build[field], str)
                and re.fullmatch(r'[0-9a-f]{64}', build[field]), f'{field} format')
    for field in ('docker_version', 'docker_platform'):
        require(isinstance(build[field], str) and build[field], f'{field} format')
    require(isinstance(build['agent_image_digest'], str)
            and re.fullmatch(r'sha256:[0-9a-f]{64}', build['agent_image_digest']),
            'agent image digest format')
    tasks = build['tasks']
    require(isinstance(tasks, dict) and tasks, 'build tasks must be a nonempty object')
    for task_id, entry in tasks.items():
        require(isinstance(task_id, str) and task_id, 'build task id')
        require(isinstance(entry, dict)
                and set(entry) == {'kind', 'project', 'vul_ref', 'vul_digest',
                                   'fix_ref', 'fix_digest', 'command_vul',
                                   'archive_sha256', 'description_sha256'},
                'build task keys')
        require(isinstance(entry['kind'], str) and entry['kind'], 'task kind')
        require(isinstance(entry['project'], str), 'task project')
        for field in ('vul_ref', 'fix_ref'):
            require(isinstance(entry[field], str) and entry[field], f'task {field}')
        for field in ('vul_digest', 'fix_digest'):
            require(isinstance(entry[field], str)
                    and re.fullmatch(r'sha256:[0-9a-f]{64}', entry[field]),
                    f'task {field}')
        require(isinstance(entry['command_vul'], list)
                and entry['command_vul']
                and all(isinstance(part, str) and part
                        for part in entry['command_vul']),
                'task command_vul')
        for field in ('archive_sha256', 'description_sha256'):
            require(isinstance(entry[field], str)
                    and re.fullmatch(r'[0-9a-f]{64}', entry[field]),
                    f'task {field}')
    executions = payload['executions']
    require(isinstance(executions, list), 'executions must be a list')
    seen_ids = set()
    for execution in executions:
        require(isinstance(execution, dict), 'execution must be an object')
        require(set(execution) == set(EXECUTION_KEYS), 'execution keys')
        cybergym_validate_execution(execution)
        require(execution['id'] not in seen_ids, 'duplicate execution id')
        seen_ids.add(execution['id'])
        task_entry = tasks.get(execution['task_id'])
        require(task_entry is not None, 'execution names a task outside the build')
        cybergym_validate_execution(execution, task_entry, build=target_build)
        require(execution['image_digest'] == task_entry[
            'vul_digest' if target_build == 'vul' else 'fix_digest'],
                'execution image digest differs from the pinned build digest')
    execution_by_id = {execution['id']: execution for execution in executions}
    trace = payload['trace']
    require(isinstance(trace, list) and trace, 'trace must be a nonempty list')
    require(len(trace) <= CYBERGYM_TRACE_FRAME_LIMIT,
            'parent trace frame limit')
    request_seqs = set()
    requests: dict[int, dict] = {}
    for i, entry in enumerate(trace):
        require(isinstance(entry, dict), 'trace entry must be an object')
        require(set(entry) == {'seq', 'kind', 'body'}
                or set(entry) == {'seq', 'kind', 'request_seq', 'body'}, 'trace entry keys')
        require(is_index(entry['seq']) and entry['seq'] == i + 1,
                'trace sequence positions must be consecutive from 1')
        if entry['kind'] == 'request':
            require(set(entry) == {'seq', 'kind', 'body'}, 'request entry keys')
            request_seqs.add(entry['seq'])
            require(isinstance(entry['body'], dict), 'request body must be an object')
            requests[entry['seq']] = entry['body']
            _validate_request_body(entry['body'], cybergym=True)
            if entry['body'].get('kind') == 'benchmark_result':
                benchmark = entry['body']
                task_entry = tasks.get(benchmark['task_id'])
                require(task_entry is not None,
                        'benchmark names a task outside the build')
                require(benchmark['vul_digest'] == task_entry['vul_digest']
                        and benchmark['fix_digest'] == task_entry['fix_digest'],
                        'benchmark image digest is not pinned to its task')
                execution = execution_by_id.get(benchmark['execution_id'])
                require(execution is not None
                        and execution['task_id'] == benchmark['task_id']
                        and execution['poc_sha256'] == benchmark['poc_sha256'],
                        'benchmark is not bound to its recorded execution')
        elif entry['kind'] == 'response':
            require(set(entry) == {'seq', 'kind', 'request_seq', 'body'}, 'response entry keys')
            require(entry['request_seq'] in request_seqs,
                    'response refers to an unknown or later request')
            _validate_cybergym_response(entry['body'], requests[entry['request_seq']])
            if (requests[entry['request_seq']]['kind'] == 'probe'
                    and entry['body'].get('status') == 'RECORDED'):
                request = requests[entry['request_seq']]
                execution = execution_by_id.get(entry['body']['execution_id'])
                require(execution is not None,
                        'probe response names an unknown execution')
                expected_event = (execution['events'][0]['event_id']
                                  if execution['events'] else None)
                require(execution['task_id'] == request['task_id']
                        and execution['poc_sha256'] == request['poc_sha256']
                        and execution['poc_size'] == request['poc_size']
                        and entry['body']['event_id'] == expected_event,
                        'probe response is not bound to its execution request')
        else:
            raise Rejected('unknown trace entry kind')
    claims = payload['claims']
    require(isinstance(claims, dict), 'claims must be an object')
    for argument_id, entry in claims.items():
        require(isinstance(argument_id, str) and ID_RE.fullmatch(argument_id),
                'argument id format')
        require(isinstance(entry, dict)
                and set(entry) == {'claim', 'available_at', 'frozen'}, 'claim record keys')
        require(is_index(entry['available_at']) and entry['available_at'] >= 1,
                'claim available_at')
        frozen = entry['frozen']
        require(isinstance(frozen, dict), 'frozen outcome must be an object')
        if frozen.get('state') == 'bound':
            require(set(frozen) == {'state', 'scope', 'binding', 'formula'},
                    'bound outcome keys')
            binding = frozen['binding']
            require(isinstance(binding, dict)
                    and set(binding) == {'execution_id', 'allocation_id', 'generation',
                                         'event_id', 'access_kind', 'task_id',
                                         'poc_sha256', 'image_digest'},
                    'cybergym binding keys')
            require(binding['execution_id'] in seen_ids,
                    'binding names an unknown execution')
            execution = next(e for e in executions if e['id'] == binding['execution_id'])
            require(binding['task_id'] == execution['task_id']
                    and binding['poc_sha256'] == execution['poc_sha256']
                    and binding['image_digest'] == execution['image_digest'],
                    'binding does not match the recorded execution')
        elif frozen.get('state') in ('unsupported', 'rejected'):
            require(set(frozen) == {'state', 'reason', 'diagnostic'},
                    'unsuccessful outcome keys')
            require(isinstance(frozen['reason'], str), 'outcome reason')
        else:
            raise Rejected('invalid frozen claim state')
    return bundle


def keygen(out_path: Path) -> int:
    require(not out_path.exists(), 'refusing to overwrite an existing key')
    fd = os.open(out_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, os.urandom(KEY_SIZE))
    finally:
        os.close(fd)
    print(json.dumps({'status': 'KEY_CREATED', 'key': str(out_path)}, indent=2))
    return 0


def record(key_path: Path, out_path: Path, *, backend_name: str = 'fixture',
           corpus_path: Path | None = None, work_dir: Path | None = None,
           artifacts_dir: Path | None = None, target_build: str = 'vul') -> int:
    key = key_path.read_bytes()
    require(len(key) == KEY_SIZE, 'runner key must be 32 bytes')
    require(target_build in ('vul', 'fix'), 'build must be vul or fix')
    backend = None
    if backend_name == 'cybergym':
        require(corpus_path is not None, 'cybergym recording requires --corpus')
        from soundtrace_live.corpus import CorpusError, load_corpus
        from soundtrace_live.cybergym_backend import CybergymBackend
        try:
            corpus = load_corpus(corpus_path)
        except CorpusError as exc:
            print(json.dumps({'status': 'REJECTED', 'reason': 'BAD_INPUT',
                              'diagnostic': exc.diagnostic}))
            return 1
        if work_dir is None:
            work_dir = (artifacts_dir or out_path.parent).resolve().parent
        backend = CybergymBackend(corpus, work_dir, artifacts_dir=artifacts_dir)
    elif backend_name != 'fixture':
        raise Rejected(f'unknown backend {backend_name!r}')
    session = _Session(key, out_path, backend=backend,
                       target_build=target_build)
    status = 0
    while True:
        raw = sys.stdin.buffer.readline(LINE_BYTE_LIMIT + 1)  # bounded before decoding
        if not raw:
            break
        if len(raw) > LINE_BYTE_LIMIT and not (len(raw) == LINE_BYTE_LIMIT + 1
                                               and raw.endswith(b'\n')):
            session.emit({'status': 'REJECTED', 'reason': 'BAD_INPUT',
                          'diagnostic': 'request line limit'})
            session.aborted = True
            return 1
        try:
            text = raw.decode('utf-8').strip()
        except UnicodeDecodeError:
            session.emit({'status': 'REJECTED', 'reason': 'BAD_INPUT',
                          'diagnostic': 'request is not valid UTF-8'})
            session.aborted = True
            return 1
        if not text:
            continue
        try:
            request = parse_json(text)
        except Rejected as exc:
            session.emit({'status': 'REJECTED', 'reason': 'BAD_INPUT',
                          'diagnostic': str(exc)})
            session.aborted = True
            return 1
        status = session.dispatch(request)
        if status != 0:
            return status
    return session.publish()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    keygen_parser = sub.add_parser('keygen')
    keygen_parser.add_argument('--out', required=True, type=Path)
    record_parser = sub.add_parser('record')
    record_parser.add_argument('--backend', choices=('fixture', 'cybergym'),
                               default='fixture')
    record_parser.add_argument('--key', required=True, type=Path)
    record_parser.add_argument('--out', required=True, type=Path)
    record_parser.add_argument('--corpus', type=Path)
    record_parser.add_argument('--work-dir', type=Path)
    record_parser.add_argument('--artifacts', type=Path)
    record_parser.add_argument('--build', choices=('vul', 'fix'),
                               default='vul')
    args = parser.parse_args()
    try:
        if args.command == 'keygen':
            return keygen(args.out)
        return record(args.key, args.out, backend_name=args.backend,
                      corpus_path=args.corpus, work_dir=args.work_dir,
                      artifacts_dir=args.artifacts, target_build=args.build)
    except ProtocolError as exc:
        print(json.dumps({'status': 'REJECTED', 'reason': exc.reason,
                          'diagnostic': exc.diagnostic}), file=sys.stderr)
        return 1
    except (Rejected, OSError) as exc:
        print(json.dumps({'status': 'REJECTED', 'reason': 'BAD_INPUT',
                          'diagnostic': str(exc)}), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
