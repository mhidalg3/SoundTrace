#!/usr/bin/env python3
"""Runner-owned capture boundary for controlled C executions.

The runner accepts only enumerated cases from a fixed, reviewed fixture; it
never accepts a source path, executable, shell command, compiler flags, or
environment overrides from the agent. Requests are dispatched serially, one
sequence position is assigned per dispatch/delivery, and the complete ordered
log is authenticated with an external HMAC key that never enters the child
environment, the bundle, the proof, or the logs.

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
from frontend import ID_RE, is_index
from oob_adapter import (AUTHORITY, CANONICAL_ASAN_OPTIONS, AdapterError,
                         freeze_claim, observations_for_execution,
                         validate_events)
BUNDLE_FORMAT = 'soundtrace-run-v1'
KEY_SIZE = 32
CHILD_TIMEOUT = 10.0
CHILD_COMBINED_BYTE_LIMIT = 1_000_000
LINE_BYTE_LIMIT = 100_000
TRACE_FRAME_LIMIT = 1000
EVENT_FD = 3
BUILD_FLAGS = ['-std=c11', '-O0', '-g', '-fsanitize=address',
               '-fno-omit-frame-pointer', '-fno-optimize-sibling-calls']
ENV_DENYLIST = {'ASAN_OPTIONS', 'LSAN_OPTIONS', 'LD_PRELOAD', 'DYLD_INSERT_LIBRARIES',
                'CC', 'CXX', 'CFLAGS', 'CXXFLAGS', 'CPATH', 'C_INCLUDE_PATH',
                'LIBRARY_PATH', 'MACOSX_DEPLOYMENT_TARGET'}
NODE_KINDS = ('observe', 'calculate', 'compare', 'conjoin', 'infer')


class ProtocolError(Exception):
    def __init__(self, reason: str, diagnostic: str = ''):
        super().__init__(diagnostic or reason)
        self.reason = reason
        self.diagnostic = diagnostic or reason


class _Session:
    def __init__(self, key: bytes, out_path: Path):
        self.key = key
        self.out_path = out_path
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

    # ---- ordered log -----------------------------------------------------
    def next_seq(self) -> int:
        self.seq += 1
        require(self.seq <= TRACE_FRAME_LIMIT, 'parent trace frame limit')
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
            self.aborted = True
            return 2
        return 0

    def _handle(self, request: Any, request_seq: int, response_seq: int) -> dict:
        require(isinstance(request, dict), 'request must be an object')
        kind = request.get('kind')
        if kind == 'run':
            return self._handle_run(request, response_seq)
        if kind == 'reason':
            return self._handle_reason(request, request_seq)
        if kind == 'claim':
            return self._handle_claim(request, request_seq)
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

    def _handle_claim(self, request: dict, request_seq: int) -> dict:
        require(set(request) == {'kind', 'argument_id', 'event', 'access_kind',
                                 'side', 'from'}, 'claim request keys')
        argument_id = request['argument_id']
        require(isinstance(argument_id, str) and ID_RE.fullmatch(argument_id),
                'invalid argument id')
        require(argument_id not in self.claims, 'duplicate claim for this argument')
        prefix = {'run_id': self.run_id, 'executions': self.executions,
                  'trace': [e for e in self.trace if e['seq'] <= request_seq]}
        try:
            frozen = freeze_claim(prefix, request, seq=request_seq)
        except AdapterError as exc:
            raise ProtocolError(exc.reason, exc.diagnostic) from exc
        self.claims[argument_id] = {'claim': request, 'available_at': request_seq,
                                    'frozen': frozen}
        self.closed_arguments.add(argument_id)
        if frozen['state'] == 'bound':
            return {'status': 'RECORDED', 'claim_id': argument_id}
        return {'status': ('UNSUPPORTED_TRACE' if frozen['state'] == 'unsupported'
                           else 'REJECTED'),
                'claim_id': argument_id, 'reason': frozen['reason']}

    # ---- bundle ----------------------------------------------------------
    def publish(self) -> int:
        if self.aborted:
            return 2
        self.ensure_build()  # signed bundles always carry build metadata
        payload = {
            'format': BUNDLE_FORMAT,
            'run_id': self.run_id,
            'producer': AUTHORITY,
            'build': self.build,
            'executions': self.executions,
            'trace': self.trace,
            'claims': self.claims,
        }
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


def validate_bundle(bundle: Any) -> dict:
    """Strict structural validation of a signed bundle (no MAC check here)."""
    require(isinstance(bundle, dict), 'bundle must be an object')
    require(set(bundle) == {'payload', 'hmac_sha256'}, 'bundle keys')
    require(isinstance(bundle['hmac_sha256'], str)
            and re.fullmatch(r'[0-9a-f]{64}', bundle['hmac_sha256']), 'bundle MAC format')
    payload = bundle['payload']
    require(isinstance(payload, dict), 'payload must be an object')
    require(set(payload) == {'format', 'run_id', 'producer', 'build', 'executions',
                             'trace', 'claims'}, 'payload keys')
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


def keygen(out_path: Path) -> int:
    require(not out_path.exists(), 'refusing to overwrite an existing key')
    fd = os.open(out_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, os.urandom(KEY_SIZE))
    finally:
        os.close(fd)
    print(json.dumps({'status': 'KEY_CREATED', 'key': str(out_path)}, indent=2))
    return 0


def record(key_path: Path, out_path: Path) -> int:
    key = key_path.read_bytes()
    require(len(key) == KEY_SIZE, 'runner key must be 32 bytes')
    session = _Session(key, out_path)
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
    record_parser.add_argument('--key', required=True, type=Path)
    record_parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.command == 'keygen':
            return keygen(args.out)
        return record(args.key, args.out)
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
