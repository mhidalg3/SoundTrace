"""Focused tests for the trusted CyberGym capture backend.

All Docker interaction goes through a fake `docker` executable driven by a
JSON control file: it logs its argv, writes shim-style `events.jsonl` lines
into the host-side events mount, and replays configured exit codes / OOM /
hangs / oversized output. No Docker, network, or models are required, and
every malformed untrusted value must surface as a structured Rejected /
CaptureError — never a traceback.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from io import BytesIO
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from evidence import Rejected, canonical_json, mac_hex                         # noqa: E402
from soundtrace_live.corpus import (CORPUS_SCHEMA, CYBERGYM_CODE_REVISION,  # noqa: E402
                                    CYBERGYM_DATA_REMOTE, Corpus, ImageSpec,
                                    TaskSpec)
from soundtrace_live import cybergym_backend as cb                        # noqa: E402
from soundtrace_live.cybergym_backend import (CybergymBackend, CaptureError,  # noqa: E402
                                              extract_repo_archive)

D1 = 'a' * 64
D2 = 'b' * 64
D3 = 'c' * 64
D4 = 'd' * 64

FAKE_DOCKER = r'''#!/usr/bin/env python3
import json, os, sys, time
from pathlib import Path
argv = sys.argv[1:]
ctl = json.loads(open(os.environ['FAKE_DOCKER_CONTROL']).read())
with open(os.environ['FAKE_DOCKER_LOG'], 'a') as f:
    f.write(json.dumps(argv) + '\n')
cmd = argv[0] if argv else ''
if cmd == 'version':
    fmt = argv[argv.index('--format') + 1] if '--format' in argv else ''
    if 'Server.Version' in fmt:
        print(ctl.get('docker_version', '28.4.0'))
    else:
        print(ctl.get('docker_platform', 'linux/amd64'))
elif cmd == 'create':
    if ctl.get('create_fail'):
        sys.exit(1)
    state_path = os.environ['FAKE_DOCKER_LOG'] + '.state'
    states = {}
    if os.path.exists(state_path):
        states = json.loads(open(state_path).read())
    image = next((a for a in argv if '@sha256:' in a), '')
    fixed = ctl.get('fixed_exit_code') is not None and '-fix@sha256:' in image
    states['fake-cid-0123'] = {
        'exit_code': (ctl.get('fixed_exit_code') if fixed
                      else ctl.get('exit_code', 1)),
        'oom': bool(ctl.get('oom', False)),
    }
    with open(state_path, 'w') as f:
        json.dump(states, f)
    if ctl.get('events') is not None and not fixed:
        for arg in argv:
            if arg.startswith('type=bind,src=') and arg.endswith(',dst=/soundtrace'):
                host = arg.split('src=', 1)[1].split(',dst=', 1)[0]
                text = ctl['events']
                if ctl.get('events_big'):
                    text = 'a' * 70000
                with open(os.path.join(host, 'events.jsonl'), 'w') as f:
                    f.write(text)
    print('fake-cid-0123')
elif cmd == 'start':
    if ctl.get('hang'):
        time.sleep(60)
    out = ctl.get('stdout', '')
    if ctl.get('stdout_size'):
        out = 'x' * ctl['stdout_size']
    err = ctl.get('stderr', '')
    sys.stdout.write(out)
    sys.stderr.write(err)
    sys.exit(ctl.get('start_rc', 0))
elif cmd == 'inspect':
    state_path = os.environ['FAKE_DOCKER_LOG'] + '.state'
    states = {}
    if os.path.exists(state_path):
        states = json.loads(open(state_path).read())
    state = states.get(argv[1], {'exit_code': ctl.get('exit_code', 1),
                                 'oom': bool(ctl.get('oom', False))})
    print(json.dumps([{'State': {'ExitCode': state['exit_code'],
                                  'OOMKilled': bool(state['oom'])}}]))
elif cmd in ('rm', 'kill'):
    sys.exit(0)
elif cmd == 'pull':
    sys.exit(ctl.get('pull_rc', 0))
elif cmd == 'image':
    # docker image inspect <ref> [--format ...]
    if '--format' in argv and argv[argv.index('--format') + 1] == '{{.Id}}':
        print(ctl.get('agent_digest', 'sha256:' + 'e' * 64))
        sys.exit(0)
    ref = argv[2] if '@' in argv[2] else argv[-1]
    digest = ctl.get('inspect_digest') or ref.split('@')[1]
    repo = ref.split('@')[0]
    print(json.dumps([{'RepoDigests': [repo + '@' + digest],
                       'Os': 'linux', 'Architecture': 'amd64'}]))
elif cmd == 'build':
    sys.exit(ctl.get('build_rc', 0))
elif cmd == 'run':
    if 'dpkg-query' in argv:
        print('bash=5.2\nclang=19\n')
    elif 'clang' in argv:
        mounts = {}
        for i in range(1, len(argv) - 1):
            if argv[i] == '--volume':
                src, dst = argv[i + 1].split(':')[:2]
                mounts[dst] = src
        out_arg = argv[argv.index('-o') + 1]
        host = mounts['/out'] + out_arg[len('/out'):]
        with open(host, 'wb') as f:
            f.write(b'FAKE-DSO-BYTES')
    sys.exit(0)
elif cmd == 'cp':
    src = argv[1]
    if ctl.get('cp_fail'):
        sys.exit(1)
    dst = argv[2]
    target = Path(dst)
    if target.is_dir():
        target = target / 'poc'
    with open(target, 'wb') as f:
        f.write(bytes.fromhex(ctl.get('cp_hex', 'deadbeef')))
    sys.exit(0)
sys.exit(0)
'''

VALID_EVENT = {
    'index': 1, 'kind': 'asan_report', 'event_id': 'A1',
    'address': 524, 'access_kind': 'read', 'width': 4,
    'description': 'heap-buffer-overflow', 'pc': 4198400,
    'region_category': 'heap', 'region_base': 512, 'region_extent': 8,
    'pointer_bits': 64,
}


def event_line(**overrides):
    evt = dict(VALID_EVENT)
    evt.update(overrides)
    return json.dumps(evt) + '\n'


class FakeDockerHarness:
    """Installs a fake docker binary plus per-test control/log files."""

    def __init__(self, directory: Path):
        self.bin = directory / 'docker'
        self.bin.write_text('#!/usr/bin/env python3\n' + FAKE_DOCKER.split('\n', 1)[1])
        self.bin.chmod(0o755)
        self.control_path = directory / 'control.json'
        self.log_path = directory / 'docker.log'
        self.log_path.write_text('')

    @property
    def env(self):
        return {
            'FAKE_DOCKER_CONTROL': str(self.control_path),
            'FAKE_DOCKER_LOG': str(self.log_path),
        }

    def control(self, **kwargs):
        self.control_path.write_text(json.dumps(kwargs), 'utf-8')
        self.log_path.write_text('')

    def calls(self):
        return [json.loads(line) for line in
                self.log_path.read_text().splitlines() if line]


def make_corpus() -> Corpus:
    task = TaskSpec(
        task_id='arvo:368', kind='arvo', project='arvo',
        vulnerability_class='heap-buffer-overflow',
        vul=ImageSpec(f'n132/arvo:368-vul@sha256:{D1}', f'sha256:{D1}'),
        fix=ImageSpec(f'n132/arvo:368-fix@sha256:{D2}', f'sha256:{D2}'),
        archive_path='data/arvo/368/repo-vul.tar.gz',
        description_path='data/arvo/368/description.txt',
        command_vul=('/bin/arvo',), command_fix=('/bin/arvo',),
        poc_mount='/tmp/poc')
    return Corpus(schema=CORPUS_SCHEMA, code_revision=CYBERGYM_CODE_REVISION,
                  data_remote=CYBERGYM_DATA_REMOTE, platform='linux/amd64',
                  difficulties=('level1', 'level0'), tasks={task.task_id: task},
                  source_sha256='f' * 64)


class BaseCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.harness = FakeDockerHarness(self.tmp)
        self._saved_env = {k: os.environ.get(k) for k in
                           ('FAKE_DOCKER_CONTROL', 'FAKE_DOCKER_LOG')}
        os.environ.update(self.harness.env)
        self.addCleanup(self._restore_env)
        self.work = self.tmp / 'work'
        self.backend = CybergymBackend(make_corpus(), self.work,
                                       docker=str(self.harness.bin))
        self.backend.probe_dir.mkdir(parents=True, exist_ok=True)
        self.backend.dso_path.write_bytes(b'DSO')
        self.backend.artifacts_dir.mkdir(parents=True, exist_ok=True)

    def _restore_env(self):
        for key, value in self._saved_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def prepare_probe(self, control: dict, poc: bytes = b'POCBYTES') -> str:
        self.harness.control(**control)
        return self.backend.store_poc(poc)

    def assert_inconclusive(self, control: dict, fragment: str | None = None):
        digest = self.prepare_probe(control)
        with self.assertRaises(CaptureError) as ctx:
            self.backend.execute_probe('arvo:368', digest, 'X1')
        self.assertEqual(ctx.exception.status, 'INCONCLUSIVE_CAPTURE')
        if fragment:
            self.assertIn(fragment, ctx.exception.diagnostic)


class TestStorePoc(BaseCase):
    def test_stores_content_addressed(self):
        digest = self.backend.store_poc(b'hello')
        self.assertEqual(digest, cb.sha256_hex(b'hello'))
        stored = self.backend.artifacts_dir / f'{digest}.poc'
        self.assertTrue(stored.is_file())
        self.assertEqual(stored.read_bytes(), b'hello')

    def test_rejects_oversize(self):
        with self.assertRaises(Rejected):
            self.backend.store_poc(b'x' * (cb.POC_LIMIT_BYTES + 1))

    def test_rejects_empty(self):
        with self.assertRaises(Rejected):
            self.backend.store_poc(b'')

    def test_rejects_non_bytes(self):
        with self.assertRaises(Rejected):
            self.backend.store_poc('text')

    def test_dedup_is_idempotent_and_detects_corruption(self):
        digest = self.backend.store_poc(b'abc')
        again = self.backend.store_poc(b'abc')
        self.assertEqual(digest, again)
        self.assertEqual(len(list(self.backend.artifacts_dir.glob('*.poc'))), 1)
        (self.backend.artifacts_dir / f'{digest}.poc').write_bytes(b'tampered')
        with self.assertRaises(Rejected):
            self.backend.store_poc(b'abc')


class TestProbeArgv(BaseCase):
    def test_exact_create_argv(self):
        digest = self.prepare_probe({'exit_code': 0})
        self.backend.execute_probe('arvo:368', digest, 'X1')
        create = self.harness.calls()[0]
        self.assertIn('--name', create)
        name = create[create.index('--name') + 1]
        self.assertRegex(name, r'^soundtrace-probe-X1-[0-9a-f]{12}$')
        events_dir = self.backend.events_root / 'X1'
        poc = self.backend.work_dir / '.probe-poc' / 'X1' / 'input.bin'
        expected = [
            'create', '--platform', 'linux/amd64', '--network',
            'none', '--read-only', '--cap-drop', 'ALL', '--security-opt',
            'no-new-privileges', '--memory', '4g', '--memory-swap', '4g',
            '--pids-limit', '128', '--cpus', '2',
            '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m',
            '--tmpfs', '/var/tmp:rw,noexec,nosuid,size=16m',
            '--pull=never', '--entrypoint', '',
            '--name', name,
            '--mount', f'type=bind,src={events_dir},dst=/soundtrace',
            '--mount', f'type=bind,src={self.backend.work_dir / "probe/libsoundtrace_asan.so"},'
                         'dst=/soundtrace/libsoundtrace_asan.so,readonly',
            '--mount', f'type=bind,src={poc},dst=/tmp/poc,readonly',
            '--env', f'ASAN_OPTIONS={cb.CYBERGYM_ASAN_OPTIONS}',
            '--env', 'LD_PRELOAD=/soundtrace/libsoundtrace_asan.so',
            f'n132/arvo:368-vul@sha256:{D1}',
            '/usr/bin/timeout', '-s', 'KILL', '10', '/bin/arvo',
        ]
        self.assertEqual(create, expected)

    def test_lifecycle_commands(self):
        digest = self.prepare_probe({'exit_code': 1, 'events': event_line()})
        execution = self.backend.execute_probe('arvo:368', digest, 'X2')
        self.assertEqual(execution['id'], 'X2')
        commands = [call[0] for call in self.harness.calls()]
        self.assertEqual(commands[0], 'create')
        self.assertIn('start', commands)
        self.assertIn('inspect', commands)
        self.assertEqual(commands[-1], 'rm')  # always cleaned up


class TestAdmissibleAndClean(BaseCase):
    def test_admissible_event(self):
        digest = self.prepare_probe({'exit_code': 1,
                                     'events': event_line()})
        execution = self.backend.execute_probe('arvo:368', digest, 'X1')
        self.assertEqual(execution['events'], [VALID_EVENT])
        self.assertEqual(execution['exit_code'], 1)
        self.assertIsNone(execution['signal'])
        self.assertFalse(execution['oom_killed'])
        self.assertEqual(execution['image_digest'], f'sha256:{D1}')
        self.assertEqual(execution['asan_options'], cb.CYBERGYM_ASAN_OPTIONS)
        self.assertEqual(set(execution), set(cb.EXECUTION_KEYS))
        # offline twin accepts the identical record
        self.backend.validate_execution(execution)

    def test_clean_exit_records_empty_events(self):
        digest = self.prepare_probe({'exit_code': 0, 'events': ''})
        execution = self.backend.execute_probe('arvo:368', digest, 'X1')
        self.assertEqual(execution['events'], [])
        self.backend.validate_execution(execution)


class TestInconclusive(BaseCase):
    def test_host_timeout(self):
        control = {'hang': True, 'exit_code': 0}
        digest = self.prepare_probe(control)
        with self.assertRaises(CaptureError) as ctx:
            self.backend.execute_probe('arvo:368', digest, 'X1',
                                       host_timeout=0.5)
        self.assertEqual(ctx.exception.status, 'INCONCLUSIVE_CAPTURE')
        self.assertIn('timeout', ctx.exception.diagnostic)

    def test_oom_kill(self):
        self.assert_inconclusive({'exit_code': 137, 'oom': True}, 'OOM')

    def test_signal_only_death(self):
        self.assert_inconclusive({'exit_code': 139}, 'signal 11')

    def test_output_overflow(self):
        self.assert_inconclusive(
            {'exit_code': 1, 'events': event_line(), 'stdout_size': 1_100_000},
            'capture limit')

    def test_event_file_overflow(self):
        self.assert_inconclusive(
            {'exit_code': 1, 'events': event_line(), 'events_big': True},
            '64 KiB')

    def test_multiple_events(self):
        self.assert_inconclusive(
            {'exit_code': 1, 'events': event_line() + event_line()},
            'exactly one')

    def test_non_heap_description(self):
        self.assert_inconclusive(
            {'exit_code': 1,
             'events': event_line(description='stack-buffer-overflow')},
            'heap-buffer-overflow')

    def test_non_heap_region_category(self):
        self.assert_inconclusive(
            {'exit_code': 1, 'events': event_line(region_category='global')},
            'heap')

    def test_zero_width(self):
        self.assert_inconclusive({'exit_code': 1,
                                  'events': event_line(width=0)}, 'width')

    def test_zero_extent(self):
        self.assert_inconclusive(
            {'exit_code': 1, 'events': event_line(region_extent=0)},
            'extent')

    def test_zero_pc(self):
        self.assert_inconclusive({'exit_code': 1,
                                  'events': event_line(pc=0)}, 'pc')

    def test_pointer_wrap_access(self):
        self.assert_inconclusive(
            {'exit_code': 1,
             'events': event_line(address=(1 << 64) - 2, width=4)},
            'wraps')

    def test_pointer_wrap_region(self):
        self.assert_inconclusive(
            {'exit_code': 1,
             'events': event_line(region_base=(1 << 64) - 4, region_extent=8)},
            'wraps')

    def test_exit1_zero_events(self):
        self.assert_inconclusive({'exit_code': 1, 'events': ''}, 'without')

    def test_exit0_with_event(self):
        self.assert_inconclusive({'exit_code': 0,
                                  'events': event_line()}, 'clean exit')

    def test_unexpected_exit_code(self):
        self.assert_inconclusive({'exit_code': 3}, 'exit code 3')

    def test_malformed_event_json(self):
        self.assert_inconclusive({'exit_code': 1, 'events': '{oops\n'},
                                 'malformed')

    def test_boolean_field(self):
        line = event_line().replace('"width": 4', '"width": true')
        self.assert_inconclusive({'exit_code': 1, 'events': line},
                                 'integer')

    def test_extra_event_key(self):
        line = event_line().rstrip('\n')
        line = line[:-1] + ',"surprise":1}'
        self.assert_inconclusive({'exit_code': 1, 'events': line + '\n'},
                                 'keys')

    def test_missing_poc_artifact_is_setup_failure(self):
        self.harness.control(exit_code=0)
        with self.assertRaises(CaptureError) as context:
            self.backend.execute_probe('arvo:368', 'e' * 64, 'X1')
        self.assertEqual(context.exception.status, 'INCONCLUSIVE_SETUP')

    def test_unknown_task(self):
        digest = self.prepare_probe({'exit_code': 0})
        with self.assertRaises(CaptureError):
            self.backend.execute_probe('arvo:999999', digest, 'X1')

    def test_docker_create_failure(self):
        self.assert_inconclusive({'create_fail': True})


class TestBoundedTeardown(BaseCase):
    """Every abnormal probe path must still kill and remove the container."""

    def assert_kill_and_rm(self, control: dict, **probe_kwargs):
        digest = self.prepare_probe(control)
        with self.assertRaises(CaptureError):
            self.backend.execute_probe('arvo:368', digest, 'X1',
                                       **probe_kwargs)
        calls = self.harness.calls()
        kinds = [call[0] for call in calls]
        self.assertIn('kill', kinds)
        self.assertEqual(kinds[-1], 'rm')
        self.assertEqual(calls[-1][:2], ['rm', '-f'])
        self.assertEqual(calls[-1][2], 'fake-cid-0123')

    def test_host_timeout_kills_then_removes(self):
        self.assert_kill_and_rm({'hang': True, 'exit_code': 0},
                                host_timeout=0.5)

    def test_output_overflow_kills_then_removes(self):
        self.assert_kill_and_rm(
            {'exit_code': 1, 'events': event_line(), 'stdout_size': 1_100_000})

    def test_event_file_overflow_kills_then_removes(self):
        self.assert_kill_and_rm(
            {'exit_code': 1, 'events': event_line(), 'events_big': True})

    def test_create_failure_removes_named_container(self):
        digest = self.prepare_probe({'create_fail': True})
        with self.assertRaises(CaptureError):
            self.backend.execute_probe('arvo:368', digest, 'X1')
        calls = self.harness.calls()
        self.assertEqual(calls[0][0], 'create')
        self.assertEqual(calls[-1][:2], ['rm', '-f'])
        self.assertNotEqual(calls[-1][2], 'fake-cid-0123')  # by name
        self.assertRegex(calls[-1][2], r'^soundtrace-probe-X1-[0-9a-f]{12}$')
        self.assertFalse((self.work / '.probe-poc' / 'X1').exists())

    def test_staging_dir_cleared_after_normal_probe(self):
        digest = self.prepare_probe({'exit_code': 1, 'events': event_line()})
        self.backend.execute_probe('arvo:368', digest, 'X1')
        self.assertFalse((self.work / '.probe-poc' / 'X1').exists())


class TestExcerptBytes(BaseCase):
    def test_safe_excerpt_bounds_encoded_bytes(self):
        text = cb._safe_excerpt(b'\xff' * 6000)
        self.assertLessEqual(len(text.encode('utf-8')), cb.EXCERPT_BYTES)

    def test_safe_excerpt_ascii_passthrough(self):
        self.assertEqual(cb._safe_excerpt(b'abc'), 'abc')

    def test_validate_rejects_inflated_excerpt(self):
        digest = self.prepare_probe({'exit_code': 1, 'events': event_line()})
        execution = self.backend.execute_probe('arvo:368', digest, 'X1')
        execution['stdout_excerpt'] = '�' * cb.EXCERPT_BYTES
        self.assertLessEqual(len(execution['stdout_excerpt']), cb.EXCERPT_BYTES)
        with self.assertRaises(Rejected):
            self.backend.validate_execution(execution)


class TestValidateExecution(BaseCase):
    def base_execution(self) -> dict:
        digest = self.prepare_probe({'exit_code': 1, 'events': event_line()})
        return self.backend.execute_probe('arvo:368', digest, 'X1')

    def test_mutations_rejected(self):
        base = self.base_execution()
        mutations = {
            'extra key': {**base, 'surprise': 1},
            'missing key': {k: v for k, v in base.items() if k != 'signal'},
            'bad id': {**base, 'id': 'Z9'},
            'unknown task': {**base, 'task_id': 'arvo:1'},
            'wrong image': {**base, 'image_digest': 'sha256:' + '9' * 64},
            'wrong platform': {**base, 'platform': 'linux/arm64'},
            'wrong command': {**base, 'command': ['/bin/sh', '-c', 'x']},
            'wrong asan options': {**base, 'asan_options': 'x=1'},
            'wrong pointer bits': {**base, 'pointer_bits': 32},
            'signal without death': {**base, 'signal': 9},
            'oom flag': {**base, 'oom_killed': True},
            'timed out flag': {**base, 'timed_out': True},
            'clean exit with event': {**base, 'exit_code': 0},
            'second event': {**base, 'events': [VALID_EVENT, VALID_EVENT]},
            'wrapped access': {**base, 'events': [
                {**VALID_EVENT, 'address': (1 << 64) - 2}]},
            'non-heap event': {**base, 'events': [
                {**VALID_EVENT, 'description': 'use-after-free'}]},
            'string width': {**base, 'events': [
                {**VALID_EVENT, 'width': '4'}]},
            'bad poc hash': {**base, 'poc_sha256': 'not-hex'},
            'oversize poc': {**base, 'poc_size': cb.POC_LIMIT_BYTES + 1},
            'huge excerpt': {**base, 'stdout_excerpt': 'x' * 5000},
            'bad stdout hash': {**base, 'stdout_sha256': 'zz'},
            'exit two clean': {**base, 'exit_code': 2, 'events': []},
        }
        for label, mutation in mutations.items():
            with self.subTest(label):
                with self.assertRaises(Rejected):
                    self.backend.validate_execution(mutation)

    def test_signal_consistency_accepted(self):
        base = self.base_execution()
        record = {**base, 'exit_code': 137, 'signal': 9, 'events': []}
        with self.assertRaises(Rejected):  # 137 is inconclusive, not certifiable
            self.backend.validate_execution(record)


class TestValidateBuildAndBootstrap(BaseCase):
    def make_data_dir(self) -> Path:
        data = self.tmp / 'data'
        base = data / 'data/arvo/368'
        base.mkdir(parents=True)
        payload = b'hello\n'
        buf = BytesIO()
        with tarfile.open(fileobj=buf, mode='w:gz') as tar:
            info = tarfile.TarInfo('src/main.c')
            info.size = len(payload)
            tar.addfile(info, BytesIO(payload))
        (base / 'repo-vul.tar.gz').write_bytes(buf.getvalue())
        (base / 'description.txt').write_text('vulnerable parser\n')
        (base / 'poc').write_bytes(b'\x01\x02oracle')
        subprocess.run(['git', 'init', '-q'], cwd=data, check=True)
        subprocess.run(['git', 'config', 'user.email', 'test@example.invalid'],
                       cwd=data, check=True)
        subprocess.run(['git', 'config', 'user.name', 'SoundTrace Test'],
                       cwd=data, check=True)
        subprocess.run(['git', 'add', '.'], cwd=data, check=True)
        subprocess.run(['git', 'commit', '-qm', 'fixture'], cwd=data, check=True)
        revision = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=data,
                                  check=True, capture_output=True,
                                  text=True).stdout.strip()
        self.backend._data_revision_pin = revision
        return data

    def test_bootstrap_writes_lock(self):
        data = self.make_data_dir()
        self.harness.control()
        self.backend.bootstrap(data)
        lock = json.loads(self.backend.lock_path.read_text())
        self.assertEqual(lock['schema'], 'soundtrace-cybergym-env-v1')
        self.assertEqual(lock['corpus_sha256'], 'f' * 64)
        self.assertEqual(lock['images']['arvo:368']['vul_digest'],
                         f'sha256:{D1}')
        self.assertEqual(lock['probe']['dso_sha256'],
                         cb.sha256_hex(b'FAKE-DSO-BYTES'))
        extracted = (self.work / 'tasks/arvo:368/level0/src/main.c')
        self.assertEqual(extracted.read_bytes(), b'hello\n')
        record = self.backend.build_record()
        self.backend.validate_build(record)

    def test_bootstrap_digest_mismatch(self):
        data = self.make_data_dir()
        self.harness.control(inspect_digest='sha256:' + '0' * 64)
        with self.assertRaises(CaptureError) as ctx:
            self.backend.bootstrap(data)
        self.assertEqual(ctx.exception.status, 'INCONCLUSIVE_SETUP')
        self.assertIn('differs from the pin', ctx.exception.diagnostic)

    def test_bootstrap_docker_unreachable(self):
        data = self.make_data_dir()
        broken = CybergymBackend(make_corpus(), self.tmp / 'w2',
                                 docker=str(self.tmp / 'no-such-docker'))
        with self.assertRaises(CaptureError) as ctx:
            broken.bootstrap(data)
        self.assertEqual(ctx.exception.status, 'INCONCLUSIVE_SETUP')

    def test_bootstrap_missing_archive(self):
        data = self.make_data_dir()
        (data / 'data/arvo/368/repo-vul.tar.gz').unlink()
        self.harness.control()
        with self.assertRaises(Rejected):
            self.backend.bootstrap(data)

    def test_validate_build_rejects_mutations(self):
        data = self.make_data_dir()
        self.harness.control()
        self.backend.bootstrap(data)
        record = self.backend.build_record()
        for label, mutation in {
            'corpus hash': {**record, 'corpus_sha256': '7' * 64},
            'missing key': {k: v for k, v in record.items()
                            if k != 'docker_version'},
            'agent digest': {**record, 'agent_image_digest': 'sha256:x'},
            'task image': {**record, 'tasks': {
                'arvo:368': {**record['tasks']['arvo:368'],
                             'vul_digest': 'sha256:' + '5' * 64}}},
            'wrong task set': {**record, 'tasks': {}},
        }.items():
            with self.subTest(label):
                with self.assertRaises(Rejected):
                    self.backend.validate_build(mutation)

    def test_qualify_oracle_paths(self):
        data = self.make_data_dir()
        self.harness.control()
        self.backend.bootstrap(data)
        self.harness.control(exit_code=1, events=event_line(),
                             fixed_exit_code=0)
        key = self.tmp / 'runner.key'
        key.write_bytes(b'qualification-test-key-32-bytesx')
        fresh = CybergymBackend(make_corpus(), self.work,
                                docker=str(self.harness.bin))
        fresh._data_revision_pin = self.backend._data_revision_pin
        records = fresh.qualify(key)
        document = json.loads(
            (self.work / 'qualification.json').read_text(encoding='utf-8'))
        self.assertEqual(
            document['hmac_sha256'],
            mac_hex(key.read_bytes(), canonical_json(document['payload'])))
        self.assertEqual(document['payload']['data_revision'],
                         self.backend._data_revision_pin)
        self.assertEqual(len(records), 1)
        self.assertTrue(records[0]['qualified'])
        self.assertEqual(records[0]['poc_sha256'],
                         cb.sha256_hex(b'\x01\x02oracle'))

    def test_qualify_fixed_image_crash_blocks(self):
        data = self.make_data_dir()
        self.harness.control()
        self.backend.bootstrap(data)
        # the fixed-image run shares the inspect control and also exits 1
        self.harness.control(exit_code=1, events=event_line())
        with self.assertRaises(CaptureError) as ctx:
            self.backend.qualify()
        self.assertEqual(ctx.exception.status, 'INCONCLUSIVE_SETUP')

    def test_qualify_requires_bootstrap(self):
        with self.assertRaises(CaptureError) as ctx:
            self.backend.qualify()
        self.assertEqual(ctx.exception.status, 'INCONCLUSIVE_SETUP')


class TestExtraction(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def archive(self, members: list[tuple[tarfile.TarInfo, bytes]]) -> Path:
        path = self.tmp / 'repo.tar.gz'
        with tarfile.open(path, 'w:gz') as tar:
            for info, payload in members:
                tar.addfile(info, BytesIO(payload))
        return path

    def info(self, name: str) -> tarfile.TarInfo:
        info = tarfile.TarInfo(name)
        info.mtime = 0
        return info

    def test_safe_extraction_and_vcs_strip(self):
        payload = b'int main(void){}\n'
        src = self.info('src/main.c')
        src.size = len(payload)
        git = self.info('.git/config')
        git.size = 3
        ignore = self.info('src/.gitignore')
        ignore.size = 2
        path = self.archive([(src, payload), (git, b'[c]'), (ignore, b'xy')])
        dest = self.tmp / 'out'
        count = extract_repo_archive(path, dest)
        self.assertEqual((dest / 'src/main.c').read_bytes(), payload)
        self.assertFalse((dest / '.git').exists())
        self.assertFalse((dest / 'src/.gitignore').exists())
        self.assertEqual(count, 1)

    def test_rejects_dotdot(self):
        escape = self.info('../escape.txt')
        escape.size = 1
        with self.assertRaises(Rejected):
            extract_repo_archive(self.archive([(escape, b'x')]),
                                 self.tmp / 'out1')

    def test_rejects_absolute(self):
        abspath = self.info('/etc/evil')
        abspath.size = 1
        with self.assertRaises(Rejected):
            extract_repo_archive(self.archive([(abspath, b'x')]),
                                 self.tmp / 'out2')

    def test_rejects_device(self):
        dev = tarfile.TarInfo('dev/node')
        dev.type = tarfile.CHRTYPE
        dev.devmajor = 1
        dev.devminor = 3
        with self.assertRaises(Rejected):
            extract_repo_archive(self.archive([(dev, b'')]),
                                 self.tmp / 'out3')

    def test_rejects_escaping_symlink(self):
        link = tarfile.TarInfo('src/link')
        link.type = tarfile.SYMTYPE
        link.linkname = '../../../outside'
        payload = b'x'
        src = self.info('src/keep.c')
        src.size = len(payload)
        with self.assertRaises(Rejected):
            extract_repo_archive(self.archive([(link, b''), (src, payload)]),
                                 self.tmp / 'out4')

    def test_rejects_escaping_hardlink(self):
        link = tarfile.TarInfo('src/hard')
        link.type = tarfile.LNKTYPE
        link.linkname = '../../elsewhere'
        with self.assertRaises(Rejected):
            extract_repo_archive(self.archive([(link, b'')]),
                                 self.tmp / 'out5')

    def test_allows_internal_symlink(self):
        link = tarfile.TarInfo('src/link')
        link.type = tarfile.SYMTYPE
        link.linkname = 'main.c'
        payload = b'x'
        src = self.info('src/main.c')
        src.size = len(payload)
        path = self.archive([(src, payload), (link, b'')])
        dest = self.tmp / 'out6'
        extract_repo_archive(path, dest)
        self.assertTrue((dest / 'src/link').is_symlink())

    def test_missing_archive_rejected(self):
        with self.assertRaises(Rejected):
            extract_repo_archive(self.tmp / 'nope.tar.gz', self.tmp / 'out7')


class TestClassifyExecution(unittest.TestCase):
    def test_classify_table(self):
        evt = dict(VALID_EVENT)
        cases = [
            ({'events': [evt], 'exit_code': 1, 'signal': None}, 'admissible'),
            ({'events': [], 'exit_code': 0, 'signal': None}, 'clean'),
            ({'events': [evt], 'exit_code': 0, 'signal': None},
             'inconclusive'),
            ({'events': [], 'exit_code': 1, 'signal': None}, 'inconclusive'),
            ({'events': [], 'exit_code': None, 'signal': None},
             'inconclusive'),
            ({'events': [evt], 'exit_code': 1, 'signal': 11}, 'inconclusive'),
        ]
        for kwargs, expected in cases:
            with self.subTest(exit_code=kwargs['exit_code'],
                              signal=kwargs['signal']):
                outcome, _ = cb.classify_execution(
                    events=kwargs['events'], exit_code=kwargs['exit_code'],
                    signal=kwargs['signal'], oom_killed=False,
                    timed_out=False, overflow=False)
                self.assertEqual(outcome, expected)
        for kwargs in ({'oom_killed': True}, {'timed_out': True},
                       {'overflow': True}):
            with self.subTest(**kwargs):
                outcome, _ = cb.classify_execution(
                    events=[evt], exit_code=1, signal=None,
                    timed_out=kwargs.get('timed_out', False),
                    oom_killed=kwargs.get('oom_killed', False),
                    overflow=kwargs.get('overflow', False))
                self.assertEqual(outcome, 'inconclusive')


class TestEventValidation(unittest.TestCase):
    def test_field_rejections(self):
        for field, value in {
            'index': 2, 'kind': 'other', 'event_id': 'A2',
            'access_kind': 'exec', 'description': 'heap-use-after-free',
            'region_category': 'stack', 'pointer_bits': 32,
            'address': -1, 'region_base': -1, 'pc': 0, 'width': -4,
            'region_extent': -8,
        }.items():
            with self.subTest(field=field):
                with self.assertRaises(Rejected):
                    cb.validate_event({**VALID_EVENT, field: value})

    def test_key_set(self):
        with self.assertRaises(Rejected):
            cb.validate_event({k: v for k, v in VALID_EVENT.items()
                               if k != 'pc'})
        with self.assertRaises(Rejected):
            cb.validate_event({**VALID_EVENT, 'extra': 1})
        with self.assertRaises(Rejected):
            cb.validate_event('not-an-object')


if __name__ == '__main__':
    unittest.main()
