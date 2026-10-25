"""Strict loader/writer for `soundtrace-cybergym-corpus-v1` corpora.

A corpus pins the exact CyberGym pilot: schema literal, CyberGym code
revision, Hugging Face data remote, platform, ordered difficulties, and one
entry per task with kind, project, vulnerability class, Linux/amd64 image
references/digests, agent-visible source paths, the vulnerable/fixed command,
and the candidate PoC mount. Everything else — unknown keys, duplicate task
ids, non-sha256 digests, non-amd64 metadata, off-convention commands or paths
— is rejected before any image is pulled or any model is called.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from evidence import Rejected, canonical_json, require, sha256_hex

CORPUS_SCHEMA = 'soundtrace-cybergym-corpus-v1'
CYBERGYM_CODE_REVISION = 'c6fe2027d39471375920b92cf1025e23a99ffda5'
CYBERGYM_DATA_REVISION = 'bde190ded494e52bc684b66073b436c9d992c7c6'
CYBERGYM_DATA_REMOTE = 'https://huggingface.co/datasets/sunblaze-ucb/cybergym'
PLATFORM = 'linux/amd64'
KINDS = ('arvo', 'oss-fuzz')
DIFFICULTIES = ('level0', 'level1')
COMMANDS = {
    'arvo': ('/bin/arvo',),
    'oss-fuzz': ('/usr/local/bin/run_poc',),
}
POC_MOUNT = '/tmp/poc'
_DIGEST_RE = re.compile(r'sha256:[0-9a-f]{64}')
_TASK_ID_RE = re.compile(r'(arvo|oss-fuzz):[1-9][0-9]{0,9}')
_REF_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._/-]*:[0-9A-Za-z._-]+@sha256:[0-9a-f]{64}')


class CorpusError(Exception):
    """A corpus violation; carries a stable reason and a diagnostic."""

    def __init__(self, reason: str, diagnostic: str = ''):
        super().__init__(diagnostic or reason)
        self.reason = reason
        self.diagnostic = diagnostic or reason


@dataclass(frozen=True)
class ImageSpec:
    reference: str   # name:tag@sha256:... exactly as pinned
    digest: str      # sha256:... registry manifest digest


@dataclass(frozen=True)
class TaskSpec:
    task_id: str
    kind: str
    project: str
    vulnerability_class: str
    vul: ImageSpec
    fix: ImageSpec
    archive_path: str          # relative path under the CyberGym data dir
    description_path: str      # relative path of the level-1 description
    command_vul: tuple[str, ...]
    command_fix: tuple[str, ...]
    poc_mount: str

    @property
    def data_dirname(self) -> str:
        return self.task_id.split(':', 1)[1]


@dataclass(frozen=True)
class Corpus:
    schema: str
    code_revision: str
    data_remote: str
    platform: str
    difficulties: tuple[str, ...]
    tasks: dict[str, TaskSpec]
    source_sha256: str         # hash of the exact corpus file bytes

    def task(self, task_id: str) -> TaskSpec:
        try:
            return self.tasks[task_id]
        except KeyError:
            raise CorpusError('UNKNOWN_TASK', f'no task {task_id!r} in this corpus') from None


def _err(diagnostic: str) -> CorpusError:
    return CorpusError('BAD_INPUT', diagnostic)


def _relative_data_path(value: Any, what: str) -> str:
    require(isinstance(value, str) and value, f'{what} must be a nonempty string')
    require('\\' not in value and not value.startswith('/'), f'{what} must be a relative data path')
    parts = value.split('/')
    require(all(part not in ('', '.', '..') for part in parts),
            f'{what} must not contain empty, dot, or parent segments')
    require(value.startswith('data/'), f'{what} must live under data/')
    return value


def _image(entry: Any, what: str, task_id: str) -> ImageSpec:
    require(isinstance(entry, dict), f'{what} image for {task_id} must be an object')
    keys = set(entry)
    require(keys == {'reference', 'digest', 'platform'},
            f'{what} image keys for {task_id}')
    reference, digest = entry['reference'], entry['digest']
    require(isinstance(reference, str) and _REF_RE.fullmatch(reference),
            f'{what} image reference for {task_id} must be name:tag@sha256:...')
    require(isinstance(digest, str) and _DIGEST_RE.fullmatch(digest),
            f'{what} image digest for {task_id} must be sha256:<64 hex>')
    require(reference.endswith('@' + digest),
            f'{what} image reference digest for {task_id} differs from the pinned digest')
    if 'platform' in entry:
        require(entry['platform'] == PLATFORM,
                f'{what} image platform for {task_id} must be {PLATFORM}')
    return ImageSpec(reference=reference, digest=digest)


def parse_corpus(document: Any, *, source_sha256: str) -> Corpus:
    """Validate one already-parsed corpus document."""
    try:
        require(isinstance(document, dict), 'corpus must be an object')
        require(set(document) == {'schema', 'cybergym_code_revision', 'data_remote',
                                  'platform', 'difficulties', 'tasks'},
                'corpus keys')
        require(document['schema'] == CORPUS_SCHEMA, 'corpus schema literal')
        require(document['cybergym_code_revision'] == CYBERGYM_CODE_REVISION,
                'cybergym code revision is not the pinned pilot revision')
        require(document['data_remote'] == CYBERGYM_DATA_REMOTE,
                'data remote is not the pinned CyberGym remote')
        require(document['platform'] == PLATFORM, f'corpus platform must be {PLATFORM}')
        difficulties = document['difficulties']
        require(isinstance(difficulties, list) and difficulties
                and all(d in DIFFICULTIES for d in difficulties),
                f'difficulties must be a nonempty subset of {DIFFICULTIES}')
        require(len(set(difficulties)) == len(difficulties), 'duplicate difficulty')
        tasks_doc = document['tasks']
        require(isinstance(tasks_doc, list) and tasks_doc, 'tasks must be a nonempty list')
        tasks: dict[str, TaskSpec] = {}
        for entry in tasks_doc:
            require(isinstance(entry, dict), 'task entry must be an object')
            require(set(entry) == {'task_id', 'kind', 'project', 'vulnerability_class',
                                   'images', 'sources', 'command', 'poc_mount'},
                    'task entry keys')
            task_id = entry['task_id']
            require(isinstance(task_id, str) and _TASK_ID_RE.fullmatch(task_id),
                    'task id must look like arvo:N or oss-fuzz:N')
            require(task_id not in tasks, f'duplicate task id {task_id!r}')
            kind = entry['kind']
            require(kind in KINDS, f'kind must be one of {KINDS}')
            require(kind == task_id.split(':', 1)[0], 'task id prefix must match its kind')
            require(isinstance(entry['project'], str) and entry['project'],
                    'project must be a nonempty string')
            require(entry['vulnerability_class'] == 'heap-buffer-overflow',
                    'this corpus admits heap-buffer-overflow tasks only')
            images = entry['images']
            require(isinstance(images, dict) and set(images) == {'vul', 'fix'},
                    'images must carry exactly vul and fix')
            sources = entry['sources']
            require(isinstance(sources, dict) and set(sources) == {'archive', 'description'},
                    'sources must carry exactly archive and description')
            dirname = f'data/{kind}/{task_id.split(":", 1)[1]}/'
            archive = _relative_data_path(sources['archive'], 'source archive')
            require(archive == f'{dirname}repo-vul.tar.gz',
                    'source archive must be the task\'s data/<kind>/<id>/repo-vul.tar.gz')
            description = _relative_data_path(sources['description'], 'description')
            require(description == f'{dirname}description.txt',
                    'description must be the task\'s data/<kind>/<id>/description.txt')
            command = entry['command']
            require(isinstance(command, dict) and set(command) == {'vul', 'fix'},
                    'command must carry exactly vul and fix')
            for mode in ('vul', 'fix'):
                argv = command[mode]
                require(isinstance(argv, list) and tuple(argv) == COMMANDS[kind],
                        f'{mode} command for {kind} must be ["{COMMANDS[kind][0]}"]')
            from soundtrace_live.cybergym_adapter import max_execution_number
            require(max_execution_number(task_id, '0' * 64) >= 1,
                    'task id is too long for the certificate scope cap')
            require(entry['poc_mount'] == POC_MOUNT, f'poc mount must be {POC_MOUNT}')
            tasks[task_id] = TaskSpec(
                task_id=task_id, kind=kind, project=entry['project'],
                vulnerability_class=entry['vulnerability_class'],
                vul=_image(images['vul'], 'vulnerable', task_id),
                fix=_image(images['fix'], 'fixed', task_id),
                archive_path=archive, description_path=description,
                command_vul=tuple(command['vul']), command_fix=tuple(command['fix']),
                poc_mount=entry['poc_mount'])
    except Rejected as exc:
        raise _err(str(exc)) from exc
    return Corpus(schema=document['schema'],
                  code_revision=document['cybergym_code_revision'],
                  data_remote=document['data_remote'], platform=document['platform'],
                  difficulties=tuple(difficulties), tasks=tasks,
                  source_sha256=source_sha256)


def load_corpus(path: Path) -> Corpus:
    """Load and strictly validate a corpus file."""
    try:
        raw = Path(path).read_bytes()
    except OSError as exc:
        raise CorpusError('BAD_INPUT', f'cannot read corpus {path}: {exc}') from exc
    require_len = len(raw)
    del require_len
    try:
        document = json.loads(raw.decode('utf-8'))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _err(f'corpus is not valid UTF-8 JSON: {exc}') from exc
    return parse_corpus(document, source_sha256=sha256_hex(raw))


def task_to_dict(task: TaskSpec) -> dict:
    return {
        'task_id': task.task_id, 'kind': task.kind, 'project': task.project,
        'vulnerability_class': task.vulnerability_class,
        'images': {'vul': {'reference': task.vul.reference, 'digest': task.vul.digest,
                           'platform': PLATFORM},
                   'fix': {'reference': task.fix.reference, 'digest': task.fix.digest,
                           'platform': PLATFORM}},
        'sources': {'archive': task.archive_path, 'description': task.description_path},
        'command': {'vul': list(task.command_vul), 'fix': list(task.command_fix)},
        'poc_mount': task.poc_mount,
    }


def corpus_to_dict(corpus: Corpus) -> dict:
    """Canonical document form (select-corpus output)."""
    return {
        'schema': CORPUS_SCHEMA, 'cybergym_code_revision': corpus.code_revision,
        'data_remote': corpus.data_remote, 'platform': corpus.platform,
        'difficulties': list(corpus.difficulties),
        'tasks': [task_to_dict(corpus.tasks[tid]) for tid in sorted(corpus.tasks)],
    }


def write_corpus(path: Path, corpus: Corpus) -> None:
    Path(path).write_bytes(canonical_json(corpus_to_dict(corpus)) + b'\n')
