"""CLI for the CyberGym live pipeline.

Commands: bootstrap, qualify, run, evaluate, select-corpus. Every command
prints exactly one JSON object and never a traceback; exit codes are 0 (ok),
3 (INCONCLUSIVE_SETUP from bootstrap/qualification), and 1 (any other
structured failure).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from evidence import Rejected, require
from soundtrace_live.corpus import (Corpus, CorpusError, ImageSpec, TaskSpec,
                                    load_corpus, write_corpus)
from soundtrace_live.cybergym_backend import CybergymBackend, CaptureError

PROVIDER_ID_RE = re.compile(r'[a-z0-9_-]{1,32}')


def _parse_chain(text: str, flag: str) -> list[tuple[str, str]]:
    """Parse a comma-separated provider:model list into chain entries."""
    entries: list[tuple[str, str]] = []
    for part in str(text).split(','):
        part = part.strip()
        if not part:
            continue
        provider, sep, model = part.partition(':')
        if (not sep or not PROVIDER_ID_RE.fullmatch(provider)
                or not model.strip()):
            raise ValueError(
                f'{flag} entries must be provider:model, got {part!r}')
        entries.append((provider, model.strip()))
    if not entries:
        raise ValueError(f'{flag} must contain at least one '
                         'provider:model entry')
    return entries


def _require_provider_keys(chains: list[list[tuple[str, str]]]) -> bool:
    """Every distinct provider in the chains must have its key env set."""
    from soundtrace_live.providers import PROVIDER_CONFIG
    seen: list[str] = []
    for chain in chains:
        for provider, _model in chain:
            if provider not in seen:
                seen.append(provider)
    missing: list[str] = []
    for provider in seen:
        config = PROVIDER_CONFIG.get(provider)
        env_name = config['key_env'] if config else None
        if env_name is None:
            missing.append(f'unknown provider {provider!r}')
        elif not os.environ.get(env_name):
            missing.append(f'provider {provider} requires {env_name} to be '
                           'set')
    if missing:
        _emit({'status': 'REJECTED', 'diagnostic': '; '.join(missing)})
        return False
    return True


def _emit(document: dict) -> None:
    print(json.dumps(document, indent=2))


def _load(path: str) -> Corpus:
    return load_corpus(Path(path))


def _backend(corpus: Corpus, work_dir: Path) -> CybergymBackend:
    backend = CybergymBackend(corpus, work_dir)
    fetched = work_dir / 'cybergym-data'
    if backend.data_dir is None and (fetched / 'tasks.json').is_file():
        backend.data_dir = fetched
    return backend


def cmd_bootstrap(args) -> int:
    try:
        corpus = _load(args.corpus)
        backend = CybergymBackend(corpus, Path(args.work_dir))
        backend.bootstrap(Path(args.data_dir) if args.data_dir else None)
    except CorpusError as exc:
        _emit({'status': 'REJECTED', 'diagnostic': str(exc)[:500]})
        return 1
    except CaptureError as exc:
        _emit({'status': exc.status, 'diagnostic': exc.diagnostic})
        return 3
    except Exception as exc:  # structured, never a traceback
        _emit({'status': 'INCONCLUSIVE_SETUP', 'diagnostic': str(exc)[:500]})
        return 3
    _emit({'status': 'BOOTSTRAPPED', 'work_dir': args.work_dir,
           'tasks': sorted(corpus.tasks)})
    return 0


def _qualification_key(args) -> Path:
    explicit = args.key is not None
    path = Path(args.key) if explicit else Path(args.work_dir) / 'runner.key'
    path.parent.mkdir(parents=True, exist_ok=True)
    if not explicit and not path.exists():
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            payload = secrets.token_bytes(32)
            offset = 0
            while offset < len(payload):
                offset += os.write(fd, payload[offset:])
        finally:
            os.close(fd)
    require(not path.is_symlink()
            and path.is_file() and path.stat().st_mode & 0o777 == 0o600
            and path.stat().st_size == 32,
            'qualification key must be a private 32-byte file')
    return path

def cmd_qualify(args) -> int:
    try:
        corpus = _load(args.corpus)
        backend = _backend(corpus, Path(args.work_dir))
        records = backend.qualify(_qualification_key(args))
    except CorpusError as exc:
        _emit({'status': 'REJECTED', 'diagnostic': str(exc)[:500]})
        return 1
    except CaptureError as exc:
        _emit({'status': exc.status, 'diagnostic': exc.diagnostic})
        return 3
    except Exception as exc:
        _emit({'status': 'INCONCLUSIVE_SETUP', 'diagnostic': str(exc)[:500]})
        return 3
    _emit({'status': 'QUALIFIED', 'tasks': records})
    return 0


def cmd_run(args) -> int:
    from soundtrace_live.orchestrator import INCONCLUSIVE_SETUP, run_task
    try:
        target_chain = _parse_chain(args.target_chain, '--target-chain')
        translator_chain = _parse_chain(args.translator_chain,
                                        '--translator-chain')
    except ValueError as exc:
        _emit({'status': 'REJECTED', 'diagnostic': str(exc)})
        return 1
    if not _require_provider_keys([target_chain, translator_chain]):
        return 1
    try:
        corpus = _load(args.corpus)
        result = run_task(corpus, args.task_id, args.difficulty,
                          work_dir=Path(args.work_dir),
                          key_path=Path(args.key), lean=args.lean,
                          out_dir=Path(args.out),
                          target_chain=target_chain,
                          translator_chain=translator_chain,
                          corpus_path=Path(args.corpus).resolve())
    except CorpusError as exc:
        _emit({'status': 'REJECTED', 'diagnostic': exc.diagnostic})
        return 1
    except Rejected as exc:
        _emit({'status': 'REJECTED', 'diagnostic': str(exc)})
        return 1
    except CaptureError as exc:
        _emit({'status': exc.status, 'diagnostic': exc.diagnostic[:500]})
        return 3 if exc.status == 'INCONCLUSIVE_SETUP' else 1
    except OSError as exc:
        _emit({'status': 'INCONCLUSIVE_SETUP', 'diagnostic': str(exc)[:500]})
        return 3
    _emit(result)
    status = result.get('session_status')
    return 3 if status == INCONCLUSIVE_SETUP else 0


def cmd_evaluate(args) -> int:
    from soundtrace_live.orchestrator import INCONCLUSIVE_SETUP, run_task
    try:
        target_chain = _parse_chain(args.target_chain, '--target-chain')
        translator_chain = _parse_chain(args.translator_chain,
                                        '--translator-chain')
    except ValueError as exc:
        _emit({'status': 'REJECTED', 'diagnostic': str(exc)})
        return 1
    if not _require_provider_keys([target_chain, translator_chain]):
        return 1
    difficulties = [d.strip() for d in args.difficulties.split(',') if d.strip()]
    if not difficulties or any(d not in ('level0', 'level1') for d in difficulties):
        _emit({'status': 'REJECTED',
               'diagnostic': '--difficulties must contain level0/level1'})
        return 1
    wanted = None
    if getattr(args, 'task_ids', None):
        wanted = [t.strip() for t in args.task_ids.split(',') if t.strip()]
    try:
        corpus = _load(args.corpus)
    except CorpusError as exc:
        _emit({'status': 'REJECTED', 'diagnostic': exc.diagnostic})
        return 1
    if wanted is not None:
        unknown = [t for t in wanted if t not in corpus.tasks]
        if unknown:
            _emit({'status': 'REJECTED',
                   'diagnostic': f'--task-ids not in corpus: '
                                 f'{", ".join(unknown)}'})
            return 1
    results = []
    for difficulty in difficulties:
        for task_id in sorted(corpus.tasks):
            if wanted is not None and task_id not in wanted:
                continue
            try:
                result = run_task(corpus, task_id, difficulty,
                                  work_dir=Path(args.work_dir),
                                  key_path=Path(args.key), lean=args.lean,
                                  out_dir=Path(args.out),
                                  target_chain=target_chain,
                                  translator_chain=translator_chain,
                                  corpus_path=Path(args.corpus))
            except (CaptureError, OSError, Rejected) as exc:
                _emit({'status': 'INCONCLUSIVE_SETUP',
                       'diagnostic': getattr(exc, 'diagnostic', str(exc))[:500]})
                return 3
            results.append(result)
    negative_tasks = {
        task_id for task_id, task in corpus.tasks.items()
        if task.vulnerability_class.lower() in ('none', 'clean', 'non-vulnerable')
    }
    certificates = sum(1 for r in results
                       if r['claim_status'] == 'VERIFIED_EVIDENCE_AND_KERNEL')
    aggregate = {
        'runs': len(results),
        'flag_successes': sum(1 for r in results if r['flag_success'] is True),
        'certificates': certificates,
        'certificate_coverage': certificates / len(results) if results else 0.0,
        'negative_ground_truth_tasks': len(negative_tasks),
        'false_acceptances': (
            None if not negative_tasks else sum(
                1 for r in results
                if r['task_id'] in negative_tasks
                and r['claim_status'] == 'VERIFIED_EVIDENCE_AND_KERNEL')),
        'benchmark_inconclusives': sum(
            1 for r in results if r['flag_success'] is None),
        'claim_rejections': _claim_rejections(results),
        'translation_abstentions': sum(
            1 for r in results
            if r['translation_status'] == 'UNSUPPORTED_TRANSLATION'),
        'session_status_counts': _counts(r['session_status'] for r in results),
        'translation_status_counts': _counts(
            str(r['translation_status']) for r in results),
        'first_pass_translation': sum(
            1 for r in results if r['first_pass_translation'] is True),
        'repaired_translation': sum(
            1 for r in results if r['first_pass_translation'] is False),
        'provider_attempts': sum(
            len(r.get('attempts', [])) or 1 for r in results),
        'fallback_engaged': sum(
            1 for r in results if len(r.get('attempts', [])) > 1),
        'per_task': [{'task_id': r['task_id'], 'difficulty': r['difficulty'],
                      'session_status': r['session_status'],
                      'flag_success': r['flag_success'],
                      'claim_status': r['claim_status'],
                      'run_dir_task': r['task_id']} for r in results],
    }
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / 'aggregate.json').write_text(json.dumps(aggregate, indent=2) + '\n',
                                        encoding='utf-8')
    _emit({'status': 'EVALUATED', 'aggregate': aggregate})
    setup_failures = sum(1 for r in results
                         if r['session_status'] == INCONCLUSIVE_SETUP)
    return 3 if setup_failures else 0


def _counts(values) -> dict:
    out: dict[str, int] = {}
    for value in values:
        out[value] = out.get(value, 0) + 1
    return out

def _claim_rejections(results: list[dict]) -> int:
    return sum(
        1 for result in results
        if result.get('session_status') == 'CHECKER_REJECTED'
        and result.get('claim_status') not in (
            'UNSUPPORTED_TRANSLATION', 'UNSUPPORTED_TRACE'))


def cmd_select_corpus(args) -> int:
    import subprocess
    data_dir = Path(args.data_dir)
    index = data_dir / 'tasks.json'
    if not index.is_file():
        _emit({'status': 'REJECTED',
               'diagnostic': f'{index} not found'})
        return 1
    try:
        entries = json.loads(index.read_text(encoding='utf-8'))
    except (OSError, ValueError) as exc:
        _emit({'status': 'REJECTED', 'diagnostic': str(exc)[:300]})
        return 1
    if isinstance(entries, dict):
        entries = entries.get('tasks', [])
    kinds = [k.strip() for k in (args.kinds or 'arvo,oss-fuzz').split(',') if k]
    ref_re = re.compile(r'[A-Za-z0-9][A-Za-z0-9._/-]*:[0-9A-Za-z._-]+'
                        r'@sha256:[0-9a-f]{64}')
    candidates: list[dict] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        task_id = entry.get('task_id')
        kind = entry.get('kind') or (task_id.split(':', 1)[0]
                                     if isinstance(task_id, str) else '')
        if kind not in kinds:
            continue
        vul, fix = entry.get('vul'), entry.get('fix')
        if not (isinstance(task_id, str) and isinstance(vul, str)
                and isinstance(fix, str) and ref_re.fullmatch(vul)
                and ref_re.fullmatch(fix)):
            continue
        archive = data_dir / 'data' / kind / task_id.split(':', 1)[1] / 'repo-vul.tar.gz'
        description = (data_dir / 'data' / kind / task_id.split(':', 1)[1]
                       / 'description.txt')
        if not archive.is_file() or not description.is_file():
            continue
        candidates.append({'task_id': task_id, 'kind': kind,
                           'project': entry.get('project') or kind,
                           'vul': vul, 'fix': fix})
        if args.limit and len(candidates) >= args.limit:
            break
    if not candidates:
        _emit({'status': 'REJECTED',
               'diagnostic': 'no qualifying task metadata found'})
        return 1
    # Pin the registry digests from the local docker daemon.
    tasks: list[TaskSpec] = []
    for candidate in candidates:
        images = {}
        for mode in ('vul', 'fix'):
            result = subprocess.run(['docker', 'image', 'inspect',
                                     candidate[mode]], capture_output=True)
            if result.returncode != 0:
                _emit({'status': 'REJECTED',
                       'diagnostic': f'cannot inspect {candidate[mode]}'})
                return 1
            try:
                digests = json.loads(result.stdout.decode('utf-8'))[0][
                    'RepoDigests']
            except (ValueError, IndexError, KeyError):
                digests = []
            digest = next((d.split('@', 1)[1] for d in digests
                           if isinstance(d, str) and '@' in d), None)
            if not digest:
                _emit({'status': 'REJECTED',
                       'diagnostic': f'no registry digest for {candidate[mode]}'})
                return 1
            images[mode] = ImageSpec(reference=candidate[mode], digest=digest)
        command = (['/bin/arvo'] if candidate['kind'] == 'arvo'
                   else ['/usr/local/bin/run_poc'])
        dirname = f"data/{candidate['kind']}/{candidate['task_id'].split(':', 1)[1]}/"
        tasks.append(TaskSpec(
            task_id=candidate['task_id'], kind=candidate['kind'],
            project=candidate['project'],
            vulnerability_class='heap-buffer-overflow',
            vul=images['vul'], fix=images['fix'],
            archive_path=dirname + 'repo-vul.tar.gz',
            description_path=dirname + 'description.txt',
            command_vul=tuple(command), command_fix=tuple(command),
            poc_mount='/tmp/poc'))
    # Oracle-qualify every selected task before freezing the manifest.
    corpus = Corpus(schema='soundtrace-cybergym-corpus-v1',
                    code_revision='c6fe2027d39471375920b92cf1025e23a99ffda5',
                    data_remote='https://huggingface.co/datasets/sunblaze-ucb/cybergym',
                    platform='linux/amd64', difficulties=('level1', 'level0'),
                    tasks={t.task_id: t for t in tasks},
                    source_sha256='0' * 64)
    work_dir = Path(args.out).resolve().parent / '.select-corpus-work'
    frozen_path = work_dir / 'selected-corpus.json'
    try:
        work_dir.mkdir(parents=True, exist_ok=True)
        write_corpus(frozen_path, corpus)
        frozen = load_corpus(frozen_path)
        backend = CybergymBackend(frozen, work_dir)
        backend.bootstrap(data_dir)
        backend.qualify()
    except CaptureError as exc:
        _emit({'status': exc.status, 'diagnostic': exc.diagnostic[:500]})
        return 3
    except Exception as exc:
        _emit({'status': 'INCONCLUSIVE_SETUP', 'diagnostic': str(exc)[:500]})
        return 3
    write_corpus(Path(args.out), frozen)
    _emit({'status': 'SELECTED', 'out': args.out,
           'tasks': [t.task_id for t in tasks]})
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog='soundtrace_live',
                                     description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    boot = sub.add_parser('bootstrap')
    boot.add_argument('--corpus', required=True)
    boot.add_argument('--data-dir')
    boot.add_argument('--work-dir', required=True)
    boot.set_defaults(fn=cmd_bootstrap)
    qual = sub.add_parser('qualify')
    qual.add_argument('--corpus', required=True)
    qual.add_argument('--work-dir', required=True)
    qual.add_argument('--key')
    qual.set_defaults(fn=cmd_qualify)
    run = sub.add_parser('run')
    run.add_argument('--corpus', required=True)
    run.add_argument('--task-id', required=True)
    run.add_argument('--difficulty', required=True,
                     choices=('level0', 'level1'))
    run.add_argument('--work-dir', required=True)
    run.add_argument('--key', required=True)
    run.add_argument('--lean', required=True)
    run.add_argument('--out', required=True)
    run.add_argument('--target-chain', default=None)
    run.add_argument('--translator-chain', default=None)
    run.set_defaults(fn=cmd_run)
    evaluate = sub.add_parser('evaluate')
    evaluate.add_argument('--corpus', required=True)
    evaluate.add_argument('--difficulties', required=True)
    evaluate.add_argument('--task-ids', default=None)
    evaluate.add_argument('--key', required=True)
    evaluate.add_argument('--lean', required=True)
    evaluate.add_argument('--work-dir', required=True)
    evaluate.add_argument('--out', required=True)
    evaluate.add_argument('--target-chain', default=None)
    evaluate.add_argument('--translator-chain', default=None)
    evaluate.set_defaults(fn=cmd_evaluate)
    select = sub.add_parser('select-corpus')
    select.add_argument('--data-dir', required=True)
    select.add_argument('--out', required=True)
    select.add_argument('--limit', type=int, default=None)
    select.add_argument('--kinds', default=None)
    select.set_defaults(fn=cmd_select_corpus)
    args = parser.parse_args(argv)
    if getattr(args, 'target_chain', None) is None:
        from soundtrace_live.orchestrator import DEFAULT_TARGET_CHAIN
        args.target_chain = ','.join(
            f'{provider}:{model}' for provider, model in DEFAULT_TARGET_CHAIN)
    if getattr(args, 'translator_chain', None) is None:
        from soundtrace_live.orchestrator import DEFAULT_TRANSLATOR_CHAIN
        args.translator_chain = ','.join(
            f'{provider}:{model}'
            for provider, model in DEFAULT_TRANSLATOR_CHAIN)
    try:
        return args.fn(args)
    except SystemExit:
        raise
    except Exception as exc:  # last-resort: one JSON object, no traceback
        _emit({'status': 'REJECTED', 'diagnostic': f'{type(exc).__name__}: '
                                                 f'{str(exc)[:400]}'})
        return 1


if __name__ == '__main__':
    sys.exit(main())
