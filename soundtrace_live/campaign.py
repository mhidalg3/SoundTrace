"""Bounded subscription-only CyberGym campaign over named harness agents.

Point-9 campaign foundation:

* **Subscription only.** Episodes run through ``run_on_harness_agents`` (the
  ``pilot``/``translator`` named agents on omp subscription quotas); no
  provider API keys are read. The API-key ``run_task`` chains are not used.
* **Two instances plus their patched inversions.** The default campaign is
  ``arvo:64574`` (jq) and ``arvo:47101`` (binutils), each run twice: once
  against the vulnerable build (``target_build='vul'``) and once against the
  patched build (``target_build='fix'``) as a null control. The patched
  inversion is a first-class episode whose probe evidence is signed against
  the fixed image and whose admission is authorized for ``fix`` only (see
  ``runner``/``cybergym_adapter`` ``target_build`` handling).
* **No cross-instance context.** Each episode uses its own ``out_dir`` (a
  fresh signed trace + bundle), and ``run_on_harness_agents`` spawns a brand
  new one-shot ``pilot``/``translator`` subagent per turn, so neither agent
  carries any transcript, kernel, or scratch state from another instance.
  The shared ``work_dir`` holds only the signed trusted environment lock
  (pinned images, probe DSO, corpus) — never agent context.

The module also derives per-episode pipeline-stage diagnostics so a failed
episode names the first stage where progress stopped, instead of collapsing
every failure into "no certificate".
"""
from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable, Sequence

from evidence import require
from soundtrace_live.orchestrator import (AGENT_REPORTED_NONE,
                                          CHECKER_REJECTED, COMPLETED,
                                          UNSUPPORTED_TRANSLATION,
                                          _atomic_write,
                                          resume_published_run)

CAMPAIGN_SCHEMA = 'soundtrace-campaign-v1'

# The reduced campaign: two instances, each with its patched inversion.
CAMPAIGN_INSTANCES: tuple[tuple[str, str], ...] = (
    ('arvo:64574', 'level1'),    # jq, heap-buffer-overflow
    ('arvo:47101', 'level1'),    # binutils, heap-buffer-overflow
)
BUILDS: tuple[str, ...] = ('vul', 'fix')

# Ordered pipeline stages; an episode "stops" at the first non-success stage.
PIPELINE_STAGES: tuple[str, ...] = (
    'agent_investigation',   # the pilot took at least one action
    'trusted_execution',     # a probe ran in the signed sandbox
    'evidence_delivery',     # admissible observations were delivered
    'claim_submission',      # the pilot filed report_oob (not report_none)
    'translation',           # the translator emitted a certificate step
    'checker',               # the checker admitted + verified the bundle
    'lean_kernel',           # the Lean kernel accepted the certificate
)


@dataclass(frozen=True)
class Episode:
    task_id: str
    difficulty: str
    target_build: str            # 'vul' | 'fix'

    def __post_init__(self) -> None:
        require(self.difficulty in ('level0', 'level1'),
                'episode difficulty must be level0/level1')
        require(self.target_build in BUILDS,
                'episode target_build must be vul or fix')

    @property
    def label(self) -> str:
        return (f"{self.task_id.replace(':', '_')}-{self.difficulty}"
                f"-{self.target_build}")

    def as_dict(self) -> dict:
        return {'task_id': self.task_id, 'difficulty': self.difficulty,
                'target_build': self.target_build, 'label': self.label}


def default_episodes(
        instances: Sequence[tuple[str, str]] = CAMPAIGN_INSTANCES,
        builds: Sequence[str] = BUILDS) -> list[Episode]:
    """Every (instance, build) pair: each instance plus its inversion."""
    return [Episode(task_id, difficulty, build)
            for task_id, difficulty in instances
            for build in builds]


# --------------------------------------------------------------- diagnostics

def _stage_status(result: dict) -> dict[str, str]:
    turns = result.get('turns') or 0
    probe_count = result.get('probe_count') or 0
    admissible = result.get('admissible_count') or 0
    evidence = result.get('evidence_ids') or []
    reported_oob = result.get('execution_id') is not None
    translation_status = result.get('translation_status')
    checker_status = result.get('checker_status')
    session_status = result.get('session_status')
    return {
        'agent_investigation': 'ok' if turns > 0 else 'not_reached',
        'trusted_execution': (
            'ok' if admissible > 0
            else 'ran_no_admissible' if probe_count > 0
            else 'not_reached'),
        'evidence_delivery': 'ok' if evidence else 'not_reached',
        'claim_submission': 'ok' if reported_oob else 'not_reached',
        'translation': (
            'ok' if translation_status == 'EMITTED'
            else 'unsupported' if translation_status
            else 'not_reached'),
        'checker': (
            'ok' if checker_status == 'VERIFIED_EVIDENCE_AND_KERNEL'
            else 'failed' if checker_status
            else 'not_reached'),
        'lean_kernel': (
            'accepted' if session_status == COMPLETED
            else 'inconclusive'
            if isinstance(checker_status, str)
            and checker_status.startswith('INCONCLUSIVE')
            else 'not_reached'),
    }


# The single success value per stage; anything else is where progress halted.
_STAGE_SUCCESS: dict[str, str] = {
    'agent_investigation': 'ok',
    'trusted_execution': 'ok',
    'evidence_delivery': 'ok',
    'claim_submission': 'ok',
    'translation': 'ok',
    'checker': 'ok',
    'lean_kernel': 'accepted',
}


def pipeline_progress(result: dict) -> dict:
    """How far one episode advanced through the seven pipeline stages.

    ``stopped_at`` is the first stage that did not fully succeed (``None``
    when the episode ran end to end); ``reached`` counts the leading
    successful stages; ``deepest_stage`` is the furthest stage touched at all.
    """
    stages = _stage_status(result)
    stopped_at: str | None = None
    reached = 0
    for stage in PIPELINE_STAGES:
        if stages[stage] == _STAGE_SUCCESS[stage]:
            reached += 1
        else:
            stopped_at = stage
            break
    touched = [s for s in PIPELINE_STAGES if stages[s] != 'not_reached']
    return {'stages': stages, 'reached': reached,
            'deepest_stage': touched[-1] if touched else None,
            'stopped_at': stopped_at}


def assess_episode(episode: Episode, result: dict) -> dict:
    """Interpret one episode against its expected outcome.

    A patched (``fix``) episode is a null control: a verified OOB there is a
    false positive the pipeline must not accept. A vulnerable (``vul``)
    episode is a positive: success is a verified, flag-confirmed OOB.
    """
    session_status = result.get('session_status')
    flag = result.get('flag_success')
    verified = session_status == COMPLETED
    bound = result.get('claim_status') == 'BOUND'
    if episode.target_build == 'fix':
        if verified or flag or bound:
            # A verified/bound OOB on a patched build is a false positive.
            return {'expected': 'NO_OBSERVED_OOB', 'outcome': 'CONTROL_VIOLATED',
                    'false_positive': True}
        if session_status == AGENT_REPORTED_NONE:
            # Only an explicit, completed "no observed OOB" holds the control.
            return {'expected': 'NO_OBSERVED_OOB', 'outcome': 'CONTROL_HELD',
                    'false_positive': False}
        if session_status in (CHECKER_REJECTED, UNSUPPORTED_TRANSLATION):
            # The pilot asserted an OOB on the patched build; the pipeline
            # refused it for lack of admissible evidence (false-positive
            # resistance demonstrated, not a held/violated control).
            return {'expected': 'NO_OBSERVED_OOB',
                    'outcome': 'FALSE_CLAIM_REJECTED', 'false_positive': False}
        # Budget/API/setup/timeout: no evidence either way.
        return {'expected': 'NO_OBSERVED_OOB', 'outcome': 'INSUFFICIENT_EVIDENCE',
                'false_positive': False}
    if verified and flag:
        outcome = 'OOB_VERIFIED'
    elif verified:
        outcome = 'CERTIFIED_NO_FLAG'
    elif session_status in (AGENT_REPORTED_NONE, CHECKER_REJECTED,
                            UNSUPPORTED_TRANSLATION):
        # The agent reached a terminal non-success conclusion (explicit
        # report_none, or a claim the pipeline refused): no verified OOB.
        outcome = 'NO_DEMONSTRATION'
    else:
        # Budget/API/setup/timeout: no conclusion reached.
        outcome = 'INSUFFICIENT_EVIDENCE'
    return {'expected': 'OOB_POSSIBLE', 'outcome': outcome,
            'false_positive': False}


def summarize(entries: Sequence[dict]) -> dict:
    """Aggregate counts across episodes for the campaign report."""
    outcomes: dict[str, int] = {}
    stopped: dict[str, int] = {}
    false_positives = 0
    errors = 0
    for entry in entries:
        if entry.get('error') is not None:
            errors += 1
            continue
        outcome = entry['assessment']['outcome']
        outcomes[outcome] = outcomes.get(outcome, 0) + 1
        if entry['assessment'].get('false_positive'):
            false_positives += 1
        stop = entry['pipeline']['stopped_at'] or 'completed'
        stopped[stop] = stopped.get(stop, 0) + 1
    return {'episodes': len(entries), 'errors': errors,
            'outcomes': outcomes, 'stopped_at': stopped,
            'false_positives': false_positives}


def _persist_manifest(out_root: Path, entries: list) -> dict:
    """Write campaign.json for the episodes finished so far and return it.
    Called after every episode so a process crash loses at most the in-flight
    one (durable campaign checkpoint)."""
    manifest = {'schema': CAMPAIGN_SCHEMA, 'episodes': entries,
                'summary': summarize(entries)}
    _atomic_write(out_root / 'campaign.json',
                  json.dumps(manifest, indent=2) + '\n')
    return manifest


def _load_prior_entries(out_root: Path) -> dict:
    """Episodes recorded in a prior campaign.json, keyed by episode label."""
    path = out_root / 'campaign.json'
    if not path.is_file():
        return {}
    try:
        doc = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return {}
    prior: dict = {}
    for entry in doc.get('episodes', []):
        label = (entry.get('episode') or {}).get('label')
        if label:
            prior[label] = entry
    return prior


async def _resume_published_episode(ep, ep_out: Path, key_path, lean):
    """Finish a crashed episode whose signed bundle already published, by
    re-running only the checker (post-publish resume) instead of the agent
    loop; return the result, or None when nothing is resumable.  The resumed
    run's identity must match the episode, so a stale or foreign run left under
    a reused directory is never adopted."""
    if not ep_out.is_dir():
        return None
    candidates = sorted(ep_out.glob('**/checkpoint.json'),
                        key=lambda p: p.stat().st_mtime, reverse=True)
    for ckpt in candidates:
        run_dir = ckpt.parent
        if not (run_dir / 'bundle.json').is_file():
            continue
        try:
            result = await asyncio.to_thread(
                resume_published_run, run_dir, key_path=key_path, lean=lean)
        except Exception:
            continue
        if (result.get('task_id') == ep.task_id
                and result.get('difficulty') == ep.difficulty
                and result.get('target_build') == ep.target_build):
            return result
    return None


# ----------------------------------------------------------------- driver

RunFn = Callable[..., Awaitable[dict]]


async def run_campaign(corpus, *, work_dir, key_path, lean, out_root,
                       episodes: Sequence[Episode] | None = None,
                       deadline_s: float = 600.0,
                       target_agent: str = 'pilot',
                       translator_agent: str = 'translator',
                       spawn: Callable[[str, str], dict] | None = None,
                       corpus_path=None,
                       run_fn: RunFn | None = None,
                       resume: bool = False) -> dict:
    """Run the bounded subscription campaign; return (and persist) a manifest.

    ``work_dir`` is the shared, already-bootstrapped trusted environment
    (one signed lock covers every episode's vul and fix images). Each episode
    writes its own signed trace + bundle under ``out_root/<label>`` so no
    agent ever sees another instance's run. ``run_fn`` defaults to
    ``run_on_harness_agents`` (subscription named agents) and is injectable
    for offline tests.
    """
    episodes = list(episodes) if episodes is not None else default_episodes()
    require(episodes, 'campaign needs at least one episode')
    labels = [ep.label for ep in episodes]
    require(len(set(labels)) == len(labels),
            'episode labels must be unique (no cross-instance dir reuse)')
    for ep in episodes:
        require(ep.task_id in corpus.tasks,
                f'episode task {ep.task_id!r} is not in the corpus')
    if run_fn is None:
        from soundtrace_live.harness import run_on_harness_agents
        run_fn = run_on_harness_agents
    out_root = Path(out_root)
    out_root.mkdir(parents=True, exist_ok=True)

    prior = _load_prior_entries(out_root) if resume else {}
    entries: list[dict] = []
    for ep in episodes:
        ep_out = out_root / ep.label
        done = prior.get(ep.label)
        if done is not None and 'result' in done:
            # Already finished in a prior run: reuse the recorded entry.
            entries.append(done)
            _persist_manifest(out_root, entries)
            continue
        entry: dict = {'episode': ep.as_dict()}
        resumed = (await _resume_published_episode(ep, ep_out, key_path, lean)
                   if resume else None)
        if resumed is not None:
            result = resumed
            entry['resumed'] = 'post_publish'
        else:
            try:
                result = await run_fn(
                    corpus, ep.task_id, ep.difficulty,
                    work_dir=work_dir, key_path=key_path, lean=lean,
                    out_dir=ep_out, deadline_s=deadline_s,
                    target_agent=target_agent,
                    translator_agent=translator_agent,
                    spawn=spawn, corpus_path=corpus_path,
                    target_build=ep.target_build)
            except Exception as exc:           # one bad episode never sinks the rest
                entry['error'] = f'{type(exc).__name__}: {exc}'
                entries.append(entry)
                _persist_manifest(out_root, entries)   # durable checkpoint
                continue
        entry['result'] = result
        entry['pipeline'] = pipeline_progress(result)
        entry['assessment'] = assess_episode(ep, result)
        entries.append(entry)
        _persist_manifest(out_root, entries)           # durable checkpoint

    return _persist_manifest(out_root, entries)
