"""Proof-dependency and source-alignment auditing for direct certificates.

Read-only over a frozen run directory (``bundle.json`` + ``certificate.json``):
builds the premise DAG, computes which steps are reachable from the final
theorem, which evidence atoms and which translator emissions (source_map
ranges) contribute to it, and which do not. Never mutates the bundle; the
report is a diagnostic, not a proof decision (the checker remains the sole
verdict).
"""
from __future__ import annotations

import json
from pathlib import Path


def _reachable(steps: list[dict]) -> tuple[set[int], int | None, set[int]]:
    """Indices reachable from the final step by premise traversal, plus the
    dangling premise references (indices that resolve to no real step, or
    malformed non-integer premises). Never raises on malformed steps."""
    if not steps:
        return set(), None, set()
    final = len(steps) - 1
    seen: set[int] = set()
    dangling: set[int] = set()
    stack: list[int] = [final]
    while stack:
        i = stack.pop()
        if not isinstance(i, int) or isinstance(i, bool):
            dangling.add(-1)
            continue
        if i in seen:
            continue
        if not 0 <= i < len(steps):
            dangling.add(i)
            continue
        seen.add(i)
        for p in (steps[i].get('premises') or []):
            if not isinstance(p, int) or isinstance(p, bool):
                dangling.add(-1)          # malformed premise reference
            else:
                stack.append(p)
    return seen, final, dangling


def audit_certificate(cert: dict) -> dict:
    """Dependency/coverage report for one direct certificate."""
    steps = cert.get('steps') or []
    reach, final, dangling = _reachable(steps)
    evidence = [steps[i]['evidence'] for i in sorted(reach)
                if steps[i].get('op') == 'observe' and 'evidence' in steps[i]]
    contributing: list = []
    noncontributing: list = []
    for source in cert.get('source_map') or []:
        span = range(source.get('first_step', 0), source.get('last_step', -1) + 1)
        (contributing if any(i in reach for i in span)
         else noncontributing).append(source.get('source_id'))
    return {
        'total_steps': len(steps),
        'reachable_steps': len(reach),
        'unused_steps': len(steps) - len(reach),
        'final_step_index': final,
        'final_premises': (steps[final].get('premises')
                           if final is not None else None),
        # Supported == a final step exists and every premise reference reached
        # on the traversal resolves to a real step (no dangling premises).
        'final_claim_supported': final is not None and not dangling,
        'dangling_premises': sorted(i for i in dangling if i != -1),
        'malformed_premises': -1 in dangling,
        'evidence_dependencies': evidence,
        'source_coverage': {
            'contributing_sources': contributing,
            'noncontributing_sources': noncontributing,
        },
    }


def audit_run(run_dir) -> dict:
    """Audit a run directory; returns the report with run/claim identity."""
    run_dir = Path(run_dir)
    cert = json.loads((run_dir / 'certificate.json').read_text(encoding='utf-8'))
    report = audit_certificate(cert)
    report['run_id'] = json.loads(
        (run_dir / 'bundle.json').read_text(encoding='utf-8')
    )['payload']['run_id']
    report['claim_id'] = cert.get('claim_id')
    report['bundle_sha256'] = cert.get('bundle_sha256')
    return report
