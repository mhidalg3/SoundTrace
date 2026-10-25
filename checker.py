#!/usr/bin/env python3
"""Observation-backed certificate verification.

`checker.py` is the only component that may report VERIFIED_OBSERVATION_BACKED.
Verification means, in order: strict loading, bundle schema validation, MAC
authentication against an external private key, re-admission of the selected
claim from authenticated raw events, deterministic reconstruction and
byte-comparison of the expected certificate for the recorded argument, the
generic frontend preflight, and the pinned Lean kernel with a complete empty
axiom audit. The generic `frontend.py --check` path reports only
KERNEL_VERIFIED_RELATIVE_TO_MANIFEST; preflight alone is never a verification
result.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from admission import admit_claim, trust_text_for
from constructor import ConstructionFailure, construct_certificate
from direct import DirectError, assemble_direct_certificate
from evidence import (Rejected, canonical_json, load_json, mac_matches,
                      sha256_hex)
from frontend import Rejected as FrontRejected, check_lean, compile_certificate
from oob_adapter import AUTHORITY, AdapterError
from runner import validate_bundle

LEAN_VERSION = '4.34.1'
TRUST_BOUNDARY = trust_text_for(AUTHORITY)


def _report(status: str, reason: str | None = None, **extra: Any) -> dict:
    out = {'status': status}
    if reason is not None:
        out['reason'] = reason
    out.update(extra)
    return out


def _classify_compile_error(message: str) -> str:
    """Map a frontend compile rejection to a stable reason.

    In direct mode the assembler does not judge arithmetic or inference, so
    these are first caught at the preflight; a specific reason keeps the
    poor-trace experiment's rejections meaningful.
    """
    m = message.lower()
    if 'limit' in m:
        return 'LIMIT_EXCEEDED'
    if 'establish the frozen claim' in m or 'claim from' in m:
        return 'CLAIM_MISMATCH'
    if 'arithmetic claim is false' in m:
        return 'FALSE_ARITHMETIC'
    if any(w in m for w in ('rule conclusion', 'unknown rule', 'premise', 'required',
                            'transport', 'conjunction', 'equality middle', 'equalities')):
        return 'INVALID_INFERENCE'
    if 'evidence' in m:
        return 'EVIDENCE_CONFLICT'
    return 'SOURCE_ALIGNMENT_FAILED'


def verify_certificate(bundle: dict, cert: dict, *, key: bytes, lean: str,
                       timeout: float = 10.0) -> dict:
    """Verify one certificate against its signed bundle; never accepts a
    replacement target, evidence authority, or bypass flag."""
    try:
        validate_bundle(bundle)
    except Rejected as exc:
        return _report('REJECTED', 'BAD_INPUT', diagnostic=str(exc))
    payload = bundle['payload']
    report = {'run_id': payload['run_id'],
              'evidence_class': payload.get('producer', AUTHORITY),
              'trust_boundary': trust_text_for(payload.get('producer'))}
    if not mac_matches(key, canonical_json(payload), bundle['hmac_sha256']):
        return _report('REJECTED', 'AUTHENTICATION_FAILED',
                       diagnostic='bundle MAC verification failed', **report)
    if not isinstance(cert, dict) or not isinstance(cert.get('claim_id'), str):
        return _report('REJECTED', 'BAD_INPUT', diagnostic='certificate must be an object '
                       'with a claim_id', **report)
    claim_id = cert['claim_id']
    report['claim_id'] = claim_id

    mode = _argument_mode(payload, claim_id)
    if mode == 'mixed':
        return _report('REJECTED', 'BAD_INPUT',
                       diagnostic='argument mixes direct (emit) and intermediate (reason) entries',
                       **report)
    if mode == 'abstained':
        return _report('UNSUPPORTED_TRANSLATION', 'UNSUPPORTED_TRANSLATION',
                       diagnostic='argument was closed by a translation abstention; '
                                  'no proof was fabricated', **report)

    if mode == 'direct':
        return _verify_direct(payload, cert, claim_id, report, lean=lean, timeout=timeout)

    try:
        manifest, argument = admit_claim(payload, claim_id)
    except AdapterError as exc:
        return _report(exc.status, exc.reason, diagnostic=exc.diagnostic, **report)
    except Rejected as exc:
        return _report('REJECTED', 'BAD_INPUT', diagnostic=str(exc))

    bundle_sha256 = sha256_hex(canonical_json(payload))
    try:
        expected = construct_certificate(manifest, argument,
                                         bundle_sha256=bundle_sha256)
    except ConstructionFailure as exc:
        claims = manifest.get('claims') if isinstance(manifest, dict) else None
        target = next(iter(claims.values()), {}) if isinstance(claims, dict) and claims else {}
        outcome_shaped = isinstance(target, dict) and set(target) == {'state', 'reason'}
        if exc.status == 'UNSUPPORTED_TRACE' or outcome_shaped or exc.reason == 'CLAIM_MISMATCH':
            extra = {k: v for k, v in exc.report().items() if k in ('source_id', 'step')}
            return _report(exc.status, exc.reason, diagnostic=str(exc), **report, **extra)
        # At the reconstruction boundary the contract under test is alignment
        # between the submitted certificate and the recorded argument; a bound
        # argument that cannot reconstruct is a source-alignment failure, with
        # the underlying defect preserved in the diagnostic.
        detail = f'{exc.status}/{exc.reason}'
        if exc.source_id:
            detail += f' at source node {exc.source_id}'
        return _report('REJECTED', 'SOURCE_ALIGNMENT_FAILED',
                       diagnostic=f'recorded argument does not reconstruct: '
                                  f'{detail}: {exc.diagnostic}', **report)
    if canonical_json(expected) != canonical_json(cert):
        return _report('REJECTED', 'SOURCE_ALIGNMENT_FAILED',
                       diagnostic='certificate does not byte-match the deterministic '
                                  'reconstruction of the recorded argument', **report)
    return _finish(manifest, cert, report, payload, lean, timeout,
                   'VERIFIED_OBSERVATION_BACKED', classify_compile=False)


def _argument_mode(payload: dict, claim_id: str) -> str:
    has_emit = has_reason = has_abstain = False
    for entry in payload['trace']:
        if entry['kind'] != 'request':
            continue
        body = entry['body']
        if body.get('argument_id') != claim_id:
            continue
        if body.get('kind') == 'emit':
            has_emit = True
        elif body.get('kind') == 'reason':
            has_reason = True
        elif body.get('kind') == 'translation_abstain':
            has_abstain = True
    if has_emit and has_reason:
        return 'mixed'
    if has_emit:
        return 'direct'
    if has_abstain:
        return 'abstained'
    if has_reason:
        return 'intermediate'
    return 'none'


def _verify_direct(payload: dict, cert: dict, claim_id: str, report: dict, *,
                   lean: str, timeout: float) -> dict:
    """Direct (signed-output) path: reconstruct from signed emissions, byte-match,
    then run the kernel; the headline result is VERIFIED_EVIDENCE_AND_KERNEL."""
    bundle_sha256 = sha256_hex(canonical_json(payload))
    try:
        manifest, _ = admit_claim(payload, claim_id)
    except AdapterError as exc:
        return _report(exc.status, exc.reason, diagnostic=exc.diagnostic, **report)
    except Rejected as exc:
        return _report('REJECTED', 'BAD_INPUT', diagnostic=str(exc), **report)
    try:
        expected = assemble_direct_certificate(payload, claim_id, bundle_sha256=bundle_sha256)
    except DirectError as exc:
        extra = {'source_id': exc.source_id} if exc.source_id else {}
        return _report(exc.status, exc.reason, diagnostic=exc.diagnostic, **report, **extra)
    if canonical_json(expected) != canonical_json(cert):
        return _report('REJECTED', 'SOURCE_ALIGNMENT_FAILED',
                       diagnostic='certificate does not byte-match the signed translator '
                                  'emissions', **report)
    return _finish(manifest, cert, report, payload, lean, timeout,
                   'VERIFIED_EVIDENCE_AND_KERNEL')


def _finish(manifest: dict, cert: dict, report: dict, payload: dict, lean: str,
            timeout: float, verified_status: str,
            *, classify_compile: bool = True) -> dict:
    """Shared tail: frontend preflight + pinned Lean kernel + result mapping."""
    try:
        code, preflight = compile_certificate(manifest, cert)
    except FrontRejected as exc:
        reason = (_classify_compile_error(str(exc))
                  if classify_compile else 'SOURCE_ALIGNMENT_FAILED')
        return _report('REJECTED', reason, diagnostic=str(exc), **report)
    backend = check_lean(code, lean, timeout=timeout)
    status = backend['status']
    if status == 'KERNEL_VERIFIED_RELATIVE_TO_MANIFEST':
        return _report(verified_status, **report, steps=preflight['steps'],
                       backend={'version': backend.get('backend_version', LEAN_VERSION),
                                'axiom_audit': 'empty'})
    out = _report(status, backend.get('reason'),
                  diagnostic=backend.get('diagnostic', ''), **report)
    if 'axiom_audit' in backend:
        out['backend'] = {'version': backend.get('backend_version', LEAN_VERSION),
                          'axiom_audit': backend['axiom_audit']}
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('bundle', type=Path)
    parser.add_argument('certificate', type=Path)
    parser.add_argument('--key', required=True, type=Path)
    parser.add_argument('--lean', required=True)
    parser.add_argument('--timeout', type=float, default=10.0)
    args = parser.parse_args()
    try:
        bundle = load_json(args.bundle)
        cert = load_json(args.certificate)
        key = args.key.read_bytes()
    except (Rejected, OSError) as exc:
        print(json.dumps(_report('REJECTED', 'BAD_INPUT', diagnostic=str(exc)), indent=2))
        return 1
    result = verify_certificate(bundle, cert, key=key, lean=args.lean,
                                timeout=args.timeout)
    print(json.dumps(result, indent=2))
    status = result['status']
    if status in ('VERIFIED_OBSERVATION_BACKED', 'VERIFIED_EVIDENCE_AND_KERNEL'):
        return 0
    if status == 'REJECTED':
        return 1
    return 2


if __name__ == '__main__':
    sys.exit(main())
