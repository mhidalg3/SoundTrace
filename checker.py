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
from typing import Any

from constructor import ConstructionFailure, construct_certificate
from evidence import (Rejected, canonical_json, load_json, mac_matches,
                      sha256_hex)
from frontend import Rejected as FrontRejected, check_lean, compile_certificate
from oob_adapter import AUTHORITY, AdapterError, admit_oob
from runner import validate_bundle

LEAN_VERSION = '4.34.1'
TRUST_BOUNDARY = ('HMAC attests that the trusted runner recorded these bytes. Soundness '
                  'is relative to the reviewed C fixture, compiler, sanitizer runtime, '
                  'collector, host, and the private-key boundary; it is not a claim '
                  'about arbitrary malicious executables or exploitability.')


def _report(status: str, reason: str | None = None, **extra: Any) -> dict:
    out = {'status': status}
    if reason is not None:
        out['reason'] = reason
    out.update(extra)
    return out


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
              'evidence_class': AUTHORITY,
              'trust_boundary': TRUST_BOUNDARY}
    if not mac_matches(key, canonical_json(payload), bundle['hmac_sha256']):
        return _report('REJECTED', 'AUTHENTICATION_FAILED',
                       diagnostic='bundle MAC verification failed', **report)
    if not isinstance(cert, dict) or not isinstance(cert.get('claim_id'), str):
        return _report('REJECTED', 'BAD_INPUT', diagnostic='certificate must be an object '
                       'with a claim_id', **report)
    claim_id = cert['claim_id']
    report['claim_id'] = claim_id

    try:
        manifest, argument = admit_oob(payload, claim_id)
    except AdapterError as exc:
        return _report(exc.status, exc.reason, diagnostic=exc.diagnostic, **report)
    except Rejected as exc:
        return _report('REJECTED', 'BAD_INPUT', diagnostic=str(exc), **report)

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
    try:
        code, preflight = compile_certificate(manifest, cert)
    except FrontRejected as exc:
        return _report('REJECTED', 'SOURCE_ALIGNMENT_FAILED', diagnostic=str(exc), **report)

    backend = check_lean(code, lean, timeout=timeout)
    status = backend['status']
    if status == 'KERNEL_VERIFIED_RELATIVE_TO_MANIFEST':
        return _report('VERIFIED_OBSERVATION_BACKED',
                       claim_id=claim_id, run_id=payload['run_id'],
                       evidence_class=AUTHORITY, steps=preflight['steps'],
                       backend={'version': backend.get('backend_version', LEAN_VERSION),
                                'axiom_audit': 'empty'},
                       trust_boundary=TRUST_BOUNDARY)
    out = _report(status, backend.get('reason'),
                  diagnostic=backend.get('diagnostic', ''), claim_id=claim_id,
                  run_id=payload['run_id'], evidence_class=AUTHORITY,
                  trust_boundary=TRUST_BOUNDARY)
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
    if status == 'VERIFIED_OBSERVATION_BACKED':
        return 0
    if status == 'REJECTED':
        return 1
    return 2


if __name__ == '__main__':
    sys.exit(main())
