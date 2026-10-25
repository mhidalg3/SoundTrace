#!/usr/bin/env python3
"""Direct-mode (signed-output) certificate assembly.

In direct mode there is no typed reasoning trace and no deterministic
constructor: the untrusted translator emits blocks of primitive certificate
steps live, and the runner signs each emission into its ordered log. The
certificate is then *assembled* — never invented — by concatenating those
signed emissions in order. The same function is used by the assembler CLI and
by the checker's reconstruction, so the two cannot drift.

Assembly enforces the live-provenance invariant that gives the certificate its
meaning: every observation step may cite only evidence the runner delivered
*before that emission's log position*. It does not judge arithmetic truth or
rule validity — those are the checker's and the kernel's job, so representable
bad reasoning survives assembly and is rejected downstream with a specific
reason.
"""
from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path
from typing import Any

from admission import admit_claim
from evidence import (Rejected, canonical_json, load_json, mac_matches, require,
                      sha256_hex)
from frontend import PROFILE, Rejected as FrontendRejected, check_id
from oob_adapter import AdapterError


class DirectError(Exception):
    """Direct-mode assembly failure: status + stable reason + optional source."""

    def __init__(self, status: str, reason: str, source_id: str | None = None,
                 diagnostic: str = ''):
        super().__init__(diagnostic or f'{status}/{reason}')
        self.status = status
        self.reason = reason
        self.source_id = source_id
        self.diagnostic = diagnostic or f'{status}/{reason}'

    def report(self) -> dict:
        out = {'status': self.status, 'reason': self.reason, 'diagnostic': self.diagnostic}
        if self.source_id is not None:
            out['source_id'] = self.source_id
        return out


def emissions_for_argument(payload: dict, claim_id: str) -> list[dict]:
    """Signed `emit` entries for one argument, in log order, with positions."""
    emissions = []
    for entry in payload['trace']:
        if entry['kind'] != 'request':
            continue
        body = entry['body']
        if body.get('kind') == 'emit' and body.get('argument_id') == claim_id:
            emission = {'seq': entry['seq'], 'id': body['id'], 'steps': body['steps']}
            if 'source_seq' in body:
                emission['source_seq'] = body['source_seq']
            emissions.append(emission)
    return emissions


def assemble_direct_certificate(payload: dict, claim_id: str, *,
                                bundle_sha256: str) -> dict:
    """Assemble the direct-mode certificate from signed emissions.

    Pure concatenation plus the per-emission availability check; raises
    DirectError on an empty argument or a provenance violation.
    """
    try:
        manifest, _ = admit_claim(payload, claim_id)
    except AdapterError as exc:
        raise DirectError(exc.status, exc.reason, diagnostic=exc.diagnostic) from exc
    except Rejected as exc:
        raise DirectError('REJECTED', 'BAD_INPUT', diagnostic=str(exc)) from exc

    target = manifest['claims'].get(claim_id, {})
    if 'state' in target:  # unsuccessful frozen outcome has no bound certificate
        status = 'REJECTED' if target['state'] != 'unsupported' else 'UNSUPPORTED_TRACE'
        if target.get('reason') == 'UNSUPPORTED_TRANSLATION':
            status = 'UNSUPPORTED_TRANSLATION'
        raise DirectError(status, target.get('reason', 'CLAIM_MISMATCH'),
                          diagnostic='frozen claim outcome is not bound')

    records = manifest['records']
    emissions = emissions_for_argument(payload, claim_id)
    if not emissions:
        raise DirectError('UNSUPPORTED_TRACE', 'MISSING_OBSERVATION',
                          diagnostic=f'no signed emissions for argument {claim_id!r}')

    steps: list[dict] = []
    source_map: list[dict] = []
    for emission in emissions:
        source_id = emission['id']
        try:
            check_id(source_id, 'emission id')
        except FrontendRejected as exc:
            raise DirectError('REJECTED', 'BAD_INPUT', diagnostic=str(exc)) from exc
        first = len(steps)
        cutoff = emission['source_seq'] if 'source_seq' in emission else emission['seq']
        # `records` is the SELECTED claim's scope (admission). The live runner's
        # self.observations spans every delivered execution, so an emission
        # citing another execution's evidence is accepted live but rejected here
        # (unknown evidence) before it could reach compile_certificate's scope
        # check — the offline assembly is the decisive provenance gate, and a
        # cross-scope citation is rejected either way. CyberGym emissions are
        # additionally held to the narration cutoff: evidence must predate the
        # words being translated, not merely the emission (the adapter already
        # re-derived this; the check here is the assembler's own gate).
        for step in emission['steps']:
            if isinstance(step, dict) and step.get('op') == 'observe':
                evidence = step.get('evidence')
                record = records.get(evidence) if isinstance(evidence, str) else None
                if record is None:
                    raise DirectError('REJECTED', 'SOURCE_ALIGNMENT_FAILED', source_id,
                                      diagnostic=f'emission cites unknown evidence {evidence!r}')
                if not record['available_at'] < cutoff:
                    raise DirectError('REJECTED', 'SOURCE_ALIGNMENT_FAILED', source_id,
                                      diagnostic='emission cites evidence not delivered '
                                               'before its source narration')
            steps.append(copy.deepcopy(step))
        source_map.append({'source_id': source_id, 'first_step': first,
                           'last_step': len(steps) - 1})

    cert = {'profile': PROFILE, 'registry_id': manifest['registry_id'],
            'claim_id': claim_id, 'bundle_sha256': bundle_sha256,
            'steps': steps, 'source_map': source_map}
    try:
        require(len(canonical_json(cert)) + 1 <= 1_000_000, 'serialized certificate byte limit')
    except Rejected as exc:
        raise DirectError('REJECTED', 'LIMIT_EXCEEDED', emissions[-1]['id'],
                          diagnostic=str(exc)) from exc
    return cert


def write_certificate(path: Path, cert: dict) -> None:
    path.write_bytes(canonical_json(cert) + b'\n')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('bundle', type=Path)
    parser.add_argument('--claim', required=True)
    parser.add_argument('--key', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    from runner import validate_bundle
    try:
        bundle = load_json(args.bundle)
        validate_bundle(bundle)
        key = args.key.read_bytes()
        payload = bundle['payload']
        if not mac_matches(key, canonical_json(payload), bundle['hmac_sha256']):
            print(json.dumps({'status': 'REJECTED', 'reason': 'AUTHENTICATION_FAILED',
                              'diagnostic': 'bundle MAC verification failed'}, indent=2))
            return 1
        cert = assemble_direct_certificate(payload, args.claim,
                                           bundle_sha256=sha256_hex(canonical_json(payload)))
        write_certificate(args.out, cert)
        print(json.dumps({'status': 'ASSEMBLED', 'claim_id': args.claim,
                          'steps': len(cert['steps']),
                          'emissions': len(cert['source_map']),
                          'certificate': str(args.out)}, indent=2))
        return 0
    except DirectError as exc:
        print(json.dumps(exc.report(), indent=2))
        return 1 if exc.status == 'REJECTED' else 2
    except (Rejected, FrontendRejected, OSError, ValueError) as exc:
        print(json.dumps({'status': 'REJECTED', 'reason': 'BAD_INPUT',
                          'diagnostic': str(exc)}, indent=2))
        return 1


if __name__ == '__main__':
    sys.exit(main())
