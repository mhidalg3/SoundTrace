"""Producer-dispatched claim admission.

`direct.py` and `checker.py` call `admit_claim` instead of binding to the
fixture producer. The fixture path delegates unchanged to `oob_adapter`;
the CyberGym path revalidates the exact machine event, task/image/PoC
binding, delivery position, translation-attempt hashes, source-narration
alignment, and the frozen claim. Dispatch is exact on the signed producer
string — there is no fallback and no union across producers.
"""
from __future__ import annotations

from typing import Any

from oob_adapter import AdapterError, admit_oob
from soundtrace_live.cybergym_adapter import AUTHORITY as CYBERGYM_AUTHORITY
from soundtrace_live.cybergym_adapter import admit_cybergym

FIXTURE_AUTHORITY = 'controlled-c-asan-v1'

PRODUCER_TRUST = {
    FIXTURE_AUTHORITY: (
        'HMAC attests that the trusted runner recorded these bytes. Soundness '
        'is relative to the reviewed C fixture, compiler, sanitizer runtime, '
        'collector, host, and the private-key boundary; it is not a claim '
        'about arbitrary malicious executables or exploitability.'
    ),
    CYBERGYM_AUTHORITY: (
        'HMAC attests that the trusted runner recorded these bytes. Soundness '
        'is relative to the pinned CyberGym image, its sanitizer runtime, the '
        'reviewed preload shim, the Docker host and orchestrator, and the '
        'private-key boundary; a deliberately malicious or exploited target '
        'process could still attack its in-container side channel, so this is '
        'not a claim about arbitrary malicious executables or exploitability.'
    ),
}


def trust_text_for(producer: Any) -> str:
    return PRODUCER_TRUST.get(producer, PRODUCER_TRUST[FIXTURE_AUTHORITY])


def admit_claim(payload: dict, claim_id: str) -> tuple[dict, list]:
    """Re-derive the manifest and recorded argument for one selected claim."""
    producer = payload.get('producer')
    if producer == FIXTURE_AUTHORITY:
        return admit_oob(payload, claim_id)
    if producer == CYBERGYM_AUTHORITY:
        return admit_cybergym(payload, claim_id)
    raise AdapterError('BAD_INPUT', f'unknown evidence producer {producer!r}')
