"""Strict JSON loading, canonical serialization, and authentication primitives.

Shared by every SoundTrace component so that no two parsing or hashing
conventions can diverge.  All JSON accepted from disk or from child processes
goes through this module: duplicate object keys, nonfinite numbers, and
unparseable or pathologically nested input are rejected input, never silently
reinterpreted.  Canonical bytes are the single hashing basis for registry
digests, bundle digests, and HMACs.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
from pathlib import Path
from typing import Any

LIMIT_BYTES = 1_000_000


class Rejected(ValueError):
    """Input rejected before any proof or verification decision is made."""


def require(test: bool, message: str) -> None:
    if not test:
        raise Rejected(message)


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict:
    obj: dict = {}
    for key, value in pairs:
        if key in obj:
            raise Rejected(f'duplicate JSON object key: {key!r}')
        obj[key] = value
    return obj


def _parse_constant(name: str) -> Any:
    raise Rejected(f'nonfinite JSON constant: {name}')


def _parse_float(text: str) -> float:
    value = float(text)
    require(math.isfinite(value), f'nonfinite JSON number: {text}')
    return value


def parse_json(text: str) -> Any:
    """Parse JSON text strictly; every malformed shape becomes Rejected."""
    require(isinstance(text, str), 'JSON input must be text')
    try:
        return json.loads(
            text,
            object_pairs_hook=_object_pairs,
            parse_constant=_parse_constant,
            parse_float=_parse_float,
        )
    except Rejected:
        raise
    except RecursionError as exc:
        raise Rejected('JSON nesting too deep') from exc
    except (json.JSONDecodeError, ValueError, TypeError) as exc:
        raise Rejected(f'invalid JSON: {exc}') from exc


def load_json(path: Path) -> dict:
    """Load a JSON object from a size-bounded file, strictly."""
    path = Path(path)
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise Rejected(f'cannot stat input file: {exc}') from exc
    require(size <= LIMIT_BYTES, 'input file size limit')
    try:
        text = path.read_text(encoding='utf-8')
    except (OSError, UnicodeDecodeError) as exc:
        raise Rejected(f'cannot read input file: {exc}') from exc
    value = parse_json(text)
    require(isinstance(value, dict), 'top-level JSON value must be an object')
    return value


def canonical_json(value: Any) -> bytes:
    """Deterministic UTF-8 serialization used for every digest and MAC.

    sort_keys makes key order irrelevant; compact separators and
    ensure_ascii=True pin the byte layout; allow_nan=False refuses values that
    strict parsing can never produce.  No trailing newline.
    """
    try:
        text = json.dumps(
            value,
            sort_keys=True,
            separators=(',', ':'),
            ensure_ascii=True,
            allow_nan=False,
        )
    except RecursionError as exc:
        raise Rejected('value too deeply nested to canonicalize') from exc
    except (TypeError, ValueError) as exc:
        raise Rejected(f'cannot canonicalize value: {exc}') from exc
    return text.encode('utf-8')


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def registry_digest(manifest: dict) -> str:
    """SHA-256 of the canonical manifest with its own registry_id omitted."""
    stripped = {k: v for k, v in manifest.items() if k != 'registry_id'}
    return sha256_hex(canonical_json(stripped))


def mac_hex(key: bytes, payload: bytes) -> str:
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def mac_matches(key: bytes, payload: bytes, claimed_hex: str) -> bool:
    if not isinstance(claimed_hex, str):
        return False
    try:
        expected = mac_hex(key, payload)
    except Rejected:
        return False
    return hmac.compare_digest(expected, claimed_hex)
