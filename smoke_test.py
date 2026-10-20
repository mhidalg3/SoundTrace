#!/usr/bin/env python3
"""Deterministic end-to-end driver over the real runner/constructor/checker CLIs.

These are real environment executions with synthetic authored arguments
(labeled `scripted_structured_trace`), not collected LLM-agent trajectories.
Everything is written under a caller-provided temporary work directory; no
historical results file inside the repository is touched, and Lean kernel runs
are counted only when the pinned backend actually executed.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PYTHON = sys.executable

CASES = [
    ('read_upper', 'VERIFIED_OBSERVATION_BACKED', None),
    ('write_upper', 'VERIFIED_OBSERVATION_BACKED', None),
    ('read_lower', 'VERIFIED_OBSERVATION_BACKED', None),
    ('write_lower', 'VERIFIED_OBSERVATION_BACKED', None),
    ('read_in_bounds', 'REJECTED', 'FALSE_ARITHMETIC'),
    ('write_in_bounds', 'REJECTED', 'FALSE_ARITHMETIC'),
    ('read_patched', 'UNSUPPORTED_TRACE', 'MISSING_ACCESS_EVIDENCE'),
    ('write_patched', 'UNSUPPORTED_TRACE', 'MISSING_ACCESS_EVIDENCE'),
]


def run(command, stdin_text=None):
    proc = subprocess.run(command, input=stdin_text, capture_output=True, text=True)
    return proc.returncode, proc.stdout, proc.stderr


def stage(work, case, expect_status, expect_reason, key, lean, report):
    bundle = work / f'{case}.bundle.json'
    session = (ROOT / 'examples' / 'sessions' / f'{case}.jsonl').read_text()
    rc, out, err = run([PYTHON, 'runner.py', 'record', '--key', str(key),
                        '--out', str(bundle)], stdin_text=session)
    record = {'case': case, 'trace_label': 'scripted_structured_trace'}
    if rc != 0 or not bundle.is_file():
        report['cases'].append({**record, 'stage': 'record', 'status': 'INCONCLUSIVE_CAPTURE',
                                'exit_code': rc, 'diagnostic': (out + err)[:500]})
        return False
    record['recorded'] = True
    cert = work / f'{case}.certificate.json'
    rc, out, err = run([PYTHON, 'constructor.py', str(bundle), '--claim', 'C1',
                        '--key', str(key), '--out', str(cert)])
    try:
        constructed = json.loads(out)
    except json.JSONDecodeError:
        constructed = {'status': 'CRASH', 'diagnostic': (out + err)[:500]}
    record['constructor'] = {k: constructed.get(k) for k in ('status', 'reason', 'source_id')}
    if expect_status == 'VERIFIED_OBSERVATION_BACKED':
        if constructed.get('status') != 'CONSTRUCTED':
            report['cases'].append({**record, 'stage': 'construct'})
            return False
        rc, out, err = run([PYTHON, 'checker.py', str(bundle), str(cert),
                            '--key', str(key), '--lean', lean])
        try:
            checked = json.loads(out)
        except json.JSONDecodeError:
            checked = {'status': 'CRASH', 'diagnostic': (out + err)[:500]}
        record['checker'] = {k: checked.get(k) for k in ('status', 'reason')}
        if checked.get('status') == 'VERIFIED_OBSERVATION_BACKED':
            report['lean_kernel_runs'] += 1
        report['cases'].append(record)
        return checked.get('status') == expect_status
    # Expected to stop at construction with the specified outcome.
    ok = (constructed.get('status') == expect_status
          and (expect_reason is None or constructed.get('reason') == expect_reason))
    record['checker'] = {'status': 'NOT_RUN_EXPECTED_CONSTRUCTOR_FAILURE'}
    report['cases'].append(record)
    return ok


def fixture_stages(work, lean, report):
    ok = True
    from evidence import canonical_json, sha256_hex
    from constructor import construct_certificate
    from frontend import compile_certificate

    for name, directory in (('arithmetic', ROOT / 'examples'),
                            ('transfer', ROOT / 'examples' / 'transfer')):
        manifest = json.loads((directory / 'manifest.json').read_text())
        argument = json.loads((directory / 'argument.json').read_text())
        digest = sha256_hex(canonical_json(argument))
        cert = construct_certificate(manifest, argument, bundle_sha256=digest)
        on_disk = (directory / 'certificate.json').read_bytes()
        entry = {'fixture': name, 'trace_label': 'synthetic_authored_argument'}
        if canonical_json(cert) + b'\n' != on_disk:
            entry['deterministic_regeneration'] = 'MISMATCH'
            ok = False
        else:
            entry['deterministic_regeneration'] = 'BYTE_IDENTICAL'
        code, result = compile_certificate(manifest, json.loads(on_disk))
        out_lean = work / f'{name}.Certificate.lean'
        out_lean.write_text(code)
        rc, out, err = run([PYTHON, 'frontend.py', str(directory / 'manifest.json'),
                            str(directory / 'certificate.json'), '--out', str(out_lean),
                            '--check', '--lean', lean])
        try:
            checked = json.loads(out)
        except json.JSONDecodeError:
            checked = {'status': 'CRASH', 'diagnostic': (out + err)[:500]}
        entry['kernel_status'] = checked.get('status')
        if checked.get('status') == 'KERNEL_VERIFIED_RELATIVE_TO_MANIFEST':
            report['lean_kernel_runs'] += 1
        else:
            ok = False
        report['fixtures'].append(entry)
    return ok


def determinism_stage(work, key, lean, report):
    """Construct twice from the same signed bundle; bytes must be identical."""
    bundle = work / 'read_upper.bundle.json'
    cert_a = work / 'determinism.a.json'
    cert_b = work / 'determinism.b.json'
    run([PYTHON, 'constructor.py', str(bundle), '--claim', 'C1', '--key', str(key),
         '--out', str(cert_a)])
    run([PYTHON, 'constructor.py', str(bundle), '--claim', 'C1', '--key', str(key),
         '--out', str(cert_b)])
    identical = cert_a.read_bytes() == cert_b.read_bytes()
    entry = {'bundle': str(bundle), 'certificates_byte_identical': identical}
    if identical:
        from evidence import canonical_json
        from frontend import compile_certificate
        manifest_cert = json.loads(cert_a.read_text())
        bundle_payload = json.loads(bundle.read_text())['payload']
        from oob_adapter import admit_oob
        manifest, argument = admit_oob(bundle_payload, 'C1')
        from constructor import construct_certificate
        from evidence import sha256_hex
        rebuilt = construct_certificate(manifest, argument,
                                        bundle_sha256=sha256_hex(canonical_json(bundle_payload)))
        code_a, _ = compile_certificate(manifest, manifest_cert)
        code_b, _ = compile_certificate(manifest, rebuilt)
        entry['generated_lean_identical'] = code_a == code_b
    report['determinism'] = entry
    return identical and entry.get('generated_lean_identical', False)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lean', required=True)
    parser.add_argument('--work-dir', required=True, type=Path)
    args = parser.parse_args()
    work = args.work_dir
    work.mkdir(parents=True, exist_ok=True)
    key = work / 'runner.key'
    if key.exists():
        print(json.dumps({'status': 'REJECTED', 'reason': 'BAD_INPUT',
                          'diagnostic': 'refusing to overwrite an existing runner key'},
                         indent=2))
        return 1
    rc, out, err = run([PYTHON, 'runner.py', 'keygen', '--out', str(key)])
    if rc != 0:
        print(json.dumps({'status': 'REJECTED', 'reason': 'BAD_INPUT',
                          'diagnostic': (out + err)[:500]}, indent=2))
        return 1

    report = {'evaluation_type': 'scripted_structured_trace_end_to_end',
              'real_environment_executions': 0,
              'real_agent_trajectories': 0,
              'model_calls': 0,
              'lean_kernel_runs': 0,
              'cases': [], 'fixtures': [], 'determinism': {}}
    ok = True
    for case, expect_status, expect_reason in CASES:
        report['real_environment_executions'] += 1
        ok = stage(work, case, expect_status, expect_reason, key, args.lean, report) and ok
    ok = fixture_stages(work, args.lean, report) and ok
    ok = determinism_stage(work, key, args.lean, report) and ok

    if args.lean and report['lean_kernel_runs'] == 0:
        report['lean_status'] = 'BACKEND_NEVER_ACCEPTED_ANY_PROOF'
        ok = False
    else:
        report['lean_status'] = f"{report['lean_kernel_runs']} kernel runs"
    report['all_expected_outcomes_matched'] = ok
    print(json.dumps(report, indent=2))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
