#!/usr/bin/env python3
"""Render the Columbia campaigns 1–3 research presentation package offline."""
from __future__ import annotations

import argparse
import csv
import hashlib
import html
import json
import math
import os
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True

DEFAULT_OUTPUT = "artifacts/columbia-campaigns-1-3-visuals"
EXISTING_OUTPUT_ERROR = "Output directory already exists; choose a new --output directory."
WIDTH, HEIGHT, FPS, FRAME_COUNT = 1920, 1080, 24, 2880
NAVY = "#102A43"
ACCENT = "#4A90C2"
BODY = "#243B53"
GREEN = "#167D5A"
BLUE = "#2463A6"
AMBER = "#A66B00"
RED = "#B54747"
GREY = "#E5EAF0"
PALE = "#F4F8FC"
WHITE = "#FFFFFF"
PROJECTS = {"arvo:64574": "jq", "arvo:47101": "binutils"}
STAGES = [
    "agent_investigation", "trusted_execution", "evidence_delivery",
    "claim_submission", "translation", "checker", "lean_kernel",
]
EXPECTED_ROWS = [
    (1, "jq", "vul", "Rc0a556b7c354a142fb6f8bfeace8a4fb", "NO_DEMONSTRATION", "UNSUPPORTED_TRANSLATION", 18, 1314.820, 1, 1),
    (1, "jq", "fix", "R46866c091bc353c1aac24454dcc72436", "CONTROL_HELD", "AGENT_REPORTED_NONE", 19, 1739.569, 2, 0),
    (1, "binutils", "vul", "R7f58de04bdf4d7abc00ace6c578e0725", "NO_DEMONSTRATION", "UNSUPPORTED_TRANSLATION", 13, 442.296, 1, 1),
    (1, "binutils", "fix", "R664515022c6ae955c3ce7c0e6921db59", "CONTROL_HELD", "AGENT_REPORTED_NONE", 16, 1454.015, 1, 0),
    (2, "jq", "vul", "R3bbaad5a88b476ee25949d375f811c2b", "INSUFFICIENT_EVIDENCE", "INCONCLUSIVE_MODEL_API", 21, 1016.885, 1, 1),
    (2, "binutils", "vul", "Rf71d84305aa7a16f8a49153e1aa16f8e", "OOB_VERIFIED", "COMPLETED", 10, 425.733, 1, 1),
    (3, "jq", "vul", "Rfd7e54b7965e046b55c3f3ad3b547a58", "OOB_VERIFIED", "COMPLETED", 21, 1775.418, 2, 1),
]
SAFE_EXCERPT = (
    "Probe X2/A1 observed a live write access out of bounds: the region extent "
    "is 16 bytes and the access is at offset 16 with width 1, both positive, "
    "so the boundary comparison extent < offset+width holds, and these "
    "observations are conjunct."
)
CAPTIONS = [
    (0, 8, "SoundTrace links public agent work logs to recorded evidence and kernel-checked certificates."),
    (8, 16, "The Pilot sends one public reasoning_chunk and one action. It is a visible work log—not hidden reasoning."),
    (16, 24, "Runner records narration before action execution, then returns the observed tool result on the next turn."),
    (24, 34, "Source and shell exploration are audited context, but they do not supply trusted memory premises."),
    (34, 44, "A separate ASan-instrumented probe records scoped observations: access, live, extent 16, offset 16, width 1."),
    (44, 54, "Evidence from X2/A1 already existed before public narration sequence 241 cited it."),
    (54, 64, "Translator emission X2-A1-upper, attempt TA21, records 26 observe, compute, and infer steps with provenance."),
    (64, 72, "At termination, Runner HMAC-seals the complete bundle once; assembly does not repair the translation."),
    (72, 80, "Recorded verdict: VERIFIED_EVIDENCE_AND_KERNEL, Lean 4.34.1, with an empty axiom audit."),
    (80, 88, "Campaign 1 ran both tasks on vulnerable and patched builds; campaigns 2 and 3 were selective follow-ups."),
    (88, 96, "Two C1 translations were unsupported, C2 jq reached a translator deadline, and two later episodes verified."),
    (96, 103, "The binutils certificate uses all 17 of 17 steps on the final dependency path."),
    (103, 110, "The jq certificate uses 19 of 52 steps; 33 are outside the final path—63.46%, not 63% incorrect."),
    (110, 116, "Admissible evidence appeared in all five vulnerable attempts; two of five produced final certificates."),
    (116, 120, "Both patched controls held. This small, selectively repeated cohort supports no general safety or false-positive-rate claim."),
]


def fail(message: str) -> None:
    raise RuntimeError(message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def formula_text(value: Any) -> str:
    if not isinstance(value, list) or not value:
        return str(value)
    op = value[0]
    if op == "atom" and len(value) == 2:
        return str(value[1])
    if op in {"eq", "lt", "le"} and len(value) == 3:
        symbol = {"eq": "=", "lt": "<", "le": "≤"}[op]
        return f"{formula_text(value[1])} {symbol} {formula_text(value[2])}"
    if op in {"add", "sub"} and len(value) == 3:
        symbol = "+" if op == "add" else "−"
        return f"{formula_text(value[1])} {symbol} {formula_text(value[2])}"
    if op == "and" and len(value) == 3:
        return f"{formula_text(value[1])} ∧ {formula_text(value[2])}"
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def bootstrap_output(repo: Path, requested: str) -> Path:
    candidate = Path(requested)
    if not candidate.is_absolute():
        candidate = repo / candidate
    candidate = candidate.absolute()
    if os.path.lexists(candidate):
        print(EXISTING_OUTPUT_ERROR, file=sys.stderr)
        raise SystemExit(2)
    try:
        os.mkdir(candidate)
    except FileExistsError:
        print(EXISTING_OUTPUT_ERROR, file=sys.stderr)
        raise SystemExit(2)
    except OSError as exc:
        fail(f"Cannot create output directory {candidate}: {exc}")
    if candidate.is_symlink():
        fail(f"Refusing output-directory symlink: {candidate}")
    for name in ("data", "figures", "video", ".mplconfig", ".tmp", ".verification"):
        (candidate / name).mkdir()
    os.environ["MPLCONFIGDIR"] = str(candidate / ".mplconfig")
    os.environ["TMPDIR"] = str(candidate / ".tmp")
    return candidate


class Sources:
    def __init__(self, repo: Path):
        self.repo = repo
        self.hashes: dict[Path, str] = {}

    def record(self, path: Path) -> None:
        path = path.resolve()
        try:
            relative = path.relative_to(self.repo)
        except ValueError:
            fail(f"Input path escapes repository: {path}")
        try:
            before = sha256_file(path)
        except OSError as exc:
            fail(f"Cannot read source {relative}: {exc}")
        prior = self.hashes.get(relative)
        if prior is not None and prior != before:
            fail(f"Source changed during extraction: {relative}")
        self.hashes[relative] = before

    def load(self, path: Path) -> dict:
        from evidence import load_json
        self.record(path)
        try:
            value = load_json(path)
        except Exception as exc:
            fail(f"Invalid source JSON {path.relative_to(self.repo)}: {exc}")
        relative = path.resolve().relative_to(self.repo)
        try:
            after = sha256_file(path)
        except OSError as exc:
            fail(f"Cannot reread source {relative}: {exc}")
        if after != self.hashes[relative]:
            fail(f"Source changed while loading: {relative}")
        return value

    def verify(self) -> None:
        changed = [str(path) for path, digest in self.hashes.items()
                   if not (self.repo / path).is_file()
                   or sha256_file(self.repo / path) != digest]
        if changed:
            fail("Consumed sources changed during rendering: " + ", ".join(changed))

    def rows(self) -> list[dict[str, str]]:
        return [{"path": str(path), "sha256": digest}
                for path, digest in sorted(self.hashes.items(), key=lambda item: str(item[0]))]


def find_run_dir(sources: Sources, campaign_dir: Path, label: str, run_id: str) -> tuple[Path, dict]:
    root = campaign_dir / label
    if not root.is_dir():
        fail(f"Missing episode archive directory: {root.relative_to(sources.repo)}")
    matches: list[tuple[Path, dict]] = []
    for bundle_path in sorted(root.rglob("bundle.json")):
        bundle = sources.load(bundle_path)
        payload = bundle.get("payload")
        if isinstance(payload, dict) and payload.get("run_id") == run_id:
            matches.append((bundle_path.parent, bundle))
    if len(matches) != 1:
        fail(f"Expected one bundle for run {run_id} below {root.relative_to(sources.repo)}; found {len(matches)}")
    return matches[0]


def extract_dataset(repo: Path, sources: Sources) -> tuple[list[dict], dict, dict, dict]:
    from evidence import canonical_json
    from soundtrace_live.proof_audit import audit_certificate

    for path in (
        repo / "evidence.py", repo / "soundtrace_live/proof_audit.py",
        repo / "soundtrace_live/orchestrator.py", repo / "soundtrace_live/translator.py",
        repo / "runner.py", repo / "checker.py", repo / "soundtrace_live/agents/pilot.md",
    ):
        sources.record(path)

    audit_path = repo / "artifacts/v4-gate1/audit_reports.json"
    saved_audits = sources.load(audit_path)
    episodes: list[dict] = []
    certificate_audits: dict[str, dict] = {}
    representative: dict | None = None

    for campaign in (1, 2, 3):
        campaign_dir = repo / f"artifacts/live-2026-10-26/campaign-live-{campaign}"
        manifest_path = campaign_dir / "campaign.json"
        manifest = sources.load(manifest_path)
        entries = manifest.get("episodes")
        if not isinstance(entries, list):
            fail(f"Invalid episodes list: {manifest_path.relative_to(repo)}")
        for manifest_entry in entries:
            episode = manifest_entry.get("episode") or {}
            result = manifest_entry.get("result") or {}
            assessment = manifest_entry.get("assessment") or {}
            pipeline = manifest_entry.get("pipeline") or {}
            task_id = episode.get("task_id")
            if task_id not in PROJECTS:
                fail(f"Unknown task_id in {manifest_path.relative_to(repo)}: {task_id!r}")
            run_id = result.get("run_id")
            label = episode.get("label")
            run_dir, bundle = find_run_dir(sources, campaign_dir, label, run_id)
            adjacent_result = sources.load(run_dir / "result.json")
            metrics = sources.load(run_dir / "metrics.json")
            payload = bundle.get("payload") or {}
            for name, actual in (("bundle", payload.get("run_id")),
                                 ("result.json", adjacent_result.get("run_id")),
                                 ("metrics.json", metrics.get("run_id"))):
                if actual != run_id:
                    fail(f"Run identity mismatch in {run_dir.relative_to(repo)}/{name}: expected {run_id}, got {actual}")
            if adjacent_result != result:
                fail(f"Manifest/result contradiction: {run_dir.relative_to(repo)}/result.json")
            if payload.get("target_build") != episode.get("target_build"):
                fail(f"Target-build mismatch: {run_dir.relative_to(repo)}/bundle.json")

            trace = payload.get("trace")
            if not isinstance(trace, list):
                fail(f"Invalid trace: {run_dir.relative_to(repo)}/bundle.json")
            emission_count = sum(
                1 for item in trace
                if item.get("kind") == "request"
                and (item.get("body") or {}).get("kind") == "emit"
            )
            cert_path, checker_path = run_dir / "certificate.json", run_dir / "checker.json"
            verified = assessment.get("outcome") == "OOB_VERIFIED"
            if verified and (not cert_path.is_file() or not checker_path.is_file()):
                fail(f"Missing certificate/checker for verified run: {run_dir.relative_to(repo)}")
            if not verified and (cert_path.exists() or checker_path.exists()):
                fail(f"Unexpected final certificate/checker for uncertified run: {run_dir.relative_to(repo)}")

            audit = None
            cert = checker = None
            if verified:
                cert = sources.load(cert_path)
                checker = sources.load(checker_path)
                expected_bundle_sha = hashlib.sha256(canonical_json(payload)).hexdigest()
                checks = {
                    "certificate bundle hash": cert.get("bundle_sha256") == expected_bundle_sha,
                    "claim identity": cert.get("claim_id") == result.get("claim_id") == checker.get("claim_id"),
                    "checker run identity": checker.get("run_id") == run_id,
                    "checker status": checker.get("status") == result.get("checker_status") == "VERIFIED_EVIDENCE_AND_KERNEL",
                    "checker step count": checker.get("steps") == len(cert.get("steps") or []),
                    "Lean version": (checker.get("backend") or {}).get("version") == "4.34.1",
                    "axiom audit": (checker.get("backend") or {}).get("axiom_audit") == "empty",
                }
                for description, valid in checks.items():
                    if not valid:
                        fail(f"Contradictory {description}: {run_dir.relative_to(repo)}")
                audit = audit_certificate(cert)
                audit["source_coverage"] = audit.get("source_coverage")
                audit["unused_fraction"] = audit["unused_steps"] / audit["total_steps"]
                audit["bundle_sha256"] = cert["bundle_sha256"]
                audit["claim_id"] = cert["claim_id"]
                audit["checker_status"] = checker["status"]
                matches = [report for report in saved_audits.values()
                           if report.get("run_id") == run_id
                           and report.get("bundle_sha256") == cert["bundle_sha256"]]
                if len(matches) != 1:
                    fail(f"Audit crosscheck missing or ambiguous for run {run_id}: {audit_path.relative_to(repo)}")
                saved = matches[0]
                for key in ("total_steps", "reachable_steps", "unused_steps", "source_coverage"):
                    if audit[key] != saved[key]:
                        fail(f"Audit crosscheck mismatch for {run_id} field {key}")
                certificate_audits[run_id] = audit

            record = {
                "campaign": campaign,
                "project": PROJECTS[task_id],
                "task_id": task_id,
                "difficulty": episode.get("difficulty"),
                "label": label,
                "target_build": episode.get("target_build"),
                "run_id": run_id,
                "outcome": assessment.get("outcome"),
                "session_status": result.get("session_status"),
                "flag_success": result.get("flag_success"),
                "translation_status": result.get("translation_status"),
                "checker_status": result.get("checker_status"),
                "turns": result.get("turns"),
                "elapsed_s": result.get("elapsed_s"),
                "probe_count": result.get("probe_count"),
                "admissible_count": result.get("admissible_count"),
                "stopped_at": pipeline.get("stopped_at"),
                "emission_count": emission_count,
                "certificate_total_steps": audit["total_steps"] if audit else None,
                "certificate_reachable_steps": audit["reachable_steps"] if audit else None,
                "certificate_unused_steps": audit["unused_steps"] if audit else None,
                "certificate_unused_fraction": audit["unused_fraction"] if audit else None,
                "pipeline": pipeline,
                "assessment": assessment,
            }
            episodes.append(record)

            if run_id == "Rfd7e54b7965e046b55c3f3ad3b547a58":
                narration = [item for item in trace if item.get("seq") == 241]
                emission = [item for item in trace if item.get("seq") == 267]
                attempts = [item for item in trace
                            if item.get("kind") == "request"
                            and (item.get("body") or {}).get("kind") == "translation_attempt"
                            and (item.get("body") or {}).get("attempt_id") == "TA21"]
                if len(narration) != 1 or len(emission) != 1 or len(attempts) != 1:
                    fail(f"Representative provenance link missing: {run_dir.relative_to(repo)}/bundle.json")
                narration_body = narration[0].get("body") or {}
                emission_body = emission[0].get("body") or {}
                attempt_body = attempts[0].get("body") or {}
                if (narration_body.get("kind") != "narrate"
                        or not str(narration_body.get("text", "")).startswith(SAFE_EXCERPT)
                        or emission_body.get("kind") != "emit"
                        or emission_body.get("id") != "X2-A1-upper"
                        or emission_body.get("source_seq") != 241
                        or emission_body.get("attempt_id") != "TA21"
                        or attempt_body.get("source_seq") != 241
                        or len(emission_body.get("steps") or []) != 26):
                    fail(f"Representative provenance contradiction: {run_dir.relative_to(repo)}/bundle.json")
                evidence_records: dict[str, dict] = {}
                for item in trace:
                    body = item.get("body") or {}
                    for observation in body.get("observations") or []:
                        evidence_id = observation.get("id")
                        if not isinstance(evidence_id, str):
                            continue
                        if evidence_id in evidence_records:
                            fail(f"Duplicate representative evidence {evidence_id}: {run_dir.relative_to(repo)}/bundle.json")
                        evidence_records[evidence_id] = observation
                for step in emission_body["steps"]:
                    if step.get("op") != "observe":
                        continue
                    evidence_id = step.get("evidence")
                    observed = evidence_records.get(evidence_id)
                    if (observed is None
                            or type(observed.get("available_at")) is not int
                            or observed["available_at"] >= 241
                            or observed.get("formula") != step.get("formula")):
                        fail(f"Representative evidence was not available before narration 241: {evidence_id!r}")
                source_ranges = [source for source in cert.get("source_map") or []
                                 if source.get("source_id") == "X2-A1-upper"]
                if len(source_ranges) != 1:
                    fail(f"Representative emission missing from certificate source_map: {cert_path.relative_to(repo)}")
                source_range = source_ranges[0]
                first, last = source_range.get("first_step"), source_range.get("last_step")
                certificate_steps = cert.get("steps") or []
                if (type(first) is not int or type(last) is not int
                        or first < 0 or last < first or last >= len(certificate_steps)
                        or certificate_steps[first:last + 1] != emission_body["steps"]):
                    fail(f"Representative emission/certificate step mismatch: {cert_path.relative_to(repo)}")
                steps = emission_body["steps"]
                observations = [{"evidence": step["evidence"], "formula": step["formula"],
                                 "display": formula_text(step["formula"])}
                                for step in steps if step.get("op") == "observe"]
                representative = {
                    "run_id": run_id,
                    "narration_seq": 241,
                    "safe_excerpt": SAFE_EXCERPT,
                    "emission_seq": 267,
                    "emission_id": "X2-A1-upper",
                    "attempt_id": "TA21",
                    "source_seq": 241,
                    "step_count": 26,
                    "operation_names": sorted({step["op"] for step in steps}),
                    "evidence": observations,
                    "certificate_step_range": {"first_step": first, "last_step": last},
                }

    if representative is None:
        fail("Representative jq block was not found")
    actual_rows = [(r["campaign"], r["project"], r["target_build"], r["run_id"],
                    r["outcome"], r["session_status"], r["turns"], r["elapsed_s"],
                    r["probe_count"], r["admissible_count"]) for r in episodes]
    if len(actual_rows) != len(EXPECTED_ROWS):
        fail(f"Expected 7 episodes; found {len(actual_rows)}")
    for actual, expected in zip(actual_rows, EXPECTED_ROWS):
        if actual[:7] != expected[:7] or actual[8:] != expected[8:] \
                or not math.isclose(actual[7], expected[7], abs_tol=1e-6):
            fail(f"Manifest acceptance row mismatch: expected {expected}, got {actual}")
    if {(a["total_steps"], a["reachable_steps"], a["unused_steps"])
            for a in certificate_audits.values()} != {(17, 17, 0), (52, 19, 33)}:
        fail("Certificate audit acceptance totals do not match 17/17/0 and 52/19/33")
    c2_jq = next(row for row in episodes if row["campaign"] == 2 and row["project"] == "jq")
    if c2_jq["emission_count"] != 2 or c2_jq["certificate_total_steps"] is not None:
        fail("C2 jq must retain two intermediate emissions and no final certificate")

    vulnerable = [row for row in episodes if row["target_build"] == "vul"]
    controls = [row for row in episodes if row["target_build"] == "fix"]
    final_certificates = [row for row in episodes if row["certificate_total_steps"] is not None]
    held_controls = [row for row in controls if row["outcome"] == "CONTROL_HELD"]
    false_positive_controls = [row for row in controls
                               if row["assessment"].get("false_positive") is True]
    unsupported = [row for row in episodes
                   if row["translation_status"] == "UNSUPPORTED_TRANSLATION"]
    deadlines = [row for row in episodes
                 if row["session_status"] == "INCONCLUSIVE_MODEL_API"
                 and row["stopped_at"] == "translation"]
    vulnerable_admissible = [row for row in vulnerable if row["admissible_count"] > 0]
    c1_flagged_uncertified = [row for row in vulnerable
                              if row["campaign"] == 1
                              and row["flag_success"] is True
                              and row["certificate_total_steps"] is None]
    campaign_counts = Counter(row["campaign"] for row in episodes)
    summary = {
        "campaign_episode_counts": {str(key): campaign_counts[key] for key in sorted(campaign_counts)},
        "tasks": len({row["task_id"] for row in episodes}),
        "episodes": len(episodes),
        "vulnerable_attempts": len(vulnerable),
        "patched_controls": len(controls),
        "final_certificates": len(final_certificates),
        "certificate_rate_numerator": len(final_certificates),
        "certificate_rate_denominator_vulnerable_attempts": len(vulnerable),
        "vulnerable_admissible_numerator": len(vulnerable_admissible),
        "vulnerable_admissible_denominator": len(vulnerable),
        "patched_controls_held_numerator": len(held_controls),
        "patched_controls_held_denominator": len(controls),
        "observed_control_false_positives": len(false_positive_controls),
        "control_false_positive_denominator": len(controls),
        "admissible_probes_numerator": sum(r["admissible_count"] for r in episodes),
        "all_probes_denominator": sum(r["probe_count"] for r in episodes),
        "unsupported_final_translations": len(unsupported),
        "final_translator_deadlines": len(deadlines),
        "c1_flagged_uncertified": len(c1_flagged_uncertified),
        "total_turns": sum(r["turns"] for r in episodes),
        "accumulated_episode_seconds": sum(r["elapsed_s"] for r in episodes),
        "accumulated_episode_minutes": round(sum(r["elapsed_s"] for r in episodes) / 60, 2),
        "not_rerun_matrix_cells": 12 - len(episodes),
        "cohort_note": "Two distinct tasks; campaigns 2 and 3 are selective vulnerable-build follow-ups, not balanced trials.",
        "token_note": "Saved named-agent token fields are placeholders and are not interpreted as measured zero use.",
    }
    expected_summary = {
        "campaign_episode_counts": {"1": 4, "2": 2, "3": 1},
        "tasks": 2, "episodes": 7, "vulnerable_attempts": 5,
        "patched_controls": 2, "final_certificates": 2,
        "vulnerable_admissible_numerator": 5,
        "patched_controls_held_numerator": 2,
        "observed_control_false_positives": 0,
        "admissible_probes_numerator": 5, "all_probes_denominator": 9,
        "unsupported_final_translations": 2, "final_translator_deadlines": 1,
        "c1_flagged_uncertified": 2, "total_turns": 118,
        "not_rerun_matrix_cells": 5,
    }
    for key, expected in expected_summary.items():
        if summary[key] != expected:
            fail(f"Cohort summary mismatch for {key}: expected {expected}, got {summary[key]}")
    if not math.isclose(summary["accumulated_episode_seconds"], 8168.736, abs_tol=1e-6):
        fail("Cohort total elapsed seconds failed numerical acceptance check")
    return episodes, certificate_audits, representative, summary


def write_data(output: Path, episodes: list[dict], audits: dict, representative: dict,
               summary: dict, sources: Sources) -> None:
    data = {
        "episodes": episodes,
        "certificate_audits": audits,
        "representative_block": representative,
        "summary": summary,
    }
    (output / "data/campaign_data.json").write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (output / "data/sources.json").write_text(
        json.dumps(sources.rows(), indent=2) + "\n", encoding="utf-8")
    fields = [
        "campaign", "project", "task_id", "target_build", "run_id", "outcome",
        "session_status", "flag_success", "translation_status", "checker_status",
        "turns", "elapsed_s", "probe_count", "admissible_count", "stopped_at",
        "certificate_total_steps", "certificate_reachable_steps",
        "certificate_unused_steps", "certificate_unused_fraction",
    ]
    with (output / "data/episodes.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for episode in episodes:
            row = {}
            for field in fields:
                value = episode.get(field)
                if value is None:
                    row[field] = ""
                elif isinstance(value, bool):
                    row[field] = str(value).lower()
                else:
                    row[field] = value
            writer.writerow(row)


def configure_matplotlib():
    from matplotlib import font_manager
    from matplotlib.backends.backend_agg import FigureCanvasAgg
    from matplotlib.figure import Figure

    regular = font_manager.FontProperties(fname="/System/Library/Fonts/Supplemental/Arial.ttf")
    bold = font_manager.FontProperties(fname="/System/Library/Fonts/Supplemental/Arial Bold.ttf")
    return Figure, FigureCanvasAgg, regular, bold


def save_figure(fig, output: Path, name: str) -> None:
    for extension in ("png", "svg", "pdf"):
        kwargs = {"dpi": 120} if extension == "png" else {}
        fig.savefig(output / f"figures/{name}.{extension}", format=extension,
                    facecolor=WHITE, edgecolor="none", **kwargs)


def figure_title(fig, title: str, subtitle: str, regular, bold) -> None:
    fig.text(0.055, 0.945, title, fontsize=28, color=NAVY, fontproperties=bold, va="top")
    fig.text(0.055, 0.902, subtitle, fontsize=13, color=BODY, fontproperties=regular, va="top")
    fig.text(0.945, 0.945, "SoundTrace — Columbia University Project", fontsize=11,
             color=ACCENT, fontproperties=bold, ha="right", va="top")


def add_box(ax, xy, width, height, text, regular, bold, *, face=WHITE, edge=ACCENT,
            title=None, fontsize=10.5):
    from matplotlib.patches import FancyBboxPatch
    patch = FancyBboxPatch(xy, width, height, boxstyle="round,pad=0.012,rounding_size=0.018",
                           facecolor=face, edgecolor=edge, linewidth=1.7)
    ax.add_patch(patch)
    x, y = xy
    if title:
        ax.text(x + width / 2, y + height * .68, title, ha="center", va="center",
                color=NAVY, fontsize=fontsize + 1, fontproperties=bold)
        ax.text(x + width / 2, y + height * .33, text, ha="center", va="center",
                color=BODY, fontsize=fontsize, fontproperties=regular, wrap=True)
    else:
        ax.text(x + width / 2, y + height / 2, text, ha="center", va="center",
                color=BODY, fontsize=fontsize, fontproperties=regular, wrap=True)
    return patch


def render_pipeline_figure(output: Path, mpl) -> None:
    Figure, Canvas, regular, bold = mpl
    fig = Figure(figsize=(16, 9), dpi=120, facecolor=WHITE)
    Canvas(fig)
    ax = fig.add_axes([0.04, 0.08, 0.92, 0.78])
    ax.set_xlim(0, 1); ax.set_ylim(0, 1); ax.axis("off")
    figure_title(fig, "Pipeline and trust boundary",
                 "Public work logs become provenance-bound primitive steps; trusted observations remain separate.", regular, bold)
    ax.axhspan(.52, .96, color="#F7FAFC")
    ax.axhspan(.06, .47, color="#EDF6FC")
    ax.text(.01, .93, "UNTRUSTED MODEL LANE", color=RED, fontsize=11, fontproperties=bold)
    ax.text(.01, .44, "TRUSTED RECORD / EVIDENCE / CHECK LANE", color=GREEN, fontsize=11, fontproperties=bold)
    add_box(ax, (.03, .66), .16, .17, "Inspects source / shell\ncontext", regular, bold,
            title="Pilot", face="#FFF8E8", edge=AMBER)
    add_box(ax, (.25, .66), .18, .17, "Visible reasoning_chunk\n+ one action", regular, bold,
            title="Public work log", face="#FFF8E8", edge=AMBER)
    add_box(ax, (.51, .66), .18, .17, "Only the block + its\nprior-evidence snapshot", regular, bold,
            title="Translator", face="#FFF8E8", edge=AMBER)
    add_box(ax, (.76, .66), .18, .17, "emit · noop\nOUT_OF_LANGUAGE", regular, bold,
            title="Primitive result", face="#FFF8E8", edge=AMBER)
    add_box(ax, (.03, .20), .17, .16, "Narration recorded before\naction execution", regular, bold,
            title="Runner / orchestrator", face=WHITE, edge=GREEN, fontsize=9.5)
    add_box(ax, (.25, .20), .16, .16, "Pinned build + ASan\ndynamic probe", regular, bold,
            title="Trusted execution", face=WHITE, edge=GREEN, fontsize=9.5)
    add_box(ax, (.46, .20), .15, .16, "Scoped machine\nobservations", regular, bold,
            title="Evidence", face=WHITE, edge=GREEN, fontsize=9.5)
    add_box(ax, (.66, .20), .13, .16, "Complete-bundle HMAC\n→ unchanged assembly", regular, bold,
            title="Seal", face=WHITE, edge=GREEN, fontsize=8.2)
    add_box(ax, (.84, .20), .13, .16, "Authenticate · admit\nreconstruct → Lean", regular, bold,
            title="Checker", face=WHITE, edge=GREEN, fontsize=8.2)
    arrows = [((.19,.745),(.25,.745)), ((.43,.745),(.51,.745)), ((.69,.745),(.76,.745)),
              ((.115,.66),(.115,.36)), ((.20,.28),(.25,.28)), ((.41,.28),(.46,.28)),
              ((.61,.28),(.66,.28)), ((.79,.28),(.84,.28)), ((.535,.36),(.60,.66))]
    for start, end in arrows:
        ax.annotate("", xy=end, xytext=start, arrowprops=dict(arrowstyle="-|>", color=ACCENT, lw=2))
    ax.annotate("actual tool result feedback", xy=(.12,.66), xytext=(.46,.48),
                color=BODY, fontsize=9.5, fontproperties=regular,
                arrowprops=dict(arrowstyle="-|>", color=ACCENT, lw=1.7, connectionstyle="arc3,rad=.3"))
    ax.text(.03, .08, "ASan is dynamic instrumentation—not static analysis. Source exploration is audited context, not trusted memory evidence.",
            color=BODY, fontsize=11, fontproperties=bold)
    save_figure(fig, output, "pipeline")


def outcome_style(outcome: str) -> tuple[str, str]:
    return {
        "OOB_VERIFIED": (GREEN, "[V] VERIFIED"),
        "CONTROL_HELD": (BLUE, "[C] CONTROL_HELD"),
        "NO_DEMONSTRATION": (AMBER, "[T] NO_DEMONSTRATION"),
        "INSUFFICIENT_EVIDENCE": (RED, "[!] INSUFFICIENT_EVIDENCE"),
    }[outcome]


def render_outcomes_figure(output: Path, episodes: list[dict], mpl) -> None:
    from matplotlib.patches import Rectangle
    Figure, Canvas, regular, bold = mpl
    fig = Figure(figsize=(16, 9), dpi=120, facecolor=WHITE); Canvas(fig)
    ax = fig.add_axes([.17,.19,.78,.65]); ax.set_xlim(0,3); ax.set_ylim(0,4); ax.invert_yaxis(); ax.axis("off")
    figure_title(fig, "Episode outcomes across selective campaigns",
                 "Seven observed episode cells; five hatched cells were not rerun.", regular, bold)
    rows = [("jq", "vul", "jq · vulnerable"), ("jq", "fix", "jq · patched control"),
            ("binutils", "vul", "binutils · vulnerable"), ("binutils", "fix", "binutils · patched control")]
    columns = [(1,"C1 (n=4)"),(2,"C2 (n=2)"),(3,"C3 (n=1)")]
    lookup = {(r["project"],r["target_build"],r["campaign"]):r for r in episodes}
    causes = {(1,"jq","vul"):"Translation unsupported", (1,"binutils","vul"):"Translation unsupported",
              (2,"jq","vul"):"Translator deadline", (1,"jq","fix"):"Report none",
              (1,"binutils","fix"):"Report none"}
    for col, (_, label) in enumerate(columns):
        ax.text(col+.5,-.18,label,ha="center",va="center",fontsize=13,color=NAVY,fontproperties=bold)
    for row, (project, build, label) in enumerate(rows):
        ax.text(-.08,row+.5,label,ha="right",va="center",fontsize=12,color=BODY,fontproperties=bold)
        for col, (campaign, _) in enumerate(columns):
            record = lookup.get((project,build,campaign))
            if record:
                color, text = outcome_style(record["outcome"])
                ax.add_patch(Rectangle((col+.04,row+.06),.92,.88,facecolor=color,edgecolor=WHITE,lw=2))
                ax.text(col+.5,row+.42,text,ha="center",va="center",fontsize=10.5,color=WHITE,fontproperties=bold)
                cause = causes.get((campaign,project,build),"Final certificate")
                ax.text(col+.5,row+.68,cause,ha="center",va="center",fontsize=9.2,color=WHITE,fontproperties=regular)
            else:
                ax.add_patch(Rectangle((col+.04,row+.06),.92,.88,facecolor=GREY,edgecolor="#9FB3C8",lw=1.3,hatch="///"))
                ax.text(col+.5,row+.5,"Not rerun",ha="center",va="center",fontsize=11,color=BODY,fontproperties=bold)
    fig.text(.055,.115,"C2/C3 are selective vulnerable-build follow-ups. C1 bug confirmations did not become certificates.",
             color=BODY,fontsize=12,fontproperties=bold)
    fig.text(.055,.075,"Outcome is assessment.outcome; flag_success and intermediate emissions are not certificate verdicts.",
             color=BODY,fontsize=10.5,fontproperties=regular)
    save_figure(fig, output, "episode_outcomes")


def render_progress_figure(output: Path, episodes: list[dict], mpl) -> None:
    from matplotlib.patches import Rectangle
    Figure, Canvas, regular, bold = mpl
    fig = Figure(figsize=(16, 9), dpi=120, facecolor=WHITE); Canvas(fig)
    ax = fig.add_axes([.18,.17,.77,.66]); ax.set_xlim(0,7); ax.set_ylim(0,7); ax.invert_yaxis(); ax.axis("off")
    figure_title(fig, "Pipeline progress by episode",
                 "Raw stage status is preserved; column counts show successful stages, not timing.", regular, bold)
    counts = [7,5,5,5,2,2,2]
    labels = ["Investigation","Trusted exec.","Evidence","Claim","Translation","Checker","Lean"]
    for col, (label,count) in enumerate(zip(labels,counts)):
        ax.text(col+.5,-.33,f"{label}\n{count}/7",ha="center",va="center",fontsize=10,color=NAVY,fontproperties=bold)
    colors = {"ok":GREEN,"accepted":GREEN,"unsupported":AMBER,"ran_no_admissible":BLUE,"not_reached":GREY}
    short = {"ok":"ok","accepted":"accepted","unsupported":"unsupported",
             "ran_no_admissible":"ran / no admissible","not_reached":"not reached"}
    for row, episode in enumerate(episodes):
        label = f"C{episode['campaign']} {episode['project']} {episode['target_build']}"
        ax.text(-.08,row+.5,label,ha="right",va="center",fontsize=10.5,color=BODY,fontproperties=bold)
        for col, stage in enumerate(STAGES):
            raw = episode["pipeline"]["stages"][stage]
            display = short[raw]
            if episode["campaign"] == 2 and episode["project"] == "jq" and stage == "translation":
                display = "deadline /\nno final translation"
            color = colors[raw]
            ax.add_patch(Rectangle((col+.04,row+.06),.92,.88,facecolor=color,edgecolor=WHITE,lw=1.5,
                                   hatch="///" if raw == "not_reached" else None))
            ax.text(col+.5,row+.5,display,ha="center",va="center",fontsize=8.2,
                    color=BODY if raw == "not_reached" else WHITE,
                    fontproperties=bold if raw in {"accepted","unsupported"} else regular)
    fig.text(.055,.105,"Trusted execution was attempted in all seven episodes; 5/7 produced admissible execution evidence.",
             color=BODY,fontsize=11,fontproperties=bold)
    fig.text(.055,.068,"Patched early stops are expected control behavior. C2 jq retained two prior emissions, but no final translation or certificate.",
             color=BODY,fontsize=10.5,fontproperties=regular)
    save_figure(fig, output, "pipeline_progress")


def render_redundancy_figure(output: Path, episodes: list[dict], mpl) -> None:
    Figure, Canvas, regular, bold = mpl
    fig = Figure(figsize=(16, 9), dpi=120, facecolor=WHITE); Canvas(fig)
    ax = fig.add_axes([.20,.25,.70,.50])
    figure_title(fig, "Final-step dependency redundancy",
                 "Only the two recorded final certificates are included.", regular, bold)
    verified = sorted((r for r in episodes if r["certificate_total_steps"] is not None),
                      key=lambda r: r["certificate_total_steps"])
    labels = [f"C{r['campaign']} {r['project']}" for r in verified]
    reachable = [r["certificate_reachable_steps"] for r in verified]
    unused = [r["certificate_unused_steps"] for r in verified]
    y = list(range(len(verified)))
    ax.barh(y,reachable,color=GREEN,label="Reachable from final step")
    ax.barh(y,unused,left=reachable,color=AMBER,hatch="//",label="Outside final dependency path")
    ax.set_yticks(y,labels,fontproperties=bold,fontsize=13); ax.set_xlim(0,70)
    ax.set_xlabel("certificate steps",color=BODY,fontproperties=regular,fontsize=11)
    ax.tick_params(colors=BODY); ax.spines[["top","right","left"]].set_visible(False)
    ax.grid(axis="x",color=GREY,lw=.8); ax.set_axisbelow(True)
    for i,row in enumerate(verified):
        total=row["certificate_total_steps"]; reach=row["certificate_reachable_steps"]; un=row["certificate_unused_steps"]
        ax.text(total+1,i,f"{reach} reachable + {un} unused = {total}  ·  {un/total:.2%} unused",
                va="center",fontsize=12,color=BODY,fontproperties=bold)
    ax.legend(loc="lower right",frameon=False,prop=regular)
    fig.text(.055,.14,"Unused = outside explicit-premise reachability from the final step (the final step itself is reachable).",
             color=BODY,fontsize=11,fontproperties=bold)
    fig.text(.055,.095,"This measures final-step dependency redundancy—not incorrectness, proven removability, or prose-to-proof faithfulness.",
             color=BODY,fontsize=10.5,fontproperties=regular)
    save_figure(fig, output, "certificate_redundancy")


def render_effort_figure(output: Path, episodes: list[dict], mpl) -> None:
    Figure, Canvas, regular, bold = mpl
    fig = Figure(figsize=(16, 9), dpi=120, facecolor=WHITE); Canvas(fig)
    figure_title(fig, "Complete episode effort",
                 "Accumulated episode duration and Pilot turns; not stage timing or a performance benchmark.", regular, bold)
    labels=[f"C{r['campaign']} {r['project']} {r['target_build']}" for r in episodes]
    colors=[outcome_style(r["outcome"])[0] for r in episodes]
    y=list(range(len(episodes)))
    ax1=fig.add_axes([.18,.20,.34,.63]); ax2=fig.add_axes([.60,.20,.34,.63],sharey=ax1)
    minutes=[r["elapsed_s"]/60 for r in episodes]; turns=[r["turns"] for r in episodes]
    ax1.barh(y,minutes,color=colors); ax2.barh(y,turns,color=colors)
    ax1.set_yticks(y,labels,fontproperties=bold,fontsize=10.5); ax1.invert_yaxis()
    ax2.tick_params(labelleft=False)
    for ax,title in ((ax1,"Elapsed minutes"),(ax2,"Pilot turns")):
        ax.set_title(title,color=NAVY,fontproperties=bold,fontsize=14,pad=12)
        ax.spines[["top","right","left"]].set_visible(False); ax.grid(axis="x",color=GREY,lw=.8); ax.set_axisbelow(True)
    for i,value in enumerate(minutes): ax1.text(value+.35,i,f"{value:.1f}",va="center",color=BODY,fontproperties=bold,fontsize=10)
    for i,value in enumerate(turns): ax2.text(value+.3,i,str(value),va="center",color=BODY,fontproperties=bold,fontsize=10)
    ax1.set_xlim(0,max(minutes)*1.22); ax2.set_xlim(0,max(turns)*1.20)
    from matplotlib.patches import Patch
    legend=[Patch(facecolor=c,label=l) for c,l in [(GREEN,"OOB_VERIFIED"),(BLUE,"CONTROL_HELD"),(AMBER,"NO_DEMONSTRATION"),(RED,"INSUFFICIENT_EVIDENCE")]]
    fig.legend(handles=legend,loc="lower center",ncol=4,frameon=False,prop=regular,bbox_to_anchor=(.5,.085))
    fig.text(.055,.055,"Probes/admissible counts appear in the gallery table. Total: 118 turns and 136.15 accumulated episode minutes.",
             color=BODY,fontsize=10.5,fontproperties=regular)
    save_figure(fig, output, "episode_effort")


def render_figures(output: Path, episodes: list[dict]) -> None:
    mpl = configure_matplotlib()
    render_pipeline_figure(output, mpl)
    render_outcomes_figure(output, episodes, mpl)
    render_progress_figure(output, episodes, mpl)
    render_redundancy_figure(output, episodes, mpl)
    render_effort_figure(output, episodes, mpl)


def load_video_fonts():
    from PIL import ImageFont
    regular = "/System/Library/Fonts/Supplemental/Arial.ttf"
    bold = "/System/Library/Fonts/Supplemental/Arial Bold.ttf"
    mono = "/System/Library/Fonts/Menlo.ttc"
    return {
        "title": ImageFont.truetype(bold, 62), "heading": ImageFont.truetype(bold, 42),
        "label": ImageFont.truetype(bold, 32), "body": ImageFont.truetype(regular, 30),
        "small": ImageFont.truetype(regular, 23), "small_bold": ImageFont.truetype(bold, 23),
        "caption": ImageFont.truetype(bold, 34), "mono": ImageFont.truetype(mono, 25),
    }


def wrap_pixels(draw, text: str, font, width: int, max_lines: int | None = None) -> list[str]:
    words=text.split(); lines=[]; current=""
    for word in words:
        candidate=f"{current} {word}".strip()
        if draw.textbbox((0,0),candidate,font=font)[2] <= width:
            current=candidate
        else:
            if current: lines.append(current)
            current=word
    if current: lines.append(current)
    if max_lines is not None and len(lines)>max_lines:
        lines=lines[:max_lines]
        while draw.textbbox((0,0),lines[-1]+"…",font=font)[2] > width and " " in lines[-1]:
            lines[-1]=lines[-1].rsplit(" ",1)[0]
        lines[-1]+="…"
    return lines


def draw_wrapped(draw, xy, text, font, fill, width, *, spacing=8, anchor="la", max_lines=None):
    lines=wrap_pixels(draw,text,font,width,max_lines)
    draw.multiline_text(xy,"\n".join(lines),font=font,fill=fill,spacing=spacing,anchor=anchor)
    return lines


def rounded_box(draw, box, title, body, fonts, *, fill=WHITE, outline=ACCENT, title_fill=NAVY):
    draw.rounded_rectangle(box,radius=24,fill=fill,outline=outline,width=4)
    x1,y1,x2,y2=box
    title_font=fonts["label"] if draw.textbbox((0,0),title,font=fonts["label"])[2] <= x2-x1-24 else fonts["small_bold"]
    draw.text(((x1+x2)//2,y1+34),title,font=title_font,fill=title_fill,anchor="ma")
    draw_wrapped(draw,((x1+x2)//2,y1+90),body,fonts["small"],BODY,x2-x1-40,anchor="ma",max_lines=4)


def scene_background(scene: int, episodes: list[dict], fonts):
    from PIL import Image, ImageDraw
    image=Image.new("RGB",(WIDTH,HEIGHT),PALE); draw=ImageDraw.Draw(image)
    draw.rectangle((0,0,WIDTH,92),fill=WHITE)
    titles=["From agent work log to auditable certificate","Pilot ↔ Runner: ordered public records",
            "Trusted dynamic evidence is a separate lane","A real block-to-certificate link",
            "Seal once, assemble unchanged, check to the kernel","Seven episodes—not three balanced trials",
            "Final-step dependency redundancy","Research findings from campaigns 1–3"]
    draw.text((72,46),titles[scene],font=fonts["heading"],fill=NAVY,anchor="lm")
    draw.text((1848,47),"SoundTrace — Columbia University Project",font=fonts["small_bold"],fill=ACCENT,anchor="rm")
    draw.text((72,1030),"Reconstructed from archived artifacts",font=fonts["small"],fill=BODY,anchor="lm")
    if scene==0:
        draw.text((960,405),"From agent work log\nto auditable certificate",font=fonts["title"],fill=NAVY,anchor="mm",align="center",spacing=15)
        draw.rounded_rectangle((560,590,1360,680),radius=30,fill="#E6F1F8",outline=ACCENT,width=3)
        draw.text((960,635),"3 campaigns · 2 tasks · 7 episodes",font=fonts["label"],fill=BODY,anchor="mm")
    elif scene==1:
        rounded_box(draw,(100,250,520,570),"Pilot","reasoning_chunk\n+ one action",fonts,fill="#FFF8E8",outline=AMBER)
        rounded_box(draw,(750,250,1170,570),"Runner","record narration\nbefore executing action",fonts,fill=WHITE,outline=GREEN)
        rounded_box(draw,(1400,250,1820,570),"Observed result","returned on the next turn",fonts,fill=WHITE,outline=ACCENT)
        draw.line((520,410,750,410),fill=ACCENT,width=7); draw.polygon([(750,410),(720,393),(720,427)],fill=ACCENT)
        draw.line((1170,410,1400,410),fill=ACCENT,width=7); draw.polygon([(1400,410),(1370,393),(1370,427)],fill=ACCENT)
        draw.arc((360,500,1560,880),0,180,fill=ACCENT,width=5)
        draw.text((960,730),"Visible work log—not hidden reasoning",font=fonts["label"],fill=AMBER,anchor="mm")
    elif scene==2:
        draw.rectangle((80,180,890,860),fill="#FFF8E8",outline=AMBER,width=4)
        draw.text((485,230),"Audited exploration context",font=fonts["label"],fill=NAVY,anchor="mm")
        draw.text((485,340),"source inspection\nshell results\nhypotheses",font=fonts["body"],fill=BODY,anchor="ma",align="center",spacing=20)
        draw.text((485,740),"does not create trusted\nmemory premises",font=fonts["label"],fill=RED,anchor="mm",align="center")
        draw.rectangle((1030,180,1840,860),fill="#EAF7F2",outline=GREEN,width=4)
        draw.text((1435,230),"Trusted ASan dynamic probe",font=fonts["label"],fill=NAVY,anchor="mm")
        draw.text((1435,300),"scope X2/A1",font=fonts["mono"],fill=BODY,anchor="mm")
    elif scene==3:
        draw.rounded_rectangle((80,160,1020,830),radius=26,fill=WHITE,outline=ACCENT,width=4)
        draw.text((120,205),"Public narration · seq 241",font=fonts["label"],fill=NAVY)
        clauses=["live write access out of bounds","extent = 16 bytes","offset = 16 · width = 1","extent < offset + width","observations are conjunct"]
        for i,text in enumerate(clauses):
            draw.text((150,300+i*90),text,font=fonts["body"],fill=BODY)
        draw.rounded_rectangle((1110,160,1840,830),radius=26,fill="#EAF7F2",outline=GREEN,width=4)
        draw.text((1475,205),"Emission X2-A1-upper",font=fonts["label"],fill=NAVY,anchor="ma")
        draw.text((1475,265),"source_seq 241 · TA21 · seq 267",font=fonts["mono"],fill=BODY,anchor="ma")
        for i,(op,text) in enumerate([("observe","X2/A1.extent → extent = 16"),("compute","16 < 16 + 1"),("infer","access AND live AND boundary")]):
            y=360+i*130; draw.rounded_rectangle((1180,y,1770,y+82),radius=18,fill=WHITE,outline=GREEN,width=3)
            draw.text((1210,y+41),op,font=fonts["small_bold"],fill=GREEN,anchor="lm")
            draw.text((1390,y+41),text,font=fonts["small"],fill=BODY,anchor="lm")
        draw.text((1475,780),"26 provenance-bound primitive steps",font=fonts["small_bold"],fill=GREEN,anchor="mm")
    elif scene==4:
        labels=["Ordered\nrecords","HMAC seal\nonce","Certificate\nassembly","Checker","Lean\nkernel"]
        xs=[90,450,810,1170,1530]
        for x,label in zip(xs,labels):
            rounded_box(draw,(x,330,x+280,600),label.replace("\n"," "),"",fonts,fill=WHITE,outline=GREEN)
        for x in xs[:-1]:
            draw.line((x+280,465,x+360,465),fill=ACCENT,width=7); draw.polygon([(x+360,465),(x+332,448),(x+332,482)],fill=ACCENT)
        draw.text((960,720),"Recorded: VERIFIED_EVIDENCE_AND_KERNEL · Lean 4.34.1 · empty axiom audit",font=fonts["label"],fill=GREEN,anchor="mm")
        draw.text((960,800),"HMAC authenticates recorded bytes; the proof is relative to admitted observations—not whole-program safety.",font=fonts["small"],fill=BODY,anchor="mm")
    elif scene==5:
        row_labels=["jq vul","jq fix","binutils vul","binutils fix"]
        col_labels=["C1 · n=4","C2 · n=2","C3 · n=1"]
        for c,label in enumerate(col_labels): draw.text((720+c*350,190),label,font=fonts["label"],fill=NAVY,anchor="mm")
        lookup={(r["project"],r["target_build"],r["campaign"]):r for r in episodes}
        for r,(project,build) in enumerate([("jq","vul"),("jq","fix"),("binutils","vul"),("binutils","fix")]):
            y=285+r*150; draw.text((390,y+50),row_labels[r],font=fonts["label"],fill=BODY,anchor="rm")
            for c,campaign in enumerate((1,2,3)):
                x=545+c*350; rec=lookup.get((project,build,campaign))
                if rec:
                    color,text=outcome_style(rec["outcome"]); label=text.replace("✓ ","").replace("◆ ","").replace("△ ","").replace("! ","")
                    draw.rounded_rectangle((x,y,x+320,y+100),radius=16,fill=color)
                    draw_wrapped(draw,(x+160,y+50),label,fonts["small_bold"],WHITE,280,anchor="mm",max_lines=2)
                else:
                    draw.rounded_rectangle((x,y,x+320,y+100),radius=16,fill=GREY,outline="#9FB3C8",width=3)
                    draw.text((x+160,y+50),"Not rerun",font=fonts["small_bold"],fill=BODY,anchor="mm")
        draw.text((960,930),"C2/C3 are selective follow-ups",font=fonts["small_bold"],fill=RED,anchor="mm")
    elif scene==6:
        draw.text((260,330),"C2 binutils",font=fonts["label"],fill=BODY,anchor="rm")
        draw.text((260,610),"C3 jq",font=fonts["label"],fill=BODY,anchor="rm")
        draw.rectangle((320,270,840,390),fill=GREEN)
        draw.text((580,330),"17 reachable",font=fonts["label"],fill=WHITE,anchor="mm")
        draw.rectangle((320,550,900,670),fill=GREEN)
        draw.rectangle((900,550,1600,670),fill=AMBER)
        draw.text((610,610),"19 reachable",font=fonts["label"],fill=WHITE,anchor="mm")
        draw.text((1250,610),"33 unused",font=fonts["label"],fill=WHITE,anchor="mm")
        draw.text((1660,610),"63.46%",font=fonts["label"],fill=AMBER,anchor="lm")
        draw.text((960,800),"Outside final dependency path ≠ incorrect",font=fonts["label"],fill=NAVY,anchor="mm")
    else:
        cards=[("5 / 5","vulnerable attempts with admissible evidence",GREEN),("2 / 5","vulnerable attempts with final certificates",ACCENT),("2 / 2","patched controls held",BLUE)]
        for i,(value,label,color) in enumerate(cards):
            x=115+i*600; draw.rounded_rectangle((x,260,x+500,610),radius=28,fill=WHITE,outline=color,width=5)
            draw.text((x+250,370),value,font=fonts["title"],fill=color,anchor="mm")
            draw_wrapped(draw,(x+250,500),label,fonts["body"],BODY,420,anchor="mm",max_lines=2)
        draw.text((960,745),"Three vulnerable attempts stopped at final translation",font=fonts["label"],fill=AMBER,anchor="mm")
        draw_wrapped(draw,(960,850),"Small cohort · selective repeated attempts · no general safety or false-positive-rate claim",fonts["small_bold"],RED,1500,anchor="mm",max_lines=2)
    return image


def caption_for_time(t: float) -> str:
    for start,end,text in CAPTIONS:
        if start <= t < end:
            return text
    return ""


def add_caption(image, text: str, fonts):
    from PIL import ImageDraw
    draw=ImageDraw.Draw(image)
    lines=wrap_pixels(draw,text,fonts["caption"],1640,max_lines=2)
    bbox=draw.multiline_textbbox((0,0),"\n".join(lines),font=fonts["caption"],spacing=8)
    h=bbox[3]-bbox[1]+42; y=HEIGHT-80-h
    draw.rounded_rectangle((100,y,1820,HEIGHT-80),radius=22,fill=NAVY)
    draw.multiline_text((960,y+21),"\n".join(lines),font=fonts["caption"],fill=WHITE,spacing=8,anchor="ma",align="center")


def compose_frame(t: float, backgrounds, episodes: list[dict], fonts):
    from PIL import ImageDraw
    boundaries=[0,8,24,44,64,80,96,110,120]
    scene=max(0,min(7,next((i for i in range(8) if boundaries[i] <= t < boundaries[i+1]),7)))
    image=backgrounds[scene].copy(); draw=ImageDraw.Draw(image)
    local=(t-boundaries[scene])/(boundaries[scene+1]-boundaries[scene])
    if scene==0:
        alpha=int(255*min(1,local*3)); draw.rectangle((0,94,WIDTH,100),fill=ACCENT if alpha>80 else GREY)
    elif scene==1:
        if local<.5: x=520+int((750-520)*(local*2)); y=410
        else: x=1170+int((1400-1170)*((local-.5)*2)); y=410
        draw.ellipse((x-18,y-18,x+18,y+18),fill=AMBER,outline=WHITE,width=4)
    elif scene==2:
        entries=[("access","write"),("live","true"),("extent","16"),("offset","16"),("width","1")]
        visible=max(1,min(5,int(local*10)))
        for i,(key,value) in enumerate(entries[:visible]):
            y=385+i*78; draw.rounded_rectangle((1120,y,1750,y+58),radius=14,fill=WHITE,outline=GREEN,width=2)
            draw.text((1150,y+29),key,font=fonts["mono"],fill=BODY,anchor="lm"); draw.text((1705,y+29),value,font=fonts["mono"],fill=GREEN,anchor="rm")
        draw.line((900,520,1030,520),fill=RED,width=6)
    elif scene==3:
        count=max(1,min(3,int(local*4)))
        for i in range(count):
            draw.rounded_rectangle((1165,345+i*130,1785,457+i*130),radius=22,outline=ACCENT,width=5)
        if local>.75:
            draw.text((960,900),"noop = no proof content · OUT_OF_LANGUAGE = explicit refusal",font=fonts["small_bold"],fill=AMBER,anchor="mm")
    elif scene==4:
        x=230+int(local*1440); draw.ellipse((x-20,445,x+20,485),fill=ACCENT,outline=WHITE,width=4)
    elif scene==5:
        draw.rectangle((80,925,80+int(1760*local),933),fill=ACCENT)
    elif scene==6:
        draw.line((320,740,320+int(1280*local),740),fill=ACCENT,width=8)
    else:
        draw.rectangle((110,650,110+int(1700*local),660),fill=GREEN)
    add_caption(image,caption_for_time(t),fonts)
    return image


def vtt_time(seconds: float) -> str:
    milliseconds=round(seconds*1000); hours,milliseconds=divmod(milliseconds,3600000)
    minutes,milliseconds=divmod(milliseconds,60000); secs,milliseconds=divmod(milliseconds,1000)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}.{milliseconds:03d}"


def render_video(output: Path, episodes: list[dict]) -> None:
    from PIL import Image, ImageDraw
    fonts=load_video_fonts()
    backgrounds=[scene_background(i,episodes,fonts) for i in range(8)]
    vtt=["WEBVTT",""]
    for index,(start,end,text) in enumerate(CAPTIONS,1):
        vtt.extend([str(index),f"{vtt_time(start)} --> {vtt_time(end)}",text,""])
    (output/"video/pipeline.vtt").write_text("\n".join(vtt),encoding="utf-8")
    poster=backgrounds[0].copy(); add_caption(poster,caption_for_time(2),fonts); poster.save(output/"video/poster.png")
    storyboard=Image.new("RGB",(1920,1080),WHITE)
    mids=[4,16,34,54,72,88,103,115]
    for i,t in enumerate(mids):
        frame=compose_frame(t,backgrounds,episodes,fonts).resize((480,270),Image.Resampling.LANCZOS)
        storyboard.paste(frame,((i%4)*480,(i//4)*540))
        panel=ImageDraw.Draw(storyboard); panel.rectangle(((i%4)*480,(i//4)*540+270,(i%4)*480+480,(i//4)*540+540),fill=WHITE)
        panel.text(((i%4)*480+24,(i//4)*540+305),f"{int(t):03d}s · Scene {i+1}",font=fonts["small_bold"],fill=NAVY)
        draw_wrapped(panel,((i%4)*480+24,(i//4)*540+355),caption_for_time(t),fonts["small"],BODY,430,max_lines=4)
    storyboard.save(output/"video/storyboard.png")
    command=["/opt/homebrew/bin/ffmpeg","-hide_banner","-loglevel","error","-n","-f","rawvideo","-pix_fmt","rgb24","-s:v",f"{WIDTH}x{HEIGHT}","-r",str(FPS),"-i","pipe:0","-an","-c:v","libx264","-preset","veryfast","-crf","20","-pix_fmt","yuv420p","-threads","2","-movflags","+faststart",str(output/"video/pipeline.mp4")]
    process=subprocess.Popen(command,stdin=subprocess.PIPE,stderr=subprocess.PIPE)
    try:
        assert process.stdin is not None
        for frame_number in range(FRAME_COUNT):
            frame=compose_frame(frame_number/FPS,backgrounds,episodes,fonts)
            process.stdin.write(frame.tobytes())
        process.stdin.close()
        assert process.stderr is not None
        stderr=process.stderr.read().decode("utf-8","replace")
        returncode=process.wait()
    except (BrokenPipeError,OSError) as exc:
        if process.stdin and not process.stdin.closed: process.stdin.close()
        stderr=(process.stderr.read().decode("utf-8","replace") if process.stderr else "")
        process.wait()
        fail(f"ffmpeg encoder failed: {exc}; {stderr.strip()}")
    if returncode != 0:
        fail(f"ffmpeg encoder failed with exit {returncode}: {stderr.strip()}")


def write_gallery(output: Path, episodes: list[dict], audits: dict, summary: dict) -> None:
    def esc(value): return html.escape("N/A" if value is None else str(value))
    rows=[]
    for r in episodes:
        cert=(f"{r['certificate_reachable_steps']}/{r['certificate_total_steps']} reachable"
              if r["certificate_total_steps"] is not None else "N/A")
        values=[f"C{r['campaign']}",r["project"],r["task_id"],r["target_build"],r["run_id"],r["outcome"],r["session_status"],r["turns"],f"{r['elapsed_s']/60:.1f}",f"{r['probe_count']} / {r['admissible_count']}",cert]
        labels=["Campaign","Project","Task","Build","Run ID","Outcome","Session","Turns","Minutes","Probes / admissible","Certificate"]
        rows.append("<tr>"+"".join(f'<td data-label="{label}">{esc(value)}</td>' for label,value in zip(labels,values))+"</tr>")
    cards=[("7","episodes"),("5 / 5","vulnerable attempts with admissible evidence"),("2 / 5","final certificates / vulnerable attempts"),("2 / 2","patched controls held"),("5 / 9","admissible probes"),("136.15","accumulated episode minutes")]
    card_html="".join(f'<div class="card"><strong>{a}</strong><span>{b}</span></div>' for a,b in cards)
    figures=[]
    descriptions={
        "pipeline":"Trust boundary and record ordering","episode_outcomes":"Seven observed outcomes and five not-rerun cells",
        "pipeline_progress":"Raw pipeline statuses across all episodes","certificate_redundancy":"Final-step dependency reachability",
        "episode_effort":"Complete episode duration and Pilot turns",
    }
    for name,description in descriptions.items():
        figures.append(f'''<article class="figure"><h3>{description}</h3><img src="figures/{name}.png" alt="{description}"><p class="links"><a href="figures/{name}.png">PNG</a> · <a href="figures/{name}.svg">SVG</a> · <a href="figures/{name}.pdf">PDF</a></p></article>''')
    transcript="".join(f"<p><strong>{vtt_time(s)}–{vtt_time(e)}</strong> {html.escape(text)}</p>" for s,e,text in CAPTIONS)
    source_runs="<br>".join(f"C{r['campaign']} · {r['project']} {r['target_build']} · <code>{r['run_id']}</code>" for r in episodes)
    document=f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SoundTrace — Columbia University Project · Campaigns 1–3</title>
<style>
:root{{--navy:{NAVY};--blue:{ACCENT};--body:{BODY};--pale:{PALE};--green:{GREEN};--amber:{AMBER};--red:{RED};--grey:{GREY}}}
*{{box-sizing:border-box}} body{{margin:0;background:var(--pale);color:var(--body);font:17px Arial,sans-serif;line-height:1.48}} main{{max-width:1320px;margin:auto;padding:32px}} header,.panel,.figure{{background:white;border:1px solid #d9e2ec;border-radius:16px;padding:28px;margin:0 0 24px}} h1,h2,h3{{color:var(--navy);line-height:1.15}} h1{{font-size:42px;margin:.15em 0}} h2{{margin-top:0}} .brand{{color:var(--blue);font-weight:700}} .scope{{font-size:22px}} .notice{{border-left:5px solid var(--amber);padding:12px 16px;background:#fff8e8}} .cards{{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin:24px 0}} .card{{background:white;border:1px solid #bcccdc;border-radius:14px;padding:20px}} .card strong{{display:block;color:var(--navy);font-size:34px}} .card span{{display:block}} video{{display:block;width:100%;background:#000;border-radius:12px}} .downloads,.links{{display:flex;gap:12px;flex-wrap:wrap}} a{{color:#195b91;font-weight:700}} .grid{{display:grid;grid-template-columns:1fr;gap:24px}} .figure img{{display:block;width:100%;height:auto;border:1px solid #e5eaf0}} table{{width:100%;border-collapse:collapse;font-size:14px}} th,td{{text-align:left;vertical-align:top;padding:10px 8px;border-bottom:1px solid #d9e2ec}} th{{color:var(--navy)}} code{{font:12px Menlo,monospace;overflow-wrap:anywhere}} details p{{border-bottom:1px solid #e5eaf0;padding-bottom:10px}} .method{{columns:2;column-gap:36px}} footer{{padding:20px 0 50px;color:#526d82}}
@media(max-width:700px){{main{{padding:12px}}header,.panel,.figure{{padding:18px}}h1{{font-size:32px}}.cards{{grid-template-columns:1fr}}.method{{columns:1}}table,tbody,tr,td{{display:block;width:100%}}thead{{display:none}}tr{{border:1px solid #d9e2ec;border-radius:10px;margin:0 0 14px;padding:8px}}td{{border:0;padding:5px 7px;overflow-wrap:anywhere}}td:before{{content:attr(data-label) ": ";font-weight:700;color:var(--navy)}}}}
</style></head><body><main>
<header><div class="brand">SoundTrace — Columbia University Project</div><h1>From agent work log to auditable certificate</h1><p class="scope">Campaigns 1–3 · 2 tasks · 7 episodes · silent captioned 120-second presentation</p><p class="notice"><strong>Reconstructed from archived artifacts.</strong> Recorded checker verdicts are reported here; this visualization did not rerun HMAC authentication, certificate checking, or Lean.</p></header>
<section class="panel"><h2>Presentation video</h2><video controls preload="metadata" poster="video/poster.png"><source src="video/pipeline.mp4" type="video/mp4"><track kind="captions" src="video/pipeline.vtt" srclang="en" label="English"></video><p class="downloads"><a href="video/pipeline.mp4">MP4</a><a href="video/pipeline.vtt">WebVTT captions</a><a href="video/poster.png">Poster</a><a href="video/storyboard.png">Storyboard</a></p><p>Captions are burned into the video; the optional WebVTT track is not enabled by default.</p></section>
<section class="cards">{card_html}</section>
<section class="panel"><h2>Cohort interpretation</h2><p>Campaign 1 contains the four task/build combinations. Campaigns 2 and 3 are selective vulnerable-build follow-ups—not equivalent 2×2 trials. Results concern two distinct tasks, not seven independent targets.</p><p>Two C1 vulnerable episodes had <code>flag_success=true</code> but ended <code>UNSUPPORTED_TRANSLATION</code>; outcome remains <code>NO_DEMONSTRATION</code>. C2 jq retained two intermediate emissions but no final translation or certificate. Missing certificate fields are <strong>N/A</strong>, not empty proofs or 0% redundancy.</p></section>
<section class="grid">{''.join(figures)}</section>
<section class="panel"><h2>Seven-episode data</h2><table><thead><tr>{''.join(f'<th>{h}</th>' for h in ['Campaign','Project','Task','Build','Run ID','Outcome','Session','Turns','Minutes','Probes / admissible','Certificate'])}</tr></thead><tbody>{''.join(rows)}</tbody></table><p class="downloads"><a href="data/episodes.csv">episodes.csv</a><a href="data/campaign_data.json">campaign_data.json</a><a href="data/sources.json">sources.json</a></p></section>
<section class="panel"><h2>Definitions and methodology</h2><div class="method"><p><strong>Outcome:</strong> <code>assessment.outcome</code>, not flag success, first-pass translation, emissions, or pipeline reach.</p><p><strong>Elapsed time:</strong> manifest <code>elapsed_s</code>; summed across episodes, not campaign wall-clock or stage timing.</p><p><strong>Unused certificate step:</strong> outside explicit-premise reachability from the final step, including the final step in the reachable set. It does not mean invalid, duplicate, or proven removable.</p><p><strong>Source coverage:</strong> diagnostic source-map contribution only; it does not establish semantic prose-to-proof faithfulness.</p><p><strong>Recorded verdict:</strong> both saved reports state <code>VERIFIED_EVIDENCE_AND_KERNEL</code>, Lean 4.34.1, and empty axiom audit.</p><p><strong>Token fields:</strong> saved named-agent transport values are placeholders; no token, cost, or cache-efficiency claim is made.</p><p><strong>Controls:</strong> 0 observed false positives among 2 patched controls. This small denominator does not support a general false-positive-rate claim.</p><p><strong>Provenance hashes:</strong> SHA-256 values identify consumed files; they do not substitute for HMAC verification.</p></div></section>
<section class="panel"><h2>Source paths and run identities</h2><p>Campaign manifests: <code>artifacts/live-2026-10-26/campaign-live-1/campaign.json</code>, <code>campaign-live-2/campaign.json</code>, and <code>campaign-live-3/campaign.json</code>. Certificate audit crosscheck: <code>artifacts/v4-gate1/audit_reports.json</code>. Full consumed-file hashes are in <a href="data/sources.json">sources.json</a>.</p><p>{source_runs}</p></section>
<section class="panel"><details><summary><strong>Caption transcript</strong></summary>{transcript}</details></section>
<footer>Research presentation artifact. No official Columbia University logo or endorsement is implied.</footer>
</main></body></html>'''
    (output/"index.html").write_text(document,encoding="utf-8")


def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",default=DEFAULT_OUTPUT,help="new output directory")
    args=parser.parse_args()
    repo=Path(__file__).resolve().parents[1]
    output=bootstrap_output(repo,args.output)
    sys.path.insert(0,str(repo))
    sources=Sources(repo)
    episodes,audits,representative,summary=extract_dataset(repo,sources)
    write_data(output,episodes,audits,representative,summary,sources)
    render_figures(output,episodes)
    render_video(output,episodes)
    write_gallery(output,episodes,audits,summary)
    sources.verify()
    print(json.dumps({
        "status":"complete","gallery":str((output/"index.html").resolve()),
        "video":str((output/"video/pipeline.mp4").resolve()),"episodes":len(episodes),
        "certificates":len(audits),"dimensions":f"{WIDTH}x{HEIGHT}",
        "frames":FRAME_COUNT,"fps":FPS,"duration_s":FRAME_COUNT/FPS,
    },separators=(",",":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as exc:
        print(f"Error: {exc}",file=sys.stderr)
        raise SystemExit(1)
