"""Codex audit invocation plus an honest tagged-source fallback."""

from __future__ import annotations

import json
import re
import subprocess
from collections import Counter
from pathlib import Path
from typing import Iterable

from .contracts import AuditReport, CallsiteAudit, ScanEvent
from .ledger import load

_TAG = re.compile(r"promptectomy:callsite_id=(?P<id>[A-Za-z0-9_-]+)\s+kind=(?P<kind>structured|classifier|freeform)")


def build_command(repo: str | Path, schema_path: str | Path, output_path: str | Path) -> list[str]:
    return [
        "codex",
        "-a",
        "never",
        "exec",
        "-C",
        str(Path(repo).resolve()),
        "--sandbox",
        "read-only",
        "--ephemeral",
        "--json",
        "--output-schema",
        str(Path(schema_path).resolve()),
        "-o",
        str(Path(output_path).resolve()),
        "-",
    ]


def audit_prompt() -> str:
    return (
        "Audit only tagged OpenAI Responses callsites. Return the requested JSON. "
        "Classify tagged structured/classifier calls as candidate and freeform as keep_model. "
        "Do not decide a verdict and never inspect or infer a sealed holdout."
    )


def static_fallback(repo: str | Path, ledger_path: str | Path | None = None) -> AuditReport:
    root = Path(repo).resolve()
    counts = Counter(event.callsite_id for event in load(ledger_path)) if ledger_path else Counter()
    callsites: list[CallsiteAudit] = []
    for path in root.rglob("*.py"):
        if any(part in {".git", ".venv", "__pycache__"} for part in path.parts):
            continue
        lines = path.read_text(encoding="utf-8").splitlines()
        for index, line in enumerate(lines):
            match = _TAG.search(line)
            if match is None:
                continue
            nearby = "\n".join(lines[index : index + 12])
            if "responses.create" not in nearby:
                continue
            kind = match.group("kind")
            callsites.append(
                CallsiteAudit(
                    callsite_id=match.group("id"),
                    file=str(path.relative_to(root)),
                    line=index + 1,
                    symbol="",
                    kind=kind,
                    eligibility="keep_model" if kind == "freeform" else "candidate",
                    sample_count=counts[match.group("id")],
                    confidence=1.0,
                    reason="tagged_static_fallback",
                )
            )
    return AuditReport(repo_path=str(root), repo_sha="unknown", callsites=callsites)


def scan(repo: str | Path, ledger_path: str | Path, schema_path: str | Path, output_path: str | Path) -> tuple[AuditReport, list[dict[str, object]]]:
    """Run Codex if available. Its clean structured result is read only from ``-o``."""
    command = build_command(repo, schema_path, output_path)
    try:
        completed = subprocess.run(command, input=audit_prompt(), text=True, capture_output=True, check=True, timeout=180)
        report = AuditReport.model_validate_json(Path(output_path).read_text(encoding="utf-8"))
        events = [json.loads(line) for line in completed.stdout.splitlines() if line.strip()]
        return report, events
    except (FileNotFoundError, subprocess.SubprocessError, ValueError, OSError):
        return static_fallback(repo, ledger_path), []


def scan_event(report: AuditReport, ledger_path: str | Path) -> ScanEvent:
    return ScanEvent(audit=report.callsites, recorded_calls=len(load(ledger_path)))
