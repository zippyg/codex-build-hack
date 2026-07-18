"""PROMPTECTOMY command-line orchestration."""

from __future__ import annotations

import json
import shutil
import sys
from collections import defaultdict
from pathlib import Path
from typing import Annotated

import typer

from .contracts import CallsiteStatusEvent, DoneEvent, DoneTotals, ReplayEvent, SwapEvent, TrafficEvent, Verdict, VerdictEvent
from .events import EventRecorder
from .ledger import load
from .scan import scan, scan_event
from .splitting import split
from .synthesize import run as synthesize
from .verify import HoldoutVerifier
from .worktrees import cleanup, create, stage

app = typer.Typer(no_args_is_help=True, add_completion=False)


def _registry_path(repo: Path) -> Path:
    return repo / ".promptectomy" / "registry.json"


def _read_registry(repo: Path) -> dict[str, object]:
    path = _registry_path(repo)
    if not path.exists():
        return {"callsites": {}}
    return json.loads(path.read_text(encoding="utf-8"))


def _write_registry(repo: Path, registry: dict[str, object]) -> None:
    path = _registry_path(repo)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(registry, indent=2, sort_keys=True) + "\n", encoding="utf-8")


@app.command()
def run(
    repo: Annotated[Path, typer.Argument()] = Path("."),
    events: Annotated[str, typer.Option("--events")] = "jsonl",
) -> None:
    """Scan, synthesize candidates in worktrees, then parent-verify sealed holdouts once."""
    if events != "jsonl":
        raise typer.BadParameter("only --events jsonl is supported")
    root = repo.resolve()
    ledger_path = root / ".promptectomy" / "ledger.jsonl"
    schema_path = root / "engine" / "schemas" / "audit-v1.json"
    audit_path = root / ".promptectomy" / "run" / "audit.json"
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    recorder = EventRecorder(sys.stdout)
    recorded = load(ledger_path)
    for event in recorded:
        recorder.emit(TrafficEvent(callsite_id=event.callsite_id, latency_ms=event.latency_ms, cost_usd=event.estimated_cost_usd or 0.0, source="llm"))
    audit, _codex_events = scan(root, ledger_path, schema_path, audit_path)
    recorder.emit(scan_event(audit, ledger_path))
    grouped = defaultdict(list)
    for event in recorded:
        grouped[event.callsite_id].append(event)
    verifier = HoldoutVerifier()
    registry = _read_registry(root)
    entries = registry.setdefault("callsites", {})
    assert isinstance(entries, dict)
    verdicts: list[Verdict] = []
    for callsite in audit.callsites:
        recorder.emit(CallsiteStatusEvent(callsite_id=callsite.callsite_id, status="queued"))
        events_for_callsite = grouped[callsite.callsite_id]
        splits = split(events_for_callsite)
        if callsite.kind == "freeform" or callsite.eligibility != "candidate":
            verdict = verifier.verify(root / "engine" / "promptectomy" / "generated" / f"{callsite.callsite_id}.py", splits.holdout, "freeform")
        else:
            fixture_dir = root / ".promptectomy" / "fixtures" / callsite.callsite_id
            fixture_dir.mkdir(parents=True, exist_ok=True)
            train_fixture = fixture_dir / "train.jsonl"
            dev_fixture = fixture_dir / "dev.jsonl"
            train_fixture.write_text("".join(event.model_dump_json() + "\n" for event in splits.train), encoding="utf-8")
            dev_fixture.write_text("".join(event.model_dump_json() + "\n" for event in splits.dev), encoding="utf-8")
            worktree = create(root, root / ".promptectomy" / "worktrees", callsite.callsite_id)
            try:
                stage(worktree, root / "engine", [train_fixture, dev_fixture])
                first = synthesize(worktree, callsite.callsite_id, callsite.kind)
                for emitted in first.events:
                    recorder.emit(emitted)
                module = worktree.path / "engine" / "promptectomy" / "generated" / f"{callsite.callsite_id}.py"
                if (first.timed_out or first.returncode != 0 or not module.exists()) and not first.timed_out:
                    second = synthesize(worktree, callsite.callsite_id, callsite.kind, resume=True)
                    for emitted in second.events:
                        recorder.emit(emitted)
                if module.exists():
                    destination = root / "engine" / "promptectomy" / "generated" / module.name
                    shutil.copy2(module, destination)
                    recorder.emit(CallsiteStatusEvent(callsite_id=callsite.callsite_id, status="replaying"))
                    verdict = verifier.verify(destination, splits.holdout, callsite.kind)
                else:
                    verdict = Verdict(callsite_id=callsite.callsite_id, status="ERROR", reason="synthesis_did_not_write_generated_module", holdout_n=len(splits.holdout))
            finally:
                cleanup(worktree)
        verdicts.append(verdict)
        recorder.emit(ReplayEvent(callsite_id=callsite.callsite_id, passed=verdict.holdout_n - len(verdict.diffs), total=verdict.holdout_n))
        if verdict.status in {"COMPILED", "COMPILED_WITH_DIFFS"}:
            template = next((event.response_raw for event in events_for_callsite if event.response_raw is not None), None)
            entries[callsite.callsite_id] = {
                "enabled": verdict.status == "COMPILED",
                "module_path": str(Path("../engine/promptectomy/generated") / f"{callsite.callsite_id}.py"),
                "response_template": template,
                "kind": callsite.kind,
                "shadow_rate": 0.01,
                "accepted_verdict": verdict.status,
            }
        recorder.emit(VerdictEvent(verdict=verdict))
        if verdict.status == "COMPILED":
            baseline = [event for event in events_for_callsite if event.latency_ms >= 0]
            recorder.emit(
                SwapEvent(
                    callsite_id=callsite.callsite_id,
                    before_ms=sum(event.latency_ms for event in baseline) / len(baseline) if baseline else 0.0,
                    after_ms=verdict.median_latency_ms or 0.0,
                    before_cost=sum((event.estimated_cost_usd or 0.0) for event in baseline),
                )
            )
        recorder.emit(CallsiteStatusEvent(callsite_id=callsite.callsite_id, status="done"))
    _write_registry(root, registry)
    compiled = sum(verdict.status == "COMPILED" for verdict in verdicts)
    kept = len(verdicts) - compiled
    baseline_cost = sum((event.estimated_cost_usd or 0.0) for event in recorded)
    compiled_cost = sum((event.estimated_cost_usd or 0.0) for event in recorded if any(verdict.callsite_id == event.callsite_id and verdict.status == "COMPILED" for verdict in verdicts))
    reduction = compiled_cost / baseline_cost * 100 if baseline_cost else 0.0
    recorder.emit(DoneEvent(totals=DoneTotals(callsites=len(verdicts), compiled=compiled, kept=kept, est_monthly_savings_usd=0.0, pipeline_cost_reduction_pct=round(reduction, 2))))


@app.command()
def accept(callsite_id: str, repo: Annotated[Path, typer.Option("--repo")] = Path(".")) -> None:
    """Explicitly enable a COMPILED_WITH_DIFFS registry entry."""
    root = repo.resolve()
    registry = _read_registry(root)
    entries = registry.get("callsites", {})
    if not isinstance(entries, dict) or callsite_id not in entries:
        raise typer.BadParameter(f"unknown callsite {callsite_id}")
    entry = entries[callsite_id]
    if not isinstance(entry, dict) or entry.get("accepted_verdict") not in {"COMPILED", "COMPILED_WITH_DIFFS"}:
        raise typer.BadParameter(f"callsite {callsite_id} has no acceptable verdict")
    entry["enabled"] = True
    _write_registry(root, registry)


@app.command()
def disable(callsite_id: str, repo: Annotated[Path, typer.Option("--repo")] = Path(".")) -> None:
    """Immediately route one callsite back to the original model."""
    root = repo.resolve()
    registry = _read_registry(root)
    entries = registry.get("callsites", {})
    if not isinstance(entries, dict) or callsite_id not in entries:
        raise typer.BadParameter(f"unknown callsite {callsite_id}")
    entry = entries[callsite_id]
    if not isinstance(entry, dict):
        raise typer.BadParameter(f"invalid registry entry for {callsite_id}")
    entry["enabled"] = False
    _write_registry(root, registry)


if __name__ == "__main__":
    app()
