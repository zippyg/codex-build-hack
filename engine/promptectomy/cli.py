"""PROMPTECTOMY command-line orchestration."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from collections import defaultdict
from importlib.resources import files
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Annotated
from urllib.parse import urlparse

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


def _remote_url(value: str) -> bool:
    parsed = urlparse(value)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def _audit_schema_path() -> Path:
    return Path(str(files("promptectomy.schema_assets").joinpath("audit-v1.json")))


class _RunRecorder:
    def __init__(self, event_path: Path, mode: str) -> None:
        self.mode = mode
        event_path.parent.mkdir(parents=True, exist_ok=True)
        self._file = event_path.open("w", encoding="utf-8")
        self._persisted = EventRecorder(self._file)
        self._console = EventRecorder(sys.stdout) if mode == "jsonl" else None

    def emit(self, event: object) -> None:
        self._persisted.emit(event)  # type: ignore[arg-type]
        if self._console is not None:
            self._console.emit(event)  # type: ignore[arg-type]
            return
        kind = getattr(event, "type", type(event).__name__)
        callsite = getattr(event, "callsite_id", "")
        if kind == "traffic":
            return
        if kind == "replay":
            typer.echo(f"replay {callsite}: {getattr(event, 'passed', 0)}/{getattr(event, 'total', 0)}")
        elif kind == "verdict":
            verdict = getattr(event, "verdict", None)
            typer.echo(f"verdict {getattr(verdict, 'callsite_id', callsite)}: {getattr(verdict, 'status', 'unknown')}")
        elif kind == "done":
            totals = getattr(event, "totals", None)
            typer.echo(f"done: {getattr(totals, 'compiled', 0)} compiled, {getattr(totals, 'kept', 0)} kept")
        else:
            suffix = f" {callsite}" if callsite else ""
            typer.echo(f"{kind}{suffix}")

    def close(self) -> None:
        self._file.close()


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
    event_log: Annotated[Path | None, typer.Option("--event-log")] = None,
) -> None:
    """Scan, synthesize candidates in worktrees, then parent-verify sealed holdouts once."""
    if events not in {"jsonl", "human"}:
        raise typer.BadParameter("--events must be jsonl or human")
    root = repo.resolve()
    if not root.is_dir() or not (root / ".git").exists():
        raise typer.BadParameter(f"run requires a local Git checkout: {root}")
    ledger_path = root / ".promptectomy" / "ledger.jsonl"
    if not ledger_path.exists() or ledger_path.stat().st_size == 0:
        raise typer.BadParameter(
            f"no captured traffic at {ledger_path}; run the application with the capture shim before compile"
        )
    schema_path = _audit_schema_path()
    audit_path = root / ".promptectomy" / "run" / "audit.json"
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    recorder = _RunRecorder((event_log or audit_path.parent / "events.ndjson").resolve(), events)
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
    recorder.close()


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


@app.command("scan")
def scan_cmd(
    repo: Annotated[str, typer.Argument()],
    out: Annotated[Path, typer.Option("--out")] = Path("."),
) -> None:
    """Audit ANY repo for LLM callsites and print the report. No traffic, no synthesis, no verdict."""
    import subprocess

    from .contracts import AuditReport
    from .scan import build_command

    schema_path = _audit_schema_path()
    out_resolved = out.resolve()
    out_path = out_resolved / "audit.json" if out_resolved.is_dir() else out_resolved
    out_path.parent.mkdir(parents=True, exist_ok=True)
    audit_prompt = (
        "Audit this repository for OpenAI or other LLM API callsites (responses.create, "
        "chat.completions.create, or equivalents). Return the required JSON. For each callsite set kind "
        "to structured, classifier, or freeform; eligibility to candidate for low-entropy structured or "
        "classification calls and keep_model for freeform generation or vision; sample_count 0; and a "
        "short reason. Do not decide a verdict and never inspect a sealed holdout."
    )
    checkout: TemporaryDirectory[str] | None = None
    try:
        if _remote_url(repo):
            parsed = urlparse(repo)
            if parsed.username is not None or parsed.password is not None:
                raise ValueError("remote repository URL must not contain credentials")
            checkout = TemporaryDirectory(prefix="promptectomy-scan-")
            root = Path(checkout.name) / "repo"
            subprocess.run(["git", "clone", "--depth", "1", "--", repo, str(root)], capture_output=True, text=True, check=True, timeout=120)
        else:
            root = Path(repo).resolve()
            if not root.is_dir():
                raise ValueError(f"repository does not exist: {root}")
        subprocess.run(build_command(root, schema_path, out_path), input=audit_prompt, text=True, capture_output=True, check=True, timeout=180)
        report = AuditReport.model_validate_json(out_path.read_text(encoding="utf-8"))
    except (subprocess.SubprocessError, ValueError, OSError) as exc:
        typer.echo(f"scan failed: {type(exc).__name__}: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    finally:
        if checkout is not None:
            checkout.cleanup()
    typer.echo(report.model_dump_json(indent=2))


@app.command()
def doctor(repo: Annotated[Path, typer.Argument()] = Path(".")) -> None:
    """Check whether a local checkout is ready for scan, compile, and live reporting."""
    root = repo.resolve()
    checks = {
        "local checkout": root.is_dir(),
        "Git repository": (root / ".git").exists(),
        "Codex CLI": shutil.which("codex") is not None,
        "captured ledger": (root / ".promptectomy" / "ledger.jsonl").exists(),
        "packaged compile schema": _audit_schema_path().exists(),
        "event log": (root / ".promptectomy" / "run" / "events.ndjson").exists(),
    }
    for name, ready in checks.items():
        typer.echo(f"{'PASS' if ready else 'MISS'}  {name}")
    if not all(checks.values()):
        raise typer.Exit(code=1)


@app.command()
def serve(
    repo: Annotated[Path, typer.Argument()] = Path("."),
    host: Annotated[str, typer.Option("--host")] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port")] = 4320,
) -> None:
    """Serve the persisted run and live SSE stream for the dashboard."""
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise typer.BadParameter("--host must be a loopback address; network serving is not supported")
    import uvicorn

    from .server import create_app

    root = repo.resolve()
    event_path = root / ".promptectomy" / "run" / "events.ndjson"
    display_host = f"[{host}]" if ":" in host else host
    typer.echo(f"events: http://{display_host}:{port}/events")
    typer.echo(f"dashboard: http://127.0.0.1:4319/?live=http://{display_host}:{port}/events")
    uvicorn.run(create_app(event_path), host=host, port=port)


if __name__ == "__main__":
    app()
