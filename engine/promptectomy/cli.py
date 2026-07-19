"""PROMPTECTOMY Phase 1A command-line surface."""

from __future__ import annotations

import json
import os
import stat
import sys
from importlib.resources import files
from pathlib import Path
from typing import Annotated
from urllib.parse import urlparse

import typer

from .connector import ResponsesConnector
from .reference import ReferenceFailure, default_state_root, execute, load_latest_run, load_run, render_report
from .reference_contracts import RunResult


app = typer.Typer(no_args_is_help=True, add_completion=False)


def _state_root(json_output: bool) -> Path:
    try:
        return default_state_root()
    except (OSError, ValueError):
        payload = {
            "schema_version": "phase1a-1",
            "status": "failed",
            "error": {
                "code": "invalid_state_root",
                "category": "state",
                "retryable": False,
                "safe_message": "The configured tool state root is invalid.",
                "next_action": "Configure PROMPTECTOMY_HOME as an absolute owner-controlled path.",
            },
        }
        if json_output:
            typer.echo(json.dumps(payload, separators=(",", ":"), sort_keys=True))
        else:
            typer.echo("error: invalid_state_root", err=True)
            typer.echo(payload["error"]["safe_message"], err=True)
        raise typer.Exit(code=9)


def _exit_code(result: RunResult) -> int:
    if result.status in {"completed", "completed_no_findings"}:
        return 0
    if result.status == "completed_with_unsupported":
        return 0 if result.mode == "inspect" else 3
    if result.status in {"cancelled", "interrupted"}:
        return 8
    if result.error is None:
        return 9
    if result.error.category == "input":
        return 2
    if result.error.category == "unsupported":
        return 3
    if result.error.category == "policy":
        return 4
    if result.error.category == "agent":
        return 6
    return 9


def _emit(result: RunResult, json_output: bool, *, preserve_run_exit: bool = True) -> None:
    if json_output:
        typer.echo(result.model_dump_json())
    else:
        typer.echo(f"run: {result.run_id}")
        typer.echo(f"mode: {result.mode}")
        typer.echo(f"status: {result.status}")
        typer.echo(f"support: {result.support.highest_level}")
        typer.echo(f"callsites: {result.support.callsites}")
        typer.echo(f"unsupported: {len(result.unsupported)}")
        if result.candidate is not None:
            typer.echo(f"candidate: {result.candidate.state} ({result.candidate.candidate_id})")
        if result.error is not None:
            typer.echo(f"error: {result.error.code}", err=True)
            typer.echo(result.error.safe_message, err=True)
            typer.echo(f"next: {result.error.next_action}", err=True)
    code = _exit_code(result) if preserve_run_exit else 0
    if code:
        raise typer.Exit(code=code)


def _execute_command(
    mode: str,
    source: str | Path,
    json_output: bool,
    *,
    policy: Path | None = None,
) -> None:
    state = _state_root(json_output)
    try:
        result = execute(
            mode,
            source,
            state_root=state,
            policy=policy,
            connector=ResponsesConnector.from_environment() if mode == "draft" else None,
        )
    except ReferenceFailure as exc:
        payload = {
            "schema_version": "phase1a-1",
            "status": "failed",
            "error": exc.error.model_dump(mode="json"),
        }
        if json_output:
            typer.echo(json.dumps(payload, separators=(",", ":"), sort_keys=True))
        else:
            typer.echo(f"error: {exc.error.code}", err=True)
            typer.echo(exc.error.safe_message, err=True)
        if exc.error.category == "input":
            raise typer.Exit(code=2)
        if exc.error.category == "unsupported":
            raise typer.Exit(code=3)
        if exc.error.category == "policy":
            raise typer.Exit(code=4)
        raise typer.Exit(code=9)
    except ValueError:
        payload = {
            "schema_version": "phase1a-1",
            "status": "failed",
            "error": {
                "code": "invalid_source",
                "category": "input",
                "retryable": False,
                "safe_message": "The selected source is invalid or unavailable.",
                "next_action": "Provide a readable local directory outside the tool state root.",
            },
        }
        if json_output:
            typer.echo(json.dumps(payload, separators=(",", ":"), sort_keys=True))
        else:
            typer.echo("error: invalid_source", err=True)
            typer.echo(payload["error"]["safe_message"], err=True)
        raise typer.Exit(code=2)
    except OSError:
        payload = {
            "schema_version": "phase1a-1",
            "status": "failed",
            "error": {
                "code": "state_unavailable",
                "category": "state",
                "retryable": True,
                "safe_message": "Private tool state is unavailable.",
                "next_action": "Check owner-only state storage permissions and free space before retrying.",
            },
        }
        if json_output:
            typer.echo(json.dumps(payload, separators=(",", ":"), sort_keys=True))
        else:
            typer.echo("error: state_unavailable", err=True)
        raise typer.Exit(code=9)
    _emit(result, json_output)


@app.command()
def doctor(
    source: Annotated[Path | None, typer.Argument()] = None,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Report Phase 1A readiness without exposing secret values."""
    state = _state_root(json_output)
    schema = files("promptectomy.schema_assets").joinpath("draft-candidate-v1.json")
    try:
        source_ready = source is None or (source.is_dir() and not source.is_symlink())
        state_outside = source is None or not state.resolve(strict=False).is_relative_to(source.resolve(strict=False))
    except (OSError, RuntimeError):
        source_ready = False
        state_outside = False
    if state.exists():
        state_info = state.lstat()
        state_ready = stat.S_ISDIR(state_info.st_mode) and not stat.S_ISLNK(state_info.st_mode) and not state_info.st_mode & 0o077
        if hasattr(os, "getuid"):
            state_ready = state_ready and state_info.st_uid == os.getuid()
    else:
        parent = state.parent
        state_ready = parent.is_dir() and os.access(parent, os.W_OK)
    checks = {
        "source_local_directory": source_ready,
        "git_metadata_detected": source is not None and (source / ".git").exists(),
        "state_root_outside_source": state_outside,
        "state_root_private_or_creatable": state_ready,
        "python_3_12_or_newer": sys.version_info >= (3, 12),
        "static_adapter_phase1a": True,
        "draft_schema_packaged": schema.is_file(),
        "responses_connector_configured": ResponsesConnector.from_environment() is not None,
        "executor_available": False,
        "protected_key_store_enabled": False,
        "local_api_available": False,
    }
    payload = {
        "schema_version": "phase1a-1",
        "operation": "doctor",
        "checks": checks,
        "capabilities": {
            "inspect": checks["source_local_directory"] and checks["state_root_outside_source"],
            "audit": checks["source_local_directory"] and checks["state_root_outside_source"],
            "draft_unverified": checks["responses_connector_configured"] and checks["draft_schema_packaged"] and checks["state_root_private_or_creatable"],
            "draft_verified": False,
        },
    }
    if json_output:
        typer.echo(json.dumps(payload, separators=(",", ":"), sort_keys=True))
    else:
        for name, ready in checks.items():
            typer.echo(f"{'PASS' if ready else 'MISS'}  {name}")
        typer.echo("Phase 1A supports unverified Draft only. No executor is configured by this phase.")
    if (
        not checks["source_local_directory"]
        or not checks["state_root_outside_source"]
        or not checks["state_root_private_or_creatable"]
        or not checks["python_3_12_or_newer"]
        or not checks["draft_schema_packaged"]
    ):
        raise typer.Exit(code=2)


@app.command("inspect")
def inspect_command(
    source: Annotated[str, typer.Argument()],
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Inventory a local source without mutation, execution, or egress."""
    _execute_command("inspect", source, json_output)


@app.command("audit")
def audit_command(
    source: Annotated[str, typer.Argument()],
    policy: Annotated[Path | None, typer.Option("--policy")] = None,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Perform deterministic static analysis without executing repository code."""
    if policy is not None:
        if json_output:
            typer.echo(
                json.dumps(
                    {
                        "schema_version": "phase1a-1",
                        "status": "failed",
                        "error": {
                            "code": "audit_external_policy_unsupported",
                            "category": "unsupported",
                            "retryable": False,
                            "safe_message": "Phase 1A Audit is local-only.",
                            "next_action": "Remove --policy or use Draft with an exact egress manifest.",
                        },
                    },
                    separators=(",", ":"),
                    sort_keys=True,
                )
            )
        else:
            typer.echo("error: audit_external_policy_unsupported", err=True)
            typer.echo("Phase 1A Audit is local-only. Remove --policy or use Draft with an exact egress manifest.", err=True)
        raise typer.Exit(code=3)
    _execute_command("audit", source, json_output)


@app.command("draft")
def draft_command(
    source: Annotated[str, typer.Argument()],
    policy: Annotated[Path | None, typer.Option("--policy")] = None,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Request an explicitly unverified patch under an exact egress manifest."""
    _execute_command("draft", source, json_output, policy=policy)


@app.command()
def status(
    run_id: Annotated[str | None, typer.Argument()] = None,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Read one persisted safe run projection."""
    state = _state_root(json_output)
    try:
        result = load_run(state, run_id) if run_id is not None else load_latest_run(state)
    except (OSError, ValueError):
        typer.echo("error: run_not_found", err=True)
        raise typer.Exit(code=9)
    _emit(result, json_output, preserve_run_exit=False)


@app.command()
def report(
    run_id: Annotated[str, typer.Argument()],
    format: Annotated[str, typer.Option("--format")] = "json",
) -> None:
    """Render the frozen Phase 1A safe JSON or Markdown projection."""
    if format not in {"json", "md"}:
        raise typer.BadParameter("--format must be json or md")
    state = _state_root(False)
    try:
        result = load_run(state, run_id)
    except (OSError, ValueError):
        typer.echo("error: run_not_found", err=True)
        raise typer.Exit(code=9)
    typer.echo(render_report(result, format), nl=False)


@app.command("scan")
def scan_alias(
    source: Annotated[str, typer.Argument()],
    out: Annotated[Path | None, typer.Option("--out")] = None,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Deprecated alias for local Inspect."""
    parsed = urlparse(source)
    if parsed.scheme:
        if parsed.username is not None or parsed.password is not None:
            typer.echo("scan failed: remote repository URL must not contain credentials", err=True)
        else:
            typer.echo("scan failed: remote_source_unsupported", err=True)
        raise typer.Exit(code=1)
    if out is not None:
        typer.echo("scan failed: --out is disabled; use report <run-id> --format json", err=True)
        raise typer.Exit(code=2)
    _execute_command("inspect", Path(source), json_output)


def _legacy_disabled(code: str, next_command: str) -> None:
    typer.echo(f"error: {code}", err=True)
    typer.echo(f"The hackathon mutation and execution path is disabled. Use {next_command}.", err=True)
    raise typer.Exit(code=4)


@app.command()
def run(source: Annotated[Path, typer.Argument()] = Path(".")) -> None:
    """Return a typed migration error for the unsafe hackathon command."""
    _ = source
    _legacy_disabled("legacy_run_disabled", "inspect, audit, or draft")


@app.command()
def accept(callsite_id: Annotated[str, typer.Argument()], repo: Annotated[Path, typer.Option("--repo")] = Path(".")) -> None:
    """Return a typed migration error for prototype hot-swap activation."""
    _ = (callsite_id, repo)
    _legacy_disabled("legacy_accept_disabled", "review the unverified candidate report")


@app.command()
def disable(callsite_id: Annotated[str, typer.Argument()], repo: Annotated[Path, typer.Option("--repo")] = Path(".")) -> None:
    """Return a typed migration error for prototype hot-swap state."""
    _ = (callsite_id, repo)
    _legacy_disabled("legacy_disable_disabled", "inspect or audit")


@app.command()
def serve(
    source: Annotated[Path, typer.Argument()] = Path("."),
    host: Annotated[str, typer.Option("--host")] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port")] = 4320,
) -> None:
    """Return a typed migration error for the recorded replay bridge."""
    _ = (source, port)
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise typer.BadParameter("--host must be a loopback address; network serving is not supported")
    _legacy_disabled("legacy_serve_disabled", "status or report")


if __name__ == "__main__":
    app()
