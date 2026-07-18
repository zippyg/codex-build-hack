"""Sandboxed Codex synthesis invocation. Holdout data is deliberately absent."""

from __future__ import annotations

import json
import os
import subprocess
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .contracts import CallsiteStatusEvent, PipelineEvent, SynthTokenEvent
from .schemas import SynthesisResultV1
from .worktrees import Worktree


@dataclass(frozen=True)
class SynthesisRun:
    returncode: int
    timed_out: bool
    result: SynthesisResultV1 | None
    events: list[PipelineEvent]
    elapsed_ms: float


def build_command(worktree: Worktree, schema_path: str | Path, output_path: str | Path) -> list[str]:
    return [
        "codex",
        "-a",
        "never",
        "exec",
        "-C",
        str(worktree.path),
        "--sandbox",
        "workspace-write",
        "--ephemeral",
        "--json",
        "--output-schema",
        str(Path(schema_path).resolve()),
        "-o",
        str(Path(output_path).resolve()),
        "-",
    ]


def prompt(callsite_id: str, kind: str, *, resume: bool = False) -> str:
    suffix = "Some train/dev cases still fail. Read the failing cases and repair the module now." if resume else "Implement the first deterministic attempt now."
    if kind == "structured":
        target = (
            "Return a Python dict with EXACTLY the same keys as response_normalized. Use None for any "
            "field not present in the ticket text. It must equal response_normalized as canonical JSON."
        )
    elif kind == "classifier":
        target = "Return the exact lowercase label string that response_normalized contains (e.g. \"billing\")."
    else:
        target = "Return a string."
    return f"""Write engine/promptectomy/generated/{callsite_id}.py exposing run(input, params) -> value.

The training data is in this worktree at:
  .promptectomy/fixtures/train.jsonl  and  .promptectomy/fixtures/dev.jsonl
Each line is a JSON object. `request_input` is the exact string your run() receives as `input`;
`response_normalized` is the exact value your run(input, params) must return for that input. Read them.

This is a {kind} callsite. {target}
Constraints: pure and deterministic, Python stdlib only, no filesystem/network/environment/clock/
randomness/subprocess, and finish within 100ms per call. Holdout data does not exist here.

Before finishing, load every train and dev line and assert your run(request_input, request_params)
equals response_normalized for ALL of them (100% agreement). {suffix}
Return the required synthesis-result JSON after the file passes."""


def _event_text(payload: object) -> tuple[str, Literal["reasoning", "code", "tool"] | None] | None:
    if not isinstance(payload, dict):
        return None
    item = payload.get("item") if isinstance(payload.get("item"), dict) else payload
    text = item.get("text") or item.get("delta") or item.get("message")
    if not isinstance(text, str) or not text:
        return None
    raw_type = str(item.get("type", payload.get("type", "")))
    kind: Literal["reasoning", "code", "tool"] | None
    if "reason" in raw_type:
        kind = "reasoning"
    elif "tool" in raw_type or "command" in raw_type:
        kind = "tool"
    else:
        kind = "code"
    return text, kind


def pipeline_events(callsite_id: str, lines: Iterator[str]) -> Iterator[PipelineEvent]:
    for line in lines:
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        extracted = _event_text(payload)
        if extracted is not None:
            text, kind = extracted
            yield SynthTokenEvent(callsite_id=callsite_id, text=text, kind=kind)


def run(worktree: Worktree, callsite_id: str, kind: str, *, resume: bool = False) -> SynthesisRun:
    """Run at most one synthesis attempt, without forwarding OpenAI credentials."""
    run_root = worktree.path / ".promptectomy" / "run"
    run_root.mkdir(parents=True, exist_ok=True)
    output_path = run_root / "synthesis-result.json"
    schema_path = worktree.path / "engine" / "schemas" / "synthesis-result-v1.json"
    env = {name: value for name, value in os.environ.items() if name != "OPENAI_API_KEY"}
    started = time.perf_counter()
    events: list[PipelineEvent] = [CallsiteStatusEvent(callsite_id=callsite_id, status="iterating" if resume else "synthesizing", round=2 if resume else 1)]
    try:
        completed = subprocess.run(
            build_command(worktree, schema_path, output_path),
            input=prompt(callsite_id, kind, resume=resume),
            text=True,
            capture_output=True,
            timeout=180 if resume else 360,
            env=env,
        )
        events.extend(pipeline_events(callsite_id, iter(completed.stdout.splitlines())))
        result = SynthesisResultV1.model_validate_json(output_path.read_text(encoding="utf-8")) if output_path.exists() else None
        return SynthesisRun(completed.returncode, False, result, events, (time.perf_counter() - started) * 1000)
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode() if isinstance(exc.stdout, bytes) else exc.stdout or ""
        events.extend(pipeline_events(callsite_id, iter(stdout.splitlines())))
        return SynthesisRun(-1, True, None, events, (time.perf_counter() - started) * 1000)
