"""NDJSON event transport shared by the CLI and dashboard adapter."""

from __future__ import annotations

import json
import time
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import TextIO

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

from .contracts import PipelineEvent


class _RecordedLine(BaseModel):
    model_config = ConfigDict(extra="forbid")

    at_ms: float = Field(ge=0)
    event: PipelineEvent


_LINE = TypeAdapter(_RecordedLine)


def encode(event: PipelineEvent, *, at_ms: float) -> str:
    validated = _LINE.validate_python({"at_ms": at_ms, "event": event})
    return json.dumps(_LINE.dump_python(validated, mode="json"), separators=(",", ":"))


def decode(line: str, *, source: str | Path = "<stream>", line_number: int = 1) -> dict[str, object]:
    try:
        validated = _LINE.validate_json(line)
    except ValueError as exc:
        raise ValueError(f"invalid pipeline event at {source}:{line_number}") from exc
    return _LINE.dump_python(validated, mode="json")


@dataclass
class EventRecorder:
    target: TextIO
    started_at: float = field(default_factory=time.perf_counter)

    def emit(self, event: PipelineEvent) -> None:
        self.target.write(encode(event, at_ms=round((time.perf_counter() - self.started_at) * 1000, 3)))
        self.target.write("\n")
        self.target.flush()


def stream(path: str | Path) -> Iterator[dict[str, object]]:
    with Path(path).open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            yield decode(line, source=path, line_number=line_number)


def emit_all(recorder: EventRecorder, events: Iterable[PipelineEvent]) -> None:
    for event in events:
        recorder.emit(event)
