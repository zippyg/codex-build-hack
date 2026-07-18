"""NDJSON event transport shared by the CLI and dashboard adapter."""

from __future__ import annotations

import json
import time
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import TextIO

from pydantic import TypeAdapter

from .contracts import PipelineEvent

_EVENT = TypeAdapter(PipelineEvent)


def encode(event: PipelineEvent, *, at_ms: float) -> str:
    validated = _EVENT.validate_python(event)
    return json.dumps({"at_ms": at_ms, "event": _EVENT.dump_python(validated, mode="json")}, separators=(",", ":"))


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
            try:
                payload = json.loads(line)
                payload["event"] = _EVENT.dump_python(_EVENT.validate_python(payload["event"]), mode="json")
                yield payload
            except Exception as exc:
                raise ValueError(f"invalid pipeline event at {path}:{line_number}") from exc


def emit_all(recorder: EventRecorder, events: Iterable[PipelineEvent]) -> None:
    for event in events:
        recorder.emit(event)
