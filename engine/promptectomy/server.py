"""Local report bridge for persisted PROMPTECTOMY event streams."""

from __future__ import annotations

import asyncio
import json
import os
from collections.abc import AsyncIterator
from pathlib import Path

from fastapi import FastAPI, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from .events import decode, stream

DEFAULT_EVENTS_FILE = Path(__file__).resolve().parents[2] / ".promptectomy" / "run" / "events.ndjson"


def _snapshot(path: Path) -> list[dict[str, object]]:
    return list(stream(path)) if path.exists() else []


def _sse_message(event_id: int, envelope: dict[str, object]) -> str:
    data = json.dumps(envelope, separators=(",", ":"))
    return f"id: {event_id}\ndata: {data}\n\n"


async def _follow(path: Path, *, after_id: int, poll_interval: float) -> AsyncIterator[str]:
    offset = 0
    buffer = b""
    physical_line = 0
    event_id = 0

    while True:
        if path.exists():
            size = path.stat().st_size
            if size < offset:
                offset = 0
                buffer = b""
                physical_line = 0
                event_id = 0
            with path.open("rb") as handle:
                handle.seek(offset)
                chunk = handle.read()
                offset = handle.tell()
            buffer += chunk

            raw_lines = buffer.split(b"\n")
            buffer = raw_lines.pop()
            if buffer:
                try:
                    buffer.decode("utf-8")
                    decode(buffer.decode("utf-8"), source=path, line_number=physical_line + len(raw_lines) + 1)
                except (UnicodeDecodeError, ValueError):
                    pass
                else:
                    raw_lines.append(buffer)
                    buffer = b""

            for raw_line in raw_lines:
                physical_line += 1
                if not raw_line.strip():
                    continue
                envelope = decode(raw_line.decode("utf-8"), source=path, line_number=physical_line)
                event_id += 1
                if event_id > after_id:
                    yield _sse_message(event_id, envelope)
                event = envelope["event"]
                if isinstance(event, dict) and event.get("type") == "done":
                    return

            if chunk:
                continue
        await asyncio.sleep(poll_interval)


def create_app(events_file: str | Path, *, poll_interval: float = 0.1) -> FastAPI:
    path = Path(events_file).resolve()
    app = FastAPI(title="PROMPTECTOMY report bridge")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:4319", "http://127.0.0.1:4319"],
        allow_methods=["GET"],
        allow_headers=["Last-Event-ID"],
    )

    @app.get("/state")
    def state() -> dict[str, object]:
        events = _snapshot(path)
        return {
            "event_count": len(events),
            "complete": bool(events and events[-1]["event"].get("type") == "done"),
            "events": events,
        }

    @app.get("/events")
    def events(last_event_id: str | None = Header(default=None)) -> StreamingResponse:
        try:
            after_id = max(0, int(last_event_id)) if last_event_id else 0
        except ValueError:
            after_id = 0
        return StreamingResponse(
            _follow(path, after_id=after_id, poll_interval=poll_interval),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    return app


app = create_app(os.environ.get("PROMPTECTOMY_EVENTS_FILE", DEFAULT_EVENTS_FILE))
