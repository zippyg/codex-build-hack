from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from promptectomy.cli import app
from promptectomy.contracts import DoneEvent, DoneTotals, TrafficEvent
from promptectomy.events import decode, encode
from promptectomy.server import _follow, create_app


def recorded_run(path: Path) -> list[dict[str, object]]:
    events = [
        TrafficEvent(callsite_id="route_ticket", latency_ms=14.5, cost_usd=0.001, source="llm"),
        DoneEvent(
            totals=DoneTotals(
                callsites=1,
                compiled=1,
                kept=0,
                est_monthly_savings_usd=2.5,
                pipeline_cost_reduction_pct=100,
            )
        ),
    ]
    lines = [encode(event, at_ms=index * 10) for index, event in enumerate(events)]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return [decode(line) for line in lines]


def test_state_serves_validated_persisted_run(tmp_path: Path) -> None:
    run_file = tmp_path / "events.ndjson"
    expected = recorded_run(run_file)

    with TestClient(create_app(run_file)) as client:
        response = client.get("/state")

    assert response.status_code == 200
    assert response.json() == {"event_count": 2, "complete": True, "events": expected}


def test_events_replays_recorded_envelopes_as_sse(tmp_path: Path) -> None:
    run_file = tmp_path / "events.ndjson"
    expected = recorded_run(run_file)

    with TestClient(create_app(run_file)) as client:
        response = client.get("/events")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    messages = [block.splitlines() for block in response.text.strip().split("\n\n")]
    assert [message[0] for message in messages] == ["id: 1", "id: 2"]
    assert [json.loads(message[1].removeprefix("data: ")) for message in messages] == expected

    with TestClient(create_app(run_file)) as client:
        resumed = client.get("/events", headers={"Last-Event-ID": "1"})

    assert "id: 1" not in resumed.text
    assert "id: 2" in resumed.text


def test_event_stream_tails_an_active_run(tmp_path: Path) -> None:
    run_file = tmp_path / "events.ndjson"
    traffic = TrafficEvent(callsite_id="route_ticket", latency_ms=14.5, cost_usd=0.001, source="llm")
    done = DoneEvent(
        totals=DoneTotals(
            callsites=1,
            compiled=1,
            kept=0,
            est_monthly_savings_usd=2.5,
            pipeline_cost_reduction_pct=100,
        )
    )
    run_file.write_text(encode(traffic, at_ms=0) + "\n", encoding="utf-8")

    async def collect() -> list[str]:
        follower = _follow(run_file, after_id=0, poll_interval=0.001)
        first = await anext(follower)
        with run_file.open("a", encoding="utf-8") as handle:
            handle.write(encode(done, at_ms=10) + "\n")
        second = await anext(follower)
        with pytest.raises(StopAsyncIteration):
            await anext(follower)
        return [first, second]

    messages = asyncio.run(collect())
    assert messages[0].startswith("id: 1\ndata: ")
    assert messages[1].startswith("id: 2\ndata: ")


def test_recorded_envelope_rejects_invalid_timing() -> None:
    event = TrafficEvent(callsite_id="route_ticket", latency_ms=1, cost_usd=0, source="llm")
    payload = json.loads(encode(event, at_ms=0))
    payload["at_ms"] = -1

    with pytest.raises(ValueError, match="invalid pipeline event at run.ndjson:4"):
        decode(json.dumps(payload), source="run.ndjson", line_number=4)


def test_serve_rejects_network_binding(tmp_path: Path) -> None:
    result = CliRunner().invoke(app, ["serve", str(tmp_path), "--host", "0.0.0.0"])

    assert result.exit_code == 2
    assert "loopback address" in result.output
