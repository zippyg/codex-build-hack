from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from promptectomy.contracts_v2 import typed_id


def timestamp() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def run_contract(*, run_id: str | None = None) -> dict[str, Any]:
    return {
        "schema_uri": "https://promptectomy.invalid/schemas/v2/run.schema.json",
        "schema_version": "2.0.0",
        "run_id": run_id or typed_id("run"),
        "snapshot_id": f"snap_sha256_{'a' * 64}",
        "authority_ids": [typed_id("authority")],
        "mode": "audit",
        "status": "created",
        "highest_support_level": "L0",
        "digests": {},
        "counters": {},
        "budgets": {},
        "cleanup_state": "not_required",
        "created_at": timestamp(),
        "last_sequence": 0,
    }


def event_contract(
    run_id: str,
    sequence: int,
    event_type: str,
    *,
    occurred_at: str | None = None,
) -> dict[str, Any]:
    schema_name = event_type.replace(".", "-")
    return {
        "schema_uri": "https://promptectomy.invalid/schemas/v2/event.schema.json",
        "schema_version": "2.0.0",
        "event_id": typed_id("event"),
        "run_id": run_id,
        "sequence": sequence,
        "occurred_at": occurred_at or timestamp(),
        "type": event_type,
        "payload_schema": f"https://promptectomy.invalid/schemas/v2/events/{schema_name}.schema.json",
        "payload_version": "2.0.0",
        "payload": {"reason": event_type},
        "artifact_refs": [],
    }


def stage_contract(run_id: str) -> dict[str, Any]:
    return {
        "schema_uri": "https://promptectomy.invalid/schemas/v2/stage.schema.json",
        "schema_version": "2.0.0",
        "stage_id": typed_id("stage"),
        "run_id": run_id,
        "kind": "scan",
        "state": "created",
        "attempt": 0,
        "max_attempts": 2,
        "retryable": True,
        "input_artifact_refs": [],
        "output_artifact_refs": [],
        "timing": {},
        "resources": {},
    }
