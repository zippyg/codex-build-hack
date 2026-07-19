from __future__ import annotations

from datetime import UTC, datetime

from .artifacts_v2 import ArtifactStore
from .contracts_v2 import canonical_json, typed_id
from .reference_contracts import RunResult
from .state_v2 import StateStore


def import_phase1_run(
    legacy: RunResult, state: StateStore, artifacts: ArtifactStore
) -> str:
    legacy_bytes = canonical_json(legacy.model_dump(mode="json"))
    source = artifacts.put(
        legacy_bytes,
        artifact_class="safe",
        media_type="application/vnd.promptectomy.phase1-run+json",
        pinned=True,
    )
    run_id = typed_id("run")
    authority_id = typed_id("authority")
    timestamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    snapshot_digest = legacy.snapshot_digest.removeprefix("sha256:")
    if len(snapshot_digest) != 64 or any(
        character not in "0123456789abcdef" for character in snapshot_digest
    ):
        snapshot_digest = source.artifact_id.removeprefix("sha256:")
    run = {
        "schema_uri": "https://promptectomy.invalid/schemas/v2/run.schema.json",
        "schema_version": "2.0.0",
        "run_id": run_id,
        "snapshot_id": f"snap_sha256_{snapshot_digest}",
        "authority_ids": [authority_id],
        "mode": legacy.mode,
        "status": "created",
        "highest_support_level": legacy.support.highest_level,
        "digests": {
            "legacy_run_artifact": source.artifact_id,
            "legacy_snapshot": legacy.snapshot_digest,
        },
        "counters": {
            "performed": legacy.work.performed,
            "skipped": legacy.work.skipped,
            "unsupported": legacy.work.unsupported,
        },
        "budgets": {},
        "cleanup_state": legacy.cleanup.status,
        "created_at": timestamp,
        "last_sequence": 0,
    }
    first = _event(
        run_id,
        1,
        "run.created",
        timestamp,
        {"legacy_run_id": legacy.run_id, "provenance": "phase1a_import"},
    )
    state.create_run(run, first, idempotency_key=f"legacy-{legacy.run_id}-created")
    for sequence, (event_type, status) in enumerate(
        (
            ("run.preflight", "preflight"),
            ("run.queued", "queued"),
            ("run.running", "running"),
            (f"run.{legacy.status}", legacy.status),
        ),
        start=2,
    ):
        state.append_event(
            _event(
                run_id,
                sequence,
                event_type,
                timestamp,
                {"provenance": "phase1a_import"},
            ),
            target_status=status,
            idempotency_key=f"legacy-{legacy.run_id}-{sequence}",
        )
    artifacts.add_reference(source.artifact_id, owner_type="run_import", owner_id=run_id)
    return run_id


def _event(
    run_id: str,
    sequence: int,
    event_type: str,
    occurred_at: str,
    payload: dict[str, str],
) -> dict[str, object]:
    return {
        "schema_uri": "https://promptectomy.invalid/schemas/v2/event.schema.json",
        "schema_version": "2.0.0",
        "event_id": typed_id("event"),
        "run_id": run_id,
        "sequence": sequence,
        "occurred_at": occurred_at,
        "type": event_type,
        "payload_schema": (
            "https://promptectomy.invalid/schemas/v2/events/"
            f"{event_type.replace('.', '-')}.schema.json"
        ),
        "payload_version": "2.0.0",
        "payload": payload,
        "artifact_refs": [],
    }
