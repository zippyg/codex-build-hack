from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import apsw
import pytest

from promptectomy.api_v2 import create_app
from promptectomy.artifacts_v2 import ArtifactError, ArtifactStore
from promptectomy.contracts_v2 import typed_id, validate_schema_document
from promptectomy.reports_v2 import freeze_report
from promptectomy.state_v2 import StateStore


def test_installed_contract_state_artifact_api_and_report(tmp_path: Path) -> None:
    validate_schema_document()
    assert tuple(int(part) for part in apsw.sqlitelibversion().split(".")) >= (3, 51, 3)
    root = tmp_path / "state"
    root.mkdir(mode=0o700)
    run_id = typed_id("run")
    timestamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    run = {
        "schema_uri": "https://promptectomy.invalid/schemas/v2/run.schema.json",
        "schema_version": "2.0.0",
        "run_id": run_id,
        "snapshot_id": f"snap_sha256_{'a' * 64}",
        "authority_ids": [typed_id("authority")],
        "mode": "audit",
        "status": "created",
        "highest_support_level": "L0",
        "digests": {},
        "counters": {},
        "budgets": {},
        "cleanup_state": "not_required",
        "created_at": timestamp,
        "last_sequence": 0,
    }
    event = {
        "schema_uri": "https://promptectomy.invalid/schemas/v2/event.schema.json",
        "schema_version": "2.0.0",
        "event_id": typed_id("event"),
        "run_id": run_id,
        "sequence": 1,
        "occurred_at": timestamp,
        "type": "run.created",
        "payload_schema": "https://promptectomy.invalid/schemas/v2/events/run-created.schema.json",
        "payload_version": "2.0.0",
        "payload": {"mode": "audit"},
        "artifact_refs": [],
    }
    with StateStore(root) as state:
        artifacts = ArtifactStore(state)
        token = "installed-v2-capability-token-000000000000"
        app = create_app(
            state,
            artifacts,
            capability_token=token,
            allowed_hosts={"testserver"},
        )
        assert "/v2/runs/{run_id}/events" in {route.path for route in app.routes}
        state.create_run(run, event, idempotency_key="installed-create-0001")
        report = freeze_report(state, artifacts, run_id)
        downloaded = artifacts.read(
            report.snapshot_artifact_id, allowed_classes={"safe"}
        )
        assert b'"payload"' not in downloaded
        protected = artifacts.put(
            b"installed-secret-canary",
            artifact_class="protected",
            media_type="text/plain",
        )
        with pytest.raises(ArtifactError, match="not authorized"):
            artifacts.read(protected.artifact_id, allowed_classes={"safe"})
