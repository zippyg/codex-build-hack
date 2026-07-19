from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from promptectomy.api_v2 import create_app
from promptectomy.artifacts_v2 import ArtifactStore
from promptectomy.state_v2 import StateStore
from v2_fixtures import event_contract, run_contract


TOKEN = "phase2-test-capability-token-0000000000000000"


def client(
    tmp_path: Path, *, max_body_bytes: int = 2_000_000
) -> tuple[StateStore, ArtifactStore, TestClient]:
    root = tmp_path / "state"
    root.mkdir(mode=0o700)
    state = StateStore(root)
    artifacts = ArtifactStore(state)
    app = create_app(
        state,
        artifacts,
        capability_token=TOKEN,
        allowed_hosts={"testserver"},
        max_body_bytes=max_body_bytes,
        requests_per_minute=100,
    )
    return state, artifacts, TestClient(
        app, headers={"Authorization": f"Bearer {TOKEN}"}
    )


def test_capability_host_origin_and_body_boundaries(tmp_path: Path) -> None:
    state, _, accepted = client(tmp_path, max_body_bytes=8)
    try:
        assert accepted.get("/v2/health").status_code == 200
        missing = TestClient(accepted.app)
        assert missing.get("/v2/health").status_code == 401
        assert accepted.get(
            "/v2/health", headers={"Host": "attacker.example"}
        ).status_code == 400
        assert accepted.get(
            "/v2/health", headers={"Origin": "https://attacker.example"}
        ).status_code == 403
        oversized = accepted.post(
            "/v2/runs",
            content=b"x",
            headers={"Content-Length": "999999999", "Idempotency-Key": "body-0001"},
        )
        assert oversized.status_code == 413
        response = accepted.get("/v2/health")
        assert "access-control-allow-origin" not in response.headers
        assert response.headers["cache-control"] == "no-store"
        streamed = accepted.post(
            "/v2/runs",
            content=iter([b'{"run":', b'"body larger than declared policy"}']),
            headers={"Content-Type": "application/json", "Idempotency-Key": "body-0002"},
        )
        assert streamed.status_code == 413
    finally:
        state.close()


def test_run_event_cursor_report_and_safe_artifact_parity(tmp_path: Path) -> None:
    state, artifacts, api = client(tmp_path)
    try:
        run = run_contract()
        created = event_contract(run["run_id"], 1, "run.created")
        first = api.post(
            "/v2/runs",
            json={"run": run, "event": created},
            headers={"Idempotency-Key": "create-0001"},
        )
        assert first.status_code == 201
        assert api.post(
            "/v2/runs",
            json={"run": run, "event": created},
            headers={"Idempotency-Key": "create-0001"},
        ).json() == first.json()

        events = api.get(f"/v2/runs/{run['run_id']}/events").json()
        assert events["next_after"] == 1
        assert events["events"] == [created]

        report_one = api.post(f"/v2/runs/{run['run_id']}/report")
        report_two = api.post(f"/v2/runs/{run['run_id']}/report")
        assert report_one.status_code == 201
        assert report_one.json() == report_two.json()
        snapshot_id = report_one.json()["snapshot_artifact_id"]
        algorithm, digest = snapshot_id.split(":", 1)
        downloaded = api.get(f"/v2/artifacts/{algorithm}/{digest}")
        assert downloaded.status_code == 200
        assert downloaded.content == artifacts.read(
            snapshot_id, allowed_classes={"safe"}
        )
        assert b'"payload"' not in downloaded.content

        protected = artifacts.put(
            b"secret canary", artifact_class="protected", media_type="text/plain"
        )
        algorithm, digest = protected.artifact_id.split(":", 1)
        denied = api.get(f"/v2/artifacts/{algorithm}/{digest}")
        assert denied.status_code == 400
        assert b"secret canary" not in denied.content
    finally:
        state.close()


def test_idempotency_conflict_and_path_mismatch_are_typed(tmp_path: Path) -> None:
    state, _, api = client(tmp_path)
    try:
        run = run_contract()
        created = event_contract(run["run_id"], 1, "run.created")
        api.post(
            "/v2/runs",
            json={"run": run, "event": created},
            headers={"Idempotency-Key": "create-0001"},
        )
        missing_key = api.post(
            "/v2/runs", json={"run": run, "event": created}
        )
        assert missing_key.status_code == 409
        assert missing_key.json()["error"]["code"] == "state_conflict"
        event = event_contract(run["run_id"], 2, "run.preflight")
        mismatch = api.post(
            "/v2/runs/run_00000000-0000-7000-8000-000000000000/events",
            json={"event": event, "target_status": "preflight"},
            headers={"Idempotency-Key": "event-0002"},
        )
        assert mismatch.status_code == 409
        assert mismatch.json()["error"]["code"] == "state_conflict"
    finally:
        state.close()


def test_duplicate_json_and_secret_canary_are_rejected_without_echo(tmp_path: Path) -> None:
    state, _, api = client(tmp_path)
    try:
        response = api.post(
            "/v2/runs",
            content=(
                b'{"run":{},"run":{"secret":"PHASE2_SECRET_CANARY"},"event":{}}'
            ),
            headers={
                "Content-Type": "application/json",
                "Idempotency-Key": "duplicate-0001",
            },
        )
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "invalid_contract"
        assert b"PHASE2_SECRET_CANARY" not in response.content
    finally:
        state.close()
