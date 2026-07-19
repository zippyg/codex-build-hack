from __future__ import annotations

import os
import sqlite3
import time
from pathlib import Path

import pytest

from promptectomy.state_v2 import EventCursorExpired, StateConflict, StateError, StateStore
from v2_fixtures import event_contract, run_contract, stage_contract


def private_root(tmp_path: Path) -> Path:
    root = tmp_path / "state"
    root.mkdir(mode=0o700)
    return root


def test_create_transition_idempotency_and_atomic_sequence(tmp_path: Path) -> None:
    run = run_contract()
    created = event_contract(run["run_id"], 1, "run.created")
    with StateStore(private_root(tmp_path)) as state:
        first = state.create_run(run, created, idempotency_key="create-0001")
        assert first["last_sequence"] == 1
        assert state.create_run(run, created, idempotency_key="create-0001") == first

        conflicting = dict(created)
        conflicting["event_id"] = event_contract(run["run_id"], 1, "run.created")["event_id"]
        with pytest.raises(StateConflict, match="idempotency key"):
            state.create_run(run, conflicting, idempotency_key="create-0001")

        gap = event_contract(run["run_id"], 3, "run.preflight")
        with pytest.raises(StateConflict, match="does not follow"):
            state.append_event(gap, target_status="preflight", idempotency_key="event-0003")
        assert state.get_run(run["run_id"])["last_sequence"] == 1
        assert len(state.events_after(run["run_id"], 0)) == 1

        preflight = event_contract(run["run_id"], 2, "run.preflight")
        updated = state.append_event(
            preflight, target_status="preflight", idempotency_key="event-0002"
        )
        assert updated["status"] == "preflight"
        with pytest.raises(StateConflict, match="invalid run transition"):
            state.append_event(
                event_contract(run["run_id"], 3, "run.completed"),
                target_status="completed",
                idempotency_key="event-invalid",
            )
        assert state.get_run(run["run_id"])["last_sequence"] == 2


def test_two_connections_read_consistent_wal_state_and_backup(tmp_path: Path) -> None:
    root = private_root(tmp_path)
    run = run_contract()
    with StateStore(root) as writer:
        writer.create_run(
            run,
            event_contract(run["run_id"], 1, "run.created"),
            idempotency_key="create-0001",
        )
        with StateStore(root) as reader:
            assert reader.get_run(run["run_id"])["last_sequence"] == 1
        backup = tmp_path / "backup.sqlite3"
        writer.backup(backup)
        writer.integrity_check()
    connection = sqlite3.connect(f"file:{backup}?mode=ro", uri=True)
    try:
        assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert connection.execute("SELECT COUNT(*) FROM runs").fetchone() == (1,)
    finally:
        connection.close()


def test_private_local_root_is_mandatory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    public = tmp_path / "public"
    public.mkdir(mode=0o755)
    with pytest.raises(StateError, match="permissions"):
        StateStore(public)

    root = private_root(tmp_path)
    monkeypatch.setattr("promptectomy.state_v2._filesystem_type", lambda _: "network:nfs")
    with pytest.raises(StateError, match="not accepted"):
        StateStore(root)


def test_newer_state_schema_fails_closed(tmp_path: Path) -> None:
    root = private_root(tmp_path)
    database = root / "state-v2.sqlite3"
    database.touch(mode=0o600)
    connection = sqlite3.connect(database)
    connection.execute("PRAGMA user_version=999")
    connection.close()
    os.chmod(database, 0o600)
    with pytest.raises(StateError, match="newer than supported"):
        StateStore(root)


def test_stale_active_run_recovers_as_interrupted(tmp_path: Path) -> None:
    run = run_contract()
    with StateStore(private_root(tmp_path)) as state:
        state.create_run(
            run,
            event_contract(run["run_id"], 1, "run.created"),
            idempotency_key="create-0001",
        )
        for sequence, status in ((2, "preflight"), (3, "queued"), (4, "running")):
            state.append_event(
                event_contract(run["run_id"], sequence, f"run.{status}"),
                target_status=status,
                idempotency_key=f"event-{sequence:04d}",
            )
        with pytest.raises(StateConflict, match="worker absence"):
            state.recover_interrupted(
                stale_before_microseconds=time.time_ns() // 1_000 + 1_000_000,
                worker_absence_verified=False,
            )
        recovered = state.recover_interrupted(
            stale_before_microseconds=time.time_ns() // 1_000 + 1_000_000,
            worker_absence_verified=True,
        )
        assert recovered == [run["run_id"]]
        assert state.get_run(run["run_id"])["status"] == "interrupted"
        assert state.get_run(run["run_id"])["last_sequence"] == 5


def test_completion_requires_performed_work_and_matching_event_type(tmp_path: Path) -> None:
    run = run_contract()
    with StateStore(private_root(tmp_path)) as state:
        state.create_run(
            run,
            event_contract(run["run_id"], 1, "run.created"),
            idempotency_key="create-0001",
        )
        for sequence, status in ((2, "preflight"), (3, "queued"), (4, "running")):
            state.append_event(
                event_contract(run["run_id"], sequence, f"run.{status}"),
                target_status=status,
                idempotency_key=f"event-{sequence:04d}",
            )
        with pytest.raises(StateConflict, match="does not match"):
            state.append_event(
                event_contract(run["run_id"], 5, "run.failed"),
                target_status="completed",
                idempotency_key="mismatch-0005",
            )
        with pytest.raises(StateConflict, match="performed-work"):
            state.append_event(
                event_contract(run["run_id"], 5, "run.completed"),
                target_status="completed",
                idempotency_key="complete-0005",
            )
        assert state.get_run(run["run_id"])["status"] == "running"


def test_retention_gap_expires_old_event_cursor(tmp_path: Path) -> None:
    run = run_contract()
    with StateStore(private_root(tmp_path)) as state:
        state.create_run(
            run,
            event_contract(run["run_id"], 1, "run.created"),
            idempotency_key="create-0001",
        )
        state.append_event(
            event_contract(run["run_id"], 2, "run.preflight"),
            target_status="preflight",
            idempotency_key="event-0002",
        )
        state.connection.execute(
            "DELETE FROM events WHERE run_id=? AND sequence=1", (run["run_id"],)
        )
        with pytest.raises(EventCursorExpired):
            state.events_after(run["run_id"], 0)


def test_stage_projection_and_event_are_one_transaction(tmp_path: Path) -> None:
    run = run_contract()
    stage = stage_contract(run["run_id"])
    with StateStore(private_root(tmp_path)) as state:
        state.create_run(
            run,
            event_contract(run["run_id"], 1, "run.created"),
            idempotency_key="create-0001",
        )
        created = state.create_stage(
            stage,
            event_contract(run["run_id"], 2, "stage.created"),
            idempotency_key="stage-create-0002",
        )
        assert created == stage
        assert state.get_run(run["run_id"])["last_sequence"] == 2
        assert state.get_stage(stage["stage_id"])["state"] == "created"
        queued = state.transition_stage(
            stage["stage_id"],
            event_contract(run["run_id"], 3, "stage.queued"),
            target_state="queued",
            idempotency_key="stage-queue-0003",
        )
        assert queued["state"] == "queued"
        with pytest.raises(StateConflict, match="does not follow"):
            state.transition_stage(
                stage["stage_id"],
                event_contract(run["run_id"], 5, "stage.running"),
                target_state="running",
                idempotency_key="stage-run-0005",
            )
        assert state.get_stage(stage["stage_id"])["state"] == "queued"
        assert state.get_run(run["run_id"])["last_sequence"] == 3
