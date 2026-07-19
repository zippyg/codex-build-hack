from __future__ import annotations

import hashlib
import os
import platform
import stat
import subprocess
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import apsw

from .contracts_v2 import canonical_json, parse_json_strict, typed_id, validate_contract


MINIMUM_SQLITE = (3, 51, 3)
SCHEMA_VERSION = 1
TERMINAL_STATUSES = {
    "completed",
    "completed_no_findings",
    "completed_with_unsupported",
    "failed",
    "cancelled",
}
RUN_TRANSITIONS = {
    "created": {"preflight", "cancelled", "failed"},
    "preflight": {"awaiting_authority", "queued", "cancelled", "failed"},
    "awaiting_authority": {"queued", "cancelled", "failed"},
    "queued": {"running", "cancelled", "failed"},
    "running": {"pausing", "cancelling", *TERMINAL_STATUSES, "interrupted"},
    "pausing": {"paused", "cancelling", "failed", "interrupted"},
    "paused": {"running", "cancelling", "cancelled", "interrupted"},
    "cancelling": {"cancelled", "failed", "interrupted"},
    "interrupted": {"queued", "cancelled", "failed"},
    "completed": set(),
    "completed_no_findings": set(),
    "completed_with_unsupported": set(),
    "failed": set(),
    "cancelled": set(),
}
STAGE_TRANSITIONS = {
    "created": {"awaiting_authority", "queued", "cancelled", "failed"},
    "awaiting_authority": {"queued", "cancelled", "failed"},
    "queued": {"running", "cancelled", "failed"},
    "running": {"pausing", "cancelling", "completed", "failed", "interrupted"},
    "pausing": {"paused", "cancelling", "failed", "interrupted"},
    "paused": {"running", "cancelling", "cancelled", "interrupted"},
    "cancelling": {"cancelled", "failed", "interrupted"},
    "interrupted": {"queued", "cancelled", "failed"},
    "completed": set(),
    "failed": set(),
    "cancelled": set(),
}
LOCAL_FILESYSTEMS = {
    "apfs",
    "btrfs",
    "ext2/ext3",
    "ext2/ext3/ext4",
    "ext4",
    "hfs",
    "hfs+",
    "tmpfs",
    "xfs",
    "zfs",
}


class StateError(RuntimeError):
    pass


class StateConflict(StateError):
    pass


class EventCursorExpired(StateError):
    pass


def _sqlite_version() -> tuple[int, int, int]:
    parts = apsw.sqlitelibversion().split(".")
    return tuple(int(part) for part in parts[:3])  # type: ignore[return-value]


def _filesystem_type(path: Path) -> str:
    system = platform.system()
    if system == "Darwin":
        result = subprocess.run(
            ["/sbin/mount"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5,
            check=False,
        )
        if result.returncode != 0:
            raise StateError("cannot inspect mounted filesystems for state storage")
        matches: list[tuple[int, str, bool]] = []
        for line in result.stdout.splitlines():
            _, separator, mounted = line.partition(" on ")
            if not separator or " (" not in mounted or not mounted.endswith(")"):
                continue
            mount_point, options_text = mounted.rsplit(" (", 1)
            mount_point = mount_point.replace("\\040", " ")
            try:
                path.relative_to(mount_point)
            except ValueError:
                continue
            options = [item.strip().lower() for item in options_text[:-1].split(",")]
            matches.append((len(mount_point), options[0], "local" in options))
        if not matches:
            raise StateError(f"cannot determine filesystem type for state root {path}")
        _, filesystem, local = max(matches)
        return filesystem if local else f"network:{filesystem}"
    elif system == "Linux":
        command = ["/usr/bin/stat", "-f", "-c", "%T", str(path)]
    else:
        raise StateError(f"state storage is unsupported on {system!r}")
    result = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=5,
        check=False,
    )
    if result.returncode != 0:
        raise StateError(f"cannot determine filesystem type for state root {path}")
    return result.stdout.strip().lower()


def ensure_private_state_root(root: Path) -> Path:
    if not root.is_absolute():
        raise StateError(f"state root must be absolute: {root}")
    if root.exists() or root.is_symlink():
        info = root.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise StateError(f"state root is not a real directory: {root}")
    else:
        root.mkdir(mode=0o700, parents=True)
        info = root.lstat()
    if hasattr(os, "getuid") and info.st_uid != os.getuid():
        raise StateError(f"state root has the wrong owner: {root}")
    if info.st_mode & 0o077:
        raise StateError(f"state root permissions are not private: {root}")
    resolved = root.resolve(strict=True)
    filesystem = _filesystem_type(resolved)
    if filesystem not in LOCAL_FILESYSTEMS:
        raise StateError(
            f"state root filesystem {filesystem!r} is not accepted for SQLite WAL"
        )
    return resolved


def _now_microseconds() -> int:
    return time.time_ns() // 1_000


class StateStore:
    def __init__(self, root: Path):
        if _sqlite_version() < MINIMUM_SQLITE:
            version = apsw.sqlitelibversion()
            raise StateError(
                f"SQLite {version} is below the required patched version 3.51.3"
            )
        self.root = ensure_private_state_root(root)
        self.path = self.root / "state-v2.sqlite3"
        if self.path.exists() or self.path.is_symlink():
            info = self.path.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise StateError(f"state database is not a regular file: {self.path}")
            if hasattr(os, "getuid") and info.st_uid != os.getuid():
                raise StateError(f"state database has the wrong owner: {self.path}")
            if info.st_mode & 0o077:
                raise StateError(f"state database permissions are not private: {self.path}")
        else:
            descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(descriptor)
        flags = (
            apsw.SQLITE_OPEN_READWRITE
            | apsw.SQLITE_OPEN_CREATE
            | apsw.SQLITE_OPEN_FULLMUTEX
            | apsw.SQLITE_OPEN_NOFOLLOW
        )
        self.connection = apsw.Connection(str(self.path), flags=flags)
        self.connection.setbusytimeout(5_000)
        self.connection.config(apsw.SQLITE_DBCONFIG_DEFENSIVE, True)
        self.connection.config(apsw.SQLITE_DBCONFIG_DQS_DDL, False)
        self.connection.config(apsw.SQLITE_DBCONFIG_DQS_DML, False)
        self.connection.config(apsw.SQLITE_DBCONFIG_TRUSTED_SCHEMA, False)
        self.connection.execute("PRAGMA foreign_keys=ON")
        self.connection.execute("PRAGMA synchronous=FULL")
        self.connection.execute("PRAGMA trusted_schema=OFF")
        self.connection.execute("PRAGMA secure_delete=ON")
        self.connection.execute("PRAGMA temp_store=MEMORY")
        mode_row = self.connection.execute("PRAGMA journal_mode=WAL").fetchone()
        if mode_row is None:
            self.connection.close()
            raise StateError(f"SQLite returned no journal mode for {self.path}")
        mode = mode_row[0]
        if str(mode).lower() != "wal":
            self.connection.close()
            raise StateError(f"SQLite refused WAL mode for {self.path}")
        self._migrate()

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> StateStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    @contextmanager
    def _transaction(self) -> Iterator[None]:
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            yield
            self.connection.execute("COMMIT")
        except BaseException:
            if not self.connection.getautocommit():
                self.connection.execute("ROLLBACK")
            raise

    def _migrate(self) -> None:
        version_row = self.connection.execute("PRAGMA user_version").fetchone()
        if version_row is None:
            raise StateError("SQLite returned no state schema version")
        version = version_row[0]
        if version > SCHEMA_VERSION:
            raise StateError(
                f"state schema version {version} is newer than supported version {SCHEMA_VERSION}"
            )
        if version == SCHEMA_VERSION:
            return
        if version != 0:
            raise StateError(f"no forward migration exists from state schema version {version}")
        with self._transaction():
            self.connection.execute(
                """
                CREATE TABLE schema_migrations(
                    version INTEGER PRIMARY KEY,
                    applied_at_microseconds INTEGER NOT NULL,
                    application_version TEXT NOT NULL
                ) STRICT
                """
            )
            self.connection.execute(
                """
                CREATE TABLE runs(
                    run_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    last_sequence INTEGER NOT NULL CHECK(last_sequence >= 0),
                    entity_json BLOB NOT NULL,
                    updated_at_microseconds INTEGER NOT NULL
                ) STRICT
                """
            )
            self.connection.execute(
                """
                CREATE TABLE events(
                    event_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE RESTRICT,
                    sequence INTEGER NOT NULL CHECK(sequence >= 1),
                    event_type TEXT NOT NULL,
                    entity_json BLOB NOT NULL,
                    occurred_at TEXT NOT NULL,
                    UNIQUE(run_id, sequence)
                ) STRICT
                """
            )
            self.connection.execute(
                """
                CREATE TABLE stages(
                    stage_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE RESTRICT,
                    state TEXT NOT NULL,
                    entity_json BLOB NOT NULL,
                    updated_at_microseconds INTEGER NOT NULL
                ) STRICT
                """
            )
            self.connection.execute(
                """
                CREATE TABLE idempotency(
                    run_id TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    key TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    response_json BLOB NOT NULL,
                    created_at_microseconds INTEGER NOT NULL,
                    PRIMARY KEY(run_id, operation, key)
                ) STRICT
                """
            )
            self.connection.execute(
                """
                CREATE TABLE artifacts(
                    artifact_id TEXT PRIMARY KEY,
                    class TEXT NOT NULL,
                    media_type TEXT NOT NULL,
                    byte_count INTEGER NOT NULL CHECK(byte_count >= 0),
                    relative_path TEXT NOT NULL UNIQUE,
                    complete INTEGER NOT NULL CHECK(complete IN (0, 1)),
                    quarantined INTEGER NOT NULL CHECK(quarantined IN (0, 1)),
                    pinned INTEGER NOT NULL CHECK(pinned IN (0, 1)),
                    retention_until_microseconds INTEGER,
                    created_at_microseconds INTEGER NOT NULL
                ) STRICT
                """
            )
            self.connection.execute(
                """
                CREATE TABLE artifact_refs(
                    artifact_id TEXT NOT NULL REFERENCES artifacts(artifact_id) ON DELETE RESTRICT,
                    owner_type TEXT NOT NULL,
                    owner_id TEXT NOT NULL,
                    PRIMARY KEY(artifact_id, owner_type, owner_id)
                ) STRICT
                """
            )
            self.connection.execute(
                "INSERT INTO schema_migrations VALUES (?, ?, ?)",
                (SCHEMA_VERSION, _now_microseconds(), "0.1.0"),
            )
            self.connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")

    def create_run(
        self,
        run: dict[str, Any],
        event: dict[str, Any],
        *,
        idempotency_key: str,
    ) -> dict[str, Any]:
        validate_contract(run)
        validate_contract(event)
        if run["status"] != "created" or run["last_sequence"] != 0:
            raise StateConflict("new run must start in created state at sequence zero")
        if event["run_id"] != run["run_id"] or event["sequence"] != 1:
            raise StateConflict("run.created event must be sequence one for the new run")
        if event["type"] != "run.created":
            raise StateConflict("new run requires a run.created event")
        request = {"run": run, "event": event}
        request_digest = hashlib.sha256(canonical_json(request)).hexdigest()
        response = dict(run)
        response["last_sequence"] = 1
        response_json = canonical_json(response)
        now = _now_microseconds()
        with self._transaction():
            existing = self.connection.execute(
                "SELECT request_digest, response_json FROM idempotency WHERE run_id=? AND operation='create_run' AND key=?",
                (run["run_id"], idempotency_key),
            ).fetchone()
            if existing is not None:
                if existing[0] != request_digest:
                    raise StateConflict("idempotency key was reused with a different create request")
                return parse_json_strict(existing[1])
            if self.connection.execute(
                "SELECT 1 FROM runs WHERE run_id=?", (run["run_id"],)
            ).fetchone() is not None:
                raise StateConflict(f"run already exists: {run['run_id']}")
            self.connection.execute(
                "INSERT INTO runs VALUES (?, ?, ?, ?, ?)",
                (run["run_id"], "created", 1, response_json, now),
            )
            self._insert_event(event)
            self.connection.execute(
                "INSERT INTO idempotency VALUES (?, 'create_run', ?, ?, ?, ?)",
                (run["run_id"], idempotency_key, request_digest, response_json, now),
            )
        return response

    def append_event(
        self,
        event: dict[str, Any],
        *,
        target_status: str | None = None,
        idempotency_key: str,
    ) -> dict[str, Any]:
        validate_contract(event)
        run_id = event["run_id"]
        if target_status is not None and event["type"] != f"run.{target_status}":
            raise StateConflict(
                f"event type {event['type']} does not match run status {target_status}"
            )
        request = {"event": event, "target_status": target_status}
        request_digest = hashlib.sha256(canonical_json(request)).hexdigest()
        now = _now_microseconds()
        with self._transaction():
            existing = self.connection.execute(
                "SELECT request_digest, response_json FROM idempotency WHERE run_id=? AND operation='append_event' AND key=?",
                (run_id, idempotency_key),
            ).fetchone()
            if existing is not None:
                if existing[0] != request_digest:
                    raise StateConflict("idempotency key was reused with a different event request")
                return parse_json_strict(existing[1])
            row = self.connection.execute(
                "SELECT status, last_sequence, entity_json FROM runs WHERE run_id=?",
                (run_id,),
            ).fetchone()
            if row is None:
                raise StateConflict(f"run does not exist: {run_id}")
            current_status, last_sequence, entity_json = row
            if event["sequence"] != last_sequence + 1:
                raise StateConflict(
                    f"event sequence {event['sequence']} does not follow {last_sequence} for {run_id}"
                )
            run = parse_json_strict(entity_json)
            if target_status is not None:
                if target_status not in RUN_TRANSITIONS.get(current_status, set()):
                    raise StateConflict(
                        f"invalid run transition for {run_id}: {current_status} to {target_status}"
                    )
                run["status"] = target_status
            if target_status in {"completed", "completed_no_findings"}:
                if run["counters"].get("performed", 0) < 1:
                    raise StateConflict(
                        f"completed run lacks performed-work evidence: {run_id}"
                    )
                if run["counters"].get("unsupported", 0) != 0:
                    raise StateConflict(
                        f"completed run contains unsupported work: {run_id}"
                    )
            if target_status == "completed_with_unsupported" and run["counters"].get(
                "unsupported", 0
            ) < 1:
                raise StateConflict(
                    f"unsupported terminal run lacks unsupported-work evidence: {run_id}"
                )
            run["last_sequence"] = event["sequence"]
            if target_status == "running" and "started_at" not in run:
                run["started_at"] = event["occurred_at"]
            if target_status in TERMINAL_STATUSES:
                run["terminal_at"] = event["occurred_at"]
            validate_contract(run)
            response_json = canonical_json(run)
            self._insert_event(event)
            self.connection.execute(
                "UPDATE runs SET status=?, last_sequence=?, entity_json=?, updated_at_microseconds=? WHERE run_id=?",
                (run["status"], run["last_sequence"], response_json, now, run_id),
            )
            self.connection.execute(
                "INSERT INTO idempotency VALUES (?, 'append_event', ?, ?, ?, ?)",
                (run_id, idempotency_key, request_digest, response_json, now),
            )
        return run

    def _insert_event(self, event: dict[str, Any]) -> None:
        if self.connection.execute(
            "SELECT 1 FROM events WHERE event_id=?", (event["event_id"],)
        ).fetchone() is not None:
            raise StateConflict(f"event already exists: {event['event_id']}")
        for identifier in event["artifact_refs"]:
            record = self.connection.execute(
                "SELECT complete, quarantined FROM artifacts WHERE artifact_id=?",
                (identifier,),
            ).fetchone()
            if record != (1, 0):
                raise StateConflict(
                    f"event references an unavailable artifact: {identifier}"
                )
        self.connection.execute(
            "INSERT INTO events VALUES (?, ?, ?, ?, ?, ?)",
            (
                event["event_id"],
                event["run_id"],
                event["sequence"],
                event["type"],
                canonical_json(event),
                event["occurred_at"],
            ),
        )
        for identifier in event["artifact_refs"]:
            self.connection.execute(
                "INSERT OR IGNORE INTO artifact_refs VALUES (?, 'event', ?)",
                (identifier, event["event_id"]),
            )

    def create_stage(
        self,
        stage: dict[str, Any],
        event: dict[str, Any],
        *,
        idempotency_key: str,
    ) -> dict[str, Any]:
        validate_contract(stage)
        validate_contract(event)
        run_id = stage["run_id"]
        if stage["state"] != "created" or event["type"] != "stage.created":
            raise StateConflict("new stage and event must both be in created state")
        if event["run_id"] != run_id:
            raise StateConflict("stage event run ID does not match its stage")
        request = {"stage": stage, "event": event}
        request_digest = hashlib.sha256(canonical_json(request)).hexdigest()
        response_json = canonical_json(stage)
        now = _now_microseconds()
        with self._transaction():
            existing = self.connection.execute(
                "SELECT request_digest, response_json FROM idempotency WHERE run_id=? AND operation='create_stage' AND key=?",
                (run_id, idempotency_key),
            ).fetchone()
            if existing is not None:
                if existing[0] != request_digest:
                    raise StateConflict("idempotency key was reused with a different stage request")
                return parse_json_strict(existing[1])
            row = self.connection.execute(
                "SELECT status, last_sequence, entity_json FROM runs WHERE run_id=?",
                (run_id,),
            ).fetchone()
            if row is None:
                raise StateConflict(f"run does not exist: {run_id}")
            if row[0] in TERMINAL_STATUSES:
                raise StateConflict(f"terminal run cannot create a stage: {run_id}")
            if event["sequence"] != row[1] + 1:
                raise StateConflict("stage event does not follow the run event sequence")
            if self.connection.execute(
                "SELECT 1 FROM stages WHERE stage_id=?", (stage["stage_id"],)
            ).fetchone() is not None:
                raise StateConflict(f"stage already exists: {stage['stage_id']}")
            run = parse_json_strict(row[2])
            run["last_sequence"] = event["sequence"]
            validate_contract(run)
            self.connection.execute(
                "INSERT INTO stages VALUES (?, ?, 'created', ?, ?)",
                (stage["stage_id"], run_id, response_json, now),
            )
            self._insert_event(event)
            self.connection.execute(
                "UPDATE runs SET last_sequence=?, entity_json=?, updated_at_microseconds=? WHERE run_id=?",
                (event["sequence"], canonical_json(run), now, run_id),
            )
            self.connection.execute(
                "INSERT INTO idempotency VALUES (?, 'create_stage', ?, ?, ?, ?)",
                (run_id, idempotency_key, request_digest, response_json, now),
            )
        return stage

    def transition_stage(
        self,
        stage_id: str,
        event: dict[str, Any],
        *,
        target_state: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        validate_contract(event)
        if event["type"] != f"stage.{target_state}":
            raise StateConflict("stage event type does not match target state")
        run_id = event["run_id"]
        request = {
            "stage_id": stage_id,
            "event": event,
            "target_state": target_state,
        }
        request_digest = hashlib.sha256(canonical_json(request)).hexdigest()
        now = _now_microseconds()
        with self._transaction():
            existing = self.connection.execute(
                "SELECT request_digest, response_json FROM idempotency WHERE run_id=? AND operation='transition_stage' AND key=?",
                (run_id, idempotency_key),
            ).fetchone()
            if existing is not None:
                if existing[0] != request_digest:
                    raise StateConflict("idempotency key was reused with a different stage transition")
                return parse_json_strict(existing[1])
            stage_row = self.connection.execute(
                "SELECT run_id, state, entity_json FROM stages WHERE stage_id=?",
                (stage_id,),
            ).fetchone()
            if stage_row is None:
                raise StateConflict(f"stage does not exist for run: {stage_id}")
            if stage_row[0] != run_id:
                raise StateConflict(f"stage does not exist for run: {stage_id}")
            if target_state not in STAGE_TRANSITIONS.get(stage_row[1], set()):
                raise StateConflict(
                    f"invalid stage transition for {stage_id}: {stage_row[1]} to {target_state}"
                )
            run_row = self.connection.execute(
                "SELECT last_sequence, entity_json FROM runs WHERE run_id=?", (run_id,)
            ).fetchone()
            if run_row is None:
                raise StateConflict(f"run does not exist: {run_id}")
            if event["sequence"] != run_row[0] + 1:
                raise StateConflict("stage event does not follow the run event sequence")
            stage = parse_json_strict(stage_row[2])
            stage["state"] = target_state
            validate_contract(stage)
            run = parse_json_strict(run_row[1])
            run["last_sequence"] = event["sequence"]
            validate_contract(run)
            response_json = canonical_json(stage)
            self._insert_event(event)
            self.connection.execute(
                "UPDATE stages SET state=?, entity_json=?, updated_at_microseconds=? WHERE stage_id=?",
                (target_state, response_json, now, stage_id),
            )
            self.connection.execute(
                "UPDATE runs SET last_sequence=?, entity_json=?, updated_at_microseconds=? WHERE run_id=?",
                (event["sequence"], canonical_json(run), now, run_id),
            )
            self.connection.execute(
                "INSERT INTO idempotency VALUES (?, 'transition_stage', ?, ?, ?, ?)",
                (run_id, idempotency_key, request_digest, response_json, now),
            )
        return stage

    def get_stage(self, stage_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT entity_json FROM stages WHERE stage_id=?", (stage_id,)
        ).fetchone()
        return None if row is None else parse_json_strict(row[0])

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT entity_json FROM runs WHERE run_id=?", (run_id,)
        ).fetchone()
        return None if row is None else parse_json_strict(row[0])

    def events_after(
        self, run_id: str, sequence: int, *, limit: int = 100
    ) -> list[dict[str, Any]]:
        if sequence < 0 or not 1 <= limit <= 1000:
            raise StateError("event cursor or limit is outside the accepted range")
        first_row = self.connection.execute(
            "SELECT MIN(sequence) FROM events WHERE run_id=?", (run_id,)
        ).fetchone()
        if first_row is None:
            raise StateError(f"event query failed for run: {run_id}")
        first = first_row[0]
        if first is None:
            if self.get_run(run_id) is None:
                raise StateError(f"run does not exist: {run_id}")
            return []
        if sequence + 1 < first:
            raise EventCursorExpired(
                f"event cursor {sequence} precedes retained sequence {first} for {run_id}"
            )
        rows = self.connection.execute(
            "SELECT entity_json FROM events WHERE run_id=? AND sequence>? ORDER BY sequence LIMIT ?",
            (run_id, sequence, limit),
        )
        events = [parse_json_strict(row[0]) for row in rows]
        expected = sequence + 1
        for event in events:
            if event["sequence"] != expected:
                raise StateError(f"event sequence gap detected for {run_id} at {expected}")
            expected += 1
        return events

    def register_artifact(
        self,
        *,
        artifact_id: str,
        artifact_class: str,
        media_type: str,
        byte_count: int,
        relative_path: str,
        pinned: bool,
        retention_until_microseconds: int | None,
    ) -> None:
        with self._transaction():
            existing = self.connection.execute(
                "SELECT class, media_type, byte_count, relative_path, complete, quarantined FROM artifacts WHERE artifact_id=?",
                (artifact_id,),
            ).fetchone()
            expected = (artifact_class, media_type, byte_count, relative_path, 1, 0)
            if existing is not None:
                if tuple(existing) != expected:
                    raise StateConflict(f"artifact metadata conflicts for {artifact_id}")
                if pinned:
                    self.connection.execute(
                        "UPDATE artifacts SET pinned=1 WHERE artifact_id=?", (artifact_id,)
                    )
                return
            self.connection.execute(
                "INSERT INTO artifacts VALUES (?, ?, ?, ?, ?, 1, 0, ?, ?, ?)",
                (
                    artifact_id,
                    artifact_class,
                    media_type,
                    byte_count,
                    relative_path,
                    int(pinned),
                    retention_until_microseconds,
                    _now_microseconds(),
                ),
            )

    def add_artifact_ref(self, artifact_id: str, owner_type: str, owner_id: str) -> None:
        with self._transaction():
            self.connection.execute(
                "INSERT OR IGNORE INTO artifact_refs VALUES (?, ?, ?)",
                (artifact_id, owner_type, owner_id),
            )

    def artifact_record(self, artifact_id: str) -> tuple[Any, ...] | None:
        return self.connection.execute(
            "SELECT class, media_type, byte_count, relative_path, complete, quarantined, pinned, retention_until_microseconds FROM artifacts WHERE artifact_id=?",
            (artifact_id,),
        ).fetchone()

    def artifact_record_by_path(self, relative_path: str) -> tuple[Any, ...] | None:
        return self.connection.execute(
            "SELECT artifact_id, class, media_type, byte_count, complete, quarantined FROM artifacts WHERE relative_path=?",
            (relative_path,),
        ).fetchone()

    def complete_artifacts(self) -> list[tuple[str, str]]:
        return list(
            self.connection.execute(
                "SELECT artifact_id, relative_path FROM artifacts WHERE complete=1 AND quarantined=0 ORDER BY artifact_id"
            )
        )

    def quarantine_artifact(self, artifact_id: str) -> None:
        with self._transaction():
            self.connection.execute(
                "UPDATE artifacts SET complete=0, quarantined=1 WHERE artifact_id=?",
                (artifact_id,),
            )
            if self.connection.changes() != 1:
                raise StateConflict(f"artifact does not exist: {artifact_id}")

    def garbage_collectable(self, now_microseconds: int) -> list[tuple[str, str]]:
        return list(
            self.connection.execute(
                """
                SELECT artifact_id, relative_path
                FROM artifacts
                WHERE complete=1 AND quarantined=0 AND pinned=0
                  AND (retention_until_microseconds IS NULL OR retention_until_microseconds<=?)
                  AND NOT EXISTS(SELECT 1 FROM artifact_refs WHERE artifact_refs.artifact_id=artifacts.artifact_id)
                ORDER BY artifact_id
                """,
                (now_microseconds,),
            )
        )

    def delete_artifact_record(self, artifact_id: str) -> None:
        with self._transaction():
            self.connection.execute(
                "DELETE FROM artifacts WHERE artifact_id=? AND pinned=0 AND NOT EXISTS(SELECT 1 FROM artifact_refs WHERE artifact_id=?)",
                (artifact_id, artifact_id),
            )
            if self.connection.changes() != 1:
                raise StateConflict(f"artifact became ineligible for deletion: {artifact_id}")

    def integrity_check(self) -> None:
        result = self.connection.execute("PRAGMA integrity_check").fetchall()
        if result != [("ok",)]:
            raise StateError(f"SQLite integrity check failed: {result!r}")
        violations = self.connection.execute("PRAGMA foreign_key_check").fetchall()
        if violations:
            raise StateError(f"SQLite foreign key check failed: {violations!r}")

    def backup(self, destination: Path) -> None:
        if destination.exists() or destination.is_symlink():
            raise StateError(f"backup destination already exists: {destination}")
        descriptor = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(descriptor)
        target = apsw.Connection(str(destination))
        try:
            with target.backup("main", self.connection, "main") as backup:
                while not backup.done:
                    backup.step(256)
        finally:
            target.close()

    def recover_interrupted(
        self,
        *,
        stale_before_microseconds: int,
        worker_absence_verified: bool,
    ) -> list[str]:
        if not worker_absence_verified:
            raise StateConflict(
                "stale runs cannot be interrupted before worker absence is verified"
            )
        rows = list(
            self.connection.execute(
                "SELECT run_id, last_sequence, entity_json FROM runs WHERE status IN ('running', 'pausing', 'paused', 'cancelling') AND updated_at_microseconds<? ORDER BY run_id",
                (stale_before_microseconds,),
            )
        )
        recovered: list[str] = []
        for run_id, last_sequence, entity_json in rows:
            event = {
                "schema_uri": "https://promptectomy.invalid/schemas/v2/event.schema.json",
                "schema_version": "2.0.0",
                "event_id": typed_id("event"),
                "run_id": run_id,
                "sequence": last_sequence + 1,
                "occurred_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                "type": "run.interrupted",
                "payload_schema": "https://promptectomy.invalid/schemas/v2/events/run-interrupted.schema.json",
                "payload_version": "2.0.0",
                "payload": {"reason": "stale_worker_lease"},
                "artifact_refs": [],
            }
            self.append_event(
                event,
                target_status="interrupted",
                idempotency_key=f"recovery-{last_sequence + 1}",
            )
            recovered.append(run_id)
        return recovered
