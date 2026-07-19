from __future__ import annotations

import hashlib
import os
import stat
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .contracts_v2 import artifact_id
from .state_v2 import StateConflict, StateError, StateStore


ARTIFACT_CLASSES = {"safe", "source", "protected", "diagnostic", "executable"}
MAX_ARTIFACT_BYTES = 1_000_000_000


class ArtifactError(StateError):
    pass


@dataclass(frozen=True)
class StoredArtifact:
    artifact_id: str
    artifact_class: str
    media_type: str
    byte_count: int
    path: Path


class ArtifactStore:
    def __init__(self, state: StateStore):
        self.state = state
        self.root = state.root / "artifacts"
        self.quarantine = state.root / "quarantine"
        for directory in (self.root, self.quarantine):
            if directory.exists() or directory.is_symlink():
                info = directory.lstat()
                if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                    raise ArtifactError(f"artifact directory is unsafe: {directory}")
                if info.st_mode & 0o077:
                    raise ArtifactError(f"artifact directory is not private: {directory}")
            else:
                directory.mkdir(mode=0o700)
        self._reconcile()

    def put(
        self,
        content: bytes,
        *,
        artifact_class: str,
        media_type: str,
        pinned: bool = False,
        retention_until_microseconds: int | None = None,
    ) -> StoredArtifact:
        if artifact_class not in ARTIFACT_CLASSES:
            raise ArtifactError(f"unknown artifact class: {artifact_class!r}")
        if not 0 <= len(content) <= MAX_ARTIFACT_BYTES:
            raise ArtifactError(f"artifact size is outside the accepted range: {len(content)}")
        if not media_type or len(media_type) > 256 or "/" not in media_type:
            raise ArtifactError(f"invalid artifact media type: {media_type!r}")
        identifier = artifact_id(content)
        existing = self.state.artifact_record(identifier)
        if existing is not None:
            stored_class, stored_media, stored_size, stored_relative, complete, quarantined, _, _ = existing
            if (
                stored_class != artifact_class
                or stored_media != media_type
                or stored_size != len(content)
                or not complete
                or quarantined
            ):
                raise StateConflict(f"artifact metadata conflicts for {identifier}")
            destination = self._path(stored_relative)
            self._verify_file(destination, identifier, len(content))
            self.state.register_artifact(
                artifact_id=identifier,
                artifact_class=artifact_class,
                media_type=media_type,
                byte_count=len(content),
                relative_path=stored_relative,
                pinned=pinned,
                retention_until_microseconds=retention_until_microseconds,
            )
            return StoredArtifact(
                identifier, artifact_class, media_type, len(content), destination
            )
        digest = identifier.removeprefix("sha256:")
        relative = PurePosixPath(artifact_class, "sha256", digest[:2], digest)
        destination = self.root.joinpath(*relative.parts)
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if destination.exists() or destination.is_symlink():
            self._verify_file(destination, identifier, len(content))
        else:
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=".incoming-", dir=destination.parent
            )
            temporary = Path(temporary_name)
            try:
                os.fchmod(descriptor, 0o600)
                view = memoryview(content)
                written = 0
                while written < len(content):
                    written += os.write(descriptor, view[written:])
                os.fsync(descriptor)
                os.close(descriptor)
                descriptor = -1
                self._verify_file(temporary, identifier, len(content))
                try:
                    os.link(temporary, destination)
                except FileExistsError:
                    self._verify_file(destination, identifier, len(content))
                temporary.unlink()
                self._sync_directory(destination.parent)
            except BaseException:
                if descriptor >= 0:
                    os.close(descriptor)
                if temporary.exists() or temporary.is_symlink():
                    quarantine = self.quarantine / f"{time.time_ns()}-{temporary.name}"
                    os.replace(temporary, quarantine)
                    self._sync_directory(self.quarantine)
                raise
        self.state.register_artifact(
            artifact_id=identifier,
            artifact_class=artifact_class,
            media_type=media_type,
            byte_count=len(content),
            relative_path=relative.as_posix(),
            pinned=pinned,
            retention_until_microseconds=retention_until_microseconds,
        )
        return StoredArtifact(identifier, artifact_class, media_type, len(content), destination)

    def read(
        self, identifier: str, *, allowed_classes: set[str]
    ) -> bytes:
        record = self.state.artifact_record(identifier)
        if record is None:
            raise ArtifactError(f"artifact does not exist: {identifier}")
        artifact_class, _, byte_count, relative, complete, quarantined, _, _ = record
        if artifact_class not in allowed_classes:
            raise ArtifactError(f"artifact class is not authorized: {artifact_class}")
        if not complete or quarantined:
            raise ArtifactError(f"artifact is incomplete or quarantined: {identifier}")
        path = self._path(relative)
        self._verify_file(path, identifier, byte_count)
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        try:
            chunks: list[bytes] = []
            remaining = byte_count
            while remaining:
                chunk = os.read(descriptor, min(remaining, 1_048_576))
                if not chunk:
                    raise ArtifactError(f"artifact was truncated while reading: {identifier}")
                chunks.append(chunk)
                remaining -= len(chunk)
            if os.read(descriptor, 1):
                raise ArtifactError(f"artifact grew while reading: {identifier}")
        finally:
            os.close(descriptor)
        content = b"".join(chunks)
        if artifact_id(content) != identifier:
            raise ArtifactError(f"artifact digest mismatch: {identifier}")
        return content

    def add_reference(self, identifier: str, *, owner_type: str, owner_id: str) -> None:
        if not owner_type or len(owner_type) > 64 or not owner_id or len(owner_id) > 256:
            raise ArtifactError("artifact reference owner is invalid")
        self.state.add_artifact_ref(identifier, owner_type, owner_id)

    def collect(self, *, dry_run: bool = True) -> list[str]:
        candidates = self.state.garbage_collectable(time.time_ns() // 1_000)
        if dry_run:
            return [identifier for identifier, _ in candidates]
        removed: list[str] = []
        for identifier, relative in candidates:
            path = self._path(relative)
            quarantine = self.quarantine / f"gc-{time.time_ns()}-{path.name}"
            os.replace(path, quarantine)
            self._sync_directory(path.parent)
            self._sync_directory(self.quarantine)
            try:
                self.state.delete_artifact_record(identifier)
            except BaseException:
                os.replace(quarantine, path)
                self._sync_directory(path.parent)
                raise
            quarantine.unlink()
            self._sync_directory(self.quarantine)
            removed.append(identifier)
        return removed

    def _path(self, relative: str) -> Path:
        pure = PurePosixPath(relative)
        if pure.is_absolute() or ".." in pure.parts or not pure.parts:
            raise ArtifactError(f"unsafe stored artifact path: {relative!r}")
        path = self.root.joinpath(*pure.parts)
        try:
            path.parent.resolve(strict=True).relative_to(self.root.resolve(strict=True))
        except (OSError, ValueError) as exc:
            raise ArtifactError(f"stored artifact path escapes the root: {relative!r}") from exc
        return path

    def _reconcile(self) -> None:
        seen: set[str] = set()
        entries = 0
        for path in self.root.rglob("*"):
            entries += 1
            if entries > 100_000:
                raise ArtifactError("artifact reconciliation exceeds the 100000-entry limit")
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode):
                continue
            relative = path.relative_to(self.root).as_posix()
            record = self.state.artifact_record_by_path(relative)
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or record is None:
                self._move_to_quarantine(path, "orphan")
                continue
            identifier, artifact_class, _, byte_count, complete, quarantined = record
            if (
                not complete
                or quarantined
                or relative.split("/", 1)[0] != artifact_class
            ):
                self._move_to_quarantine(path, "invalid")
                self.state.quarantine_artifact(identifier)
                continue
            try:
                self._verify_file(path, identifier, byte_count)
            except ArtifactError:
                self._move_to_quarantine(path, "tampered")
                self.state.quarantine_artifact(identifier)
                continue
            seen.add(identifier)
        for identifier, _ in self.state.complete_artifacts():
            if identifier not in seen:
                self.state.quarantine_artifact(identifier)

    def _move_to_quarantine(self, path: Path, reason: str) -> None:
        destination = self.quarantine / f"{reason}-{time.time_ns()}-{path.name}"
        os.replace(path, destination)
        self._sync_directory(path.parent)
        self._sync_directory(self.quarantine)

    @staticmethod
    def _verify_file(path: Path, identifier: str, expected_size: int) -> None:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise ArtifactError(f"artifact is not a regular file: {identifier}")
        if info.st_mode & 0o077:
            raise ArtifactError(f"artifact permissions are not private: {identifier}")
        if hasattr(os, "getuid") and info.st_uid != os.getuid():
            raise ArtifactError(f"artifact has the wrong owner: {identifier}")
        if info.st_size != expected_size:
            raise ArtifactError(f"artifact size mismatch: {identifier}")
        digest = hashlib.sha256()
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        try:
            while chunk := os.read(descriptor, 1_048_576):
                digest.update(chunk)
        finally:
            os.close(descriptor)
        if f"sha256:{digest.hexdigest()}" != identifier:
            raise ArtifactError(f"artifact digest mismatch: {identifier}")

    @staticmethod
    def _sync_directory(directory: Path) -> None:
        descriptor = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
