from __future__ import annotations

import os
from pathlib import Path

import pytest

from promptectomy.artifacts_v2 import ArtifactError, ArtifactStore
from promptectomy.state_v2 import StateConflict, StateStore


def stores(tmp_path: Path) -> tuple[StateStore, ArtifactStore]:
    root = tmp_path / "state"
    root.mkdir(mode=0o700)
    state = StateStore(root)
    return state, ArtifactStore(state)


def test_artifact_write_read_class_and_metadata_integrity(tmp_path: Path) -> None:
    state, artifacts = stores(tmp_path)
    with state:
        stored = artifacts.put(
            b"safe report", artifact_class="safe", media_type="text/plain"
        )
        assert artifacts.read(stored.artifact_id, allowed_classes={"safe"}) == b"safe report"
        with pytest.raises(ArtifactError, match="not authorized"):
            artifacts.read(stored.artifact_id, allowed_classes={"protected"})
        with pytest.raises(StateConflict, match="metadata conflicts"):
            artifacts.put(
                b"safe report", artifact_class="protected", media_type="text/plain"
            )


def test_tamper_and_symlink_are_detected(tmp_path: Path) -> None:
    state, artifacts = stores(tmp_path)
    with state:
        stored = artifacts.put(b"original", artifact_class="safe", media_type="text/plain")
        stored.path.write_bytes(b"tampered")
        with pytest.raises(ArtifactError, match="size mismatch|digest mismatch"):
            artifacts.read(stored.artifact_id, allowed_classes={"safe"})

        second = artifacts.put(b"second", artifact_class="safe", media_type="text/plain")
        original = tmp_path / "original-artifact"
        second.path.rename(original)
        second.path.symlink_to(original)
        with pytest.raises(ArtifactError, match="not a regular file"):
            artifacts.read(second.artifact_id, allowed_classes={"safe"})


def test_garbage_collection_defaults_to_dry_run_and_respects_refs(tmp_path: Path) -> None:
    state, artifacts = stores(tmp_path)
    with state:
        unreferenced = artifacts.put(b"one", artifact_class="safe", media_type="text/plain")
        referenced = artifacts.put(b"two", artifact_class="safe", media_type="text/plain")
        artifacts.add_reference(referenced.artifact_id, owner_type="run", owner_id="run-1")
        assert artifacts.collect() == [unreferenced.artifact_id]
        assert unreferenced.path.exists()
        assert artifacts.collect(dry_run=False) == [unreferenced.artifact_id]
        assert not unreferenced.path.exists()
        assert referenced.path.exists()


def test_failed_atomic_link_is_quarantined(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state, artifacts = stores(tmp_path)
    with state:
        monkeypatch.setattr(os, "link", lambda *_: (_ for _ in ()).throw(OSError("fault")))
        with pytest.raises(OSError, match="fault"):
            artifacts.put(b"fault", artifact_class="safe", media_type="text/plain")
        assert list(artifacts.quarantine.iterdir())
        assert state.artifact_record(
            "sha256:75aee9dcc9f1d5f07d2b48b8f8494e3dce7a1f5c4f3b9c0a08318e2f8b3d6e0a"
        ) is None


def test_startup_reconciles_orphan_and_tampered_files(tmp_path: Path) -> None:
    state, artifacts = stores(tmp_path)
    with state:
        stored = artifacts.put(b"known", artifact_class="safe", media_type="text/plain")
        orphan = artifacts.root / "safe" / "sha256" / "ff" / ("f" * 64)
        orphan.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        orphan.write_bytes(b"orphan")
        orphan.chmod(0o600)
        ArtifactStore(state)
        assert not orphan.exists()
        assert state.artifact_record(stored.artifact_id) is not None

        stored.path.write_bytes(b"bad!!")
        ArtifactStore(state)
        record = state.artifact_record(stored.artifact_id)
        assert record is not None
        assert record[4:6] == (0, 1)
        assert not stored.path.exists()
