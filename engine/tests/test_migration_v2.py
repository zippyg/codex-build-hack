from __future__ import annotations

from pathlib import Path

from promptectomy.artifacts_v2 import ArtifactStore
from promptectomy.migration_v2 import import_phase1_run
from promptectomy.reference import execute
from promptectomy.state_v2 import StateStore


def test_phase1_run_import_preserves_target_and_provenance(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    callsite = source / "app.py"
    callsite.write_text(
        "from openai import OpenAI\nOpenAI().responses.create(model='gpt-5', input='hello')\n",
        encoding="utf-8",
    )
    before = callsite.read_bytes()
    legacy_root = tmp_path / "legacy"
    legacy = execute("inspect", source, state_root=legacy_root)
    v2_root = tmp_path / "v2"
    v2_root.mkdir(mode=0o700)
    with StateStore(v2_root) as state:
        artifacts = ArtifactStore(state)
        run_id = import_phase1_run(legacy, state, artifacts)
        imported = state.get_run(run_id)
        assert imported is not None
        assert imported["status"] == legacy.status
        assert imported["last_sequence"] == 5
        assert imported["digests"]["legacy_snapshot"] == legacy.snapshot_digest
        assert len(state.events_after(run_id, 0)) == 5
    assert callsite.read_bytes() == before
