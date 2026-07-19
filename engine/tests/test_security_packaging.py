from __future__ import annotations

import json
from importlib.resources import files
from pathlib import Path

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from promptectomy.cli import app
from promptectomy.contracts import CallsiteAudit, LedgerEventV1
from promptectomy.guard import ImpureEngine, assert_pure
from promptectomy.worktrees import Worktree, cleanup, create, stage


@pytest.mark.parametrize(
    "source",
    [
        'def run(input, params):\n    return __builtins__["open"]("/etc/passwd").read()\n',
        'def run(input, params):\n    reader = open\n    return reader("/etc/passwd").read()\n',
        'def run(input, params):\n    return run.__globals__["__builtins__"]["open"]("/etc/passwd").read()\n',
        'def run(input, params):\n    return ().__class__.__base__.__subclasses__()\n',
    ],
)
def test_guard_rejects_indirect_builtin_access(tmp_path: Path, source: str) -> None:
    module = tmp_path / "escape.py"
    module.write_text(source, encoding="utf-8")

    with pytest.raises(ImpureEngine, match="forbidden"):
        assert_pure(module)


def test_guard_allows_input_parameter_but_rejects_builtin_input(tmp_path: Path) -> None:
    pure = tmp_path / "pure.py"
    pure.write_text("def run(input, params):\n    return input\n", encoding="utf-8")
    assert_pure(pure)

    impure = tmp_path / "impure.py"
    impure.write_text("def run(value, params):\n    return input(value)\n", encoding="utf-8")
    with pytest.raises(ImpureEngine, match="calls forbidden builtin 'input'"):
        assert_pure(impure)


@pytest.mark.parametrize("callsite_id", ["../escape", "valid/../../escape", "x\n--force", "-branch", "a" * 129])
def test_contracts_reject_unsafe_callsite_ids(callsite_id: str) -> None:
    with pytest.raises(ValidationError):
        LedgerEventV1(
            event_id="event",
            recorded_at="2026-07-18T00:00:00Z",
            repo_sha="sha",
            callsite_id=callsite_id,
            model="gpt-5",
            request_input={},
            latency_ms=1,
        )

    with pytest.raises(ValidationError):
        CallsiteAudit(
            callsite_id=callsite_id,
            file="example.py",
            line=1,
            kind="structured",
            eligibility="candidate",
            sample_count=0,
        )


def test_worktree_rejects_unsafe_id_before_git(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="invalid callsite_id"):
        create(tmp_path, tmp_path / "worktrees", "../../escape")


def test_stage_rejects_destination_symlink_outside_worktree(tmp_path: Path) -> None:
    worktrees_root = tmp_path / "worktrees"
    worktree_path = worktrees_root / "safe_id"
    worktree_path.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    (worktree_path / "engine").symlink_to(outside, target_is_directory=True)
    source = tmp_path / "source"
    source.mkdir()
    worktree = Worktree(
        repo_root=tmp_path,
        worktrees_root=worktrees_root,
        path=worktree_path,
        branch="pt/safe_id",
        callsite_id="safe_id",
    )

    with pytest.raises(ValueError, match="path escapes"):
        stage(worktree, source, [])

    assert (worktree_path / "engine").is_symlink()
    assert list(outside.iterdir()) == []


def test_cleanup_rejects_mismatched_branch_before_git(tmp_path: Path) -> None:
    worktrees_root = tmp_path / "worktrees"
    worktree_path = worktrees_root / "safe_id"
    worktree_path.mkdir(parents=True)
    worktree = Worktree(
        repo_root=tmp_path,
        worktrees_root=worktrees_root,
        path=worktree_path,
        branch="--force",
        callsite_id="safe_id",
    )

    with pytest.raises(ValueError, match="branch does not match"):
        cleanup(worktree)


def test_bundled_schema_assets_are_importable() -> None:
    assets = files("promptectomy.schema_assets")

    for name in ("audit-v1.json", "draft-candidate-v1.json", "synthesis-result-v1.json", "verdict-v1.json"):
        schema = assets.joinpath(name)
        assert schema.is_file()
        assert json.loads(schema.read_text(encoding="utf-8"))["type"] == "object"


def test_scan_rejects_credential_bearing_remote_url(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        app,
        ["scan", "https://user:token@example.com/repo.git", "--out", str(tmp_path / "audit.json")],
    )

    assert result.exit_code == 1
    assert "must not contain credentials" in result.output
    assert "token" not in result.output
