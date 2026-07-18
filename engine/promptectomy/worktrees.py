"""Small Git CLI wrapper for isolated synthesis worktrees."""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .contracts import CALLSITE_ID_PATTERN


@dataclass(frozen=True)
class Worktree:
    repo_root: Path
    worktrees_root: Path
    path: Path
    branch: str
    callsite_id: str


def _validated_callsite_id(callsite_id: str) -> str:
    if not isinstance(callsite_id, str) or re.fullmatch(CALLSITE_ID_PATTERN, callsite_id) is None:
        raise ValueError(f"invalid callsite_id {callsite_id!r}")
    return callsite_id


def _contained_path(root: Path, *parts: str) -> Path:
    resolved_root = root.resolve()
    candidate = resolved_root.joinpath(*parts).resolve()
    if candidate == resolved_root or not candidate.is_relative_to(resolved_root):
        raise ValueError(f"path escapes {resolved_root}: {candidate}")
    return candidate


def _validate_worktree(worktree: Worktree) -> None:
    callsite_id = _validated_callsite_id(worktree.callsite_id)
    expected_path = _contained_path(worktree.worktrees_root, callsite_id)
    if worktree.path.resolve() != expected_path:
        raise ValueError(f"worktree path does not match callsite_id {callsite_id!r}: {worktree.path}")
    expected_branch = f"pt/{callsite_id}"
    if worktree.branch != expected_branch:
        raise ValueError(f"worktree branch does not match callsite_id {callsite_id!r}: {worktree.branch!r}")


def create(repo_root: str | Path, worktrees_root: str | Path, callsite_id: str) -> Worktree:
    root = Path(repo_root).resolve()
    worktrees = Path(worktrees_root).resolve()
    callsite_id = _validated_callsite_id(callsite_id)
    path = _contained_path(worktrees, callsite_id)
    branch = f"pt/{callsite_id}"
    if path.exists():
        raise FileExistsError(f"worktree path already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "-C", str(root), "worktree", "add", "-b", branch, str(path)], check=True)
    return Worktree(repo_root=root, worktrees_root=worktrees, path=path, branch=branch, callsite_id=callsite_id)


def stage(worktree: Worktree, engine_root: str | Path, fixtures: list[str | Path]) -> None:
    """Copy only engine source and train/dev fixtures into an isolated worktree."""
    _validate_worktree(worktree)
    source = Path(engine_root).resolve()
    destination = _contained_path(worktree.path, "engine")
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(source, destination, ignore=shutil.ignore_patterns(".venv", "__pycache__", ".pytest_cache"))
    fixture_root = _contained_path(worktree.path, ".promptectomy", "fixtures")
    fixture_root.mkdir(parents=True, exist_ok=True)
    for fixture in fixtures:
        fixture_path = Path(fixture)
        shutil.copy2(fixture_path, _contained_path(fixture_root, fixture_path.name))


def cleanup(worktree: Worktree) -> None:
    _validate_worktree(worktree)
    subprocess.run(["git", "-C", str(worktree.repo_root), "worktree", "remove", "--force", str(worktree.path)], check=True)
    subprocess.run(["git", "-C", str(worktree.repo_root), "branch", "-D", worktree.branch], check=True)
