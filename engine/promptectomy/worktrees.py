"""Small Git CLI wrapper for isolated synthesis worktrees."""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Worktree:
    repo_root: Path
    path: Path
    branch: str
    callsite_id: str


def create(repo_root: str | Path, worktrees_root: str | Path, callsite_id: str) -> Worktree:
    root = Path(repo_root).resolve()
    path = Path(worktrees_root).resolve() / callsite_id
    branch = f"pt/{callsite_id}"
    if path.exists():
        raise FileExistsError(f"worktree path already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "-C", str(root), "worktree", "add", "-b", branch, str(path)], check=True)
    return Worktree(repo_root=root, path=path, branch=branch, callsite_id=callsite_id)


def stage(worktree: Worktree, engine_root: str | Path, fixtures: list[str | Path]) -> None:
    """Copy only engine source and train/dev fixtures into an isolated worktree."""
    source = Path(engine_root).resolve()
    destination = worktree.path / "engine"
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(source, destination, ignore=shutil.ignore_patterns(".venv", "__pycache__", ".pytest_cache"))
    fixture_root = worktree.path / ".promptectomy" / "fixtures"
    fixture_root.mkdir(parents=True, exist_ok=True)
    for fixture in fixtures:
        fixture_path = Path(fixture)
        shutil.copy2(fixture_path, fixture_root / fixture_path.name)


def cleanup(worktree: Worktree) -> None:
    subprocess.run(["git", "-C", str(worktree.repo_root), "worktree", "remove", "--force", str(worktree.path)], check=True)
    subprocess.run(["git", "-C", str(worktree.repo_root), "branch", "-D", worktree.branch], check=True)
