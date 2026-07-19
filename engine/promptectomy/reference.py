from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import unicodedata
import uuid
from collections import Counter
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Literal
from urllib.parse import urlparse

from pydantic import ValidationError

from .connector import ConnectorCancelled, ConnectorFailure, ResponsesConnector
from .discovery_javascript import ADAPTER_VERSION as JAVASCRIPT_ADAPTER_VERSION
from .discovery_javascript import discover_javascript
from .discovery_python import ADAPTER_VERSION as PYTHON_ADAPTER_VERSION
from .discovery_python import discover_python
from .reference_contracts import (
    AuthoritySummary,
    Callsite,
    CandidateSummary,
    CleanupSummary,
    DraftPolicy,
    Finding,
    ReceiptSummary,
    RetentionSummary,
    RunMode,
    RunResult,
    SafeError,
    SupportSummary,
    UnsupportedArea,
    WorkSummary,
)


_RUN_ID = re.compile(r"^run_[0-9a-f]{32}$")
_SOURCE_EXTENSIONS = {
    ".py": "python",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".js": "javascript",
    ".jsx": "javascript",
}
_INVENTORY_EXTENSIONS = {
    **_SOURCE_EXTENSIONS,
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".kt": "kotlin",
    ".rb": "ruby",
    ".php": "php",
    ".swift": "swift",
    ".cs": "csharp",
}
_IGNORED_DIRECTORIES = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "coverage",
    "__pycache__",
}
_MAX_FILES = 20_000
_MAX_FILE_BYTES = 2_000_000
_MAX_DIGEST_FILE_BYTES = 100_000_000
_MAX_DIGEST_TOTAL_BYTES = 2_000_000_000
_SECRET = re.compile(
    r"(?i)(?:sk-[a-z0-9_-]{16,}|api[_-]?key\s*[:=]\s*['\"]?[a-z0-9_-]{16,}|authorization\s*[:=]\s*bearer\s+[a-z0-9._-]{12,})"
)
_CONNECTOR_ERROR_CODES = {
    "agent_budget_exceeded",
    "agent_input_budget_exceeded",
    "agent_output_budget_exceeded",
    "agent_response_incomplete",
    "agent_response_schema_invalid",
    "agent_timeout",
    "cancelled",
    "policy_denied_destination",
    "safe_agent_transport_unavailable",
}


class ReferenceFailure(RuntimeError):
    def __init__(self, error: SafeError) -> None:
        super().__init__(error.code)
        self.error = error


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _digest_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _opaque(prefix: str, value: str | bytes) -> str:
    raw = value.encode("utf-8", errors="surrogatepass") if isinstance(value, str) else value
    return f"{prefix}_{hashlib.sha256(raw).hexdigest()}"


def _safe_error(
    code: str,
    category: Literal["input", "unsupported", "policy", "agent", "cancel", "state", "internal"],
    message: str,
    next_action: str,
    *,
    retryable: bool = False,
) -> SafeError:
    return SafeError(code=code, category=category, retryable=retryable, safe_message=message, next_action=next_action)


def default_state_root() -> Path:
    configured = os.environ.get("PROMPTECTOMY_HOME")
    if configured:
        path = Path(configured)
        if not path.is_absolute():
            raise ValueError("PROMPTECTOMY_HOME must be an absolute path")
        return path
    if os.name == "nt":
        local = os.environ.get("LOCALAPPDATA")
        if not local:
            raise ValueError("LOCALAPPDATA is unavailable")
        return Path(local) / "PROMPTECTOMY"
    if sys_platform() == "darwin":
        return Path.home() / "Library" / "Application Support" / "PROMPTECTOMY"
    data_home = os.environ.get("XDG_DATA_HOME")
    return Path(data_home) / "promptectomy" if data_home else Path.home() / ".local" / "share" / "promptectomy"


def sys_platform() -> str:
    import sys

    return sys.platform


def _ensure_private_directory(path: Path) -> None:
    if path.exists():
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise ReferenceFailure(
                _safe_error("unsafe_state_root", "state", "The tool state root is not a private directory.", "Select a new private state directory.")
            )
        if info.st_mode & 0o077:
            raise ReferenceFailure(
                _safe_error("unsafe_state_permissions", "state", "The tool state root is accessible to other users.", "Restrict the directory to owner-only access.")
            )
        if hasattr(os, "getuid") and info.st_uid != os.getuid():
            raise ReferenceFailure(
                _safe_error("unsafe_state_owner", "state", "The tool state root has the wrong owner.", "Select a state directory owned by the current user.")
            )
        return
    path.mkdir(mode=0o700, parents=True)
    path.chmod(0o700)


def _check_private_directory(path: Path) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise ValueError("private state directory is unavailable") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077:
        raise ValueError("private state directory is invalid")
    if hasattr(os, "getuid") and info.st_uid != os.getuid():
        raise ValueError("private state directory owner is invalid")


def _write_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    temporary = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        path.chmod(0o600)
    finally:
        if temporary.exists():
            temporary.unlink()


class _RunStore:
    def __init__(self, root: Path, run_id: str) -> None:
        _ensure_private_directory(root)
        runs = root / "runs"
        _ensure_private_directory(runs)
        self.root = root
        self.run_dir = runs / run_id
        self.run_dir.mkdir(mode=0o700)
        self.events = self.run_dir / "events.ndjson"
        self.sequence = 0

    def event(self, event_type: str, payload: dict[str, object]) -> None:
        self.sequence += 1
        envelope = {
            "schema_version": "phase1a-1",
            "run_id": self.run_dir.name,
            "sequence": self.sequence,
            "occurred_at": datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z"),
            "type": event_type,
            "payload": payload,
        }
        descriptor = os.open(self.events, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(descriptor, "ab") as handle:
            handle.write(_json_bytes(envelope) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())

    def artifact(self, group: str, data: bytes) -> str:
        digest = hashlib.sha256(data).hexdigest()
        directory = self.run_dir / group
        _ensure_private_directory(directory)
        path = directory / digest
        if path.exists():
            if path.read_bytes() != data:
                raise ReferenceFailure(
                    _safe_error("artifact_digest_collision", "state", "Stored artifact bytes do not match their digest.", "Move the state root aside and inspect it.")
                )
        else:
            _write_private(path, data)
        return f"sha256:{digest}"

    def save(self, result: RunResult) -> None:
        _write_private(self.run_dir / "run.json", _json_bytes(result.model_dump(mode="json")) + b"\n")


def _iter_entries(root: Path, *, excluded_names: frozenset[str] = frozenset()):
    stack = [root]
    while stack:
        directory = stack.pop()
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
        except (PermissionError, OSError) as exc:
            raise ReferenceFailure(
                _safe_error("source_unreadable", "input", "The selected source cannot be read safely.", "Fix source permissions or select another source.")
            ) from exc
        for entry in entries:
            if entry.name in excluded_names:
                continue
            path = Path(entry.path)
            yield path, entry
            try:
                if entry.is_dir(follow_symlinks=False) and not entry.is_symlink():
                    stack.append(path)
            except OSError as exc:
                raise ReferenceFailure(
                    _safe_error("source_unreadable", "input", "The selected source cannot be inventoried safely.", "Fix source permissions or select another source.")
                ) from exc


def _tree_digest(root: Path, *, excluded_names: frozenset[str] = frozenset()) -> str:
    digest = hashlib.sha256(b"promptectomy-phase1a-source\0")
    count = 0
    total_bytes = 0
    for path, entry in _iter_entries(root, excluded_names=excluded_names):
        count += 1
        if count > _MAX_FILES * 10:
            raise ReferenceFailure(
                _safe_error("source_quota_exceeded", "input", "The source exceeds the Phase 1A entry limit.", "Select a smaller source root.")
            )
        relative = os.fsencode(path.relative_to(root).as_posix())
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        try:
            info = entry.stat(follow_symlinks=False)
            if stat.S_ISLNK(info.st_mode):
                digest.update(b"l")
                target = os.fsencode(os.readlink(path))
                digest.update(len(target).to_bytes(8, "big"))
                digest.update(target)
            elif stat.S_ISREG(info.st_mode):
                if info.st_size > _MAX_DIGEST_FILE_BYTES or total_bytes + info.st_size > _MAX_DIGEST_TOTAL_BYTES:
                    raise ReferenceFailure(
                        _safe_error("source_quota_exceeded", "input", "The source exceeds the Phase 1A digest byte limit.", "Select a smaller source root or remove oversized artifacts.")
                    )
                digest.update(b"f")
                observed = 0
                descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                try:
                    opened = os.fstat(descriptor)
                    if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                        raise ReferenceFailure(
                            _safe_error("source_changed_during_read", "input", "The source changed during the safe digest read.", "Stabilize the source before retrying.")
                        )
                    while chunk := os.read(descriptor, 1024 * 1024):
                        observed += len(chunk)
                        if observed > _MAX_DIGEST_FILE_BYTES or total_bytes + observed > _MAX_DIGEST_TOTAL_BYTES:
                            raise ReferenceFailure(
                                _safe_error("source_quota_exceeded", "input", "The source grew beyond the Phase 1A digest byte limit.", "Stabilize and reduce the source before retrying.")
                            )
                        digest.update(chunk)
                finally:
                    os.close(descriptor)
                total_bytes += observed
            elif stat.S_ISDIR(info.st_mode):
                digest.update(b"d")
            else:
                digest.update(b"o")
        except (PermissionError, OSError) as exc:
            raise ReferenceFailure(
                _safe_error("source_unreadable", "input", "The source changed or became unreadable during inspection.", "Retry after stabilizing the source.")
            ) from exc
    return f"sha256:{digest.hexdigest()}"


def _read_git_pointer(path: Path, *, shared: bool = False) -> bytes:
    label = "Shared Git metadata" if shared else "Git metadata"
    try:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_size > 4096:
            raise ReferenceFailure(
                _safe_error("git_metadata_invalid", "input", f"{label} has an invalid pointer.", "Repair the local checkout before retrying.")
            )
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            observed = os.fstat(descriptor)
            if (
                not stat.S_ISREG(observed.st_mode)
                or observed.st_size > 4096
                or (observed.st_dev, observed.st_ino) != (info.st_dev, info.st_ino)
            ):
                raise ReferenceFailure(
                    _safe_error("git_metadata_invalid", "input", f"{label} has an invalid pointer.", "Repair the local checkout before retrying.")
                )
            value = os.read(descriptor, 4097)
        finally:
            os.close(descriptor)
    except ReferenceFailure:
        raise
    except (OSError, PermissionError) as exc:
        raise ReferenceFailure(
            _safe_error("git_metadata_unreadable", "input", f"{label} cannot be read safely.", "Repair the local checkout before retrying.")
        ) from exc
    if len(value) > 4096:
        raise ReferenceFailure(
            _safe_error("git_metadata_invalid", "input", f"{label} has an invalid pointer.", "Repair the local checkout before retrying.")
        )
    return value


def _resolve_git_directory(path: Path) -> Path:
    resolved = path.resolve()
    try:
        info = resolved.lstat()
    except OSError as exc:
        raise ReferenceFailure(
            _safe_error("git_metadata_invalid", "input", "The checkout Git metadata directory is unavailable.", "Repair the local checkout before retrying.")
        ) from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise ReferenceFailure(
            _safe_error("git_metadata_invalid", "input", "The checkout Git metadata directory is unavailable.", "Repair the local checkout before retrying.")
        )
    return resolved


def _decode_git_pointer(value: bytes, *, prefix: str | None = None) -> str:
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ReferenceFailure(
            _safe_error("git_metadata_invalid", "input", "The checkout has an invalid Git metadata pointer.", "Repair the local checkout before retrying.")
        ) from exc
    normalized = text.rstrip("\r\n")
    if not normalized or "\n" in normalized or "\r" in normalized or (prefix is not None and not normalized.startswith(prefix)):
        raise ReferenceFailure(
            _safe_error("git_metadata_invalid", "input", "The checkout has an invalid Git metadata pointer.", "Repair the local checkout before retrying.")
        )
    return normalized.removeprefix(prefix) if prefix is not None else normalized


def _git_metadata_roots(root: Path) -> tuple[list[Path], bytes | None]:
    marker = root / ".git"
    if marker.is_symlink():
        raise ReferenceFailure(
            _safe_error("git_metadata_invalid", "input", "The checkout uses an unsafe Git metadata symlink.", "Repair the local checkout before retrying.")
        )
    if marker.is_dir():
        git_dir = _resolve_git_directory(marker)
        common_marker = git_dir / "commondir"
        if common_marker.exists() or common_marker.is_symlink():
            common_value = _decode_git_pointer(_read_git_pointer(common_marker, shared=True))
            common = Path(common_value)
            common_dir = _resolve_git_directory(git_dir / common if not common.is_absolute() else common)
            if common_dir != git_dir and not common_dir.is_relative_to(git_dir):
                raise ReferenceFailure(
                    _safe_error("git_metadata_invalid", "input", "Shared Git metadata escapes the checkout metadata directory.", "Repair the local checkout before retrying.")
                )
            return [git_dir, common_dir] if common_dir != git_dir else [git_dir], b"directory"
        return [git_dir], b"directory"
    elif marker.is_file() and not marker.is_symlink():
        marker_value = _read_git_pointer(marker)
        candidate = Path(_decode_git_pointer(marker_value, prefix="gitdir: ").strip())
        if not str(candidate):
            raise ReferenceFailure(
                _safe_error("git_metadata_invalid", "input", "The checkout has an invalid Git metadata pointer.", "Repair the local checkout before retrying.")
            )
        git_dir = _resolve_git_directory(root / candidate if not candidate.is_absolute() else candidate)
    else:
        return [], None

    backlink_marker = git_dir / "gitdir"
    common_marker = git_dir / "commondir"
    if not backlink_marker.exists() or not common_marker.exists():
        raise ReferenceFailure(
            _safe_error("git_metadata_invalid", "input", "The linked-worktree metadata is incomplete.", "Repair the local checkout before retrying.")
        )
    backlink_value = _decode_git_pointer(_read_git_pointer(backlink_marker))
    backlink = Path(backlink_value)
    backlink_path = _resolve_git_directory(backlink.parent) / backlink.name if backlink.is_absolute() else (git_dir / backlink).resolve()
    if backlink_path != marker.resolve():
        raise ReferenceFailure(
            _safe_error("git_metadata_invalid", "input", "The linked-worktree metadata does not point back to this checkout.", "Repair the local checkout before retrying.")
        )
    common_value = _decode_git_pointer(_read_git_pointer(common_marker, shared=True))
    common = Path(common_value)
    common_dir = _resolve_git_directory(git_dir / common if not common.is_absolute() else common)
    if git_dir.parent.resolve() != (common_dir / "worktrees").resolve():
        raise ReferenceFailure(
            _safe_error("git_metadata_invalid", "input", "The linked-worktree metadata has an invalid common directory.", "Repair the local checkout before retrying.")
        )
    for required in (common_dir / "HEAD", common_dir / "config", common_dir / "objects"):
        if not required.exists() or required.is_symlink():
            raise ReferenceFailure(
                _safe_error("git_metadata_invalid", "input", "The linked-worktree common metadata is incomplete.", "Repair the local checkout before retrying.")
            )
    return [git_dir, common_dir], marker_value


def _source_digest(root: Path) -> str:
    git_roots, marker = _git_metadata_roots(root)
    components = [{"class": "source", "digest": _tree_digest(root, excluded_names=frozenset({".git"}))}]
    if marker is not None:
        components.append({"class": "git_marker", "digest": _digest_bytes(marker)})
    excluded = frozenset({"lfs", "modules", "objects"})
    for git_root in git_roots:
        components.append({"class": "git_metadata", "digest": _tree_digest(git_root, excluded_names=excluded)})
    return _digest_bytes(_json_bytes(components))


def _entity_ref(relative: str) -> str:
    return _opaque("entry", relative)


def _unsupported(
    code: str,
    relative: str,
    highest: Literal["L0", "L1"],
    next_action: str,
    *,
    adapter: str = "phase1a-static-1",
) -> UnsupportedArea:
    return UnsupportedArea(
        code=code,
        entity_ref=_entity_ref(relative),
        adapter=adapter,
        highest_level=highest,
        next_action=next_action,
    )


def _python_callsites(source: bytes, relative: str, snapshot_digest: str) -> tuple[list[Callsite], list[UnsupportedArea]]:
    result = discover_python(source)
    found = [
        _callsite_from_discovery(item, relative, snapshot_digest, PYTHON_ADAPTER_VERSION)
        for item in result.calls
    ]
    unsupported = [
        _unsupported(item.code, relative, item.highest_level, item.next_action, adapter=PYTHON_ADAPTER_VERSION)
        for item in result.gaps
    ]
    return found, unsupported


def _callsite_from_discovery(item, relative: str, snapshot_digest: str, adapter_version: str) -> Callsite:
    adapter_version = item.adapter_version or adapter_version
    enclosing_symbol_ref = _opaque("symbol", f"{relative}\0{item.enclosing_symbol}")
    identity = (
        f"{snapshot_digest}\0{relative}\0{item.enclosing_symbol}\0{item.operation}"
        f"\0{item.normalized_ast_digest}\0{item.ast_ordinal}\0{adapter_version}"
    )
    return Callsite(
        callsite_id=_opaque("cs", identity),
        path_ref=_opaque("path", relative),
        line=item.line,
        language=item.language,
        operation=item.operation,
        stability=item.stability,
        adapter_version=adapter_version,
        normalized_ast_digest=item.normalized_ast_digest,
        ast_ordinal=item.ast_ordinal,
        enclosing_symbol_ref=enclosing_symbol_ref,
        features=list(item.features),
    )


def _javascript_callsites(
    source: bytes, relative: str, snapshot_digest: str, language: str
) -> tuple[list[Callsite], list[UnsupportedArea]]:
    result = discover_javascript(source, language, relative=relative)
    found = [
        _callsite_from_discovery(item, relative, snapshot_digest, JAVASCRIPT_ADAPTER_VERSION)
        for item in result.calls
    ]
    unsupported = [
        _unsupported(item.code, relative, item.highest_level, item.next_action, adapter=JAVASCRIPT_ADAPTER_VERSION)
        for item in result.gaps
    ]
    return found, unsupported


def _inventory(root: Path, snapshot_digest: str) -> tuple[list[Callsite], list[UnsupportedArea], dict[str, int], int]:
    callsites: list[Callsite] = []
    unsupported: list[UnsupportedArea] = []
    languages: Counter[str] = Counter()
    excluded = 0
    file_count = 0
    stack = [root]
    while stack:
        directory = stack.pop()
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
        except (PermissionError, OSError) as exc:
            raise ReferenceFailure(
                _safe_error("source_unreadable", "input", "The selected source cannot be inventoried safely.", "Fix source permissions or select another source.")
            ) from exc
        for entry in entries:
            path = Path(entry.path)
            relative = path.relative_to(root).as_posix()
            try:
                try:
                    _relative_path(relative)
                except ReferenceFailure:
                    unsupported.append(_unsupported("unsafe_path", relative, "L0", "Rename the entry to a normalized cross-platform-safe relative path."))
                    continue
                if entry.is_symlink():
                    unsupported.append(_unsupported("unsafe_symlink", relative, "L0", "Replace the symlink with an in-root regular file for analysis."))
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if entry.name == ".git":
                        if directory != root:
                            unsupported.append(_unsupported("nested_repository", relative, "L0", "Inspect the nested repository as a separate source."))
                        excluded += 1
                        continue
                    if os.path.lexists(path / ".git"):
                        unsupported.append(_unsupported("nested_repository", relative, "L0", "Inspect the nested repository as a separate source."))
                        excluded += 1
                        continue
                    if entry.name in _IGNORED_DIRECTORIES:
                        excluded += 1
                        continue
                    stack.append(path)
                    continue
                if not entry.is_file(follow_symlinks=False):
                    unsupported.append(_unsupported("unsupported_file_type", relative, "L0", "Remove or separately review the special file."))
                    continue
                file_count += 1
                if file_count > _MAX_FILES:
                    raise ReferenceFailure(
                        _safe_error("source_quota_exceeded", "input", "The source exceeds the Phase 1A file limit.", "Select a smaller source root.")
                    )
                language = _INVENTORY_EXTENSIONS.get(path.suffix.lower())
                if language is None:
                    continue
                languages[language] += 1
                if path.suffix.lower() not in _SOURCE_EXTENSIONS:
                    unsupported.append(_unsupported("unsupported_language", relative, "L0", "Use a stable language adapter or keep this area at inventory level."))
                    continue
                info = entry.stat(follow_symlinks=False)
                if info.st_size > _MAX_FILE_BYTES:
                    unsupported.append(_unsupported("source_file_too_large", relative, "L0", "Select a smaller file or narrower source root."))
                    continue
                source = path.read_bytes()
                try:
                    if language == "python":
                        discovered, gaps = _python_callsites(source, relative, snapshot_digest)
                    else:
                        discovered, gaps = _javascript_callsites(source, relative, snapshot_digest, language)
                    callsites.extend(discovered)
                    unsupported.extend(gaps)
                except ValueError:
                    unsupported.append(_unsupported("malformed_source", relative, "L0", "Fix the source encoding or syntax before static discovery."))
            except (PermissionError, OSError) as exc:
                raise ReferenceFailure(
                    _safe_error("source_unreadable", "input", "A selected source entry cannot be read safely.", "Fix source permissions or exclude the entry.")
                ) from exc
    callsites.sort(key=lambda item: item.callsite_id)
    unsupported.sort(key=lambda item: (item.code, item.entity_ref))
    return callsites, unsupported, dict(sorted(languages.items())), excluded


def _authority(mode: RunMode, policy: DraftPolicy | None) -> AuthoritySummary:
    manifest = {
        "schema_version": "phase1a-1",
        "mode": mode,
        "reads": ["selected_source_bytes", "source_metadata", "git_metadata"],
        "writes": ["tool_owned_state"] if mode != "draft" else ["tool_owned_state", "tool_owned_snapshot", "tool_owned_candidate"],
        "executes": [],
        "destinations": ["openai_responses"] if policy is not None else [],
        "environment_names": ["OPENAI_API_KEY"] if policy is not None else [],
        "policy_digest": _digest_bytes(_json_bytes(policy.model_dump(mode="json"))) if policy is not None else None,
    }
    return AuthoritySummary(
        manifest_digest=_digest_bytes(_json_bytes(manifest)),
        reads=manifest["reads"],
        writes=manifest["writes"],
        executes=[],
        destinations=manifest["destinations"],
        environment_names=manifest["environment_names"],
    )


def _strict_json_object(value: str) -> dict[str, object]:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = item
        return result

    parsed = json.loads(value, object_pairs_hook=reject_duplicates)
    if not isinstance(parsed, dict):
        raise ValueError("JSON value is not an object")
    return parsed


def _load_policy(value: dict[str, object] | Path | None) -> DraftPolicy | None:
    if value is None:
        return None
    try:
        if isinstance(value, Path):
            parsed = _strict_json_object(value.read_text(encoding="utf-8"))
        else:
            parsed = value
        return DraftPolicy.model_validate(parsed)
    except (OSError, ValueError, ValidationError) as exc:
        raise ReferenceFailure(
            _safe_error("invalid_egress_manifest", "policy", "The Draft egress manifest is invalid.", "Provide a valid, exact Phase 1A Draft policy.")
        ) from exc


def _relative_path(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    reserved = {"con", "prn", "aux", "nul", *(f"com{number}" for number in range(1, 10)), *(f"lpt{number}" for number in range(1, 10))}
    invalid_component = any(
        not component
        or component.endswith((" ", "."))
        or ":" in component
        or component.casefold().split(".", 1)[0] in reserved
        or len(os.fsencode(component)) > 255
        for component in path.parts
    )
    if (
        not value
        or len(value.encode("utf-8", errors="surrogatepass")) > 4096
        or path.is_absolute()
        or ".." in path.parts
        or "\\" in value
        or value != path.as_posix()
        or unicodedata.normalize("NFC", value) != value
        or any(unicodedata.category(character) in {"Cc", "Cf"} for character in value)
        or invalid_component
    ):
        raise ReferenceFailure(
            _safe_error("policy_path_outside_snapshot", "policy", "An approved source path is outside the immutable snapshot.", "Use a normalized repository-relative path.")
        )
    return path


def _read_confined(root: Path, relative: PurePosixPath) -> bytes:
    if os.name == "posix" and hasattr(os, "O_NOFOLLOW"):
        descriptors: list[int] = []
        try:
            directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            descriptors.append(directory_fd)
            for component in relative.parts[:-1]:
                directory_fd = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=directory_fd,
                )
                descriptors.append(directory_fd)
            file_fd = os.open(relative.parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
            descriptors.append(file_fd)
            info = os.fstat(file_fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size > _MAX_FILE_BYTES:
                raise ReferenceFailure(
                    _safe_error("policy_path_outside_snapshot", "policy", "An approved source path is not a bounded regular file.", "Approve a regular source file within the size limit.")
                )
            chunks: list[bytes] = []
            remaining = _MAX_FILE_BYTES + 1
            while remaining:
                chunk = os.read(file_fd, min(1024 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            content = b"".join(chunks)
            if len(content) > _MAX_FILE_BYTES:
                raise ReferenceFailure(
                    _safe_error("source_file_too_large", "input", "An approved source file exceeds the Phase 1A limit.", "Approve a smaller source slice.")
                )
            return content
        except (FileNotFoundError, NotADirectoryError, PermissionError, OSError) as exc:
            raise ReferenceFailure(
                _safe_error("policy_path_outside_snapshot", "policy", "An approved source path is unavailable or unsafe.", "Approve an in-root regular source file.")
            ) from exc
        finally:
            for descriptor in reversed(descriptors):
                os.close(descriptor)
    path = root.joinpath(*relative.parts)
    try:
        resolved_before = path.resolve(strict=True)
        if not resolved_before.is_relative_to(root) or path.is_symlink() or not path.is_file():
            raise ReferenceFailure(
                _safe_error("policy_path_outside_snapshot", "policy", "An approved source path is unavailable or unsafe.", "Approve an in-root regular source file.")
            )
        content = path.read_bytes()
        if path.resolve(strict=True) != resolved_before or len(content) > _MAX_FILE_BYTES:
            raise ReferenceFailure(
                _safe_error("source_changed_during_read", "input", "An approved source file changed during the safe read.", "Stabilize the source and approve a new manifest.")
            )
        return content
    except (PermissionError, OSError) as exc:
        raise ReferenceFailure(
            _safe_error("source_unreadable", "input", "An approved source slice cannot be read.", "Fix source permissions and approve a new manifest.")
        ) from exc


def _approved_slices(root: Path, snapshot_digest: str, policy: DraftPolicy, store: _RunStore) -> tuple[list[dict[str, object]], str]:
    if policy.source_digest != snapshot_digest:
        raise ReferenceFailure(
            _safe_error("stale_egress_manifest", "policy", "The egress manifest does not match the current source snapshot.", "Run Inspect again and approve the new manifest digest.")
        )
    snapshot = store.run_dir / "snapshot"
    _ensure_private_directory(snapshot)
    slices: list[dict[str, object]] = []
    seen: set[str] = set()
    total = 0
    for approved in policy.slices:
        relative = _relative_path(approved.path)
        normalized = relative.as_posix()
        if normalized in seen:
            raise ReferenceFailure(
                _safe_error("duplicate_egress_slice", "policy", "The egress manifest contains a duplicate source slice.", "Approve each normalized path only once.")
            )
        seen.add(normalized)
        content = _read_confined(root, relative)
        if hashlib.sha256(content).hexdigest() != approved.sha256:
            raise ReferenceFailure(
                _safe_error("stale_egress_slice", "policy", "An approved source slice changed after approval.", "Run Inspect again and approve a new manifest.")
            )
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ReferenceFailure(
                _safe_error("malformed_source", "input", "An approved source slice is not valid UTF-8.", "Fix the source encoding before Draft.")
            ) from exc
        lines = text.splitlines()
        if approved.end_line < approved.start_line or approved.end_line > len(lines):
            raise ReferenceFailure(
                _safe_error("invalid_egress_range", "policy", "An approved source line range is invalid.", "Approve an existing line range.")
            )
        selected = "\n".join(lines[approved.start_line - 1 : approved.end_line]) + "\n"
        if _SECRET.search(selected):
            raise ReferenceFailure(
                _safe_error("policy_denied_content", "policy", "An approved source slice contains credential-like content.", "Remove the credential and approve a minimized slice.")
            )
        selected_bytes = selected.encode("utf-8")
        total += len(selected_bytes)
        if total > policy.max_input_bytes:
            raise ReferenceFailure(
                _safe_error("agent_input_budget_exceeded", "policy", "Approved source content exceeds the egress byte budget.", "Approve fewer bytes or increase the explicit budget.")
            )
        _write_private(snapshot / hashlib.sha256(normalized.encode()).hexdigest(), selected_bytes)
        slices.append(
            {
                "path": normalized,
                "path_ref": _opaque("path", normalized),
                "start_line": approved.start_line,
                "end_line": approved.end_line,
                "sha256": _digest_bytes(selected_bytes),
                "content": selected,
            }
        )
    content_manifest = {
        "source_digest": snapshot_digest,
        "slices": [
            {name: value for name, value in item.items() if name != "content"}
            for item in slices
        ],
        "destination": "openai_responses",
        "max_input_bytes": policy.max_input_bytes,
        "max_output_tokens": policy.max_output_tokens,
    }
    return slices, _digest_bytes(_json_bytes(content_manifest))


def _validate_policy_paths(policy: DraftPolicy, snapshot_digest: str) -> None:
    if policy.source_digest != snapshot_digest:
        raise ReferenceFailure(
            _safe_error("stale_egress_manifest", "policy", "The egress manifest does not match the current source snapshot.", "Run Inspect again and approve the new manifest digest.")
        )
    seen: set[str] = set()
    for approved in policy.slices:
        normalized = _relative_path(approved.path).as_posix()
        if normalized in seen:
            raise ReferenceFailure(
                _safe_error("duplicate_egress_slice", "policy", "The egress manifest contains a duplicate source slice.", "Approve each normalized path only once.")
            )
        seen.add(normalized)


def _remove_snapshot(store: _RunStore) -> bool:
    snapshot = store.run_dir / "snapshot"
    if not snapshot.exists():
        return True
    try:
        for path in snapshot.iterdir():
            if path.is_file() and not path.is_symlink():
                path.unlink()
            else:
                return False
        snapshot.rmdir()
        return True
    except OSError:
        return False


def _validate_candidate_paths(affected: list[str], patch: str, approved: set[str]) -> list[str]:
    normalized = {_relative_path(value).as_posix() for value in affected}
    headers: set[str] = set()
    for line in patch.splitlines():
        if line.startswith("--- ") or line.startswith("+++ "):
            value = line[4:].split("\t", 1)[0]
            if value == "/dev/null":
                continue
            if value.startswith("a/") or value.startswith("b/"):
                value = value[2:]
            headers.add(_relative_path(value).as_posix())
    if not headers or normalized != headers or not normalized.issubset(approved):
        raise ReferenceFailure(
            _safe_error("unexpected_patch_target", "agent", "The proposed patch targets unapproved source paths.", "Generate a new proposal restricted to the approved slices.")
        )
    return sorted(_opaque("path", value) for value in normalized)


def _terminal_status(callsites: list[Callsite], unsupported: list[UnsupportedArea]) -> str:
    if unsupported:
        return "completed_with_unsupported"
    if not callsites:
        return "completed_no_findings"
    return "completed"


def _base_result(
    run_id: str,
    mode: RunMode,
    source_id: str,
    snapshot_digest: str,
    authority: AuthoritySummary,
    callsites: list[Callsite],
    findings: list[Finding],
    unsupported: list[UnsupportedArea],
    languages: dict[str, int],
    excluded: int,
    status: str,
    steps: list[str],
    *,
    retention_days: int,
    external_copies: Literal["provider_policy_applies", "none"],
    error: SafeError | None = None,
    cleanup: CleanupSummary | None = None,
) -> RunResult:
    return RunResult(
        run_id=run_id,
        mode=mode,
        status=status,
        source_id=source_id,
        snapshot_digest=snapshot_digest,
        authority=authority,
        work=WorkSummary(
            performed=len(steps),
            skipped=0,
            unsupported=len(unsupported),
            zero_work=False,
            steps=steps,
        ),
        support=SupportSummary(
            highest_level="L1" if callsites else "L0",
            languages=languages,
            callsites=len(callsites),
            supported_callsites=len(callsites),
            unsupported_areas=len(unsupported),
            excluded_entries=excluded,
            feature_coverage=dict(sorted(Counter(feature for item in callsites for feature in item.features).items())),
        ),
        callsites=callsites,
        findings=findings,
        unsupported=unsupported,
        error=error,
        retention=RetentionSummary(
            safe_artifacts_days=retention_days,
            external_copies=external_copies,
        ),
        cleanup=cleanup or CleanupSummary(status="not_required", source_snapshot_removed=True),
    )


def _projection(result: RunResult) -> dict[str, object]:
    return result.model_dump(mode="json", exclude={"receipt", "report_artifacts"})


def render_report(result: RunResult, format: Literal["json", "md"] | str) -> str:
    projection = _projection(result)
    if format == "json":
        return json.dumps(projection, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if format != "md":
        raise ValueError("report format must be json or md")
    error = result.error.code if result.error else "none"
    lines = [
        f"# PROMPTECTOMY {result.mode.title()} report",
        "",
        "This Phase 1A report is local, digest-bound consistency evidence. It is not signed, attested, or a verification result.",
        "",
        f"- Run: `{result.run_id}`",
        f"- Source: `{result.source_id}`",
        f"- Snapshot: `{result.snapshot_digest}`",
        f"- Status: `{result.status}`",
        f"- Highest support: `{result.support.highest_level}`",
        f"- Callsites: {result.support.callsites}",
        f"- Unsupported areas: {len(result.unsupported)}",
        f"- Error: `{error}`",
        "- Target checkout writes: none",
        f"- Tool-owned writes: {', '.join(result.authority.writes)}",
        f"- Target or generated code executed: {'yes' if result.authority.executes else 'no'}",
        f"- Source snapshot cleanup: `{result.cleanup.status}`",
        "",
        "## Supported and unsupported work",
        "",
        f"- Languages inventoried: {', '.join(f'{name}={count}' for name, count in result.support.languages.items()) or 'none'}",
        f"- Unsupported codes: {', '.join(sorted({item.code for item in result.unsupported})) or 'none'}",
        "",
        "## Candidate",
        "",
        *(
            [
                f"- ID: `{result.candidate.candidate_id}`",
                f"- State: `{result.candidate.state}`",
                f"- Patch artifact: `{result.candidate.patch_artifact}`",
                f"- Proposed-tests artifact: `{result.candidate.tests_artifact}`",
                f"- Evidence grade: `{result.candidate.evidence_grade}`",
            ]
            if result.candidate is not None
            else ["No candidate was produced."]
        ),
        "",
        "## Limitations",
        "",
        "- Phase 1A uses deterministic static discovery and does not execute repository or generated code.",
        "- Any candidate is unverified until a later accepted executor and evaluator complete.",
        "- Paths and source bodies are excluded from this safe report.",
    ]
    return "\n".join(lines) + "\n"


def _finalize(store: _RunStore, result: RunResult) -> RunResult:
    json_report = render_report(result, "json").encode("utf-8")
    markdown_report = render_report(result, "md").encode("utf-8")
    result.report_artifacts = {
        "json": store.artifact("reports", json_report),
        "md": store.artifact("reports", markdown_report),
    }
    receipt_manifest = {
        "schema_version": "phase1a-receipt-1",
        "semantics": "digest_bound_local_consistency",
        "run_id": result.run_id,
        "mode": result.mode,
        "status": result.status,
        "snapshot_digest": result.snapshot_digest,
        "authority_manifest_digest": result.authority.manifest_digest,
        "candidate_patch": result.candidate.patch_artifact if result.candidate else None,
        "candidate_tests": result.candidate.tests_artifact if result.candidate else None,
        "report_artifacts": result.report_artifacts,
        "support": result.support.model_dump(mode="json"),
        "error_code": result.error.code if result.error else None,
        "cleanup": result.cleanup.model_dump(mode="json"),
    }
    receipt_bytes = _json_bytes(receipt_manifest)
    receipt_artifact = store.artifact("receipts", receipt_bytes)
    result.receipt = ReceiptSummary(receipt_id=f"receipt_{receipt_artifact.removeprefix('sha256:')}")
    store.event(
        "run.terminal",
        {
            "status": result.status,
            "performed": result.work.performed,
            "unsupported": result.work.unsupported,
            "error_code": result.error.code if result.error else None,
            "cleanup_status": result.cleanup.status,
            "receipt_id": result.receipt.receipt_id,
        },
    )
    store.save(result)
    return result


def execute(
    operation: RunMode | str,
    source: str | Path,
    *,
    state_root: str | Path | None = None,
    policy: dict[str, object] | Path | None = None,
    connector: ResponsesConnector | None = None,
    cancelled: Callable[[], bool] | None = None,
) -> RunResult:
    if operation not in {"inspect", "audit", "draft"}:
        raise ValueError(f"unsupported reference operation: {operation}")
    mode: RunMode = operation
    source_value = str(source)
    parsed_source = urlparse(source_value)
    source_input = Path(source_value)
    if parsed_source.scheme and not source_input.drive:
        if parsed_source.username is not None or parsed_source.password is not None:
            raise ReferenceFailure(
                _safe_error("source_credentials_forbidden", "input", "Source locators must not contain credentials.", "Remove credentials and use a future approved acquisition broker.")
            )
        if parsed_source.scheme in {"http", "https", "ssh", "git", "file"}:
            raise ReferenceFailure(
                _safe_error("remote_source_unsupported", "unsupported", "Phase 1A accepts local source directories only.", "Use a local checkout or wait for the safe acquisition phase.")
            )
        raise ReferenceFailure(
            _safe_error("unsupported_source_scheme", "unsupported", "The source locator scheme is unsupported.", "Use a local source directory.")
        )
    if source_input.is_symlink():
        raise ValueError("source root must not be a symlink")
    try:
        root = source_input.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ValueError("source does not exist") from exc
    if not root.is_dir():
        raise ValueError("source is not a directory")
    state = Path(state_root) if state_root is not None else default_state_root()
    state_resolved = state.resolve(strict=False)
    if state_resolved == root or state_resolved.is_relative_to(root):
        raise ValueError("state root must be outside the source")
    git_roots, _ = _git_metadata_roots(root)
    for git_root in git_roots:
        if state_resolved == git_root or state_resolved.is_relative_to(git_root):
            raise ValueError("state root must be outside Git metadata")
    run_id = f"run_{uuid.uuid4().hex}"
    store = _RunStore(state_resolved, run_id)
    source_id = _opaque("source", str(root))
    parsed_policy: DraftPolicy | None = None
    before: str | None = None
    try:
        parsed_policy = _load_policy(policy) if mode == "draft" else None
        authority = _authority(mode, parsed_policy)
        store.event("run.created", {"mode": mode, "source_id": source_id, "authority_manifest_digest": authority.manifest_digest})
        before = _source_digest(root)
        callsites, unsupported, languages, excluded = _inventory(root, before)
        if mode == "draft" and parsed_policy is not None:
            _validate_policy_paths(parsed_policy, before)
        steps = ["source_preflight", "repository_inventory", "static_discovery"]
        findings = (
            [
                Finding(
                    finding_id=_opaque("finding", item.callsite_id),
                    callsite_id=item.callsite_id,
                    rationale="A supported OpenAI Responses callsite requires evidence-linked candidate analysis.",
                    limitations=["No runtime evidence was evaluated.", "No repository or generated code was executed."],
                )
                for item in callsites
            ]
            if mode in {"audit", "draft"}
            else []
        )
        store.event(
            "inventory.completed",
            {
                "callsites": len(callsites),
                "unsupported": len(unsupported),
                "highest_support_level": "L1" if callsites else "L0",
            },
        )
        if cancelled is not None and cancelled():
            result = _base_result(
                run_id,
                mode,
                source_id,
                before,
                authority,
                callsites,
                findings,
                unsupported,
                languages,
                excluded,
                "cancelled",
                steps,
                retention_days=parsed_policy.retention_days if parsed_policy else 30,
                external_copies="none",
                error=_safe_error("cancelled", "cancel", "The run was cancelled.", "Start a new run when ready."),
                cleanup=CleanupSummary(status="completed", source_snapshot_removed=True),
            )
            return _finalize(store, result)
        if mode != "draft":
            result = _base_result(
                run_id,
                mode,
                source_id,
                before,
                authority,
                callsites,
                findings,
                unsupported,
                languages,
                excluded,
                _terminal_status(callsites, unsupported),
                steps + (["static_audit"] if mode == "audit" else []),
                retention_days=30,
                external_copies="none",
            )
        elif parsed_policy is None:
            result = _base_result(
                run_id,
                mode,
                source_id,
                before,
                authority,
                callsites,
                findings,
                unsupported,
                languages,
                excluded,
                "failed",
                steps,
                retention_days=30,
                external_copies="none",
                error=_safe_error(
                    "missing_egress_manifest",
                    "policy",
                    "Draft requires an exact approved egress manifest.",
                    "Run Inspect, create the minimized Draft policy, and approve its digest.",
                ),
                cleanup=CleanupSummary(status="completed", source_snapshot_removed=True),
            )
        elif not callsites:
            result = _base_result(
                run_id,
                mode,
                source_id,
                before,
                authority,
                callsites,
                findings,
                unsupported,
                languages,
                excluded,
                "completed_with_unsupported" if unsupported else "completed_no_findings",
                steps,
                retention_days=parsed_policy.retention_days,
                external_copies="none",
                error=None,
                cleanup=CleanupSummary(status="completed", source_snapshot_removed=True),
            )
        elif not any(
            item.path_ref == _opaque("path", approved.path)
            and approved.start_line <= item.line <= approved.end_line
            for item in callsites
            for approved in parsed_policy.slices
        ):
            result = _base_result(
                run_id,
                mode,
                source_id,
                before,
                authority,
                callsites,
                findings,
                unsupported,
                languages,
                excluded,
                "failed",
                steps,
                retention_days=parsed_policy.retention_days,
                external_copies="none",
                error=_safe_error(
                    "egress_slice_without_supported_callsite",
                    "policy",
                    "The approved source slices do not contain a supported callsite.",
                    "Approve a minimized range containing one discovered OpenAI Responses callsite.",
                ),
                cleanup=CleanupSummary(status="completed", source_snapshot_removed=True),
            )
        elif connector is None and ResponsesConnector.from_environment() is None:
            result = _base_result(
                run_id,
                mode,
                source_id,
                before,
                authority,
                callsites,
                findings,
                unsupported,
                languages,
                excluded,
                "failed",
                steps,
                retention_days=parsed_policy.retention_days,
                external_copies="none",
                error=_safe_error(
                    "safe_agent_transport_unavailable",
                    "agent",
                    "Tool-free structured Codex Draft is unavailable.",
                    "Configure the approved Responses connector or run Audit.",
                ),
                cleanup=CleanupSummary(status="completed", source_snapshot_removed=True),
            )
        else:
            active_connector = connector or ResponsesConnector.from_environment()
            assert active_connector is not None
            slices, content_manifest_digest = _approved_slices(root, before, parsed_policy, store)
            try:
                proposal, connector_record = active_connector.generate(
                    parsed_policy,
                    slices,
                    content_manifest_digest=content_manifest_digest,
                    cancelled=cancelled,
                )
                approved_paths = {item.path for item in parsed_policy.slices}
                affected_refs = _validate_candidate_paths(proposal.affected_paths, proposal.patch, approved_paths)
                patch_artifact = store.artifact("artifacts", proposal.patch.encode("utf-8"))
                tests_artifact = store.artifact(
                    "artifacts",
                    _json_bytes(
                        {
                            "proposed_tests": proposal.proposed_tests,
                            "rationale": proposal.rationale,
                            "evidence": proposal.evidence,
                            "limitations": proposal.limitations,
                        }
                    ),
                )
                candidate_id = _opaque("candidate", patch_artifact + tests_artifact + before)
                removed = _remove_snapshot(store)
                cleanup = CleanupSummary(status="completed" if removed else "failed", source_snapshot_removed=removed)
                if not removed:
                    raise ReferenceFailure(
                        _safe_error("cleanup_failed", "state", "The temporary source snapshot could not be removed.", "Retry cleanup before using retained artifacts.")
                    )
                result = _base_result(
                    run_id,
                    mode,
                    source_id,
                    before,
                    authority,
                    callsites,
                    findings,
                    unsupported,
                    languages,
                    excluded,
                    "completed_with_unsupported" if unsupported else "completed",
                    steps + ["egress_manifest_validated", "candidate_proposed"],
                    retention_days=parsed_policy.retention_days,
                    external_copies="provider_policy_applies",
                    cleanup=cleanup,
                )
                result.candidate = CandidateSummary(
                    candidate_id=candidate_id,
                    patch_artifact=patch_artifact,
                    tests_artifact=tests_artifact,
                    affected_path_refs=affected_refs,
                    limitations=[
                        "Candidate code and proposed tests were not executed.",
                        "Model-provided rationale and limitations remain inside the private candidate artifact boundary.",
                    ],
                )
                result.connector = connector_record
                store.event(
                    "candidate.proposed",
                    {
                        "candidate_id": candidate_id,
                        "state": "unverified",
                        "patch_artifact": patch_artifact,
                        "tests_artifact": tests_artifact,
                    },
                )
            except ConnectorCancelled:
                removed = _remove_snapshot(store)
                result = _base_result(
                    run_id,
                    mode,
                    source_id,
                    before,
                    authority,
                    callsites,
                    findings,
                    unsupported,
                    languages,
                    excluded,
                    "cancelled",
                    steps + ["egress_manifest_validated"],
                    retention_days=parsed_policy.retention_days,
                    external_copies="provider_policy_applies",
                    error=_safe_error("cancelled", "cancel", "The Draft request was cancelled.", "Start a new Draft when ready."),
                    cleanup=CleanupSummary(status="completed" if removed else "failed", source_snapshot_removed=removed),
                )
            except ConnectorFailure as exc:
                removed = _remove_snapshot(store)
                error_code = exc.code if exc.code in _CONNECTOR_ERROR_CODES else "agent_failure"
                result = _base_result(
                    run_id,
                    mode,
                    source_id,
                    before,
                    authority,
                    callsites,
                    findings,
                    unsupported,
                    languages,
                    excluded,
                    "failed",
                    steps + ["egress_manifest_validated"],
                    retention_days=parsed_policy.retention_days,
                    external_copies="provider_policy_applies",
                    error=_safe_error(
                        error_code,
                        "agent",
                        "The bounded Draft connector did not produce an acceptable candidate.",
                        "Review the policy, model capability, schema, timeout, and budget before retrying.",
                        retryable=error_code in {"agent_timeout", "safe_agent_transport_unavailable"},
                    ),
                    cleanup=CleanupSummary(status="completed" if removed else "failed", source_snapshot_removed=removed),
                )
        after = _source_digest(root)
        if after != before:
            result.status = "failed"
            result.error = _safe_error(
                "target_changed_during_run",
                "state",
                "The source changed during the run, so the result is invalid.",
                "Stabilize the source and run the operation again.",
            )
            result.candidate = None
            result.connector = None
        return _finalize(store, result)
    except KeyboardInterrupt:
        removed = _remove_snapshot(store)
        authority = _authority(mode, parsed_policy)
        snapshot = before or _digest_bytes(str(root).encode("utf-8", errors="surrogatepass"))
        result = _base_result(
            run_id,
            mode,
            source_id,
            snapshot,
            authority,
            [],
            [],
            [],
            {},
            0,
            "cancelled",
            ["source_preflight"],
            retention_days=parsed_policy.retention_days if parsed_policy else 30,
            external_copies="provider_policy_applies" if parsed_policy else "none",
            error=_safe_error("cancelled", "cancel", "The run was cancelled.", "Start a new run when ready."),
            cleanup=CleanupSummary(status="completed" if removed else "failed", source_snapshot_removed=removed),
        )
        return _finalize(store, result)
    except ReferenceFailure as exc:
        removed = _remove_snapshot(store)
        authority = _authority(mode, parsed_policy)
        snapshot = before or _digest_bytes(str(root).encode("utf-8", errors="surrogatepass"))
        result = _base_result(
            run_id,
            mode,
            source_id,
            snapshot,
            authority,
            [],
            [],
            [],
            {},
            0,
            "failed",
            ["source_preflight"],
            retention_days=parsed_policy.retention_days if parsed_policy else 30,
            external_copies="none",
            error=exc.error,
            cleanup=CleanupSummary(status="completed" if removed else "failed", source_snapshot_removed=removed),
        )
        return _finalize(store, result)
    except (TypeError, ValueError):
        removed = _remove_snapshot(store)
        authority = _authority(mode, parsed_policy)
        snapshot = before or _digest_bytes(str(root).encode("utf-8", errors="surrogatepass"))
        result = _base_result(
            run_id,
            mode,
            source_id,
            snapshot,
            authority,
            [],
            [],
            [],
            {},
            0,
            "failed",
            ["source_preflight"],
            retention_days=parsed_policy.retention_days if parsed_policy else 30,
            external_copies="none",
            error=_safe_error("internal_failure", "internal", "The trusted Phase 1A operation failed safely.", "Review protected diagnostics and retry after correcting the implementation fault."),
            cleanup=CleanupSummary(status="completed" if removed else "failed", source_snapshot_removed=removed),
        )
        return _finalize(store, result)


def load_run(state_root: str | Path, run_id: str) -> RunResult:
    if _RUN_ID.fullmatch(run_id) is None:
        raise ValueError("invalid run ID")
    root = Path(state_root).resolve(strict=True)
    _check_private_directory(root)
    runs = root / "runs"
    _check_private_directory(runs)
    run_dir = runs / run_id
    if run_dir.is_symlink() or not run_dir.is_dir() or run_dir.stat().st_mode & 0o077:
        raise ValueError("run state is invalid")
    path = run_dir / "run.json"
    if path.is_symlink() or not path.resolve(strict=False).is_relative_to(root):
        raise ValueError("run state is invalid")
    try:
        return RunResult.model_validate_json(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError("run not found") from exc
    except (OSError, ValidationError) as exc:
        raise ValueError("run state is invalid") from exc


def load_latest_run(state_root: str | Path) -> RunResult:
    root = Path(state_root).resolve(strict=True)
    _check_private_directory(root)
    runs = root / "runs"
    _check_private_directory(runs)
    candidates = [
        path
        for path in runs.iterdir()
        if path.is_dir() and not path.is_symlink() and _RUN_ID.fullmatch(path.name) and not path.stat().st_mode & 0o077
    ]
    if not candidates:
        raise ValueError("no runs found")
    latest = max(candidates, key=lambda path: (path / "run.json").stat().st_mtime_ns)
    return load_run(state_root, latest.name)
