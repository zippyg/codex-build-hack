"""Validated, redacted JSONL storage for captured LLM calls."""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from .contracts import LedgerEventV1

_SENSITIVE_KEYS = {"authorization", "api_key", "apikey", "token", "secret", "password", "headers", "env", "environment"}


def redact(value: Any, *, key: str = "") -> Any:
    """Remove known credential-bearing fields before a value reaches disk."""
    normalized_key = key.lower().replace("-", "_")
    if normalized_key in _SENSITIVE_KEYS or any(marker in normalized_key for marker in ("authorization", "api_key", "apikey", "secret", "password", "bearer")):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(name): redact(item, key=str(name)) for name, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if hasattr(value, "model_dump"):
        return redact(value.model_dump(mode="json"))
    return str(value)


def _lock(handle: Any) -> None:
    try:
        import fcntl

        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
    except ImportError:  # pragma: no cover - Windows only
        return


def _unlock(handle: Any) -> None:
    try:
        import fcntl

        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    except ImportError:  # pragma: no cover - Windows only
        return


def append(path: str | Path, event: LedgerEventV1) -> LedgerEventV1:
    """Append one validated, redacted ledger event with user-only file permissions."""
    ledger_path = Path(path)
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    payload = redact(event.model_dump(mode="json"))
    safe_event = LedgerEventV1.model_validate(payload)
    fd = os.open(ledger_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as handle:
        _lock(handle)
        try:
            handle.write(json.dumps(safe_event.model_dump(mode="json"), separators=(",", ":"), ensure_ascii=False))
            handle.write("\n")
        finally:
            _unlock(handle)
    return safe_event


def iter_events(path: str | Path) -> Iterator[LedgerEventV1]:
    """Yield validated events in append order. Corrupt lines fail loudly."""
    ledger_path = Path(path)
    if not ledger_path.exists():
        return
    with ledger_path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                yield LedgerEventV1.model_validate_json(line)
            except Exception as exc:
                raise ValueError(f"invalid ledger event at {ledger_path}:{line_number}") from exc


def load(path: str | Path, *, callsite_id: str | None = None) -> list[LedgerEventV1]:
    return [event for event in iter_events(path) if callsite_id is None or event.callsite_id == callsite_id]
