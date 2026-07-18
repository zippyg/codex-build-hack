"""Narrow synchronous ``Responses.create`` recorder and hot-swap shim."""

from __future__ import annotations

import ast
import hashlib
import importlib.util
import inspect
import json
import threading
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable

from openai.resources.responses.responses import Responses

from .contracts import LedgerEventV1, Usage
from .guard import assert_pure
from .ledger import append, redact
from .pricing import estimate_cost

_original_create: Callable[..., Any] | None = None
_config: tuple[Path, Path, Path] | None = None
_tag_prefix = "promptectomy:callsite_id="

# (path, line) -> resolved id. Source does not change during a run, so caching removes a source
# read (and, for untagged sites, an AST parse) from the compiled hot path, which targets sub-ms.
_tag_id_cache: dict[tuple[str, int], str | None] = {}
_ast_ordinal_cache: dict[tuple[str, int], int] = {}


def _json_value(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return _json_value(value.model_dump(mode="json"))
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _registry(path: Path) -> dict[str, dict[str, Any]]:
    if not path.exists():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    entries = payload.get("callsites", payload) if isinstance(payload, dict) else {}
    return entries if isinstance(entries, dict) else {}


def _tagged_id(path: Path, line: int) -> str | None:
    key = (str(path), line)
    if key in _tag_id_cache:
        return _tag_id_cache[key]
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        _tag_id_cache[key] = None
        return None
    result: str | None = None
    for candidate in reversed(lines[max(0, line - 6) : line]):
        if _tag_prefix not in candidate:
            continue
        result = candidate.split(_tag_prefix, 1)[1].split()[0]
        break
    _tag_id_cache[key] = result
    return result


def _ast_ordinal(path: Path, line: int) -> int:
    key = (str(path), line)
    if key in _ast_ordinal_cache:
        return _ast_ordinal_cache[key]
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError):
        _ast_ordinal_cache[key] = line
        return line
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "create"
        and isinstance(node.func.value, ast.Attribute)
        and node.func.value.attr == "responses"
    ]
    calls.sort(key=lambda node: node.lineno)
    ordinal = next((index for index, node in enumerate(calls, start=1) if node.lineno >= line), len(calls) + 1)
    _ast_ordinal_cache[key] = ordinal
    return ordinal


def _callsite_id(repo_root: Path) -> tuple[str, Path | None, int | None]:
    shim_path = Path(__file__).resolve()
    for frame in inspect.stack()[2:]:
        path = Path(frame.filename).resolve()
        try:
            relative = path.relative_to(repo_root)
        except ValueError:
            continue
        if path == shim_path or "site-packages" in path.parts:
            continue
        tagged = _tagged_id(path, frame.lineno)
        if tagged:
            return tagged, path, frame.lineno
        raw = f"{relative}:{frame.function}:{_ast_ordinal(path, frame.lineno)}:responses.create"
        return hashlib.sha256(raw.encode()).hexdigest()[:12], path, frame.lineno
    return "unknown", None, None


def _usage(response: Any) -> Usage:
    value = getattr(response, "usage", None)
    if value is None:
        return Usage()
    payload = _json_value(value)
    if not isinstance(payload, dict):
        return Usage()
    input_tokens = int(payload.get("input_tokens") or payload.get("prompt_tokens") or 0)
    output_tokens = int(payload.get("output_tokens") or payload.get("completion_tokens") or 0)
    total_tokens = int(payload.get("total_tokens") or input_tokens + output_tokens)
    return Usage(input_tokens=input_tokens, output_tokens=output_tokens, total_tokens=total_tokens)


def _response_raw(response: Any) -> Any:
    if hasattr(response, "to_dict"):
        return _json_value(response.to_dict())
    if hasattr(response, "model_dump"):
        return _json_value(response.model_dump(mode="json"))
    return _json_value(response)


def _normalized(response: Any, kind: str | None) -> Any:
    text = getattr(response, "output_text", None)
    if kind == "structured" and isinstance(text, str):
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return text
    return text if isinstance(text, str) else None


def _engine(config: dict[str, Any], registry_path: Path) -> Callable[[Any, dict[str, Any]], Any]:
    location = config.get("module_path") or config.get("module")
    if not isinstance(location, str):
        raise ValueError("enabled compiled registry entry has no module_path")
    path = Path(location)
    if not path.is_absolute():
        path = registry_path.parent / path
    path = path.resolve()
    allowed_root = (registry_path.parent.parent / "engine" / "promptectomy" / "generated").resolve()
    if not path.is_relative_to(allowed_root):
        raise ValueError(f"compiled module {path} is outside the generated directory {allowed_root}")
    assert_pure(path)
    spec = importlib.util.spec_from_file_location(f"promptectomy_swap_{path.stem}", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot import compiled engine {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    run = getattr(module, "run", None)
    if not callable(run):
        raise TypeError(f"compiled engine {path} lacks run(input, params)")
    return run


def _compiled_response(template: Any, output: Any) -> Any:
    """Rehydrate a real SDK Response envelope while replacing its visible text."""
    from openai.types.responses.response import Response

    if not isinstance(template, dict):
        raise ValueError("compiled registry entry has no stored response envelope template")
    envelope = json.loads(json.dumps(template))
    text = output if isinstance(output, str) else json.dumps(output, separators=(",", ":"), ensure_ascii=False)
    for item in envelope.get("output", []):
        if not isinstance(item, dict):
            continue
        for content in item.get("content", []):
            if isinstance(content, dict) and content.get("type") == "output_text":
                content["text"] = text
                return Response.model_validate(envelope)
    raise ValueError("stored response envelope has no output_text content to replace")


def _record(
    ledger_path: Path,
    callsite_id: str,
    mode: str,
    kwargs: dict[str, Any],
    response: Any | None,
    elapsed_ms: float,
    config: dict[str, Any],
    error: Exception | None = None,
) -> None:
    model = str(kwargs.get("model", "unknown"))
    usage = _usage(response) if response is not None else Usage()
    raw = _response_raw(response) if response is not None else None
    event = LedgerEventV1(
        event_id=str(uuid.uuid4()),
        recorded_at=datetime.now(UTC).isoformat(),
        repo_sha="unknown",
        callsite_id=callsite_id,
        mode=mode,
        model=model,
        request_input=_json_value(kwargs.get("input")),
        request_params=redact({key: _json_value(value) for key, value in kwargs.items() if key not in {"input", "extra_headers"}}),
        response_raw=raw,
        response_normalized=_normalized(response, str(config.get("kind", ""))) if response is not None else None,
        usage=usage,
        latency_ms=max(0.0, elapsed_ms),
        estimated_cost_usd=estimate_cost(usage, model),
        status="error" if error else "ok",
    )
    append(ledger_path, event)


def _shadow_selected(callsite_id: str, request_id: str, kwargs: dict[str, Any], rate: float) -> bool:
    if rate <= 0:
        return False
    payload = json.dumps(_json_value(kwargs.get("input")), sort_keys=True, separators=(",", ":"))
    return int(hashlib.sha256(f"{callsite_id}:{request_id}:{payload}".encode()).hexdigest(), 16) % 10_000 < int(rate * 10_000)


def _shadow(original: Callable[..., Any], self: Responses, args: tuple[Any, ...], kwargs: dict[str, Any], ledger_path: Path, callsite_id: str, config: dict[str, Any]) -> None:
    started = time.perf_counter()
    try:
        response = original(self, *args, **kwargs)
        _record(ledger_path, callsite_id, "shadow", kwargs, response, (time.perf_counter() - started) * 1000, config)
    except Exception as exc:
        _record(ledger_path, callsite_id, "shadow", kwargs, None, (time.perf_counter() - started) * 1000, config, exc)


def _wrapped(self: Responses, *args: Any, **kwargs: Any) -> Any:
    if _original_create is None or _config is None:
        raise RuntimeError("promptectomy shim is not installed")
    repo_root, ledger_path, registry_path = _config
    if kwargs.get("stream") is True:
        return _original_create(self, *args, **kwargs)
    callsite_id, _path, _line = _callsite_id(repo_root)
    config = _registry(registry_path).get(callsite_id, {})
    started = time.perf_counter()
    try:
        if config.get("enabled"):
            compiled = _engine(config, registry_path)(kwargs.get("input"), redact({key: _json_value(value) for key, value in kwargs.items() if key != "input"}))
            response = _compiled_response(config.get("response_template"), compiled)
            elapsed_ms = (time.perf_counter() - started) * 1000
            _record(ledger_path, callsite_id, "compiled", kwargs, response, elapsed_ms, config)
            if _shadow_selected(callsite_id, uuid.uuid4().hex, kwargs, float(config.get("shadow_rate", 0.01))):
                threading.Thread(
                    target=_shadow,
                    args=(_original_create, self, args, dict(kwargs), ledger_path, callsite_id, config),
                    daemon=True,
                ).start()
            return response
        response = _original_create(self, *args, **kwargs)
        _record(ledger_path, callsite_id, "original", kwargs, response, (time.perf_counter() - started) * 1000, config)
        return response
    except Exception as exc:
        _record(ledger_path, callsite_id, "compiled" if config.get("enabled") else "original", kwargs, None, (time.perf_counter() - started) * 1000, config, exc)
        raise


def install(repo_root: str | Path, ledger_path: str | Path, registry_path: str | Path) -> None:
    """Install or retarget the supported synchronous, non-streaming SDK patch."""
    global _original_create, _config
    _config = (Path(repo_root).resolve(), Path(ledger_path).resolve(), Path(registry_path).resolve())
    if _original_create is None:
        _original_create = Responses.create
        Responses.create = _wrapped
