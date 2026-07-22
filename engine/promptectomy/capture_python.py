from __future__ import annotations

import asyncio
import re
import time
import uuid
from collections.abc import AsyncIterator, Callable, Iterator, Mapping
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

from .evidence_phase4 import (
    CallsiteCandidate,
    CaptureRecord,
    NormalizedObservation,
    capture_metadata,
)


_CALLSITE_ID = re.compile(r"^(?:cs_|callsite_sha256_)[0-9a-f]{64}$")
_SAFE_FIELDS = {
    "background",
    "context_management",
    "conversation",
    "error",
    "events",
    "include",
    "input",
    "input_tokens",
    "instructions",
    "max_output_tokens",
    "max_tool_calls",
    "metadata",
    "model",
    "moderation",
    "output",
    "output_tokens",
    "parallel_tool_calls",
    "previous_response_id",
    "prompt",
    "prompt_cache_key",
    "prompt_cache_options",
    "prompt_cache_retention",
    "reasoning",
    "response",
    "retries_taken",
    "safety_identifier",
    "service_tier",
    "store",
    "stream",
    "stream_options",
    "temperature",
    "text",
    "text_format",
    "tool_choice",
    "tools",
    "top_logprobs",
    "top_p",
    "truncation",
    "usage",
    "user",
    "verbosity",
}


class CaptureConfigurationError(ValueError):
    pass


class CaptureCallbackError(RuntimeError):
    pass


class SyncResponses(Protocol):
    def create(self, **kwargs: Any) -> Any: ...

    def parse(self, **kwargs: Any) -> Any: ...


class AsyncResponses(Protocol):
    async def create(self, **kwargs: Any) -> Any: ...

    async def parse(self, **kwargs: Any) -> Any: ...


ObservationSink = Callable[[NormalizedObservation], None]


def _is_exact(value: Any, *expected: type[Any]) -> bool:
    return object.__getattribute__(value, "__class__") in expected


def _fields(value: Any) -> Mapping[str, Any] | None:
    if _is_exact(value, dict):
        return value
    try:
        fields = object.__getattribute__(value, "__dict__")
    except (AttributeError, TypeError):
        return None
    return fields if _is_exact(fields, dict) else None


def _shape(value: Any, *, depth: int = 0) -> Any:
    if depth >= 6:
        return {"kind": "depth_limited"}
    if value is None:
        return {"kind": "null"}
    if _is_exact(value, bool):
        return {"kind": "boolean"}
    if _is_exact(value, int):
        return {"kind": "integer"}
    if _is_exact(value, float):
        return {"kind": "number"}
    if _is_exact(value, str):
        return {"kind": "string"}
    if _is_exact(value, bytes):
        return {"kind": "bytes"}
    if _is_exact(value, list, tuple):
        return {
            "kind": "array",
            "count": len(value),
            "items": [_shape(item, depth=depth + 1) for item in value[:16]],
        }
    fields = _fields(value)
    if fields is None:
        return {"kind": "object"}
    if len(fields) > 256:
        return {"kind": "object", "field_count": "over_limit"}
    safe = {
        key: _shape(item, depth=depth + 1)
        for key, item in fields.items()
        if _is_exact(key, str) and key in _SAFE_FIELDS
    }
    return {
        "kind": "object",
        "fields": safe,
        "unknown_field_count": len(fields) - len(safe),
    }


def _field(value: Any, name: str) -> Any:
    fields = _fields(value)
    if fields is None or len(fields) > 256:
        return None
    for key, item in fields.items():
        if _is_exact(key, str) and key == name:
            return item
    return None


def _token(value: Any) -> int | None:
    return value if _is_exact(value, int) and 0 <= value <= 2**64 - 1 else None


def _usage(value: Any) -> tuple[int | None, int | None]:
    usage = _field(value, "usage")
    return _token(_field(usage, "input_tokens")), _token(_field(usage, "output_tokens"))


def _retry_count(value: Any) -> int:
    for name in ("retries_taken", "_retries_taken"):
        count = _field(value, name)
        if _is_exact(count, int) and count > 0:
            return count
    return 0


def _stream_summary(event: Any, count: int) -> dict[str, Any]:
    response = _field(event, "response")
    source = event if response is None else response
    input_tokens, output_tokens = _usage(source)
    summary: dict[str, Any] = {"stream": {"events": count}}
    if input_tokens is not None or output_tokens is not None:
        summary["usage"] = {"input_tokens": input_tokens, "output_tokens": output_tokens}
    retries = _retry_count(source)
    if retries:
        summary["retries_taken"] = retries
    return summary


def _model(request_model: str, response: Any) -> str:
    response_model = _field(response, "model")
    if _is_exact(response_model, str) and len(response_model) <= 256:
        return response_model
    return request_model


def _request_model(request: Mapping[str, Any]) -> str:
    model = request.get("model")
    return model if _is_exact(model, str) and len(model) <= 256 else "unknown"


def _status(error: BaseException) -> Literal["error", "cancelled"]:
    return "cancelled" if isinstance(error, (asyncio.CancelledError, GeneratorExit)) else "error"


def _verified_callsites(
    callsite_id: str,
    callsites: tuple[CallsiteCandidate, ...],
) -> tuple[CallsiteCandidate, ...]:
    matches = [item for item in callsites if item.callsite_id == callsite_id]
    if not _CALLSITE_ID.fullmatch(callsite_id) or len(matches) != 1:
        raise CaptureConfigurationError("Capture requires one registry-verified callsite ID")
    return callsites


@dataclass
class _Attempt:
    operation: Literal["responses.create", "responses.parse"]
    asynchronous: bool
    callsite_id: str
    callsites: tuple[CallsiteCandidate, ...]
    request_shape: Any
    request_model: str
    streaming: bool
    tools: bool
    structured_output: bool
    sink: ObservationSink
    started_at_unix_nano: int = field(default_factory=time.time_ns)
    attempt_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    finished: bool = False

    def finish(
        self,
        status: Literal["ok", "error", "cancelled"],
        response: Any = None,
    ) -> None:
        if self.finished:
            return
        self.finished = True
        input_tokens, output_tokens = _usage(response)
        flags = {"asynchronous" if self.asynchronous else "synchronous"}
        if self.streaming:
            flags.add("streaming")
        if self.tools:
            flags.add("tools")
        if self.structured_output:
            flags.add("structured_output")
        if status == "error":
            flags.add("error")
        if status == "cancelled":
            flags.add("cancellation")
        if _retry_count(response):
            flags.add("retry")
        observation = capture_metadata(
            CaptureRecord(
                runtime="python",
                attempt_id=self.attempt_id,
                callsite_id=self.callsite_id,
                provider="openai",
                model=_model(self.request_model, response),
                operation=self.operation,
                started_at_unix_nano=self.started_at_unix_nano,
                ended_at_unix_nano=max(time.time_ns(), self.started_at_unix_nano),
                status=status,
                request_shape=self.request_shape,
                response_shape=_shape(response),
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                flags=tuple(sorted(flags)),
            ),
            callsites=self.callsites,
        )
        try:
            result = self.sink(observation)
        except BaseException as exc:
            raise CaptureCallbackError("The capture observation callback failed") from exc
        if result is not None:
            raise CaptureCallbackError("The capture observation callback must return None")

    def finish_preserving(self, error: BaseException) -> None:
        try:
            self.finish(_status(error), error)
        except BaseException:
            pass


def _attempt(
    operation: Literal["responses.create", "responses.parse"],
    asynchronous: bool,
    callsite_id: str,
    callsites: tuple[CallsiteCandidate, ...],
    kwargs: dict[str, Any],
    sink: ObservationSink,
) -> _Attempt:
    return _Attempt(
        operation=operation,
        asynchronous=asynchronous,
        callsite_id=callsite_id,
        callsites=callsites,
        request_shape=_shape(kwargs),
        request_model=_request_model(kwargs),
        streaming=kwargs.get("stream") is True,
        tools="tools" in kwargs,
        structured_output=operation == "responses.parse"
        or bool({"text", "text_format", "response_format"} & kwargs.keys()),
        sink=sink,
    )


class _CapturedSyncStream(Iterator[Any]):
    def __init__(self, stream: Any, attempt: _Attempt) -> None:
        self._stream = stream
        self._iterator = iter(stream)
        self._attempt = attempt
        self._events = 0
        self._summary = _stream_summary(None, 0)

    def __iter__(self) -> _CapturedSyncStream:
        return self

    def __next__(self) -> Any:
        try:
            event = next(self._iterator)
        except StopIteration:
            self._attempt.finish("ok", self._summary)
            raise
        except BaseException as exc:
            self._attempt.finish_preserving(exc)
            raise
        self._events += 1
        current = _stream_summary(event, self._events)
        if "usage" in current or "retries_taken" in current:
            self._summary = current
        else:
            self._summary["stream"] = current["stream"]
        return event

    def close(self) -> None:
        try:
            close = getattr(self._stream, "close")
            close()
        except AttributeError:
            pass
        except BaseException as exc:
            self._attempt.finish_preserving(exc)
            raise
        if not self._attempt.finished:
            self._attempt.finish("cancelled", self._summary)

    def __enter__(self) -> _CapturedSyncStream:
        try:
            enter = getattr(self._stream, "__enter__", None)
            if enter is not None:
                entered = enter()
                self._stream = entered
                self._iterator = iter(entered)
        except BaseException as exc:
            self._attempt.finish_preserving(exc)
            raise
        return self

    def __exit__(self, exc_type: Any, exc: BaseException | None, traceback: Any) -> Any:
        exit_method = getattr(self._stream, "__exit__", None)
        try:
            result = None if exit_method is None else exit_method(exc_type, exc, traceback)
        except BaseException as exit_error:
            self._attempt.finish_preserving(exit_error)
            raise
        if not self._attempt.finished:
            if exc is None:
                self._attempt.finish("cancelled", self._summary)
            else:
                self._attempt.finish_preserving(exc)
        return result


class _CapturedAsyncStream(AsyncIterator[Any]):
    def __init__(self, stream: Any, attempt: _Attempt) -> None:
        self._stream = stream
        self._iterator = stream.__aiter__()
        self._attempt = attempt
        self._events = 0
        self._summary = _stream_summary(None, 0)

    def __aiter__(self) -> _CapturedAsyncStream:
        return self

    async def __anext__(self) -> Any:
        try:
            event = await self._iterator.__anext__()
        except StopAsyncIteration:
            self._attempt.finish("ok", self._summary)
            raise
        except BaseException as exc:
            self._attempt.finish_preserving(exc)
            raise
        self._events += 1
        current = _stream_summary(event, self._events)
        if "usage" in current or "retries_taken" in current:
            self._summary = current
        else:
            self._summary["stream"] = current["stream"]
        return event

    async def aclose(self) -> None:
        close = getattr(self._stream, "close", None)
        aclose = getattr(self._stream, "aclose", None)
        try:
            if aclose is not None:
                await aclose()
            elif close is not None:
                result = close()
                if hasattr(result, "__await__"):
                    await result
        except BaseException as exc:
            self._attempt.finish_preserving(exc)
            raise
        if not self._attempt.finished:
            self._attempt.finish("cancelled", self._summary)

    async def __aenter__(self) -> _CapturedAsyncStream:
        try:
            enter = getattr(self._stream, "__aenter__", None)
            if enter is not None:
                entered = await enter()
                self._stream = entered
                self._iterator = entered.__aiter__()
        except BaseException as exc:
            self._attempt.finish_preserving(exc)
            raise
        return self

    async def __aexit__(self, exc_type: Any, exc: BaseException | None, traceback: Any) -> Any:
        exit_method = getattr(self._stream, "__aexit__", None)
        try:
            result = None if exit_method is None else await exit_method(exc_type, exc, traceback)
        except BaseException as exit_error:
            self._attempt.finish_preserving(exit_error)
            raise
        if not self._attempt.finished:
            if exc is None:
                self._attempt.finish("cancelled", self._summary)
            else:
                self._attempt.finish_preserving(exc)
        return result


class CapturedResponses:
    """Explicit metadata-only wrapper for one verified synchronous Responses callsite."""

    def __init__(
        self,
        responses: SyncResponses,
        *,
        callsite_id: str,
        callsites: tuple[CallsiteCandidate, ...],
        sink: ObservationSink,
    ) -> None:
        self._responses = responses
        self._callsite_id = callsite_id
        self._callsites = _verified_callsites(callsite_id, callsites)
        self._sink = sink

    def _call(self, operation: Literal["responses.create", "responses.parse"], kwargs: dict[str, Any]) -> Any:
        attempt = _attempt(operation, False, self._callsite_id, self._callsites, kwargs, self._sink)
        try:
            result = getattr(self._responses, operation.rsplit(".", 1)[1])(**kwargs)
        except BaseException as exc:
            attempt.finish_preserving(exc)
            raise
        if kwargs.get("stream") is True:
            try:
                return _CapturedSyncStream(result, attempt)
            except BaseException as exc:
                attempt.finish_preserving(exc)
                raise
        attempt.finish("ok", result)
        return result

    def create(self, **kwargs: Any) -> Any:
        return self._call("responses.create", kwargs)

    def parse(self, **kwargs: Any) -> Any:
        return self._call("responses.parse", kwargs)


class CapturedAsyncResponses:
    """Explicit metadata-only wrapper for one verified asynchronous Responses callsite."""

    def __init__(
        self,
        responses: AsyncResponses,
        *,
        callsite_id: str,
        callsites: tuple[CallsiteCandidate, ...],
        sink: ObservationSink,
    ) -> None:
        self._responses = responses
        self._callsite_id = callsite_id
        self._callsites = _verified_callsites(callsite_id, callsites)
        self._sink = sink

    async def _call(self, operation: Literal["responses.create", "responses.parse"], kwargs: dict[str, Any]) -> Any:
        attempt = _attempt(operation, True, self._callsite_id, self._callsites, kwargs, self._sink)
        try:
            result = await getattr(self._responses, operation.rsplit(".", 1)[1])(**kwargs)
        except BaseException as exc:
            attempt.finish_preserving(exc)
            raise
        if kwargs.get("stream") is True:
            try:
                return _CapturedAsyncStream(result, attempt)
            except BaseException as exc:
                attempt.finish_preserving(exc)
                raise
        attempt.finish("ok", result)
        return result

    async def create(self, **kwargs: Any) -> Any:
        return await self._call("responses.create", kwargs)

    async def parse(self, **kwargs: Any) -> Any:
        return await self._call("responses.parse", kwargs)
