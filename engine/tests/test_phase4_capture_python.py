from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

import pytest
from openai.types.responses.response import Response as OpenAIResponse
from openai.types.responses.response_usage import ResponseUsage

from promptectomy.capture_python import (
    CaptureCallbackError,
    CaptureConfigurationError,
    CapturedAsyncResponses,
    CapturedResponses,
)
from promptectomy.evidence_phase4 import CallsiteCandidate, NormalizedObservation


CALLSITE_ID = "cs_" + "a" * 64
CALLSITES = (CallsiteCandidate(CALLSITE_ID, "src/client.py", "send"),)
CANARY = "CAPTURE_BODY_CANARY_MUST_NOT_PERSIST"
LABEL_CANARY = "CAPTURE_LABEL_CANARY_MUST_NOT_PERSIST"


@dataclass
class Usage:
    input_tokens: int
    output_tokens: int


@dataclass
class Response:
    model: str
    output: str
    usage: Usage
    retries_taken: int = 0


@dataclass
class CompletedEvent:
    response: Response


class SyncResource:
    def __init__(self, response: Any = None, error: BaseException | None = None) -> None:
        self.response = response
        self.error = error
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def create(self, **kwargs: Any) -> Any:
        self.calls.append(("create", kwargs))
        if self.error is not None:
            raise self.error
        return self.response

    def parse(self, **kwargs: Any) -> Any:
        self.calls.append(("parse", kwargs))
        if self.error is not None:
            raise self.error
        return self.response


class AsyncResource:
    def __init__(self, response: Any = None, error: BaseException | None = None) -> None:
        self.response = response
        self.error = error

    async def create(self, **kwargs: Any) -> Any:
        if self.error is not None:
            raise self.error
        return self.response

    async def parse(self, **kwargs: Any) -> Any:
        if self.error is not None:
            raise self.error
        return self.response


class SyncStream:
    def __init__(self, events: list[Any], error: BaseException | None = None) -> None:
        self.events = iter(events)
        self.error = error
        self.closed = False

    def __iter__(self) -> SyncStream:
        return self

    def __next__(self) -> Any:
        try:
            return next(self.events)
        except StopIteration:
            if self.error is not None:
                raise self.error
            raise

    def close(self) -> None:
        self.closed = True


class AsyncStream:
    def __init__(self, events: list[Any], error: BaseException | None = None) -> None:
        self.events = iter(events)
        self.error = error
        self.closed = False

    def __aiter__(self) -> AsyncStream:
        return self

    async def __anext__(self) -> Any:
        try:
            return next(self.events)
        except StopIteration:
            if self.error is not None:
                raise self.error
            raise StopAsyncIteration from None

    async def aclose(self) -> None:
        self.closed = True


def test_sync_create_and_parse_are_explicit_metadata_only_wrappers() -> None:
    observations: list[NormalizedObservation] = []
    response = Response(LABEL_CANARY, CANARY, Usage(13, 8), retries_taken=2)
    resource = SyncResource(response)
    captured = CapturedResponses(resource, callsite_id=CALLSITE_ID, callsites=CALLSITES, sink=observations.append)

    assert captured.create(model=LABEL_CANARY, input=CANARY, tools=[{"name": LABEL_CANARY}]) is response
    assert captured.parse(model=LABEL_CANARY, input=CANARY, text_format=dict) is response

    assert [call[0] for call in resource.calls] == ["create", "parse"]
    create, parse = observations
    assert create.callsite_id == CALLSITE_ID
    assert create.operation == "responses.create"
    assert create.status == "ok"
    assert create.input_tokens == 13
    assert create.output_tokens == 8
    assert create.flags == ("retry", "synchronous", "tools")
    assert parse.operation == "responses.parse"
    assert parse.flags == ("retry", "structured_output", "synchronous")
    assert CANARY not in repr(observations)
    assert LABEL_CANARY not in repr(observations)


def test_pinned_openai_response_shape_and_usage_are_supported() -> None:
    usage = ResponseUsage.model_construct(
        input_tokens=5,
        input_tokens_details=None,
        output_tokens=3,
        output_tokens_details=None,
        total_tokens=8,
    )
    response = OpenAIResponse.model_construct(model=LABEL_CANARY, output=[CANARY], usage=usage)
    observations: list[NormalizedObservation] = []
    captured = CapturedResponses(
        SyncResource(response), callsite_id=CALLSITE_ID, callsites=CALLSITES, sink=observations.append
    )
    assert captured.create(model=LABEL_CANARY, input=CANARY) is response
    assert observations[0].input_tokens == 5
    assert observations[0].output_tokens == 3
    assert CANARY not in repr(observations)
    assert LABEL_CANARY not in repr(observations)


def test_unverified_callsites_are_rejected_before_the_sdk_is_called() -> None:
    resource = SyncResource(Response("gpt", "output", Usage(1, 1)))
    with pytest.raises(CaptureConfigurationError):
        CapturedResponses(resource, callsite_id="cs_" + "b" * 64, callsites=CALLSITES, sink=lambda _: None)
    assert resource.calls == []


def test_sync_error_identity_is_preserved_even_when_capture_callback_fails() -> None:
    error = RuntimeError(CANARY)
    captured = CapturedResponses(
        SyncResource(error=error),
        callsite_id=CALLSITE_ID,
        callsites=CALLSITES,
        sink=lambda _: (_ for _ in ()).throw(RuntimeError("sink failed")),
    )
    with pytest.raises(RuntimeError) as caught:
        captured.create(model="gpt", input=CANARY)
    assert caught.value is error


def test_callback_failure_is_typed_after_a_successful_call() -> None:
    captured = CapturedResponses(
        SyncResource(Response("gpt", "output", Usage(1, 1))),
        callsite_id=CALLSITE_ID,
        callsites=CALLSITES,
        sink=lambda _: (_ for _ in ()).throw(RuntimeError("sink failed")),
    )
    with pytest.raises(CaptureCallbackError):
        captured.create(model="gpt", input="input")


def test_callback_must_return_none_without_inspecting_the_returned_object() -> None:
    class HostileReturn:
        @property
        def __await__(self) -> Any:
            raise AssertionError("capture inspected a callback return value")

    captured = CapturedResponses(
        SyncResource(Response("gpt", "output", Usage(1, 1))),
        callsite_id=CALLSITE_ID,
        callsites=CALLSITES,
        sink=lambda _: HostileReturn(),  # type: ignore[return-value]
    )
    with pytest.raises(CaptureCallbackError):
        captured.create(model="gpt", input="input")


def test_shape_capture_is_bounded_and_does_not_invoke_hostile_mapping_keys() -> None:
    class HostileKey:
        def __init__(self) -> None:
            self.active = False

        def __hash__(self) -> int:
            if self.active:
                raise AssertionError("capture invoked an attacker-controlled key hash")
            return hash("input")

        def __eq__(self, other: object) -> bool:
            raise AssertionError("capture invoked attacker-controlled equality")

    key = HostileKey()
    hostile = {key: CANARY}
    key.active = True
    observations: list[NormalizedObservation] = []
    captured = CapturedResponses(
        SyncResource(Response("gpt", CANARY, Usage(1, 1))),
        callsite_id=CALLSITE_ID,
        callsites=CALLSITES,
        sink=observations.append,
    )
    result = captured.create(model="gpt", input={str(index): CANARY for index in range(300)})
    assert result.output == CANARY
    result = captured.create(model="gpt", input=hostile)
    assert result.output == CANARY
    assert len(observations) == 2
    assert CANARY not in repr(observations)


def test_sync_stream_emits_once_on_exhaustion_and_once_on_early_close() -> None:
    observations: list[NormalizedObservation] = []
    completed = CompletedEvent(Response(LABEL_CANARY, CANARY, Usage(34, 21), retries_taken=1))
    stream = SyncStream([{"delta": CANARY}, completed])
    wrapped = CapturedResponses(
        SyncResource(stream), callsite_id=CALLSITE_ID, callsites=CALLSITES, sink=observations.append
    ).create(model=LABEL_CANARY, input=CANARY, stream=True, tools=[{"name": LABEL_CANARY}])
    assert list(wrapped) == [{"delta": CANARY}, completed]
    assert len(observations) == 1
    assert observations[0].status == "ok"
    assert observations[0].input_tokens == 34
    assert observations[0].output_tokens == 21
    assert observations[0].flags == ("retry", "streaming", "synchronous", "tools")

    early = SyncStream([1, 2, 3])
    wrapped = CapturedResponses(
        SyncResource(early), callsite_id=CALLSITE_ID, callsites=CALLSITES, sink=observations.append
    ).create(model="gpt", input=CANARY, stream=True)
    assert next(wrapped) == 1
    wrapped.close()
    wrapped.close()
    assert early.closed is True
    assert len(observations) == 2
    assert observations[1].status == "cancelled"
    assert observations[1].flags == ("cancellation", "streaming", "synchronous")
    assert CANARY not in repr(observations)
    assert LABEL_CANARY not in repr(observations)


def test_sync_stream_error_is_preserved_and_observed_once() -> None:
    error = ValueError(CANARY)
    observations: list[NormalizedObservation] = []
    wrapped = CapturedResponses(
        SyncResource(SyncStream([1], error)),
        callsite_id=CALLSITE_ID,
        callsites=CALLSITES,
        sink=observations.append,
    ).create(model="gpt", input=CANARY, stream=True)
    assert next(wrapped) == 1
    with pytest.raises(ValueError) as caught:
        next(wrapped)
    assert caught.value is error
    assert len(observations) == 1
    assert observations[0].status == "error"
    assert observations[0].flags == ("error", "streaming", "synchronous")


def test_async_create_parse_stream_and_close_preserve_semantics() -> None:
    async def exercise() -> list[NormalizedObservation]:
        observations: list[NormalizedObservation] = []
        response = Response(LABEL_CANARY, CANARY, Usage(21, 13))
        captured = CapturedAsyncResponses(
            AsyncResource(response), callsite_id=CALLSITE_ID, callsites=CALLSITES, sink=observations.append
        )
        assert await captured.create(model=LABEL_CANARY, input=CANARY) is response
        assert await captured.parse(model=LABEL_CANARY, input=CANARY, text_format=dict) is response

        stream = AsyncStream([{"delta": CANARY}, {"delta": CANARY}])
        wrapped = await CapturedAsyncResponses(
            AsyncResource(stream), callsite_id=CALLSITE_ID, callsites=CALLSITES, sink=observations.append
        ).create(model=LABEL_CANARY, input=CANARY, stream=True)
        events = [event async for event in wrapped]
        assert events == [{"delta": CANARY}, {"delta": CANARY}]

        early = AsyncStream([1, 2])
        wrapped = await CapturedAsyncResponses(
            AsyncResource(early), callsite_id=CALLSITE_ID, callsites=CALLSITES, sink=observations.append
        ).create(model="gpt", input=CANARY, stream=True)
        assert await wrapped.__anext__() == 1
        await wrapped.aclose()
        await wrapped.aclose()
        return observations

    observations = asyncio.run(exercise())
    assert [item.status for item in observations] == ["ok", "ok", "ok", "cancelled"]
    assert observations[0].flags == ("asynchronous",)
    assert observations[1].flags == ("asynchronous", "structured_output")
    assert observations[2].flags == ("asynchronous", "streaming")
    assert observations[3].flags == ("asynchronous", "cancellation", "streaming")
    assert CANARY not in repr(observations)
    assert LABEL_CANARY not in repr(observations)


def test_async_cancellation_identity_is_preserved_and_recorded() -> None:
    async def exercise() -> list[NormalizedObservation]:
        observations: list[NormalizedObservation] = []

        class BlockingResource(AsyncResource):
            async def create(self, **kwargs: Any) -> Any:
                await asyncio.Event().wait()

        captured = CapturedAsyncResponses(
            BlockingResource(), callsite_id=CALLSITE_ID, callsites=CALLSITES, sink=observations.append
        )
        task = asyncio.create_task(captured.create(model="gpt", input=CANARY))
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        return observations

    observations = asyncio.run(exercise())
    assert len(observations) == 1
    assert observations[0].status == "cancelled"
    assert observations[0].flags == ("asynchronous", "cancellation")
    assert CANARY not in repr(observations)
