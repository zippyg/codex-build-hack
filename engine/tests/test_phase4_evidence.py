from __future__ import annotations

import json
from typing import Literal, cast

import pytest
from google.protobuf.json_format import ParseDict
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (
    ExportTraceServiceRequest,
)

from promptectomy.evidence_phase4 import (
    CallsiteCandidate,
    CaptureRecord,
    EvidenceError,
    ImportLimits,
    capture_metadata,
    import_otlp_grpc,
    import_otlp_http_json,
)


def _attribute(key: str, value: str | int) -> dict[str, object]:
    encoded: dict[str, object]
    if isinstance(value, int):
        encoded = {"intValue": str(value)}
    else:
        encoded = {"stringValue": value}
    return {"key": key, "value": encoded}


def _span(
    *,
    trace_id: str = "a" * 32,
    span_id: str = "b" * 16,
    start: int = 1_000_000,
    end: int = 2_000_000,
    attributes: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return {
        "traceId": trace_id,
        "spanId": span_id,
        "startTimeUnixNano": str(start),
        "endTimeUnixNano": str(end),
        "status": {"code": "STATUS_CODE_OK"},
        "attributes": attributes or [],
    }


def _payload(spans: list[object], *, partial: bool = False) -> bytes:
    document: dict[str, object] = {
        "resourceSpans": [{"scopeSpans": [{"spans": spans}]}],
    }
    if partial:
        document["partialSuccess"] = {"rejectedSpans": "1"}
    return json.dumps(document, separators=(",", ":")).encode()


def test_otlp_metadata_mapping_drops_protected_content_and_correlates_exactly() -> None:
    canary = "PROMPT_CANARY_DO_NOT_PERSIST"
    callsite_id = "cs_" + "1" * 64
    attributes = [
        _attribute("gen_ai.system", "openai"),
        _attribute("gen_ai.operation.name", "responses"),
        _attribute("gen_ai.request.model", "gpt-5"),
        _attribute("gen_ai.response.model", "gpt-5.1"),
        _attribute("gen_ai.usage.input_tokens", 12),
        _attribute("gen_ai.usage.output_tokens", 8),
        _attribute("promptectomy.callsite_id", callsite_id),
        _attribute("openinference.span.kind", "LLM"),
        _attribute("gen_ai.prompt", canary),
        _attribute("unmapped.private.attribute", canary),
    ]
    report = import_otlp_http_json(
        _payload([_span(attributes=attributes)]),
        callsites=(CallsiteCandidate(callsite_id, "src/client.py", "send"),),
    )
    assert len(report.observations) == 1
    observation = report.observations[0]
    assert observation.callsite_id == callsite_id
    assert observation.correlation.confidence == 1.0
    assert observation.correlation.reason == "declared_callsite_id"
    assert observation.provider == "openai"
    assert observation.model.startswith("sha256:")
    assert "gpt-5.1" not in repr(observation)
    assert observation.operation == "responses"
    assert observation.trace_id.startswith("trace_sha256_")
    assert observation.span_id.startswith("span_sha256_")
    assert observation.attempt_id.startswith("attempt_sha256_")
    assert "a" * 32 not in repr(observation)
    assert "b" * 16 not in repr(observation)
    assert observation.sdk_version_digest.startswith("sha256:")
    assert observation.cost_kind == "unknown"
    assert observation.cost_microusd is None
    assert observation.pricing_source_digest is None
    assert observation.provenance_digest.startswith("sha256:")
    assert observation.input_tokens == 12
    assert observation.output_tokens == 8
    assert observation.flags == ("genai", "openinference")
    assert observation.unmapped_attribute_count == 1
    assert "protected_attribute_dropped" in report.warnings
    assert "unknown_attributes_dropped" in report.warnings
    assert canary not in repr(report)


def test_duplicate_out_of_order_partial_and_malformed_spans_are_explicit() -> None:
    late = _span(span_id="1" * 16, start=5_000, end=8_000)
    early = _span(span_id="2" * 16, start=1_000, end=3_000)
    malformed = {"traceId": "missing-fields"}
    report = import_otlp_http_json(
        _payload([late, early, early, malformed], partial=True)
    )
    assert [item.observed_at_unix_nano for item in report.observations] == [
        1_000,
        5_000,
    ]
    assert report.duplicate_count == 1
    assert report.rejected_count == 1
    assert report.input_out_of_order is True
    assert report.partial is True
    assert report.warnings == (
        "duplicate_spans_dropped",
        "input_out_of_order",
        "malformed_spans_rejected",
        "upstream_partial_success",
    )


@pytest.mark.parametrize(
    ("payload", "limits", "code"),
    [
        (b'{"resourceSpans":[],"resourceSpans":[]}', ImportLimits(), "malformed_otlp"),
        (
            _payload([_span(), _span(span_id="c" * 16)]),
            ImportLimits(max_spans=1),
            "backpressure_limit_exceeded",
        ),
        (_payload([]), ImportLimits(max_payload_bytes=1), "payload_limit_exceeded"),
        (_payload([{"traceId": "x"}]), ImportLimits(), "all_spans_rejected"),
    ],
)
def test_import_limits_and_strict_json_fail_typed(
    payload: bytes, limits: ImportLimits, code: str
) -> None:
    with pytest.raises(EvidenceError) as caught:
        import_otlp_http_json(payload, limits=limits)
    assert caught.value.code == code


def test_correlation_never_silently_upgrades_ambiguous_or_weak_evidence() -> None:
    callsites = (
        CallsiteCandidate("cs_" + "a" * 64, "src/a.py", "send"),
        CallsiteCandidate("cs_" + "b" * 64, "src/b.py", "send"),
    )
    path_and_symbol = _span(
        span_id="1" * 16,
        start=1_000,
        end=2_000,
        attributes=[
            _attribute("code.filepath", "src/a.py"),
            _attribute("code.function.name", "send"),
        ],
    )
    path_only = _span(
        span_id="2" * 16,
        start=2_000,
        end=3_000,
        attributes=[_attribute("code.filepath", "src/b.py")],
    )
    ambiguous = _span(
        span_id="3" * 16,
        start=3_000,
        end=4_000,
        attributes=[_attribute("code.function.name", "send")],
    )
    unmatched = _span(
        span_id="4" * 16,
        start=4_000,
        end=5_000,
        attributes=[_attribute("code.function.name", "other")],
    )
    report = import_otlp_http_json(
        _payload([path_and_symbol, path_only, ambiguous, unmatched]),
        callsites=callsites,
    )
    correlations = [item.correlation for item in report.observations]
    assert [
        (item.callsite_id, item.confidence, item.reason) for item in correlations
    ] == [
        ("cs_" + "a" * 64, 0.9, "path_and_symbol"),
        ("cs_" + "b" * 64, 0.6, "path_only"),
        (None, 0.0, "ambiguous"),
        (None, 0.0, "unmatched"),
    ]


def test_otlp_grpc_protobuf_uses_the_same_bounded_normalization() -> None:
    request = ExportTraceServiceRequest()
    ParseDict(
        json.loads(
            _payload([_span(attributes=[_attribute("gen_ai.system", "openai")])])
        ),
        request,
    )
    report = import_otlp_grpc(request.SerializeToString())
    assert len(report.observations) == 1
    assert report.observations[0].provider == "openai"


def test_otlp_grpc_rejects_malformed_and_oversized_payloads() -> None:
    with pytest.raises(EvidenceError) as caught:
        import_otlp_grpc(b"not-a-protobuf-message")
    assert caught.value.code == "malformed_otlp"
    with pytest.raises(EvidenceError) as caught:
        import_otlp_grpc(b"x" * 2, limits=ImportLimits(max_payload_bytes=1))
    assert caught.value.code == "payload_limit_exceeded"
    request = ExportTraceServiceRequest()
    with pytest.raises(EvidenceError) as caught:
        import_otlp_grpc(request.SerializeToString() + b"\xa0\x06\x01")
    assert caught.value.code == "unknown_otlp_fields"


@pytest.mark.parametrize("runtime", ["python", "node"])
def test_runtime_capture_is_metadata_only_across_semantic_cells(runtime: str) -> None:
    canary = "CAPTURE_CONTENT_CANARY"
    callsite_id = "cs_" + "a" * 64
    observation = capture_metadata(
        CaptureRecord(
            runtime=cast(Literal["python", "node"], runtime),
            attempt_id=f"{runtime}-attempt-1",
            callsite_id=callsite_id,
            provider="openai",
            model="gpt-5.1",
            operation="responses.create",
            started_at_unix_nano=1_000_000,
            ended_at_unix_nano=2_000_000,
            status="ok",
            request_shape={"input": canary, "tools": [{"name": canary}]},
            response_shape={"output": canary},
            input_tokens=10,
            output_tokens=20,
            flags=("streaming", "tools", "retry", "structured_output", "cancellation"),
            trace_id=f"{runtime}-raw-trace",
            span_id=f"{runtime}-raw-span",
            request_id=f"{runtime}-raw-request",
            sdk_version="2.46.0" if runtime == "python" else "6.48.0",
            protected_content_refs=("protected_ref_sha256_" + "b" * 64,),
            cost_kind="estimated",
            cost_microusd=125,
            pricing_source="openai-pricing",
            pricing_version="2026-07-21",
            tool_call_count=2,
            retry_count=1,
        ),
        callsites=(CallsiteCandidate(callsite_id, "src/client.py", "send"),),
    )
    assert observation.callsite_id == callsite_id
    assert observation.flags == (
        "cancellation",
        "retry",
        "streaming",
        "structured_output",
        "tools",
    )
    assert observation.trace_id.startswith("trace_sha256_")
    assert observation.span_id.startswith("span_sha256_")
    assert observation.request_id is not None and observation.request_id.startswith(
        "request_sha256_"
    )
    assert observation.attempt_id.startswith("attempt_sha256_")
    assert observation.stream_mode == "streaming"
    assert observation.tool_call_count == 2
    assert observation.structured_output is True
    assert observation.retry_count == 1
    assert observation.cost_kind == "estimated"
    assert observation.cost_microusd == 125
    assert observation.pricing_source_digest is not None
    assert observation.pricing_version_digest is not None
    assert observation.protected_content_refs == ("protected_ref_sha256_" + "b" * 64,)
    assert f"{runtime}-raw-trace" not in repr(observation)
    assert f"{runtime}-raw-span" not in repr(observation)
    assert f"{runtime}-raw-request" not in repr(observation)
    assert "openai-pricing" not in repr(observation)
    assert canary not in repr(observation)


def test_capture_and_otlp_never_copy_untrusted_labels_or_unverified_callsites() -> None:
    canary = "UNTRUSTED_SAFE_SURFACE_CANARY"
    observation = capture_metadata(
        CaptureRecord(
            runtime="python",
            attempt_id="attempt",
            callsite_id=canary,
            provider=canary,
            model=canary,
            operation="responses.create",
            started_at_unix_nano=1,
            ended_at_unix_nano=2,
            status="ok",
            request_shape={},
            response_shape={},
        )
    )
    assert observation.callsite_id is None
    assert observation.provider == "unknown"
    assert canary not in repr(observation)
    report = import_otlp_http_json(
        _payload(
            [
                _span(
                    attributes=[
                        _attribute("gen_ai.system", canary),
                        _attribute("gen_ai.request.model", canary),
                        _attribute("gen_ai.operation.name", canary),
                        _attribute("promptectomy.callsite_id", canary),
                    ]
                )
            ]
        )
    )
    assert canary not in repr(report)
    assert report.observations[0].correlation.reason == "unmatched"


def test_runtime_capture_rejects_unbounded_or_unknown_shapes() -> None:
    base = dict(
        runtime="python",
        attempt_id="attempt",
        callsite_id="callsite",
        provider="openai",
        model="gpt-5",
        operation="responses.create",
        started_at_unix_nano=1,
        ended_at_unix_nano=2,
        status="ok",
        response_shape={},
    )
    with pytest.raises(EvidenceError) as caught:
        capture_metadata(
            CaptureRecord(**base, request_shape={"items": list(range(257))})
        )
    assert caught.value.code == "capture_shape_limit_exceeded"


@pytest.mark.parametrize(
    "overrides",
    [
        {"protected_content_refs": ("not-a-protected-reference",)},
        {"cost_kind": "unknown", "cost_microusd": 1},
        {"cost_kind": "observed", "cost_microusd": 1},
        {
            "cost_kind": "estimated",
            "cost_microusd": -1,
            "pricing_source": "source",
            "pricing_version": "v1",
        },
        {
            "cost_kind": "invalid",
            "cost_microusd": 1,
            "pricing_source": "source",
            "pricing_version": "v1",
        },
        {"retry_count": -1},
        {"status": "SECRET_CANARY"},
        {"runtime": "browser"},
        {"operation": "responses.delete"},
        {"provider": 7},
        {"flags": ("streaming", 7)},
        {"trace_id": "x" * 257},
        {"protected_content_refs": ("protected_ref_sha256_" + "a" * 64,) * 129},
    ],
)
def test_runtime_capture_rejects_invalid_provenance_and_cost(
    overrides: dict[str, object],
) -> None:
    record = {
        "runtime": "python",
        "attempt_id": "attempt",
        "callsite_id": "callsite",
        "provider": "openai",
        "model": "gpt-5",
        "operation": "responses.create",
        "started_at_unix_nano": 1,
        "ended_at_unix_nano": 2,
        "status": "ok",
        "request_shape": {},
        "response_shape": {},
        **overrides,
    }
    with pytest.raises(EvidenceError) as caught:
        capture_metadata(CaptureRecord(**record))
    assert caught.value.code == "malformed_capture"
