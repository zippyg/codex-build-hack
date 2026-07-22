from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Literal

from google.protobuf.json_format import MessageToDict
from google.protobuf.message import DecodeError
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (
    ExportTraceServiceRequest,
)

from .contracts_v2 import ContractError, parse_json_strict


MAPPING_VERSION = "otlp-openinference-2026-07-1"


class EvidenceError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


@dataclass(frozen=True)
class ImportLimits:
    max_payload_bytes: int = 4 * 1024 * 1024
    max_spans: int = 10_000
    max_attributes_per_span: int = 256
    max_attribute_key_bytes: int = 256
    max_attribute_value_bytes: int = 4_096


@dataclass(frozen=True)
class CallsiteCandidate:
    callsite_id: str
    relative_path: str
    symbol: str


@dataclass(frozen=True)
class Correlation:
    callsite_id: str | None
    confidence: float
    reason: Literal[
        "declared_callsite_id",
        "path_and_symbol",
        "path_only",
        "symbol_only",
        "ambiguous",
        "unmatched",
    ]


@dataclass(frozen=True)
class NormalizedObservation:
    observation_id: str
    trace_id: str
    span_id: str
    request_id: str | None
    attempt_id: str
    callsite_id: str | None
    provider: str
    model: str
    sdk_version_digest: str
    operation: str
    observed_at_unix_nano: int
    status: Literal["ok", "error", "cancelled", "unknown"]
    duration_microseconds: int
    input_tokens: int | None
    output_tokens: int | None
    request_shape_digest: str
    response_shape_digest: str
    flags: tuple[str, ...]
    stream_mode: Literal["streaming", "non_streaming", "unknown"]
    tool_call_count: int | None
    structured_output: bool | None
    retry_count: int | None
    capture_policy_digest: str
    redaction_policy_digest: str
    retention_policy_digest: str
    protected_content_refs: tuple[str, ...]
    cost_kind: Literal["observed", "estimated", "unknown"]
    cost_microusd: int | None
    pricing_source_digest: str | None
    pricing_version_digest: str | None
    provenance_digest: str
    correlation: Correlation
    mapping_version: str
    unmapped_attribute_count: int


@dataclass(frozen=True)
class ImportReport:
    observations: tuple[NormalizedObservation, ...]
    duplicate_count: int
    rejected_count: int
    input_out_of_order: bool
    partial: bool
    warnings: tuple[str, ...]


@dataclass(frozen=True)
class CaptureRecord:
    runtime: Literal["python", "node"]
    attempt_id: str
    callsite_id: str
    provider: str
    model: str
    operation: Literal["responses.create", "responses.parse"]
    started_at_unix_nano: int
    ended_at_unix_nano: int
    status: Literal["ok", "error", "cancelled", "unknown"]
    request_shape: Any
    response_shape: Any
    input_tokens: int | None = None
    output_tokens: int | None = None
    flags: tuple[str, ...] = ()
    trace_id: str | None = None
    span_id: str | None = None
    request_id: str | None = None
    sdk_version: str = "unknown"
    capture_policy_id: str = "promptectomy.capture.v1"
    redaction_policy_id: str = "promptectomy.redaction.v1"
    retention_policy_id: str = "promptectomy.retention.local.v1"
    protected_content_refs: tuple[str, ...] = ()
    cost_kind: Literal["observed", "estimated", "unknown"] = "unknown"
    cost_microusd: int | None = None
    pricing_source: str | None = None
    pricing_version: str | None = None
    tool_call_count: int | None = None
    retry_count: int | None = None
    provenance: str = "promptectomy.runtime-capture.v1"


_MAPPED_ATTRIBUTES = {
    "code.filepath",
    "code.function.name",
    "error.type",
    "gen_ai.operation.name",
    "gen_ai.request.model",
    "gen_ai.response.model",
    "gen_ai.system",
    "gen_ai.usage.input_tokens",
    "gen_ai.usage.output_tokens",
    "openinference.span.kind",
    "promptectomy.callsite_id",
}

_PROTECTED_KEYS = {
    "authorization",
    "gen_ai.completion",
    "gen_ai.input.value",
    "gen_ai.output.value",
    "gen_ai.prompt",
    "gen_ai.retrieval",
    "gen_ai.tool.arguments",
    "gen_ai.tool.result",
}
_PROTECTED_SEGMENTS = {"api_key", "content", "cookie", "document", "password", "secret"}
_CAPTURE_FLAGS = {
    "asynchronous",
    "cancellation",
    "error",
    "retry",
    "streaming",
    "structured_output",
    "synchronous",
    "tools",
}
_CALLSITE_ID = re.compile(r"^(?:cs_|callsite_sha256_)[0-9a-f]{64}$")
_PROTECTED_REF = re.compile(r"^protected_ref_sha256_[0-9a-f]{64}$")
_SAFE_PROVIDERS = {"openai"}
_SAFE_OPERATIONS = {
    "chat",
    "execute_tool",
    "responses",
    "responses.create",
    "responses.parse",
}


def _digest(*parts: str) -> str:
    payload = "\0".join(parts).encode()
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def _identity(scope: str, *parts: str) -> str:
    payload = "\0".join((scope, *parts)).encode()
    return f"{scope}_sha256_{hashlib.sha256(payload).hexdigest()}"


def _protected_key(key: str) -> bool:
    lowered = key.lower().replace("-", "_")
    if lowered in _PROTECTED_KEYS:
        return True
    return bool(set(lowered.split(".")) & _PROTECTED_SEGMENTS)


def _metadata_shape(value: Any, *, depth: int = 0) -> Any:
    if depth > 8:
        raise EvidenceError(
            "capture_shape_limit_exceeded", "Capture shape exceeds the depth bound"
        )
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, bytes):
        return "bytes"
    if isinstance(value, (list, tuple)):
        if len(value) > 256:
            raise EvidenceError(
                "capture_shape_limit_exceeded", "Capture array exceeds the item bound"
            )
        return {
            "array": [_metadata_shape(item, depth=depth + 1) for item in value[:16]],
            "count": len(value),
        }
    if isinstance(value, dict):
        if len(value) > 256 or any(not isinstance(key, str) for key in value):
            raise EvidenceError(
                "capture_shape_limit_exceeded",
                "Capture object exceeds the member bound",
            )
        return {
            "object": sorted(
                (_digest("capture-key", key), _metadata_shape(item, depth=depth + 1))
                for key, item in value.items()
            )
        }
    raise EvidenceError(
        "capture_shape_unsupported",
        "Capture shape contains an unsupported runtime value",
    )


def _safe_provider(value: str) -> str:
    return value if value in _SAFE_PROVIDERS else "unknown"


def _safe_operation(value: str) -> str:
    return value if value in _SAFE_OPERATIONS else "unknown"


def _model_digest(value: str) -> str:
    return _digest("model", value)


def capture_metadata(
    record: CaptureRecord,
    *,
    callsites: tuple[CallsiteCandidate, ...] = (),
) -> NormalizedObservation:
    if not isinstance(record.runtime, str) or record.runtime not in {"python", "node"}:
        raise EvidenceError("malformed_capture", "Capture runtime is invalid")
    if (
        not isinstance(record.operation, str)
        or record.operation not in {"responses.create", "responses.parse"}
        or not isinstance(record.status, str)
        or record.status not in {"ok", "error", "cancelled", "unknown"}
    ):
        raise EvidenceError(
            "malformed_capture", "Capture operation or status is invalid"
        )
    if (
        not isinstance(record.attempt_id, str)
        or not record.attempt_id
        or len(record.attempt_id) > 256
        or not isinstance(record.callsite_id, str)
        or not record.callsite_id
    ):
        raise EvidenceError(
            "malformed_capture", "Capture identity is missing or oversized"
        )
    start = _bounded_int(record.started_at_unix_nano, field="started_at_unix_nano")
    end = _bounded_int(record.ended_at_unix_nano, field="ended_at_unix_nano")
    if end < start:
        raise EvidenceError("malformed_capture", "Capture ends before it starts")
    if (
        not isinstance(record.flags, tuple)
        or any(not isinstance(flag, str) for flag in record.flags)
        or not set(record.flags) <= _CAPTURE_FLAGS
    ):
        raise EvidenceError(
            "malformed_capture", "Capture contains an unsupported semantic flag"
        )
    if (
        not isinstance(record.provider, str)
        or not isinstance(record.model, str)
        or len(record.provider) > 128
        or len(record.model) > 256
    ):
        raise EvidenceError(
            "malformed_capture", "Capture provider or model is oversized"
        )
    if any(
        value is not None
        and (
            not isinstance(value, str)
            or not value
            or len(value.encode()) > 256
        )
        for value in (record.trace_id, record.span_id, record.request_id)
    ):
        raise EvidenceError(
            "malformed_capture", "Capture correlation identity is missing or oversized"
        )
    labels = (
        record.sdk_version,
        record.capture_policy_id,
        record.redaction_policy_id,
        record.retention_policy_id,
        record.provenance,
    )
    if any(
        not isinstance(value, str) or not value or len(value.encode()) > 256
        for value in labels
    ):
        raise EvidenceError(
            "malformed_capture", "Capture provenance label is missing or oversized"
        )
    if (
        not isinstance(record.protected_content_refs, tuple)
        or len(record.protected_content_refs) > 128
        or any(
            not isinstance(reference, str)
            or not _PROTECTED_REF.fullmatch(reference)
        for reference in record.protected_content_refs
        )
    ):
        raise EvidenceError(
            "malformed_capture", "Capture protected-content reference is invalid"
        )
    if len(set(record.protected_content_refs)) != len(record.protected_content_refs):
        raise EvidenceError(
            "malformed_capture",
            "Capture protected-content references contain duplicates",
        )
    for field, value in (
        ("tool_call_count", record.tool_call_count),
        ("retry_count", record.retry_count),
    ):
        if value is not None:
            _bounded_capture_int(value, field=field)
    if not isinstance(record.cost_kind, str) or record.cost_kind not in {
        "observed",
        "estimated",
        "unknown",
    }:
        raise EvidenceError("malformed_capture", "Capture cost kind is invalid")
    if record.cost_kind == "unknown":
        if (
            record.cost_microusd is not None
            or record.pricing_source is not None
            or record.pricing_version is not None
        ):
            raise EvidenceError(
                "malformed_capture",
                "Unknown capture cost cannot include pricing metadata",
            )
    elif (
        record.cost_microusd is None
        or not isinstance(record.pricing_source, str)
        or not record.pricing_source
        or not isinstance(record.pricing_version, str)
        or not record.pricing_version
        or len(record.pricing_source.encode()) > 256
        or len(record.pricing_version.encode()) > 256
    ):
        raise EvidenceError(
            "malformed_capture",
            "Known capture cost requires bounded pricing provenance",
        )
    if record.cost_microusd is not None:
        _bounded_capture_int(record.cost_microusd, field="cost_microusd")
    request_shape = _metadata_shape(record.request_shape)
    response_shape = _metadata_shape(record.response_shape)
    correlation = _correlate(
        {"promptectomy.callsite_id": record.callsite_id}, callsites
    )
    return NormalizedObservation(
        observation_id=_digest(
            "capture", record.runtime, record.attempt_id, str(start)
        ),
        trace_id=_identity(
            "trace", record.runtime, record.trace_id or record.attempt_id
        ),
        span_id=_identity("span", record.runtime, record.span_id or record.attempt_id),
        request_id=None
        if record.request_id is None
        else _identity("request", record.runtime, record.request_id),
        attempt_id=_identity("attempt", record.runtime, record.attempt_id),
        callsite_id=correlation.callsite_id,
        provider=_safe_provider(record.provider),
        model=_model_digest(record.model),
        sdk_version_digest=_digest("sdk-version", record.runtime, record.sdk_version),
        operation=_safe_operation(record.operation),
        observed_at_unix_nano=start,
        status=record.status,
        duration_microseconds=(end - start) // 1_000,
        input_tokens=None
        if record.input_tokens is None
        else _bounded_capture_int(record.input_tokens, field="input_tokens"),
        output_tokens=None
        if record.output_tokens is None
        else _bounded_capture_int(record.output_tokens, field="output_tokens"),
        request_shape_digest=_digest("capture-request-shape", repr(request_shape)),
        response_shape_digest=_digest("capture-response-shape", repr(response_shape)),
        flags=tuple(sorted(set(record.flags))),
        stream_mode="streaming" if "streaming" in record.flags else "non_streaming",
        tool_call_count=record.tool_call_count,
        structured_output="structured_output" in record.flags,
        retry_count=record.retry_count,
        capture_policy_digest=_digest("capture-policy", record.capture_policy_id),
        redaction_policy_digest=_digest("redaction-policy", record.redaction_policy_id),
        retention_policy_digest=_digest("retention-policy", record.retention_policy_id),
        protected_content_refs=tuple(sorted(record.protected_content_refs)),
        cost_kind=record.cost_kind,
        cost_microusd=record.cost_microusd,
        pricing_source_digest=(
            None
            if record.pricing_source is None
            else _digest("pricing-source", record.pricing_source)
        ),
        pricing_version_digest=(
            None
            if record.pricing_version is None
            else _digest("pricing-version", record.pricing_version)
        ),
        provenance_digest=_digest("provenance", record.provenance),
        correlation=correlation,
        mapping_version=MAPPING_VERSION,
        unmapped_attribute_count=0,
    )


def _bounded_int(value: Any, *, field: str, minimum: int = 0) -> int:
    if isinstance(value, str) and value.isascii() and value.isdecimal():
        value = int(value)
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise EvidenceError(
            "malformed_span", f"{field} must be an integer at least {minimum}"
        )
    if value > 2**64 - 1:
        raise EvidenceError(
            "malformed_span", f"{field} exceeds the OTLP unsigned integer range"
        )
    return value


def _bounded_capture_int(value: Any, *, field: str) -> int:
    try:
        return _bounded_int(value, field=field)
    except EvidenceError as exc:
        raise EvidenceError("malformed_capture", str(exc)) from exc


def _any_value(value: Any, limits: ImportLimits) -> str | int | bool | None:
    if not isinstance(value, dict) or len(value) != 1:
        raise EvidenceError(
            "malformed_span", "OTLP attribute value must contain one typed value"
        )
    kind, item = next(iter(value.items()))
    if kind == "stringValue":
        if (
            not isinstance(item, str)
            or len(item.encode()) > limits.max_attribute_value_bytes
        ):
            raise EvidenceError(
                "attribute_limit_exceeded", "OTLP string attribute exceeds its bound"
            )
        return item
    if kind == "intValue":
        if isinstance(item, str):
            try:
                item = int(item)
            except ValueError as exc:
                raise EvidenceError(
                    "malformed_span", "OTLP integer attribute is invalid"
                ) from exc
        if isinstance(item, bool) or not isinstance(item, int):
            raise EvidenceError("malformed_span", "OTLP integer attribute is invalid")
        return item
    if kind == "boolValue" and isinstance(item, bool):
        return item
    if kind in {"arrayValue", "kvlistValue", "bytesValue", "doubleValue"}:
        return None
    raise EvidenceError(
        "malformed_span", "OTLP attribute uses an unknown value encoding"
    )


def _attributes(
    items: Any, limits: ImportLimits
) -> tuple[dict[str, str | int | bool | None], int, tuple[str, ...]]:
    if items is None:
        return {}, 0, ()
    if not isinstance(items, list) or len(items) > limits.max_attributes_per_span:
        raise EvidenceError(
            "attribute_limit_exceeded", "OTLP span attribute count exceeds its bound"
        )
    mapped: dict[str, str | int | bool | None] = {}
    unknown = 0
    warnings: set[str] = set()
    for item in items:
        if not isinstance(item, dict) or set(item) != {"key", "value"}:
            raise EvidenceError(
                "malformed_span", "OTLP attribute must contain only key and value"
            )
        key = item["key"]
        if (
            not isinstance(key, str)
            or not key
            or len(key.encode()) > limits.max_attribute_key_bytes
        ):
            raise EvidenceError(
                "attribute_limit_exceeded", "OTLP attribute key is invalid or oversized"
            )
        if _protected_key(key):
            warnings.add("protected_attribute_dropped")
            continue
        if key not in _MAPPED_ATTRIBUTES:
            unknown += 1
            warnings.add("unknown_attributes_dropped")
            continue
        if key in mapped:
            raise EvidenceError(
                "malformed_span", "OTLP span contains duplicate mapped attributes"
            )
        mapped[key] = _any_value(item["value"], limits)
    return mapped, unknown, tuple(sorted(warnings))


def _text(attributes: dict[str, Any], key: str, fallback: str) -> str:
    value = attributes.get(key)
    if isinstance(value, str) and 0 < len(value) <= 256:
        return value
    return fallback


def _optional_int(attributes: dict[str, Any], key: str) -> int | None:
    value = attributes.get(key)
    if value is None:
        return None
    return _bounded_int(value, field=key)


def _correlate(
    attributes: dict[str, Any], callsites: tuple[CallsiteCandidate, ...]
) -> Correlation:
    declared = attributes.get("promptectomy.callsite_id")
    if isinstance(declared, str):
        matches = [
            item
            for item in callsites
            if _CALLSITE_ID.fullmatch(item.callsite_id) and item.callsite_id == declared
        ]
        if len(matches) == 1:
            return Correlation(declared, 1.0, "declared_callsite_id")
        return Correlation(None, 0.0, "unmatched")

    path = attributes.get("code.filepath")
    symbol = attributes.get("code.function.name")
    path_matches = [
        item
        for item in callsites
        if isinstance(path, str) and item.relative_path == path
    ]
    symbol_matches = [
        item for item in callsites if isinstance(symbol, str) and item.symbol == symbol
    ]
    both = [item for item in path_matches if item in symbol_matches]
    if len(both) == 1:
        return Correlation(both[0].callsite_id, 0.9, "path_and_symbol")
    if len(both) > 1:
        return Correlation(None, 0.0, "ambiguous")
    if len(path_matches) == 1:
        return Correlation(path_matches[0].callsite_id, 0.6, "path_only")
    if len(path_matches) > 1:
        return Correlation(None, 0.0, "ambiguous")
    if len(symbol_matches) == 1:
        return Correlation(symbol_matches[0].callsite_id, 0.5, "symbol_only")
    if len(symbol_matches) > 1:
        return Correlation(None, 0.0, "ambiguous")
    return Correlation(None, 0.0, "unmatched")


def _status(
    span: dict[str, Any], attributes: dict[str, Any]
) -> Literal["ok", "error", "cancelled", "unknown"]:
    status = span.get("status")
    code = status.get("code") if isinstance(status, dict) else None
    error_type = attributes.get("error.type")
    if isinstance(error_type, str) and "cancel" in error_type.lower():
        return "cancelled"
    if code in {"STATUS_CODE_ERROR", 2} or isinstance(error_type, str):
        return "error"
    if code in {"STATUS_CODE_OK", 1}:
        return "ok"
    return "unknown"


def _shape_digest(attributes: dict[str, Any], prefix: str) -> str:
    keys = sorted(
        key
        for key in attributes
        if key.startswith(prefix) and key in _MAPPED_ATTRIBUTES
    )
    return _digest(MAPPING_VERSION, prefix, *keys)


def _normalize_span(
    span: Any,
    callsites: tuple[CallsiteCandidate, ...],
    limits: ImportLimits,
) -> tuple[NormalizedObservation, tuple[str, ...], str]:
    if not isinstance(span, dict):
        raise EvidenceError("malformed_span", "OTLP span must be an object")
    required = ("traceId", "spanId", "startTimeUnixNano", "endTimeUnixNano")
    if any(field not in span for field in required):
        raise EvidenceError(
            "malformed_span", "OTLP span lacks an identity or timestamp"
        )
    trace_id = span["traceId"]
    span_id = span["spanId"]
    if (
        not isinstance(trace_id, str)
        or not isinstance(span_id, str)
        or not trace_id
        or not span_id
    ):
        raise EvidenceError(
            "malformed_span", "OTLP trace and span identities must be non-empty strings"
        )
    start = _bounded_int(span["startTimeUnixNano"], field="startTimeUnixNano")
    end = _bounded_int(span["endTimeUnixNano"], field="endTimeUnixNano")
    if end < start:
        raise EvidenceError("malformed_span", "OTLP span ends before it starts")
    attributes, unmapped, warnings = _attributes(span.get("attributes"), limits)
    correlation = _correlate(attributes, callsites)
    provider = _safe_provider(_text(attributes, "gen_ai.system", "unknown"))
    raw_model = _text(
        attributes,
        "gen_ai.response.model",
        _text(attributes, "gen_ai.request.model", "unknown"),
    )
    model = _model_digest(raw_model)
    operation = _safe_operation(_text(attributes, "gen_ai.operation.name", "unknown"))
    flags: set[str] = set()
    if attributes.get("openinference.span.kind") == "LLM":
        flags.add("openinference")
    if operation in {"chat", "responses", "execute_tool"}:
        flags.add("genai")
    identity = _digest("otlp-span", trace_id, span_id, str(start))
    observation = NormalizedObservation(
        observation_id=identity,
        trace_id=_identity("trace", trace_id),
        span_id=_identity("span", trace_id, span_id),
        request_id=None,
        attempt_id=_identity("attempt", trace_id, span_id, str(start)),
        callsite_id=correlation.callsite_id,
        provider=provider,
        model=model,
        sdk_version_digest=_digest("sdk-version", "otlp", "unknown"),
        operation=operation,
        observed_at_unix_nano=start,
        status=_status(span, attributes),
        duration_microseconds=(end - start) // 1_000,
        input_tokens=_optional_int(attributes, "gen_ai.usage.input_tokens"),
        output_tokens=_optional_int(attributes, "gen_ai.usage.output_tokens"),
        request_shape_digest=_shape_digest(attributes, "gen_ai.request."),
        response_shape_digest=_shape_digest(attributes, "gen_ai.response."),
        flags=tuple(sorted(flags)),
        stream_mode="unknown",
        tool_call_count=None,
        structured_output=None,
        retry_count=None,
        capture_policy_digest=_digest("capture-policy", "otlp-import-v1"),
        redaction_policy_digest=_digest("redaction-policy", "otlp-content-drop-v1"),
        retention_policy_digest=_digest("retention-policy", "local-import-v1"),
        protected_content_refs=(),
        cost_kind="unknown",
        cost_microusd=None,
        pricing_source_digest=None,
        pricing_version_digest=None,
        provenance_digest=_digest("provenance", "otlp", MAPPING_VERSION),
        correlation=correlation,
        mapping_version=MAPPING_VERSION,
        unmapped_attribute_count=unmapped,
    )
    return observation, warnings, identity


def _spans(document: Any) -> list[Any]:
    if not isinstance(document, dict) or set(document) - {
        "resourceSpans",
        "partialSuccess",
    }:
        raise EvidenceError("malformed_otlp", "OTLP JSON root is unsupported")
    resources = document.get("resourceSpans")
    if not isinstance(resources, list):
        raise EvidenceError(
            "malformed_otlp", "OTLP JSON resourceSpans must be an array"
        )
    spans: list[Any] = []
    for resource in resources:
        if not isinstance(resource, dict):
            raise EvidenceError(
                "malformed_otlp", "OTLP resource span must be an object"
            )
        scopes = resource.get("scopeSpans", [])
        if not isinstance(scopes, list):
            raise EvidenceError("malformed_otlp", "OTLP scopeSpans must be an array")
        for scope in scopes:
            if not isinstance(scope, dict) or not isinstance(
                scope.get("spans", []), list
            ):
                raise EvidenceError(
                    "malformed_otlp", "OTLP scope span must contain a spans array"
                )
            spans.extend(scope.get("spans", []))
    return spans


def import_otlp_http_json(
    payload: bytes,
    *,
    callsites: tuple[CallsiteCandidate, ...] = (),
    limits: ImportLimits = ImportLimits(),
) -> ImportReport:
    if len(payload) > limits.max_payload_bytes:
        raise EvidenceError(
            "payload_limit_exceeded", "OTLP payload exceeds its byte bound"
        )
    try:
        document = parse_json_strict(payload)
    except ContractError as exc:
        raise EvidenceError(
            "malformed_otlp", "OTLP payload is not strict JSON"
        ) from exc
    spans = _spans(document)
    if len(spans) > limits.max_spans:
        raise EvidenceError(
            "backpressure_limit_exceeded", "OTLP span count exceeds the admission bound"
        )

    accepted: list[NormalizedObservation] = []
    seen: set[str] = set()
    duplicate_count = 0
    rejected_count = 0
    warnings: set[str] = set()
    previous_start = -1
    input_out_of_order = False
    for span in spans:
        try:
            observation, span_warnings, identity = _normalize_span(
                span, callsites, limits
            )
        except EvidenceError:
            rejected_count += 1
            continue
        if identity in seen:
            duplicate_count += 1
            continue
        seen.add(identity)
        if observation.observed_at_unix_nano < previous_start:
            input_out_of_order = True
        previous_start = observation.observed_at_unix_nano
        accepted.append(observation)
        warnings.update(span_warnings)
    if spans and not accepted and rejected_count:
        raise EvidenceError(
            "all_spans_rejected", "No OTLP span passed the bounded mapping contract"
        )
    accepted.sort(key=lambda item: (item.observed_at_unix_nano, item.observation_id))
    partial_success = isinstance(document, dict) and bool(
        document.get("partialSuccess")
    )
    partial = rejected_count > 0 or partial_success
    if rejected_count:
        warnings.add("malformed_spans_rejected")
    if duplicate_count:
        warnings.add("duplicate_spans_dropped")
    if input_out_of_order:
        warnings.add("input_out_of_order")
    if partial_success:
        warnings.add("upstream_partial_success")
    return ImportReport(
        observations=tuple(accepted),
        duplicate_count=duplicate_count,
        rejected_count=rejected_count,
        input_out_of_order=input_out_of_order,
        partial=partial,
        warnings=tuple(sorted(warnings)),
    )


def import_otlp_grpc(
    payload: bytes,
    *,
    callsites: tuple[CallsiteCandidate, ...] = (),
    limits: ImportLimits = ImportLimits(),
) -> ImportReport:
    if len(payload) > limits.max_payload_bytes:
        raise EvidenceError(
            "payload_limit_exceeded", "OTLP payload exceeds its byte bound"
        )
    request = ExportTraceServiceRequest()
    try:
        request.ParseFromString(payload)
    except DecodeError as exc:
        raise EvidenceError(
            "malformed_otlp", "OTLP gRPC payload is not an ExportTraceServiceRequest"
        ) from exc
    known_fields = ExportTraceServiceRequest()
    known_fields.CopyFrom(request)
    known_fields.DiscardUnknownFields()
    if known_fields.SerializeToString(deterministic=True) != request.SerializeToString(
        deterministic=True
    ):
        raise EvidenceError(
            "unknown_otlp_fields",
            "OTLP gRPC payload contains unsupported unknown fields",
        )
    document = MessageToDict(request, preserving_proto_field_name=False)
    encoded = json.dumps(document, separators=(",", ":")).encode()
    return import_otlp_http_json(encoded, callsites=callsites, limits=limits)
