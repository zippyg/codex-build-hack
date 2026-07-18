"""Frozen contracts for PROMPTECTOMY. Do not change without the integrator (main owner).

These Pydantic models are the single source of truth for:
  - the JSONL ledger of recorded LLM calls (LedgerEventV1),
  - the callsite audit that Codex emits under --output-schema (AuditReport),
  - the per-callsite Verdict the PARENT verifier emits (never Codex),
  - the PipelineEvent stream written to NDJSON and consumed by the dashboard.

The PipelineEvent JSON shape is mirrored exactly in ui/lib/contracts.ts (Zod). Same wire shape,
two validators. The engine emits PipelineEvents; the Next route validates and forwards them.
"""

from __future__ import annotations

from typing import Annotated, Literal, Union

from pydantic import BaseModel, ConfigDict, Field, JsonValue


class Closed(BaseModel):
    model_config = ConfigDict(extra="forbid")


# --- Ledger (recording of real LLM calls; internal to the engine) ---------------------

CallKind = Literal["structured", "classifier", "freeform"]
CostSource = Literal["llm", "compiled"]


class Usage(Closed):
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0


class LedgerEventV1(Closed):
    schema_version: Literal["1"] = "1"
    event_id: str
    recorded_at: str
    repo_sha: str
    callsite_id: str
    mode: Literal["original", "compiled", "shadow"] = "original"
    api: Literal["responses.create", "chat.completions.create"] = "responses.create"
    model: str
    # Never record Authorization, API keys, env, or raw headers.
    request_input: JsonValue
    request_params: dict[str, JsonValue] = Field(default_factory=dict)
    response_raw: JsonValue | None = None
    response_normalized: JsonValue | None = None
    usage: Usage = Field(default_factory=Usage)
    latency_ms: float = Field(ge=0)
    estimated_cost_usd: float | None = Field(default=None, ge=0)
    status: Literal["ok", "error"] = "ok"


# --- Callsite audit (Codex emits under --output-schema; verdict is NOT decided here) ---


class AuditSample(Closed):
    # str, not JsonValue: these are display previews, and OpenAI strict --output-schema rejects
    # a field with no concrete type (JsonValue), which silently forced the scanner onto its fallback.
    event_id: str
    input_preview: str = ""
    output_preview: str = ""


class CallsiteAudit(Closed):
    callsite_id: str
    file: str
    line: int = Field(ge=1)
    symbol: str = ""
    kind: CallKind  # structured | classifier | freeform (UI-facing simplification)
    eligibility: Literal["candidate", "keep_model", "unsupported"]
    sample_count: int = Field(ge=0)
    confidence: float = Field(ge=0, le=1, default=0.5)
    reason: str = ""
    samples: list[AuditSample] = Field(default_factory=list, max_length=3)


class AuditReport(Closed):
    schema_version: Literal["1"] = "1"
    repo_path: str
    repo_sha: str
    callsites: list[CallsiteAudit]


# --- Verdict (the PARENT verifier emits this after the sealed holdout; Codex never does) ---

VerdictStatus = Literal["COMPILED", "COMPILED_WITH_DIFFS", "NOT_COMPILABLE", "ERROR"]


class Diff(Closed):
    event_id: str = ""
    input: JsonValue
    expected: JsonValue
    got: JsonValue
    summary: str = ""


class Verdict(Closed):
    schema_version: Literal["1"] = "1"
    callsite_id: str
    status: VerdictStatus
    reason: str = ""
    agreement: float | None = Field(default=None, ge=0, le=1)
    holdout_n: int = Field(ge=0, default=0)
    diffs: list[Diff] = Field(default_factory=list)
    module_path: str | None = None
    median_latency_ms: float | None = None


# --- PipelineEvent stream (NDJSON; consumed by the dashboard). Mirror of contracts.ts ---


class ScanEvent(Closed):
    type: Literal["scan"] = "scan"
    audit: list[CallsiteAudit]
    recorded_calls: int


class TrafficEvent(Closed):
    type: Literal["traffic"] = "traffic"
    callsite_id: str
    latency_ms: float
    cost_usd: float
    source: CostSource


class CallsiteStatusEvent(Closed):
    type: Literal["callsiteStatus"] = "callsiteStatus"
    callsite_id: str
    status: Literal["queued", "synthesizing", "replaying", "iterating", "done"]
    round: int | None = None


class SynthTokenEvent(Closed):
    type: Literal["synthToken"] = "synthToken"
    callsite_id: str
    text: str
    kind: Literal["reasoning", "code", "tool"] | None = None


class ReplayEvent(Closed):
    type: Literal["replay"] = "replay"
    callsite_id: str
    passed: int
    total: int


class VerdictEvent(Closed):
    type: Literal["verdict"] = "verdict"
    verdict: Verdict


class SwapSample(Closed):
    input: JsonValue
    llm_output: JsonValue
    compiled_output: JsonValue


class SwapEvent(Closed):
    type: Literal["swap"] = "swap"
    callsite_id: str
    before_ms: float
    after_ms: float
    before_cost: float
    samples: list[SwapSample] = Field(default_factory=list)


class DoneTotals(Closed):
    callsites: int
    compiled: int
    kept: int
    est_monthly_savings_usd: float
    pipeline_cost_reduction_pct: float


class DoneEvent(Closed):
    type: Literal["done"] = "done"
    totals: DoneTotals


PipelineEvent = Annotated[
    Union[
        ScanEvent,
        TrafficEvent,
        CallsiteStatusEvent,
        SynthTokenEvent,
        ReplayEvent,
        VerdictEvent,
        SwapEvent,
        DoneEvent,
    ],
    Field(discriminator="type"),
]
