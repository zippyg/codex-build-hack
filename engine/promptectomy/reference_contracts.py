from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints


RunMode = Literal["inspect", "audit", "draft"]
SafeText = Annotated[str, StringConstraints(min_length=1, max_length=4_000)]
TerminalStatus = Literal[
    "completed",
    "completed_no_findings",
    "completed_with_unsupported",
    "failed",
    "cancelled",
    "interrupted",
]


class Closed(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SafeError(Closed):
    code: str
    category: Literal["input", "unsupported", "policy", "agent", "cancel", "state", "internal"]
    retryable: bool
    safe_message: str
    next_action: str


class UnsupportedArea(Closed):
    code: str
    entity_ref: str
    adapter: str
    highest_level: Literal["L0", "L1"]
    retryable: bool = False
    next_action: str


class WorkSummary(Closed):
    performed: int = Field(ge=0)
    skipped: int = Field(ge=0)
    unsupported: int = Field(ge=0)
    zero_work: bool
    steps: list[str]


class SupportSummary(Closed):
    highest_level: Literal["L0", "L1"]
    languages: dict[str, int]
    callsites: int = Field(ge=0)
    supported_callsites: int = Field(ge=0)
    unsupported_areas: int = Field(ge=0)
    excluded_entries: int = Field(ge=0)
    feature_coverage: dict[str, int] = Field(default_factory=dict)


class Callsite(Closed):
    callsite_id: str
    path_ref: str
    line: int = Field(ge=1)
    language: Literal["python", "typescript", "javascript"]
    provider: Literal["openai"] = "openai"
    operation: Literal["responses.create", "responses.parse"] = "responses.create"
    support_level: Literal["L1"] = "L1"
    stability: Literal["reference", "stable"] = "reference"
    adapter_version: str = "phase1a-static-1"
    normalized_ast_digest: str = Field(default="sha256:" + "0" * 64, pattern=r"^sha256:[0-9a-f]{64}$")
    ast_ordinal: int = Field(default=0, ge=0)
    enclosing_symbol_ref: str = "symbol_legacy"
    discovery_confidence: Literal["deterministic"] = "deterministic"
    features: list[str]


class Finding(Closed):
    finding_id: str
    callsite_id: str
    category: Literal["candidate_analysis_required"] = "candidate_analysis_required"
    evidence_grade: Literal["insufficient"] = "insufficient"
    rationale: str
    limitations: list[str]


class AuthoritySummary(Closed):
    manifest_digest: str
    reads: list[str]
    writes: list[str]
    executes: list[str]
    destinations: list[str]
    environment_names: list[str]


class CandidateSummary(Closed):
    candidate_id: str
    state: Literal["unverified"] = "unverified"
    patch_artifact: str
    tests_artifact: str
    affected_path_refs: list[str]
    evidence_grade: Literal["insufficient"] = "insufficient"
    limitations: list[str]


class ConnectorRecord(Closed):
    configured_model: str = Field(pattern=r"^gpt-[A-Za-z0-9.-]*codex[A-Za-z0-9.-]*$")
    returned_model: str = Field(pattern=r"^gpt-[A-Za-z0-9.-]*codex[A-Za-z0-9.-]*$")
    reasoning_effort: str
    endpoint_class: Literal["openai_responses"] = "openai_responses"
    prompt_digest: str
    schema_digest: str
    content_manifest_digest: str
    response_id: str = Field(pattern=r"^resp_[A-Za-z0-9_-]{1,200}$")
    input_tokens: int = Field(ge=0, le=1_000_000_000)
    output_tokens: int = Field(ge=0, le=1_000_000_000)
    total_tokens: int = Field(ge=0, le=1_000_000_000)
    max_output_tokens: int = Field(ge=1)


class RetentionSummary(Closed):
    safe_artifacts_days: int = Field(ge=0)
    source_snapshot: Literal["deleted_at_terminal"] = "deleted_at_terminal"
    external_copies: Literal["provider_policy_applies", "none"]


class CleanupSummary(Closed):
    status: Literal["completed", "failed", "not_required"]
    source_snapshot_removed: bool


class ReceiptSummary(Closed):
    receipt_id: str
    semantics: Literal["digest_bound_local_consistency"] = "digest_bound_local_consistency"
    canonicalization: Literal["sorted_compact_json"] = "sorted_compact_json"
    algorithm: Literal["sha256"] = "sha256"


class RunResult(Closed):
    schema_version: Literal["phase1a-1"] = "phase1a-1"
    run_id: str
    mode: RunMode
    status: TerminalStatus
    source_id: str
    snapshot_digest: str
    authority: AuthoritySummary
    work: WorkSummary
    support: SupportSummary
    callsites: list[Callsite]
    findings: list[Finding]
    unsupported: list[UnsupportedArea]
    candidate: CandidateSummary | None = None
    connector: ConnectorRecord | None = None
    error: SafeError | None = None
    retention: RetentionSummary
    cleanup: CleanupSummary
    receipt: ReceiptSummary | None = None
    report_artifacts: dict[str, str] = Field(default_factory=dict)


class DraftSlice(Closed):
    path: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class DraftPolicy(Closed):
    schema_version: Literal["1"] = "1"
    operation: Literal["draft"] = "draft"
    approved: Literal[True]
    source_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    destination: Literal["https://api.openai.com/v1/responses"]
    model: str = Field(pattern=r"^gpt-[A-Za-z0-9.-]*codex[A-Za-z0-9.-]*$", min_length=1, max_length=128)
    reasoning_effort: Literal["low", "medium", "high"] = "medium"
    max_input_bytes: int = Field(ge=1, le=1_000_000)
    max_output_tokens: int = Field(ge=1, le=20_000)
    timeout_seconds: int = Field(ge=1, le=300)
    retention_days: int = Field(ge=0, le=365)
    slices: list[DraftSlice] = Field(min_length=1, max_length=32)


class CandidateProposal(Closed):
    schema_version: Literal["1"] = "1"
    patch: str = Field(min_length=1, max_length=1_000_000)
    affected_paths: list[str] = Field(min_length=1, max_length=64)
    proposed_tests: list[SafeText] = Field(min_length=1, max_length=64)
    rationale: SafeText
    evidence: list[SafeText] = Field(min_length=1, max_length=64)
    limitations: list[SafeText] = Field(min_length=1, max_length=64)
