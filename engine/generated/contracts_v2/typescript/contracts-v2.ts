export const SCHEMA_SHA256 = "d3ff401e7d27ba7e19eeca6c7afdc2a430515e6a7541d5ccd290d866f096284c" as const;

export interface Repository {
  "schema_uri": "https://promptectomy.invalid/schemas/v2/repository.schema.json";
  "schema_version": string;
  "repository_id": string;
  "source_kind": "local" | "https_git" | "ssh_git" | "archive" | "bundle";
  "display_name": string;
  "redacted_locator": string;
  "canonical_origin_digest"?: string;
  "created_at": string;
}

export interface Snapshot {
  "schema_uri": "https://promptectomy.invalid/schemas/v2/snapshot.schema.json";
  "schema_version": string;
  "snapshot_id": string;
  "repository_id": string;
  "revision": string;
  "dirty_diff_digest"?: string;
  "tree_digest": string;
  "selected_roots": Array<string>;
  "exclusions": Array<string>;
  "policy_digest": string;
  "inventory": Record<string, unknown>;
  "quota_outcome": "within_limit" | "truncated" | "rejected";
  "created_at": string;
}

export interface Authority {
  "schema_uri": "https://promptectomy.invalid/schemas/v2/authority.schema.json";
  "schema_version": string;
  "authority_id": string;
  "subject_id": string;
  "mode": "inspect" | "audit" | "draft" | "apply" | "integrate";
  "manifest": Record<string, unknown>;
  "manifest_digest": string;
  "approved_at": string;
  "expires_at"?: string;
  "approval_origin": string;
  "revoked": boolean;
}

export interface Run {
  "schema_uri": "https://promptectomy.invalid/schemas/v2/run.schema.json";
  "schema_version": string;
  "run_id": string;
  "snapshot_id": string;
  "authority_ids": Array<string>;
  "mode": "inspect" | "audit" | "draft" | "apply" | "integrate";
  "status": "created" | "preflight" | "awaiting_authority" | "queued" | "running" | "pausing" | "paused" | "cancelling" | "completed" | "completed_no_findings" | "completed_with_unsupported" | "failed" | "cancelled" | "interrupted";
  "highest_support_level": "L0" | "L1" | "L2" | "L3" | "L4" | "L5";
  "digests": Record<string, string>;
  "counters": Record<string, number>;
  "budgets": Record<string, number>;
  "cleanup_state": "not_required" | "pending" | "running" | "completed" | "failed";
  "created_at": string;
  "started_at"?: string;
  "terminal_at"?: string;
  "last_sequence": number;
}

export interface Stage {
  "schema_uri": "https://promptectomy.invalid/schemas/v2/stage.schema.json";
  "schema_version": string;
  "stage_id": string;
  "run_id": string;
  "kind": string;
  "state": "created" | "awaiting_authority" | "queued" | "running" | "pausing" | "paused" | "cancelling" | "cancelled" | "completed" | "failed" | "interrupted";
  "attempt": number;
  "max_attempts": number;
  "retryable": boolean;
  "lease"?: Record<string, string> | null;
  "input_artifact_refs": string[];
  "output_artifact_refs": string[];
  "error_id"?: string | null;
  "timing": Record<string, number>;
  "resources": Record<string, number>;
}

export interface Event {
  "schema_uri": "https://promptectomy.invalid/schemas/v2/event.schema.json";
  "schema_version": string;
  "event_id": string;
  "run_id": string;
  "sequence": number;
  "occurred_at": string;
  "type": string;
  "payload_schema": string;
  "payload_version": string;
  "payload": Record<string, string>;
  "artifact_refs": string[];
}

export interface Callsite {
  "schema_uri": "https://promptectomy.invalid/schemas/v2/callsite.schema.json";
  "schema_version": string;
  "callsite_id": string;
  "snapshot_id": string;
  "language": string;
  "provider": string;
  "operation": string;
  "sdk_surface": string;
  "adapter_version": string;
  "relative_path": string;
  "symbol": string;
  "ast_digest": string;
  "source_range": Record<string, unknown>;
  "support_level": "L0" | "L1" | "L2" | "L3" | "L4" | "L5";
  "support_state": "stable" | "experimental" | "unsupported";
  "evidence": Array<string>;
  "confidence": string;
  "coverage": Record<string, string>;
}

export interface Observation {
  "schema_uri": "https://promptectomy.invalid/schemas/v2/observation.schema.json";
  "schema_version": string;
  "observation_id": string;
  "callsite_id": string;
  "adapter": string;
  "adapter_version": string;
  "provider": string;
  "model": string;
  "operation": string;
  "observed_at": string;
  "request_shape_digest": string;
  "response_shape_digest": string;
  "protected_artifact_refs"?: string[];
  "status": "completed" | "failed" | "cancelled" | "unknown";
  "flags": Array<"streaming" | "tools" | "structured" | "retry" | "error" | "cancelled">;
  "duration_microseconds": number;
  "usage": Record<string, number>;
  "cost": Record<string, unknown>;
  "correlation": Record<string, unknown>;
  "policy_digests": Record<string, string>;
}

export interface Finding {
  "schema_uri": "https://promptectomy.invalid/schemas/v2/finding.schema.json";
  "schema_version": string;
  "finding_id": string;
  "run_id": string;
  "callsite_id": string;
  "category": string;
  "severity": "info" | "low" | "medium" | "high" | "critical";
  "opportunity_type": string;
  "support_level": "L0" | "L1" | "L2" | "L3" | "L4" | "L5";
  "evidence_grade": "insufficient" | "static" | "observed" | "evaluated" | "verified";
  "rationale": Record<string, string>;
  "uncertainty": Array<string>;
  "required_evidence": Array<string>;
  "limitations": Array<string>;
  "input_artifact_refs": string[];
  "producer_digests": Record<string, string>;
}

export interface Candidate {
  "schema_uri": "https://promptectomy.invalid/schemas/v2/candidate.schema.json";
  "schema_version": string;
  "candidate_id": string;
  "finding_id": string;
  "snapshot_id": string;
  "candidate_class": string;
  "target_interface": string;
  "producer_digests": Record<string, string>;
  "patch_artifact_ref": string;
  "test_artifact_refs": string[];
  "dependency_artifact_refs": string[];
  "state": "proposed" | "unverified" | "evaluating" | "eligible" | "ineligible" | "failed" | "superseded";
  "attempt": number;
  "budgets": Record<string, number>;
  "nondeterminism": Array<string>;
}

export interface Evaluation {
  "schema_uri": "https://promptectomy.invalid/schemas/v2/evaluation.schema.json";
  "schema_version": string;
  "evaluation_id": string;
  "candidate_id": string;
  "evaluator_digests": Record<string, string>;
  "evidence": Record<string, string>;
  "runtime_digests": Record<string, string>;
  "results": Record<string, string>;
  "termination": Record<string, string>;
  "resources": Record<string, number>;
  "timing": Record<string, number>;
  "eligible": boolean;
  "policy_digest": string;
  "limitations": Array<string>;
  "artifact_refs": string[];
  "error_id"?: string | null;
}

export interface Patch {
  "schema_uri": "https://promptectomy.invalid/schemas/v2/patch.schema.json";
  "schema_version": string;
  "patch_id": string;
  "candidate_id": string;
  "base_snapshot_id": string;
  "base_revision": string;
  "media_type": string;
  "artifact_ref": string;
  "affected_paths": Array<string>;
  "change_summary": Record<string, string>;
  "preconditions": Array<string>;
  "approved_checks": Array<string>;
  "destination_branch_policy": string;
}

export interface Artifact {
  "schema_uri": "https://promptectomy.invalid/schemas/v2/artifact.schema.json";
  "schema_version": string;
  "artifact_id": string;
  "byte_count": number;
  "media_type": string;
  "class": "safe" | "source" | "protected" | "diagnostic" | "executable";
  "created_by": string;
  "policy_digest": string;
  "retention": Record<string, string>;
  "encryption"?: Record<string, string> | null;
  "complete": true;
  "quarantined": false;
  "pinned": boolean;
  "references": Array<string>;
}

export interface Receipt {
  "schema_uri": "https://promptectomy.invalid/schemas/v2/receipt.schema.json";
  "schema_version": string;
  "receipt_id": string;
  "receipt_kind": string;
  "policy_version": string;
  "bindings": Record<string, string>;
  "evidence_grade": "insufficient" | "static" | "observed" | "evaluated" | "verified";
  "support_level": "L0" | "L1" | "L2" | "L3" | "L4" | "L5";
  "limitations": Array<string>;
  "resources": Record<string, number>;
  "timestamps": Record<string, string>;
  "canonicalization": "rfc8785";
  "digest_algorithm": "sha256";
  "trusted_core_version": string;
  "nondeterministic_fields": Array<string>;
}

export interface Error {
  "schema_uri": "https://promptectomy.invalid/schemas/v2/error.schema.json";
  "schema_version": string;
  "error_id": string;
  "code": string;
  "category": "input" | "unsupported" | "policy" | "acquisition" | "adapter" | "agent" | "executor" | "candidate" | "evaluator" | "state" | "storage" | "apply" | "cancel" | "internal";
  "retryable": boolean;
  "safe_message": string;
  "next_action": string;
  "stage_id": string | null;
  "entity_refs": Array<string>;
  "diagnostic_artifact_ref": string | null;
}
