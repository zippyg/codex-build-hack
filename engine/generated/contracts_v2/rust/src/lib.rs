use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub const SCHEMA_SHA256: &str = "d3ff401e7d27ba7e19eeca6c7afdc2a430515e6a7541d5ccd290d866f096284c";

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Repository {
    pub schema_uri: String,
    pub schema_version: String,
    pub repository_id: String,
    pub source_kind: String,
    pub display_name: String,
    pub redacted_locator: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonical_origin_digest: Option<String>,
    pub created_at: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub schema_uri: String,
    pub schema_version: String,
    pub snapshot_id: String,
    pub repository_id: String,
    pub revision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dirty_diff_digest: Option<String>,
    pub tree_digest: String,
    pub selected_roots: Vec<String>,
    pub exclusions: Vec<String>,
    pub policy_digest: String,
    pub inventory: BTreeMap<String, Value>,
    pub quota_outcome: String,
    pub created_at: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Authority {
    pub schema_uri: String,
    pub schema_version: String,
    pub authority_id: String,
    pub subject_id: String,
    pub mode: String,
    pub manifest: BTreeMap<String, Value>,
    pub manifest_digest: String,
    pub approved_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    pub approval_origin: String,
    pub revoked: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Run {
    pub schema_uri: String,
    pub schema_version: String,
    pub run_id: String,
    pub snapshot_id: String,
    pub authority_ids: Vec<String>,
    pub mode: String,
    pub status: String,
    pub highest_support_level: String,
    pub digests: BTreeMap<String, String>,
    pub counters: BTreeMap<String, u64>,
    pub budgets: BTreeMap<String, u64>,
    pub cleanup_state: String,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_at: Option<String>,
    pub last_sequence: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Stage {
    pub schema_uri: String,
    pub schema_version: String,
    pub stage_id: String,
    pub run_id: String,
    pub kind: String,
    pub state: String,
    pub attempt: u64,
    pub max_attempts: u64,
    pub retryable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease: Option<BTreeMap<String, String>>,
    pub input_artifact_refs: Vec<String>,
    pub output_artifact_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_id: Option<String>,
    pub timing: BTreeMap<String, u64>,
    pub resources: BTreeMap<String, u64>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub schema_uri: String,
    pub schema_version: String,
    pub event_id: String,
    pub run_id: String,
    pub sequence: u64,
    pub occurred_at: String,
    #[serde(rename = "type")]
    pub r#type: String,
    pub payload_schema: String,
    pub payload_version: String,
    pub payload: BTreeMap<String, String>,
    pub artifact_refs: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Callsite {
    pub schema_uri: String,
    pub schema_version: String,
    pub callsite_id: String,
    pub snapshot_id: String,
    pub language: String,
    pub provider: String,
    pub operation: String,
    pub sdk_surface: String,
    pub adapter_version: String,
    pub relative_path: String,
    pub symbol: String,
    pub ast_digest: String,
    pub source_range: BTreeMap<String, Value>,
    pub support_level: String,
    pub support_state: String,
    pub evidence: Vec<String>,
    pub confidence: String,
    pub coverage: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub schema_uri: String,
    pub schema_version: String,
    pub observation_id: String,
    pub callsite_id: String,
    pub adapter: String,
    pub adapter_version: String,
    pub provider: String,
    pub model: String,
    pub operation: String,
    pub observed_at: String,
    pub request_shape_digest: String,
    pub response_shape_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protected_artifact_refs: Option<Vec<String>>,
    pub status: String,
    pub flags: Vec<String>,
    pub duration_microseconds: u64,
    pub usage: BTreeMap<String, u64>,
    pub cost: BTreeMap<String, Value>,
    pub correlation: BTreeMap<String, Value>,
    pub policy_digests: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub schema_uri: String,
    pub schema_version: String,
    pub finding_id: String,
    pub run_id: String,
    pub callsite_id: String,
    pub category: String,
    pub severity: String,
    pub opportunity_type: String,
    pub support_level: String,
    pub evidence_grade: String,
    pub rationale: BTreeMap<String, String>,
    pub uncertainty: Vec<String>,
    pub required_evidence: Vec<String>,
    pub limitations: Vec<String>,
    pub input_artifact_refs: Vec<String>,
    pub producer_digests: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Candidate {
    pub schema_uri: String,
    pub schema_version: String,
    pub candidate_id: String,
    pub finding_id: String,
    pub snapshot_id: String,
    pub candidate_class: String,
    pub target_interface: String,
    pub producer_digests: BTreeMap<String, String>,
    pub patch_artifact_ref: String,
    pub test_artifact_refs: Vec<String>,
    pub dependency_artifact_refs: Vec<String>,
    pub state: String,
    pub attempt: u64,
    pub budgets: BTreeMap<String, u64>,
    pub nondeterminism: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Evaluation {
    pub schema_uri: String,
    pub schema_version: String,
    pub evaluation_id: String,
    pub candidate_id: String,
    pub evaluator_digests: BTreeMap<String, String>,
    pub evidence: BTreeMap<String, String>,
    pub runtime_digests: BTreeMap<String, String>,
    pub results: BTreeMap<String, String>,
    pub termination: BTreeMap<String, String>,
    pub resources: BTreeMap<String, u64>,
    pub timing: BTreeMap<String, u64>,
    pub eligible: bool,
    pub policy_digest: String,
    pub limitations: Vec<String>,
    pub artifact_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Patch {
    pub schema_uri: String,
    pub schema_version: String,
    pub patch_id: String,
    pub candidate_id: String,
    pub base_snapshot_id: String,
    pub base_revision: String,
    pub media_type: String,
    pub artifact_ref: String,
    pub affected_paths: Vec<String>,
    pub change_summary: BTreeMap<String, String>,
    pub preconditions: Vec<String>,
    pub approved_checks: Vec<String>,
    pub destination_branch_policy: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub schema_uri: String,
    pub schema_version: String,
    pub artifact_id: String,
    pub byte_count: u64,
    pub media_type: String,
    #[serde(rename = "class")]
    pub r#class: String,
    pub created_by: String,
    pub policy_digest: String,
    pub retention: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption: Option<BTreeMap<String, String>>,
    pub complete: String,
    pub quarantined: String,
    pub pinned: bool,
    pub references: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub schema_uri: String,
    pub schema_version: String,
    pub receipt_id: String,
    pub receipt_kind: String,
    pub policy_version: String,
    pub bindings: BTreeMap<String, String>,
    pub evidence_grade: String,
    pub support_level: String,
    pub limitations: Vec<String>,
    pub resources: BTreeMap<String, u64>,
    pub timestamps: BTreeMap<String, String>,
    pub canonicalization: String,
    pub digest_algorithm: String,
    pub trusted_core_version: String,
    pub nondeterministic_fields: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Error {
    pub schema_uri: String,
    pub schema_version: String,
    pub error_id: String,
    pub code: String,
    pub category: String,
    pub retryable: bool,
    pub safe_message: String,
    pub next_action: String,
    pub stage_id: Option<String>,
    pub entity_refs: Vec<String>,
    pub diagnostic_artifact_ref: Option<String>,
}
