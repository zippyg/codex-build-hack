use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

use promptectomy_contracts::{
    MAX_SAFE_JSON_BYTES, SCHEMA_BASE, SCHEMA_VERSION, artifact_id, canonical_json,
    parse_strict_json, receipt_id, validate_contract, validate_relative_path,
};
use rusqlite::{Connection, OpenFlags, OptionalExtension, config::DbConfig, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use thiserror::Error;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use time::macros::format_description;
use uuid::{Uuid, Variant};

const CURRENT_SCHEMA: u32 = 5;
const MAX_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_EVENT_LIMIT: u64 = 1_000;
const MINIMUM_SQLITE: (u64, u64, u64) = (3, 51, 3);

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityMode {
    Inspect,
    Audit,
    Draft,
    Apply,
    Integrate,
}

impl AuthorityMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Inspect => "inspect",
            Self::Audit => "audit",
            Self::Draft => "draft",
            Self::Apply => "apply",
            Self::Integrate => "integrate",
        }
    }

    fn permits_ceiling(self, action: AuthorityAction) -> bool {
        match self {
            Self::Inspect => matches!(
                action,
                AuthorityAction::ReadSource | AuthorityAction::WriteState
            ),
            Self::Audit => matches!(
                action,
                AuthorityAction::ReadSource
                    | AuthorityAction::WriteState
                    | AuthorityAction::ReadSafeArtifacts
            ),
            Self::Draft => matches!(
                action,
                AuthorityAction::ReadSource
                    | AuthorityAction::WriteState
                    | AuthorityAction::ReadSafeArtifacts
                    | AuthorityAction::WriteCandidateArtifacts
            ),
            Self::Apply | Self::Integrate => false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityAction {
    ReadSource,
    WriteState,
    ReadSafeArtifacts,
    WriteCandidateArtifacts,
    ExternalModelEgress,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Created,
    Preflight,
    AwaitingAuthority,
    Queued,
    Running,
    Pausing,
    Paused,
    Cancelling,
    Completed,
    CompletedNoFindings,
    CompletedWithUnsupported,
    Failed,
    Cancelled,
    Interrupted,
}

impl RunStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Preflight => "preflight",
            Self::AwaitingAuthority => "awaiting_authority",
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Pausing => "pausing",
            Self::Paused => "paused",
            Self::Cancelling => "cancelling",
            Self::Completed => "completed",
            Self::CompletedNoFindings => "completed_no_findings",
            Self::CompletedWithUnsupported => "completed_with_unsupported",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Interrupted => "interrupted",
        }
    }

    fn parse(value: &str) -> Result<Self, CoreError> {
        match value {
            "created" => Ok(Self::Created),
            "preflight" => Ok(Self::Preflight),
            "awaiting_authority" => Ok(Self::AwaitingAuthority),
            "queued" => Ok(Self::Queued),
            "running" => Ok(Self::Running),
            "pausing" => Ok(Self::Pausing),
            "paused" => Ok(Self::Paused),
            "cancelling" => Ok(Self::Cancelling),
            "completed" => Ok(Self::Completed),
            "completed_no_findings" => Ok(Self::CompletedNoFindings),
            "completed_with_unsupported" => Ok(Self::CompletedWithUnsupported),
            "failed" => Ok(Self::Failed),
            "cancelled" => Ok(Self::Cancelled),
            "interrupted" => Ok(Self::Interrupted),
            _ => Err(CoreError::safe("state_corrupt")),
        }
    }

    fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed
                | Self::CompletedNoFindings
                | Self::CompletedWithUnsupported
                | Self::Failed
                | Self::Cancelled
                | Self::Interrupted
        )
    }

    fn can_transition(self, next: Self) -> bool {
        matches!(
            (self, next),
            (
                Self::Created,
                Self::Preflight | Self::Queued | Self::Running | Self::Cancelled | Self::Failed
            ) | (
                Self::Preflight,
                Self::AwaitingAuthority | Self::Queued | Self::Cancelled | Self::Failed
            ) | (
                Self::AwaitingAuthority | Self::Interrupted,
                Self::Queued | Self::Cancelled | Self::Failed
            ) | (
                Self::Queued,
                Self::Running | Self::Cancelled | Self::Failed | Self::Interrupted
            ) | (
                Self::Running,
                Self::Pausing
                    | Self::Cancelling
                    | Self::Completed
                    | Self::CompletedNoFindings
                    | Self::CompletedWithUnsupported
                    | Self::Failed
                    | Self::Cancelled
                    | Self::Interrupted
            ) | (
                Self::Pausing,
                Self::Paused | Self::Cancelling | Self::Failed | Self::Interrupted
            ) | (
                Self::Paused,
                Self::Running | Self::Cancelling | Self::Cancelled | Self::Interrupted
            ) | (
                Self::Cancelling,
                Self::Cancelled | Self::Failed | Self::Interrupted
            )
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StageState {
    Created,
    AwaitingAuthority,
    Queued,
    Running,
    Pausing,
    Paused,
    Cancelling,
    Cancelled,
    Completed,
    Failed,
    Interrupted,
}

impl StageState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::AwaitingAuthority => "awaiting_authority",
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Pausing => "pausing",
            Self::Paused => "paused",
            Self::Cancelling => "cancelling",
            Self::Cancelled => "cancelled",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Interrupted => "interrupted",
        }
    }

    fn parse(value: &str) -> Result<Self, CoreError> {
        match value {
            "created" => Ok(Self::Created),
            "awaiting_authority" => Ok(Self::AwaitingAuthority),
            "queued" => Ok(Self::Queued),
            "running" => Ok(Self::Running),
            "pausing" => Ok(Self::Pausing),
            "paused" => Ok(Self::Paused),
            "cancelling" => Ok(Self::Cancelling),
            "cancelled" => Ok(Self::Cancelled),
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            "interrupted" => Ok(Self::Interrupted),
            _ => Err(CoreError::safe("state_corrupt")),
        }
    }

    fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Cancelled | Self::Completed | Self::Failed | Self::Interrupted
        )
    }

    fn can_transition(self, next: Self) -> bool {
        matches!(
            (self, next),
            (
                Self::Created,
                Self::AwaitingAuthority | Self::Queued | Self::Cancelled | Self::Failed
            ) | (
                Self::AwaitingAuthority,
                Self::Queued | Self::Cancelled | Self::Failed
            ) | (
                Self::Queued,
                Self::Running | Self::Cancelled | Self::Interrupted
            ) | (
                Self::Running,
                Self::Pausing
                    | Self::Cancelling
                    | Self::Completed
                    | Self::Failed
                    | Self::Interrupted
            ) | (
                Self::Pausing,
                Self::Paused | Self::Running | Self::Interrupted
            ) | (Self::Paused, Self::Running | Self::Cancelled)
                | (Self::Cancelling, Self::Cancelled | Self::Interrupted)
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanupState {
    NotRequired,
    Pending,
    Completed,
    Failed,
}

impl CleanupState {
    fn as_str(self) -> &'static str {
        match self {
            Self::NotRequired => "not_required",
            Self::Pending => "pending",
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactClass {
    Safe,
    Source,
    Protected,
    Diagnostic,
    Executable,
}

impl ArtifactClass {
    fn as_str(self) -> &'static str {
        match self {
            Self::Safe => "safe",
            Self::Source => "source",
            Self::Protected => "protected",
            Self::Diagnostic => "diagnostic",
            Self::Executable => "executable",
        }
    }

    fn parse(value: &str) -> Result<Self, CoreError> {
        match value {
            "safe" => Ok(Self::Safe),
            "source" => Ok(Self::Source),
            "protected" => Ok(Self::Protected),
            "diagnostic" => Ok(Self::Diagnostic),
            "executable" => Ok(Self::Executable),
            _ => Err(CoreError::safe("state_corrupt")),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SafeError {
    pub code: String,
    pub category: String,
    pub retryable: bool,
    pub safe_message: String,
    pub next_action: String,
}

#[derive(Debug, Error)]
#[error("{safe_message}")]
pub struct CoreError {
    pub code: String,
    pub category: String,
    pub retryable: bool,
    pub safe_message: String,
    pub next_action: String,
}

impl CoreError {
    #[allow(clippy::too_many_lines)]
    fn safe(code: &str) -> Self {
        let (category, retryable, message, action) = match code {
            "invalid_authority_mode" => (
                "policy",
                false,
                "The requested authority mode is not permitted by this core.",
                "Use inspect, audit, or draft authority for this phase.",
            ),
            "authority_denied" => (
                "policy",
                false,
                "The requested operation exceeds the approved authority.",
                "Create a new explicit authority manifest before retrying.",
            ),
            "invalid_state_root" => (
                "state",
                false,
                "The state root is not a private local directory.",
                "Select an absolute owner-only state directory.",
            ),
            "state_unavailable" => (
                "state",
                true,
                "Private state is unavailable.",
                "Repair local storage and retry.",
            ),
            "migration_failed" => (
                "storage",
                false,
                "The state migration failed and was rolled back.",
                "Inspect the migration backup and retry with a supported state version.",
            ),
            "sqlite_too_old" => (
                "storage",
                false,
                "The SQLite runtime is below the required patched version.",
                "Install the supported bundled SQLite runtime.",
            ),
            "writer_conflict" => (
                "state",
                true,
                "Another trusted core writer already owns this state root.",
                "Reuse the running daemon or wait for its writer lock to close.",
            ),
            "event_cursor_expired" => (
                "state",
                false,
                "The event cursor precedes the retained event floor.",
                "Reload the durable run projection and resume from the retained floor.",
            ),
            "idempotency_conflict" => (
                "state",
                false,
                "An idempotency key was reused for a different mutation.",
                "Use a new idempotency key for the changed request.",
            ),
            "import_invalid" => (
                "storage",
                false,
                "The Python v2 state database is unsupported or corrupt.",
                "Select an intact Phase 2 database with the exact supported schema.",
            ),
            "backup_invalid" => (
                "storage",
                false,
                "The selected migration backup is invalid.",
                "Select a trusted backup created by this core.",
            ),
            "invalid_transition" => (
                "state",
                false,
                "The requested run or stage transition is invalid.",
                "Reload current state and issue a valid transition.",
            ),
            "budget_exceeded" => (
                "policy",
                false,
                "The run exceeded an approved budget.",
                "Approve a bounded larger budget or reduce work.",
            ),
            "lease_conflict" => (
                "state",
                true,
                "The stage lease is held by another live worker.",
                "Wait for lease expiry or recover the run.",
            ),
            "artifact_invalid" => (
                "storage",
                false,
                "The artifact bytes do not match their receipt.",
                "Quarantine the artifact and rerun the producer.",
            ),
            "artifact_forbidden" => (
                "policy",
                false,
                "The artifact class is not safe to read through this boundary.",
                "Use an explicit protected-artifact authority.",
            ),
            "receipt_gate_unmet" => (
                "state",
                false,
                "The run is missing evidence required for receipt completion.",
                "Complete terminal stages, cleanup, and budget accounting before receipt.",
            ),
            "state_corrupt" => (
                "storage",
                false,
                "The durable state projection is corrupt.",
                "Restore from a verified migration backup.",
            ),
            _ => (
                "internal",
                false,
                "The trusted core rejected the request at an internal boundary.",
                "Quarantine the run and inspect safe diagnostics.",
            ),
        };
        Self {
            code: code.to_owned(),
            category: category.to_owned(),
            retryable,
            safe_message: message.to_owned(),
            next_action: action.to_owned(),
        }
    }

    pub fn safe_error(&self) -> SafeError {
        SafeError {
            code: self.code.clone(),
            category: self.category.clone(),
            retryable: self.retryable,
            safe_message: self.safe_message.clone(),
            next_action: self.next_action.clone(),
        }
    }
}

impl From<rusqlite::Error> for CoreError {
    fn from(_: rusqlite::Error) -> Self {
        Self::safe("state_unavailable")
    }
}

impl From<std::io::Error> for CoreError {
    fn from(_: std::io::Error) -> Self {
        Self::safe("state_unavailable")
    }
}

impl From<serde_json::Error> for CoreError {
    fn from(_: serde_json::Error) -> Self {
        Self::safe("state_corrupt")
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct BudgetLedger {
    pub wall_ms: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub bytes: u64,
    pub attempts: u64,
}

impl BudgetLedger {
    fn checked_add(&self, delta: &Self, limit: &Self) -> Result<Self, CoreError> {
        let next = Self {
            wall_ms: self
                .wall_ms
                .checked_add(delta.wall_ms)
                .ok_or_else(|| CoreError::safe("budget_exceeded"))?,
            input_tokens: self
                .input_tokens
                .checked_add(delta.input_tokens)
                .ok_or_else(|| CoreError::safe("budget_exceeded"))?,
            output_tokens: self
                .output_tokens
                .checked_add(delta.output_tokens)
                .ok_or_else(|| CoreError::safe("budget_exceeded"))?,
            bytes: self
                .bytes
                .checked_add(delta.bytes)
                .ok_or_else(|| CoreError::safe("budget_exceeded"))?,
            attempts: self
                .attempts
                .checked_add(delta.attempts)
                .ok_or_else(|| CoreError::safe("budget_exceeded"))?,
        };
        if next.wall_ms > limit.wall_ms
            || next.input_tokens > limit.input_tokens
            || next.output_tokens > limit.output_tokens
            || next.bytes > limit.bytes
            || next.attempts > limit.attempts
        {
            return Err(CoreError::safe("budget_exceeded"));
        }
        Ok(next)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Lease {
    pub owner: String,
    pub heartbeat_ms: u64,
    pub deadline_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ArtifactRecord {
    pub artifact_id: String,
    pub byte_count: u64,
    pub media_type: String,
    pub class: ArtifactClass,
    pub created_by: String,
    pub policy_digest: String,
    pub pinned: bool,
    pub complete: bool,
    pub quarantined: bool,
    pub retention_until_ms: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityManifest {
    pub schema_uri: String,
    pub schema_version: String,
    pub authority_id: String,
    pub subject_id: String,
    pub mode: AuthorityMode,
    pub manifest: Value,
    pub manifest_digest: String,
    pub approved_at: String,
    pub expires_at: Option<String>,
    pub approval_origin: String,
    pub revoked: bool,
    #[serde(skip)]
    pub snapshot_id: String,
}

impl AuthorityManifest {
    pub fn from_contract_json(snapshot_id: &str, bytes: &[u8]) -> Result<Self, CoreError> {
        let value = parse_strict_json(bytes, MAX_SAFE_JSON_BYTES)
            .map_err(|_| CoreError::safe("authority_denied"))?;
        validate_contract(&value).map_err(|_| CoreError::safe("authority_denied"))?;
        let mut authority: Self =
            serde_json::from_value(value).map_err(|_| CoreError::safe("authority_denied"))?;
        snapshot_id.clone_into(&mut authority.snapshot_id);
        validate_authority(&authority)?;
        Ok(authority)
    }

    fn contract_value(&self) -> Result<Value, CoreError> {
        let mut value = serde_json::to_value(self)?;
        value
            .as_object_mut()
            .ok_or_else(|| CoreError::safe("authority_denied"))?
            .remove("snapshot_id");
        Ok(value)
    }

    pub fn permits(&self, action: AuthorityAction) -> bool {
        if validate_authority(self).is_err() {
            return false;
        }
        let values = |field: &str| {
            self.manifest
                .get(field)
                .and_then(Value::as_array)
                .map(|values| values.iter().filter_map(Value::as_str).collect::<Vec<_>>())
                .unwrap_or_default()
        };
        let reads = values("reads");
        let writes = values("writes");
        let granted = match action {
            AuthorityAction::ReadSource => reads.contains(&"selected_source_bytes"),
            AuthorityAction::WriteState => writes.contains(&"tool_owned_state"),
            AuthorityAction::ReadSafeArtifacts => reads.contains(&"safe_artifacts"),
            AuthorityAction::WriteCandidateArtifacts => writes.contains(&"tool_owned_candidate"),
            AuthorityAction::ExternalModelEgress => self
                .manifest
                .get("network_destinations")
                .and_then(Value::as_array)
                .is_some_and(|values| !values.is_empty()),
        };
        if !granted {
            return false;
        }
        if action == AuthorityAction::ExternalModelEgress {
            return matches!(self.mode, AuthorityMode::Audit | AuthorityMode::Draft);
        }
        self.mode.permits_ceiling(action)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EventProjection {
    pub schema_uri: String,
    pub schema_version: String,
    pub event_id: String,
    pub run_id: String,
    pub sequence: u64,
    pub occurred_at: String,
    #[serde(rename = "type")]
    pub event_type: String,
    pub payload_schema: String,
    pub payload_version: String,
    pub payload: Value,
    pub artifact_refs: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EventPage {
    pub retained_floor: u64,
    pub events: Vec<EventProjection>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportFormat {
    Json,
    Markdown,
}

impl ReportFormat {
    fn media_type(self) -> &'static str {
        match self {
            Self::Json => "application/json",
            Self::Markdown => "text/markdown",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GarbageCollectionPlan {
    pub dry_run: bool,
    pub candidates: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RunProjection {
    pub run_id: String,
    pub snapshot_id: String,
    pub mode: AuthorityMode,
    pub status: RunStatus,
    pub counters: BudgetLedger,
    pub budgets: BudgetLedger,
    pub cleanup_state: CleanupState,
    pub last_sequence: u64,
    pub receipt_id: Option<String>,
    pub authority_id: String,
    pub authority_digest: String,
    pub legacy_report_only: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StageProjection {
    pub stage_id: String,
    pub run_id: String,
    pub kind: String,
    pub state: StageState,
    pub attempt: u64,
    pub max_attempts: u64,
    pub retryable: bool,
    pub lease: Option<Lease>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReportProjection {
    pub schema_version: String,
    pub run: RunProjection,
    pub stages: Vec<StageProjection>,
    pub artifacts: Vec<ArtifactRecord>,
    pub limitations: Vec<String>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ArtifactAccess {
    pub protected: bool,
    pub executable: bool,
}

pub struct CoreStore {
    root: PathBuf,
    conn: Connection,
    _writer_lock: File,
}

struct IdempotencyRequest<'a> {
    operation: &'static str,
    key: &'a str,
    digest: String,
}

impl CoreStore {
    pub fn open(root: &Path) -> Result<Self, CoreError> {
        ensure_private_dir(root)?;
        let writer_lock = open_writer_lock(root)?;
        let db = root.join("state.sqlite");
        reject_symlink(&db)?;
        ensure_private_file(&db)?;
        let mut conn = Connection::open(&db)?;
        require_sqlite_version(&conn)?;
        configure_sqlite(&conn)?;
        migrate(root, &mut conn)?;
        verify_sqlite_health(&conn, "state_corrupt")?;
        Ok(Self {
            root: root.to_path_buf(),
            conn,
            _writer_lock: writer_lock,
        })
    }

    pub fn create_run(
        &mut self,
        authority: &AuthorityManifest,
        budgets: BudgetLedger,
    ) -> Result<RunProjection, CoreError> {
        self.create_run_inner(authority, budgets, None)
    }

    pub fn create_run_idempotent(
        &mut self,
        authority: &AuthorityManifest,
        budgets: BudgetLedger,
        idempotency_key: &str,
    ) -> Result<RunProjection, CoreError> {
        let request = idempotency_request(
            "create_run",
            idempotency_key,
            &json!({"authority": authority.contract_value()?, "budgets": budgets}),
        )?;
        self.create_run_inner(authority, budgets, Some(&request))
    }

    fn create_run_inner(
        &mut self,
        authority: &AuthorityManifest,
        budgets: BudgetLedger,
        idempotency: Option<&IdempotencyRequest<'_>>,
    ) -> Result<RunProjection, CoreError> {
        if let Some(run_id) = self.replay_idempotency(idempotency)? {
            return self.run(&run_id);
        }
        if matches!(
            authority.mode,
            AuthorityMode::Apply | AuthorityMode::Integrate
        ) {
            return Err(CoreError::safe("invalid_authority_mode"));
        }
        validate_authority(authority)?;
        let approved_budget = authority_budget(authority)?;
        if budgets.wall_ms > approved_budget.wall_ms
            || budgets.input_tokens > approved_budget.input_tokens
            || budgets.output_tokens > approved_budget.output_tokens
            || budgets.bytes > approved_budget.bytes
            || budgets.attempts > approved_budget.attempts
        {
            return Err(CoreError::safe("budget_exceeded"));
        }
        let run_id = prefixed_id("run");
        validate_entity_id(&run_id, "run")?;
        let now = now_rfc3339()?;
        let counters = BudgetLedger::default();
        let authority_contract = canonical_text(&authority.contract_value()?)?;
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO runs(run_id,snapshot_id,mode,status,counters,budgets,cleanup_state,created_at,last_sequence,authority_id,authority_digest,authority_contract,legacy_report_only)
             VALUES(?1,?2,?3,'created',?4,?5,'pending',?6,0,?7,?8,?9,0)",
            params![
                run_id,
                authority.snapshot_id,
                authority.mode.as_str(),
                json_text(&counters)?,
                json_text(&budgets)?,
                now,
                authority.authority_id,
                authority.manifest_digest,
                authority_contract,
            ],
        )?;
        append_event(
            &tx,
            &run_id,
            "run.created",
            &json!({
                "authority_id": authority.authority_id,
                "authority_digest": authority.manifest_digest,
                "mode": authority.mode.as_str(),
                "snapshot_id": authority.snapshot_id,
            }),
            &[],
        )?;
        save_idempotency(&tx, &run_id, idempotency, &run_id)?;
        tx.commit()?;
        self.run(&run_id)
    }

    pub fn add_stage(
        &mut self,
        run_id: &str,
        kind: &str,
        max_attempts: u64,
    ) -> Result<StageProjection, CoreError> {
        self.add_stage_inner(run_id, kind, max_attempts, None)
    }

    pub fn add_stage_idempotent(
        &mut self,
        run_id: &str,
        kind: &str,
        max_attempts: u64,
        idempotency_key: &str,
    ) -> Result<StageProjection, CoreError> {
        let request = idempotency_request(
            "add_stage",
            idempotency_key,
            &json!({"run_id": run_id, "kind": kind, "max_attempts": max_attempts}),
        )?;
        self.add_stage_inner(run_id, kind, max_attempts, Some(&request))
    }

    fn add_stage_inner(
        &mut self,
        run_id: &str,
        kind: &str,
        max_attempts: u64,
        idempotency: Option<&IdempotencyRequest<'_>>,
    ) -> Result<StageProjection, CoreError> {
        if let Some(stage_id) = self.replay_idempotency(idempotency)? {
            return self.stage(&stage_id);
        }
        if max_attempts == 0 || !is_safe_name(kind, 64) {
            return Err(CoreError::safe("state_corrupt"));
        }
        let run = self.run(run_id)?;
        self.require_run_action(run_id, AuthorityAction::WriteState)?;
        if run.status.is_terminal() {
            return Err(CoreError::safe("invalid_transition"));
        }
        let stage_id = prefixed_id("stage");
        validate_entity_id(&stage_id, "stage")?;
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO stages(stage_id,run_id,kind,state,attempt,max_attempts,retryable,lease)
             VALUES(?1,?2,?3,'created',0,?4,1,NULL)",
            params![stage_id, run_id, kind, sql_i64(max_attempts)?],
        )?;
        append_event(
            &tx,
            run_id,
            "stage.created",
            &json!({"stage_id": stage_id, "kind": kind}),
            &[],
        )?;
        save_idempotency(&tx, run_id, idempotency, &stage_id)?;
        tx.commit()?;
        self.stage(&stage_id)
    }

    pub fn transition_run(
        &mut self,
        run_id: &str,
        next: RunStatus,
    ) -> Result<RunProjection, CoreError> {
        self.transition_run_inner(run_id, next, None)
    }

    pub fn transition_run_idempotent(
        &mut self,
        run_id: &str,
        next: RunStatus,
        idempotency_key: &str,
    ) -> Result<RunProjection, CoreError> {
        let request = idempotency_request(
            "transition_run",
            idempotency_key,
            &json!({"run_id": run_id, "status": next.as_str()}),
        )?;
        self.transition_run_inner(run_id, next, Some(&request))
    }

    fn transition_run_inner(
        &mut self,
        run_id: &str,
        next: RunStatus,
        idempotency: Option<&IdempotencyRequest<'_>>,
    ) -> Result<RunProjection, CoreError> {
        if let Some(response) = self.replay_idempotency(idempotency)? {
            return self.run(&response);
        }
        let current = self.run(run_id)?;
        self.require_run_action(run_id, AuthorityAction::WriteState)?;
        if current.status == next {
            if idempotency.is_some() {
                let tx = self.conn.transaction()?;
                save_idempotency(&tx, run_id, idempotency, run_id)?;
                tx.commit()?;
            }
            return Ok(current);
        }
        if !current.status.can_transition(next) {
            return Err(CoreError::safe("invalid_transition"));
        }
        let tx = self.conn.transaction()?;
        tx.execute(
            "UPDATE runs SET status=?2, started_at=CASE WHEN ?2='running' AND started_at IS NULL THEN ?3 ELSE started_at END,
             terminal_at=CASE WHEN ?4 THEN ?3 ELSE terminal_at END WHERE run_id=?1",
            params![run_id, next.as_str(), now_rfc3339()?, next.is_terminal()],
        )?;
        append_event(
            &tx,
            run_id,
            "run.transitioned",
            &json!({"status": next.as_str()}),
            &[],
        )?;
        save_idempotency(&tx, run_id, idempotency, run_id)?;
        tx.commit()?;
        self.run(run_id)
    }

    pub fn transition_stage(
        &mut self,
        stage_id: &str,
        next: StageState,
    ) -> Result<StageProjection, CoreError> {
        self.transition_stage_inner(stage_id, next, None)
    }

    pub fn transition_stage_idempotent(
        &mut self,
        stage_id: &str,
        next: StageState,
        idempotency_key: &str,
    ) -> Result<StageProjection, CoreError> {
        let request = idempotency_request(
            "transition_stage",
            idempotency_key,
            &json!({"stage_id": stage_id, "state": next.as_str()}),
        )?;
        self.transition_stage_inner(stage_id, next, Some(&request))
    }

    fn transition_stage_inner(
        &mut self,
        stage_id: &str,
        next: StageState,
        idempotency: Option<&IdempotencyRequest<'_>>,
    ) -> Result<StageProjection, CoreError> {
        if let Some(response) = self.replay_idempotency(idempotency)? {
            return self.stage(&response);
        }
        let current = self.stage(stage_id)?;
        self.require_run_action(&current.run_id, AuthorityAction::WriteState)?;
        if current.state == next {
            if idempotency.is_some() {
                let tx = self.conn.transaction()?;
                save_idempotency(&tx, &current.run_id, idempotency, stage_id)?;
                tx.commit()?;
            }
            return Ok(current);
        }
        if !current.state.can_transition(next) {
            return Err(CoreError::safe("invalid_transition"));
        }
        let next_attempt = if next == StageState::Running {
            current
                .attempt
                .checked_add(1)
                .ok_or_else(|| CoreError::safe("budget_exceeded"))?
        } else {
            current.attempt
        };
        if next_attempt > current.max_attempts {
            return Err(CoreError::safe("budget_exceeded"));
        }
        let tx = self.conn.transaction()?;
        tx.execute(
            "UPDATE stages SET state=?2, attempt=?3, lease=CASE WHEN ?2='running' THEN lease ELSE NULL END WHERE stage_id=?1",
            params![stage_id, next.as_str(), sql_i64(next_attempt)?],
        )?;
        append_event(
            &tx,
            &current.run_id,
            "stage.transitioned",
            &json!({"stage_id": stage_id, "state": next.as_str()}),
            &[],
        )?;
        save_idempotency(&tx, &current.run_id, idempotency, stage_id)?;
        tx.commit()?;
        self.stage(stage_id)
    }

    pub fn record_budget(
        &mut self,
        run_id: &str,
        delta: &BudgetLedger,
    ) -> Result<RunProjection, CoreError> {
        let run = self.run(run_id)?;
        self.require_run_action(run_id, AuthorityAction::WriteState)?;
        let next = run.counters.checked_add(delta, &run.budgets)?;
        let tx = self.conn.transaction()?;
        tx.execute(
            "UPDATE runs SET counters=?2 WHERE run_id=?1",
            params![run_id, json_text(&next)?],
        )?;
        append_event(
            &tx,
            run_id,
            "budget.recorded",
            &json!({"counters": next}),
            &[],
        )?;
        tx.commit()?;
        self.run(run_id)
    }

    pub fn record_budget_idempotent(
        &mut self,
        run_id: &str,
        delta: &BudgetLedger,
        idempotency_key: &str,
    ) -> Result<RunProjection, CoreError> {
        let request = idempotency_request(
            "record_budget",
            idempotency_key,
            &json!({"run_id": run_id, "delta": delta}),
        )?;
        if let Some(response) = self.replay_idempotency(Some(&request))? {
            return self.run(&response);
        }
        let run = self.run(run_id)?;
        self.require_run_action(run_id, AuthorityAction::WriteState)?;
        let next = run.counters.checked_add(delta, &run.budgets)?;
        let tx = self.conn.transaction()?;
        tx.execute(
            "UPDATE runs SET counters=?2 WHERE run_id=?1",
            params![run_id, json_text(&next)?],
        )?;
        append_event(
            &tx,
            run_id,
            "budget.recorded",
            &json!({"counters": next}),
            &[],
        )?;
        save_idempotency(&tx, run_id, Some(&request), run_id)?;
        tx.commit()?;
        self.run(run_id)
    }

    pub fn acquire_lease(
        &mut self,
        stage_id: &str,
        owner: &str,
        now_ms: u64,
        ttl_ms: u64,
    ) -> Result<StageProjection, CoreError> {
        self.acquire_lease_inner(stage_id, owner, now_ms, ttl_ms, None)
    }

    pub fn acquire_lease_idempotent(
        &mut self,
        stage_id: &str,
        owner: &str,
        now_ms: u64,
        ttl_ms: u64,
        idempotency_key: &str,
    ) -> Result<StageProjection, CoreError> {
        let request = idempotency_request(
            "acquire_lease",
            idempotency_key,
            &json!({"stage_id": stage_id, "owner": owner, "now_ms": now_ms, "ttl_ms": ttl_ms}),
        )?;
        self.acquire_lease_inner(stage_id, owner, now_ms, ttl_ms, Some(&request))
    }

    fn acquire_lease_inner(
        &mut self,
        stage_id: &str,
        owner: &str,
        now_ms: u64,
        ttl_ms: u64,
        idempotency: Option<&IdempotencyRequest<'_>>,
    ) -> Result<StageProjection, CoreError> {
        if let Some(response) = self.replay_idempotency(idempotency)? {
            return self.stage(&response);
        }
        if owner.is_empty()
            || owner.len() > 256
            || owner.chars().any(char::is_control)
            || ttl_ms == 0
        {
            return Err(CoreError::safe("lease_conflict"));
        }
        let current = self.stage(stage_id)?;
        self.require_run_action(&current.run_id, AuthorityAction::WriteState)?;
        if current.state == StageState::Running {
            if let Some(lease) = &current.lease
                && lease.deadline_ms > now_ms
            {
                if lease.owner == owner {
                    if idempotency.is_some() {
                        let tx = self.conn.transaction()?;
                        save_idempotency(&tx, &current.run_id, idempotency, stage_id)?;
                        tx.commit()?;
                    }
                    return Ok(current);
                }
                return Err(CoreError::safe("lease_conflict"));
            }
        } else if current.state != StageState::Queued {
            return Err(CoreError::safe("invalid_transition"));
        }
        if current
            .attempt
            .checked_add(1)
            .ok_or_else(|| CoreError::safe("budget_exceeded"))?
            > current.max_attempts
        {
            return Err(CoreError::safe("budget_exceeded"));
        }
        let deadline_ms = now_ms
            .checked_add(ttl_ms)
            .ok_or_else(|| CoreError::safe("budget_exceeded"))?;
        let lease = Lease {
            owner: owner.to_owned(),
            heartbeat_ms: now_ms,
            deadline_ms,
        };
        let tx = self.conn.transaction()?;
        tx.execute(
            "UPDATE stages SET state='running', attempt=attempt+1, lease=?2 WHERE stage_id=?1",
            params![stage_id, json_text(&lease)?],
        )?;
        append_event(
            &tx,
            &current.run_id,
            "stage.lease_acquired",
            &json!({"stage_id": stage_id}),
            &[],
        )?;
        save_idempotency(&tx, &current.run_id, idempotency, stage_id)?;
        tx.commit()?;
        self.stage(stage_id)
    }

    pub fn recover_expired_leases(
        &mut self,
        now_ms: u64,
        worker_absence_verified: bool,
    ) -> Result<usize, CoreError> {
        if !worker_absence_verified {
            return Err(CoreError::safe("lease_conflict"));
        }
        let mut expired = Vec::new();
        {
            let mut statement = self
                .conn
                .prepare("SELECT stage_id, run_id, lease FROM stages WHERE state='running' AND lease IS NOT NULL")?;
            let rows = statement.query_map([], |row| {
                let lease_text: String = row.get(2)?;
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    lease_text,
                ))
            })?;
            for row in rows {
                let (stage_id, run_id, lease_text) = row?;
                let lease: Lease = serde_json::from_str(&lease_text)?;
                if lease.deadline_ms <= now_ms {
                    expired.push((stage_id, run_id));
                }
            }
        }
        let tx = self.conn.transaction()?;
        for (stage_id, run_id) in &expired {
            tx.execute(
                "UPDATE stages SET state='interrupted', lease=NULL WHERE stage_id=?1",
                params![stage_id],
            )?;
            tx.execute(
                "UPDATE runs SET status='interrupted', terminal_at=?2 WHERE run_id=?1 AND status='running'",
                params![run_id, now_rfc3339()?],
            )?;
            append_event(
                &tx,
                run_id,
                "stage.lease_expired",
                &json!({"stage_id": stage_id}),
                &[],
            )?;
        }
        tx.commit()?;
        Ok(expired.len())
    }

    pub fn recover_startup_leases(
        &mut self,
        now_ms: u64,
        worker_absence_verified: bool,
    ) -> Result<usize, CoreError> {
        self.recover_expired_leases(now_ms, worker_absence_verified)
    }

    pub fn request_cancel(&mut self, run_id: &str) -> Result<RunProjection, CoreError> {
        self.request_cancel_inner(run_id, None)
    }

    pub fn request_cancel_idempotent(
        &mut self,
        run_id: &str,
        idempotency_key: &str,
    ) -> Result<RunProjection, CoreError> {
        let request = idempotency_request(
            "request_cancel",
            idempotency_key,
            &json!({"run_id": run_id}),
        )?;
        self.request_cancel_inner(run_id, Some(&request))
    }

    fn request_cancel_inner(
        &mut self,
        run_id: &str,
        idempotency: Option<&IdempotencyRequest<'_>>,
    ) -> Result<RunProjection, CoreError> {
        if let Some(response) = self.replay_idempotency(idempotency)? {
            return self.run(&response);
        }
        let run = self.run(run_id)?;
        if run.status == RunStatus::Cancelled || run.status == RunStatus::Cancelling {
            if idempotency.is_some() {
                let tx = self.conn.transaction()?;
                save_idempotency(&tx, run_id, idempotency, run_id)?;
                tx.commit()?;
            }
            return Ok(run);
        }
        if run.status.is_terminal() {
            return Err(CoreError::safe("invalid_transition"));
        }
        let tx = self.conn.transaction()?;
        revoke_run_authority(&tx, run_id)?;
        tx.execute(
            "UPDATE stages SET state=CASE WHEN state='running' THEN 'cancelling' ELSE 'cancelled' END
             WHERE run_id=?1 AND state NOT IN ('completed','failed','cancelled','interrupted')",
            params![run_id],
        )?;
        tx.execute(
            "UPDATE runs SET status='cancelling' WHERE run_id=?1",
            params![run_id],
        )?;
        append_event(&tx, run_id, "run.cancelling", &json!({}), &[])?;
        save_idempotency(&tx, run_id, idempotency, run_id)?;
        tx.commit()?;
        self.run(run_id)
    }

    pub fn confirm_cancelled(
        &mut self,
        run_id: &str,
        worker_absence_verified: bool,
    ) -> Result<RunProjection, CoreError> {
        self.confirm_cancelled_inner(run_id, worker_absence_verified, None)
    }

    pub fn confirm_cancelled_idempotent(
        &mut self,
        run_id: &str,
        worker_absence_verified: bool,
        idempotency_key: &str,
    ) -> Result<RunProjection, CoreError> {
        let request = idempotency_request(
            "confirm_cancelled",
            idempotency_key,
            &json!({"run_id": run_id, "worker_absence_verified": worker_absence_verified}),
        )?;
        self.confirm_cancelled_inner(run_id, worker_absence_verified, Some(&request))
    }

    fn confirm_cancelled_inner(
        &mut self,
        run_id: &str,
        worker_absence_verified: bool,
        idempotency: Option<&IdempotencyRequest<'_>>,
    ) -> Result<RunProjection, CoreError> {
        if let Some(response) = self.replay_idempotency(idempotency)? {
            return self.run(&response);
        }
        let run = self.run(run_id)?;
        if run.status == RunStatus::Cancelled {
            if idempotency.is_some() {
                let tx = self.conn.transaction()?;
                save_idempotency(&tx, run_id, idempotency, run_id)?;
                tx.commit()?;
            }
            return Ok(run);
        }
        if run.status != RunStatus::Cancelling
            || !worker_absence_verified
            || run.cleanup_state == CleanupState::Pending
            || self.stages(run_id)?.iter().any(|stage| {
                !matches!(
                    stage.state,
                    StageState::Completed
                        | StageState::Failed
                        | StageState::Cancelled
                        | StageState::Interrupted
                        | StageState::Cancelling
                )
            })
        {
            return Err(CoreError::safe("receipt_gate_unmet"));
        }
        let tx = self.conn.transaction()?;
        tx.execute(
            "UPDATE stages SET state='cancelled', lease=NULL WHERE run_id=?1 AND state='cancelling'",
            params![run_id],
        )?;
        tx.execute(
            "UPDATE runs SET status='cancelled', terminal_at=?2 WHERE run_id=?1",
            params![run_id, now_rfc3339()?],
        )?;
        append_event(&tx, run_id, "run.cancelled", &json!({}), &[])?;
        save_idempotency(&tx, run_id, idempotency, run_id)?;
        tx.commit()?;
        self.run(run_id)
    }

    pub fn mark_cleanup(
        &mut self,
        run_id: &str,
        state: CleanupState,
    ) -> Result<RunProjection, CoreError> {
        self.mark_cleanup_inner(run_id, state, None)
    }

    pub fn mark_cleanup_idempotent(
        &mut self,
        run_id: &str,
        state: CleanupState,
        idempotency_key: &str,
    ) -> Result<RunProjection, CoreError> {
        let request = idempotency_request(
            "mark_cleanup",
            idempotency_key,
            &json!({"run_id": run_id, "state": state.as_str()}),
        )?;
        self.mark_cleanup_inner(run_id, state, Some(&request))
    }

    fn mark_cleanup_inner(
        &mut self,
        run_id: &str,
        state: CleanupState,
        idempotency: Option<&IdempotencyRequest<'_>>,
    ) -> Result<RunProjection, CoreError> {
        if let Some(response) = self.replay_idempotency(idempotency)? {
            return self.run(&response);
        }
        let run = self.run(run_id)?;
        if run.status != RunStatus::Cancelling {
            self.require_run_action(run_id, AuthorityAction::WriteState)?;
        }
        if run.cleanup_state == state {
            if idempotency.is_some() {
                let tx = self.conn.transaction()?;
                save_idempotency(&tx, run_id, idempotency, run_id)?;
                tx.commit()?;
            }
            return Ok(run);
        }
        let tx = self.conn.transaction()?;
        tx.execute(
            "UPDATE runs SET cleanup_state=?2 WHERE run_id=?1",
            params![run_id, state.as_str()],
        )?;
        append_event(
            &tx,
            run_id,
            "cleanup.updated",
            &json!({"state": state.as_str()}),
            &[],
        )?;
        save_idempotency(&tx, run_id, idempotency, run_id)?;
        tx.commit()?;
        self.run(run_id)
    }

    pub fn put_artifact(
        &mut self,
        bytes: &[u8],
        media_type: &str,
        class: ArtifactClass,
        created_by: &str,
        policy_digest: &str,
        pinned: bool,
    ) -> Result<ArtifactRecord, CoreError> {
        if !valid_media_type(media_type)
            || created_by.is_empty()
            || created_by.len() > 256
            || created_by.chars().any(char::is_control)
        {
            return Err(CoreError::safe("artifact_invalid"));
        }
        validate_digest(policy_digest).map_err(|_| CoreError::safe("artifact_invalid"))?;
        let byte_count =
            u64::try_from(bytes.len()).map_err(|_| CoreError::safe("artifact_invalid"))?;
        if byte_count > MAX_ARTIFACT_BYTES {
            return Err(CoreError::safe("artifact_invalid"));
        }
        let id = artifact_id(bytes);
        if let Ok(existing) = self.artifact(&id)
            && (existing.byte_count != byte_count
                || existing.media_type != media_type
                || existing.class != class
                || existing.created_by != created_by
                || existing.policy_digest != policy_digest
                || !existing.complete
                || existing.quarantined)
        {
            return Err(CoreError::safe("artifact_invalid"));
        }
        let path = self.artifact_path(&id)?;
        write_cas_file(&self.root, &path, bytes)?;
        let record = ArtifactRecord {
            artifact_id: id.clone(),
            byte_count,
            media_type: media_type.to_owned(),
            class,
            created_by: created_by.to_owned(),
            policy_digest: policy_digest.to_owned(),
            pinned,
            complete: true,
            quarantined: false,
            retention_until_ms: None,
        };
        self.conn.execute(
            "INSERT INTO artifacts(artifact_id,byte_count,media_type,class,created_by,policy_digest,pinned,complete,quarantined,retention_until_ms)
             VALUES(?1,?2,?3,?4,?5,?6,?7,1,0,NULL)
             ON CONFLICT(artifact_id) DO UPDATE SET
             byte_count=excluded.byte_count, media_type=excluded.media_type, class=excluded.class,
             created_by=excluded.created_by, policy_digest=excluded.policy_digest, pinned=excluded.pinned,
             complete=excluded.complete, quarantined=excluded.quarantined,
             retention_until_ms=excluded.retention_until_ms",
            params![
                record.artifact_id,
                sql_i64(record.byte_count)?,
                record.media_type,
                record.class.as_str(),
                record.created_by,
                record.policy_digest,
                record.pinned
            ],
        )?;
        Ok(record)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn put_run_artifact(
        &mut self,
        run_id: &str,
        bytes: &[u8],
        media_type: &str,
        class: ArtifactClass,
        created_by: &str,
        policy_digest: &str,
        pinned: bool,
    ) -> Result<ArtifactRecord, CoreError> {
        self.run(run_id)?;
        let action = if matches!(class, ArtifactClass::Source | ArtifactClass::Executable) {
            AuthorityAction::WriteCandidateArtifacts
        } else {
            AuthorityAction::WriteState
        };
        self.require_run_action(run_id, action)?;
        let record =
            self.put_artifact(bytes, media_type, class, created_by, policy_digest, pinned)?;
        self.link_artifact_to_run(run_id, &record.artifact_id, "run")?;
        Ok(record)
    }

    pub fn link_artifact_to_run(
        &mut self,
        run_id: &str,
        artifact_id_value: &str,
        purpose: &str,
    ) -> Result<(), CoreError> {
        self.run(run_id)?;
        self.require_run_action(run_id, AuthorityAction::WriteState)?;
        self.artifact(artifact_id_value)?;
        if purpose.is_empty()
            || purpose.len() > 64
            || !purpose.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_.-".contains(&byte)
            })
        {
            return Err(CoreError::safe("artifact_invalid"));
        }
        self.conn.execute(
            "INSERT OR IGNORE INTO artifact_refs(artifact_id,entity_id,purpose) VALUES(?1,?2,?3)",
            params![artifact_id_value, run_id, purpose],
        )?;
        Ok(())
    }

    pub fn garbage_collect(
        &mut self,
        now_ms: u64,
        dry_run: bool,
    ) -> Result<GarbageCollectionPlan, CoreError> {
        let mut statement = self.conn.prepare(
            "SELECT artifact_id FROM artifacts
             WHERE complete=1 AND quarantined=0 AND pinned=0
               AND class IN ('safe','diagnostic')
               AND (retention_until_ms IS NULL OR retention_until_ms<=?1)
               AND NOT EXISTS(
                   SELECT 1 FROM artifact_refs WHERE artifact_refs.artifact_id=artifacts.artifact_id
               )
             ORDER BY artifact_id",
        )?;
        let candidates = statement
            .query_map(params![sql_i64(now_ms)?], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        if !dry_run {
            for id in &candidates {
                let path = self.artifact_path(id)?;
                let quarantine = self.root.join("quarantine");
                ensure_private_dir(&quarantine)?;
                let held = quarantine.join(format!("gc-{}", prefixed_id("artifact")));
                if path.exists() {
                    reject_symlink(&path)?;
                    fs::rename(&path, &held)?;
                }
                let deleted = self.conn.execute(
                    "DELETE FROM artifacts WHERE artifact_id=?1 AND pinned=0
                     AND class IN ('safe','diagnostic')
                     AND NOT EXISTS(SELECT 1 FROM artifact_refs WHERE artifact_id=?1)",
                    params![id],
                )?;
                if deleted != 1 {
                    if held.exists() {
                        fs::rename(held, path)?;
                    }
                    return Err(CoreError::safe("artifact_invalid"));
                }
                if held.exists() {
                    fs::remove_file(held)?;
                }
            }
        }
        Ok(GarbageCollectionPlan {
            dry_run,
            candidates,
        })
    }

    pub fn read_artifact(
        &self,
        artifact_id_value: &str,
        access: ArtifactAccess,
    ) -> Result<Vec<u8>, CoreError> {
        let record = self.artifact(artifact_id_value)?;
        if matches!(record.class, ArtifactClass::Protected) && !access.protected {
            return Err(CoreError::safe("artifact_forbidden"));
        }
        if matches!(record.class, ArtifactClass::Executable) && !access.executable {
            return Err(CoreError::safe("artifact_forbidden"));
        }
        let path = self.artifact_path(artifact_id_value)?;
        reject_symlink(&path)?;
        let bytes = fs::read(path).map_err(|_| CoreError::safe("artifact_invalid"))?;
        verify_artifact_bytes(artifact_id_value, &bytes, record.byte_count)?;
        Ok(bytes)
    }

    pub fn reconcile_artifacts(&mut self) -> Result<usize, CoreError> {
        let mut bad = Vec::new();
        {
            let mut statement = self
                .conn
                .prepare("SELECT artifact_id, byte_count FROM artifacts WHERE complete=1")?;
            let rows = statement.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?;
            for row in rows {
                let (artifact, bytes) = row?;
                let bytes = sql_u64(bytes)?;
                let path = self.artifact_path(&artifact)?;
                let valid = reject_symlink(&path)
                    .and_then(|()| fs::read(&path).map_err(CoreError::from))
                    .and_then(|content| {
                        verify_artifact_bytes(&artifact, &content, bytes).map(|()| content)
                    })
                    .is_ok();
                if !valid {
                    bad.push(artifact);
                }
            }
        }
        let tx = self.conn.transaction()?;
        for artifact in &bad {
            tx.execute(
                "UPDATE artifacts SET quarantined=1 WHERE artifact_id=?1",
                params![artifact],
            )?;
        }
        tx.commit()?;
        Ok(bad.len())
    }

    pub fn complete_run(
        &mut self,
        run_id: &str,
        status: RunStatus,
    ) -> Result<RunProjection, CoreError> {
        self.complete_run_inner(run_id, status, None)
    }

    pub fn complete_run_idempotent(
        &mut self,
        run_id: &str,
        status: RunStatus,
        idempotency_key: &str,
    ) -> Result<RunProjection, CoreError> {
        let request = idempotency_request(
            "complete_run",
            idempotency_key,
            &json!({"run_id": run_id, "status": status.as_str()}),
        )?;
        self.complete_run_inner(run_id, status, Some(&request))
    }

    fn complete_run_inner(
        &mut self,
        run_id: &str,
        status: RunStatus,
        idempotency: Option<&IdempotencyRequest<'_>>,
    ) -> Result<RunProjection, CoreError> {
        if let Some(response) = self.replay_idempotency(idempotency)? {
            return self.run(&response);
        }
        if !matches!(
            status,
            RunStatus::Completed
                | RunStatus::CompletedNoFindings
                | RunStatus::CompletedWithUnsupported
                | RunStatus::Failed
        ) {
            return Err(CoreError::safe("receipt_gate_unmet"));
        }
        let run = self.run(run_id)?;
        self.require_run_action(run_id, AuthorityAction::WriteState)?;
        if run.status == status && run.receipt_id.is_some() {
            if idempotency.is_some() {
                let tx = self.conn.transaction()?;
                save_idempotency(&tx, run_id, idempotency, run_id)?;
                tx.commit()?;
            }
            return Ok(run);
        }
        if !run.status.can_transition(status) {
            return Err(CoreError::safe("invalid_transition"));
        }
        let stages = self.stages(run_id)?;
        if !matches!(
            run.cleanup_state,
            CleanupState::Completed | CleanupState::NotRequired
        ) || stages.is_empty()
            || stages.iter().any(|stage| !stage.state.is_terminal())
            || run.counters.attempts == 0
        {
            return Err(CoreError::safe("receipt_gate_unmet"));
        }
        let artifacts = self.artifacts_for_run(run_id)?;
        if artifacts
            .iter()
            .any(|artifact| !artifact.complete || artifact.quarantined)
        {
            return Err(CoreError::safe("receipt_gate_unmet"));
        }
        let terminal_at = now_rfc3339()?;
        let mut manifest = json!({
            "schema_uri": format!("{SCHEMA_BASE}receipt.schema.json"),
            "schema_version": SCHEMA_VERSION,
            "receipt_id": "",
            "receipt_kind": "trusted_core_run",
            "policy_version": "phase3-core-1",
            "bindings": {
                "run_id": run.run_id,
                "snapshot_id": run.snapshot_id,
                "authority_id": run.authority_id,
                "authority_digest": run.authority_digest,
                "artifact_ids": artifacts.iter().map(|artifact| artifact.artifact_id.clone()).collect::<Vec<_>>().join(","),
                "status": status.as_str(),
            },
            "evidence_grade": "insufficient",
            "support_level": "L0",
            "limitations": ["No target repository or generated code was executed."],
            "resources": {
                "wall_ms": run.counters.wall_ms,
                "input_tokens": run.counters.input_tokens,
                "output_tokens": run.counters.output_tokens,
                "bytes": run.counters.bytes,
                "attempts": run.counters.attempts,
            },
            "timestamps": {"terminal_at": terminal_at},
            "canonicalization": "rfc8785",
            "digest_algorithm": "sha256",
            "trusted_core_version": env!("CARGO_PKG_VERSION"),
            "nondeterministic_fields": ["timestamps.terminal_at"]
        });
        let id = receipt_id(&manifest).map_err(|_| CoreError::safe("receipt_gate_unmet"))?;
        manifest["receipt_id"] = Value::String(id.clone());
        validate_contract(&manifest).map_err(|_| CoreError::safe("receipt_gate_unmet"))?;
        let tx = self.conn.transaction()?;
        tx.execute(
            "UPDATE runs SET status=?2, terminal_at=?3, receipt_id=?4 WHERE run_id=?1",
            params![run_id, status.as_str(), terminal_at, id],
        )?;
        append_event(
            &tx,
            run_id,
            "receipt.completed",
            &json!({"receipt_id": id, "status": status.as_str()}),
            &[],
        )?;
        save_idempotency(&tx, run_id, idempotency, run_id)?;
        tx.commit()?;
        self.run(run_id)
    }

    pub fn report_projection(&self, run_id: &str) -> Result<ReportProjection, CoreError> {
        Ok(ReportProjection {
            schema_version: SCHEMA_VERSION.to_owned(),
            run: self.run(run_id)?,
            stages: self.stages(run_id)?,
            artifacts: self.artifacts_for_run(run_id)?,
            limitations: vec!["No target repository or generated code was executed.".to_owned()],
        })
    }

    pub fn report_json(&self, run_id: &str) -> Result<String, CoreError> {
        serde_json::to_string_pretty(&self.report_projection(run_id)?).map_err(CoreError::from)
    }

    pub fn report_bytes(&self, run_id: &str, format: ReportFormat) -> Result<Vec<u8>, CoreError> {
        match format {
            ReportFormat::Json => self.report_json(run_id).map(String::into_bytes),
            ReportFormat::Markdown => self.report_markdown(run_id).map(String::into_bytes),
        }
    }

    pub fn put_report_artifact(
        &mut self,
        run_id: &str,
        format: ReportFormat,
    ) -> Result<ArtifactRecord, CoreError> {
        let bytes = self.report_bytes(run_id, format)?;
        self.put_run_artifact(
            run_id,
            &bytes,
            format.media_type(),
            ArtifactClass::Safe,
            "trusted_core_report",
            &format!("sha256:{}", sha256_hex(b"phase3-core-1")),
            true,
        )
    }

    pub fn report_markdown(&self, run_id: &str) -> Result<String, CoreError> {
        let report = self.report_projection(run_id)?;
        let mut markdown = String::new();
        markdown.push_str("# PROMPTECTOMY Core Report\n\n");
        markdown.push_str("## Decision Facts\n\n");
        push_fact(&mut markdown, "run_id", &report.run.run_id);
        push_fact(&mut markdown, "snapshot_id", &report.run.snapshot_id);
        push_fact(&mut markdown, "mode", report.run.mode.as_str());
        push_fact(&mut markdown, "status", report.run.status.as_str());
        push_fact(
            &mut markdown,
            "cleanup_state",
            report.run.cleanup_state.as_str(),
        );
        push_fact(
            &mut markdown,
            "receipt_id",
            report.run.receipt_id.as_deref().unwrap_or("none"),
        );
        markdown.push_str("\n## Budgets\n\n");
        push_fact(
            &mut markdown,
            "attempts",
            &report.run.counters.attempts.to_string(),
        );
        push_fact(
            &mut markdown,
            "bytes",
            &report.run.counters.bytes.to_string(),
        );
        markdown.push_str("\n## Stages\n\n");
        for stage in report.stages {
            markdown.push_str("- ");
            markdown.push_str(&stage.kind);
            markdown.push_str(": ");
            markdown.push_str(stage.state.as_str());
            markdown.push('\n');
        }
        markdown.push_str("\n## Artifacts\n\n");
        for artifact in report.artifacts {
            markdown.push_str("- ");
            markdown.push_str(&artifact.artifact_id);
            markdown.push(' ');
            markdown.push_str(artifact.class.as_str());
            markdown.push('\n');
        }
        markdown.push_str("\n## Limitations\n\n");
        for limitation in report.limitations {
            markdown.push_str("- ");
            markdown.push_str(&limitation);
            markdown.push('\n');
        }
        Ok(markdown)
    }

    pub fn backup(&self) -> Result<PathBuf, CoreError> {
        let backups = self.root.join("backups");
        ensure_private_dir(&backups)?;
        let stamp = Uuid::now_v7();
        let target = backups.join(format!("state-{stamp}.sqlite"));
        self.conn
            .execute("VACUUM INTO ?1", params![target.to_string_lossy().as_ref()])?;
        #[cfg(unix)]
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600))?;
        let digest = file_digest(&target)?;
        let renamed = backups.join(format!("state-{stamp}-{digest}.sqlite"));
        fs::rename(target, &renamed)?;
        OpenOptions::new().write(true).open(&renamed)?.sync_all()?;
        sync_parent(&renamed)?;
        Ok(renamed)
    }

    pub fn import_backup(&mut self, backup: &Path) -> Result<(), CoreError> {
        reject_symlink(backup)?;
        if !backup.is_file() {
            return Err(CoreError::safe("backup_invalid"));
        }
        let candidate = Connection::open_with_flags(backup, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|_| CoreError::safe("backup_invalid"))?;
        let version: u32 = candidate
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(|_| CoreError::safe("backup_invalid"))?;
        if version != CURRENT_SCHEMA {
            return Err(CoreError::safe("backup_invalid"));
        }
        verify_rust_schema(&candidate, true).map_err(|_| CoreError::safe("backup_invalid"))?;
        verify_sqlite_health(&candidate, "backup_invalid")?;
        drop(candidate);
        let db = self.root.join("state.sqlite");
        let rollback = self.backup()?;
        let incoming = self.root.join(format!(".import-{}.sqlite", Uuid::now_v7()));
        copy_private_synced(backup, &incoming, "backup_invalid")?;
        self.conn
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .map_err(|_| CoreError::safe("backup_invalid"))?;
        let old = std::mem::replace(&mut self.conn, Connection::open_in_memory()?);
        drop(old);
        let installed = (|| {
            remove_sqlite_sidecars(&db, "backup_invalid")?;
            fs::rename(&incoming, &db).map_err(|_| CoreError::safe("backup_invalid"))?;
            sync_parent(&db).map_err(|_| CoreError::safe("backup_invalid"))?;
            open_validated_state(&db, "backup_invalid")
        })();
        if let Ok(conn) = installed {
            self.conn = conn;
            Ok(())
        } else {
            self.conn = restore_state_connection(&self.root, &rollback)?;
            Err(CoreError::safe("backup_invalid"))
        }
    }

    pub fn import_python_v2(&mut self, source: &Path) -> Result<usize, CoreError> {
        reject_symlink(source).map_err(|_| CoreError::safe("import_invalid"))?;
        if !source.is_file() {
            return Err(CoreError::safe("import_invalid"));
        }
        let source_identity =
            fs::canonicalize(source).map_err(|_| CoreError::safe("import_invalid"))?;
        let target_identity = fs::canonicalize(self.root.join("state.sqlite"))
            .map_err(|_| CoreError::safe("import_invalid"))?;
        if source_identity == target_identity {
            return Err(CoreError::safe("import_invalid"));
        }
        validate_quiescent_sqlite_source(source)?;
        let source_digest = file_digest(source).map_err(|_| CoreError::safe("import_invalid"))?;
        let staged = self
            .root
            .join(format!(".python-import-{}.sqlite", Uuid::now_v7()));
        if copy_private_synced(source, &staged, "import_invalid").is_err() {
            let _ = cleanup_staged_sqlite(&staged);
            return Err(CoreError::safe("import_invalid"));
        }
        let extracted = (|| {
            validate_quiescent_sqlite_source(source)?;
            let source_digest_after =
                file_digest(source).map_err(|_| CoreError::safe("import_invalid"))?;
            let staged_digest =
                file_digest(&staged).map_err(|_| CoreError::safe("import_invalid"))?;
            if source_digest != source_digest_after || source_digest != staged_digest {
                return Err(CoreError::safe("import_invalid"));
            }
            let source_conn =
                Connection::open_with_flags(&staged, OpenFlags::SQLITE_OPEN_READ_ONLY)
                    .map_err(|_| CoreError::safe("import_invalid"))?;
            source_conn
                .execute_batch("BEGIN")
                .map_err(|_| CoreError::safe("import_invalid"))?;
            let state = validate_python_source(&source_conn)
                .and_then(|()| extract_python_state(&source_conn));
            source_conn
                .execute_batch(if state.is_ok() { "COMMIT" } else { "ROLLBACK" })
                .map_err(|_| CoreError::safe("import_invalid"))?;
            state
        })();
        cleanup_staged_sqlite(&staged)?;
        let state = extracted?;
        ensure_no_import_collisions(&self.conn, &state)?;
        self.backup()?;
        let copied = copy_python_artifacts(
            source_identity
                .parent()
                .ok_or_else(|| CoreError::safe("import_invalid"))?,
            &self.root,
            &state.artifacts,
        )?;
        let count = state.runs.len();
        let tx = self.conn.transaction()?;
        let imported = insert_python_state(&tx, &state)
            .and_then(|()| tx.commit().map_err(|_| CoreError::safe("import_invalid")));
        if let Err(error) = imported {
            cleanup_imported_files(&copied);
            return Err(error);
        }
        Ok(count)
    }

    pub fn run(&self, run_id: &str) -> Result<RunProjection, CoreError> {
        validate_entity_id(run_id, "run")?;
        self.conn
            .query_row(
                "SELECT run_id,snapshot_id,mode,status,counters,budgets,cleanup_state,last_sequence,receipt_id,authority_id,authority_digest,legacy_report_only FROM runs WHERE run_id=?1",
                params![run_id],
                |row| {
                    let mode: String = row.get(2)?;
                    let status: String = row.get(3)?;
                    let counters: String = row.get(4)?;
                    let budgets: String = row.get(5)?;
                    let cleanup_state: String = row.get(6)?;
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        mode,
                        status,
                        counters,
                        budgets,
                        cleanup_state,
                        row.get::<_, i64>(7)?,
                        row.get::<_, Option<String>>(8)?,
                        row.get::<_, String>(9)?,
                        row.get::<_, String>(10)?,
                        row.get::<_, i64>(11)?,
                    ))
                },
            )
            .optional()?
            .ok_or_else(|| CoreError::safe("state_corrupt"))
            .and_then(|(run_id_value, snapshot_id, mode, status, counters, budgets, cleanup, last_sequence, receipt, authority_id, authority_digest, legacy_report_only)| {
                validate_entity_id(&run_id_value, "run")?;
                validate_snapshot_id(&snapshot_id)?;
                validate_entity_id(&authority_id, "auth")?;
                let legacy_report_only = sql_bool(legacy_report_only)?;
                if !legacy_report_only {
                    validate_digest(&authority_digest)?;
                } else if !authority_digest.is_empty() {
                    return Err(CoreError::safe("state_corrupt"));
                }
                Ok(RunProjection {
                    run_id: run_id_value,
                    snapshot_id,
                    mode: parse_mode(&mode)?,
                    status: RunStatus::parse(&status)?,
                    counters: serde_json::from_str(&counters)?,
                    budgets: serde_json::from_str(&budgets)?,
                    cleanup_state: parse_cleanup(&cleanup)?,
                    last_sequence: sql_u64(last_sequence)?,
                    receipt_id: receipt,
                    authority_id,
                    authority_digest,
                    legacy_report_only,
                })
            })
    }

    pub fn list_runs(&self) -> Result<Vec<RunProjection>, CoreError> {
        let mut statement = self
            .conn
            .prepare("SELECT run_id FROM runs ORDER BY created_at DESC, run_id DESC")?;
        let ids = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        ids.iter().map(|id| self.run(id)).collect()
    }

    pub fn events_after(
        &self,
        run_id: &str,
        cursor: u64,
        limit: u64,
    ) -> Result<EventPage, CoreError> {
        self.run(run_id)?;
        if limit == 0 || limit > MAX_EVENT_LIMIT {
            return Err(CoreError::safe("state_corrupt"));
        }
        let floor = self
            .conn
            .query_row(
                "SELECT MIN(sequence) FROM events WHERE run_id=?1",
                params![run_id],
                |row| row.get::<_, Option<i64>>(0),
            )?
            .map(sql_u64)
            .transpose()?
            .unwrap_or_else(|| cursor.checked_add(1).unwrap_or(cursor));
        let expected_first = cursor
            .checked_add(1)
            .ok_or_else(|| CoreError::safe("event_cursor_expired"))?;
        if expected_first < floor {
            return Err(CoreError::safe("event_cursor_expired"));
        }
        let mut statement = self.conn.prepare(
            "SELECT event_id,run_id,sequence,occurred_at,type,payload,artifact_refs
             FROM events WHERE run_id=?1 AND sequence>?2 ORDER BY sequence LIMIT ?3",
        )?;
        let rows =
            statement.query_map(params![run_id, sql_i64(cursor)?, sql_i64(limit)?], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                ))
            })?;
        let mut events = Vec::new();
        let mut expected = expected_first;
        for row in rows {
            let (event_id, event_run_id, sequence, occurred_at, event_type, payload, refs) = row?;
            let sequence = sql_u64(sequence)?;
            if sequence != expected {
                return Err(CoreError::safe("state_corrupt"));
            }
            validate_entity_id(&event_id, "evt")?;
            let artifact_refs: Vec<String> = serde_json::from_str(&refs)?;
            artifact_refs
                .iter()
                .try_for_each(|id| validate_artifact_id(id))?;
            let stored: Value = serde_json::from_str(&payload)?;
            let projection = if stored.get("schema_uri").is_some() {
                let mut event: EventProjection = serde_json::from_value(stored)?;
                event.artifact_refs = artifact_refs;
                event
            } else {
                EventProjection {
                    schema_uri: format!("{SCHEMA_BASE}event.schema.json"),
                    schema_version: SCHEMA_VERSION.to_owned(),
                    event_id,
                    run_id: event_run_id,
                    sequence,
                    occurred_at,
                    payload_schema: format!(
                        "{SCHEMA_BASE}events/{}.schema.json",
                        event_type.replace('.', "-")
                    ),
                    payload_version: SCHEMA_VERSION.to_owned(),
                    event_type,
                    payload: stored,
                    artifact_refs,
                }
            };
            events.push(projection);
            expected = expected
                .checked_add(1)
                .ok_or_else(|| CoreError::safe("state_corrupt"))?;
        }
        Ok(EventPage {
            retained_floor: floor,
            events,
        })
    }

    pub fn stage(&self, stage_id: &str) -> Result<StageProjection, CoreError> {
        validate_entity_id(stage_id, "stage")?;
        self.conn
            .query_row(
                "SELECT stage_id,run_id,kind,state,attempt,max_attempts,retryable,lease FROM stages WHERE stage_id=?1",
                params![stage_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, i64>(6)?,
                        row.get::<_, Option<String>>(7)?,
                    ))
                },
            )
            .optional()?
            .ok_or_else(|| CoreError::safe("state_corrupt"))
            .and_then(|(stage_id_value, run_id, kind, state, attempt, max_attempts, retryable, lease)| {
                Ok(StageProjection {
                    stage_id: stage_id_value,
                    run_id,
                    kind,
                    state: StageState::parse(&state)?,
                    attempt: sql_u64(attempt)?,
                    max_attempts: sql_u64(max_attempts)?,
                    retryable: sql_bool(retryable)?,
                    lease: lease.map(|value| serde_json::from_str(&value)).transpose()?,
                })
            })
    }

    pub fn stages(&self, run_id: &str) -> Result<Vec<StageProjection>, CoreError> {
        let mut statement = self
            .conn
            .prepare("SELECT stage_id FROM stages WHERE run_id=?1 ORDER BY kind, stage_id")?;
        let ids = statement
            .query_map(params![run_id], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        ids.iter().map(|id| self.stage(id)).collect()
    }

    pub fn artifact(&self, artifact_id_value: &str) -> Result<ArtifactRecord, CoreError> {
        validate_artifact_id(artifact_id_value)?;
        self.conn
            .query_row(
                "SELECT artifact_id,byte_count,media_type,class,created_by,policy_digest,pinned,complete,quarantined,retention_until_ms FROM artifacts WHERE artifact_id=?1",
                params![artifact_id_value],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, i64>(6)?,
                        row.get::<_, i64>(7)?,
                        row.get::<_, i64>(8)?,
                        row.get::<_, Option<i64>>(9)?,
                    ))
                },
            )
            .optional()?
            .ok_or_else(|| CoreError::safe("artifact_invalid"))
            .and_then(|(id, byte_count, media_type, class, created_by, policy_digest, pinned, complete, quarantined, retention_until_ms)| {
                Ok(ArtifactRecord {
                    artifact_id: id,
                    byte_count: sql_u64(byte_count)?,
                    media_type,
                    class: ArtifactClass::parse(&class)?,
                    created_by,
                    policy_digest,
                    pinned: sql_bool(pinned)?,
                    complete: sql_bool(complete)?,
                    quarantined: sql_bool(quarantined)?,
                    retention_until_ms: retention_until_ms.map(sql_u64).transpose()?,
                })
            })
    }

    pub fn artifacts(&self) -> Result<Vec<ArtifactRecord>, CoreError> {
        let mut statement = self
            .conn
            .prepare("SELECT artifact_id FROM artifacts ORDER BY artifact_id")?;
        let ids = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        ids.iter().map(|id| self.artifact(id)).collect()
    }

    pub fn artifacts_for_run(&self, run_id: &str) -> Result<Vec<ArtifactRecord>, CoreError> {
        self.run(run_id)?;
        let mut statement = self.conn.prepare(
            "SELECT DISTINCT artifacts.artifact_id
             FROM artifacts JOIN artifact_refs ON artifact_refs.artifact_id=artifacts.artifact_id
             WHERE artifact_refs.entity_id=?1
                OR artifact_refs.entity_id IN (SELECT event_id FROM events WHERE run_id=?1)
                OR artifact_refs.entity_id IN (SELECT stage_id FROM stages WHERE run_id=?1)
             ORDER BY artifacts.artifact_id",
        )?;
        let ids = statement
            .query_map(params![run_id], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        ids.iter().map(|id| self.artifact(id)).collect()
    }

    fn artifact_path(&self, id: &str) -> Result<PathBuf, CoreError> {
        validate_artifact_id(id)?;
        let hex = id
            .strip_prefix("sha256:")
            .ok_or_else(|| CoreError::safe("artifact_invalid"))?;
        let prefix = hex
            .get(0..2)
            .ok_or_else(|| CoreError::safe("artifact_invalid"))?;
        Ok(self.root.join("cas").join("sha256").join(prefix).join(hex))
    }

    fn replay_idempotency(
        &self,
        request: Option<&IdempotencyRequest<'_>>,
    ) -> Result<Option<String>, CoreError> {
        let Some(request) = request else {
            return Ok(None);
        };
        let existing = self
            .conn
            .query_row(
                "SELECT request_digest,response FROM idempotency WHERE operation=?1 AND key=?2",
                params![request.operation, request.key],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        match existing {
            Some((digest, response)) if digest == request.digest => Ok(Some(response)),
            Some(_) => Err(CoreError::safe("idempotency_conflict")),
            None => Ok(None),
        }
    }

    fn require_run_action(&self, run_id: &str, action: AuthorityAction) -> Result<(), CoreError> {
        let (snapshot_id, authority_id, authority_digest, contract, legacy): (
            String,
            String,
            String,
            Option<String>,
            i64,
        ) = self.conn.query_row(
            "SELECT snapshot_id,authority_id,authority_digest,authority_contract,legacy_report_only
             FROM runs WHERE run_id=?1",
            params![run_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )?;
        if sql_bool(legacy)? {
            return Err(CoreError::safe("authority_denied"));
        }
        let contract = contract.ok_or_else(|| CoreError::safe("state_corrupt"))?;
        let authority = AuthorityManifest::from_contract_json(&snapshot_id, contract.as_bytes())?;
        if authority.authority_id != authority_id
            || authority.manifest_digest != authority_digest
            || !authority.permits(action)
        {
            return Err(CoreError::safe("authority_denied"));
        }
        Ok(())
    }
}

fn idempotency_request<'a>(
    operation: &'static str,
    key: &'a str,
    value: &Value,
) -> Result<IdempotencyRequest<'a>, CoreError> {
    if !valid_idempotency_key(key) {
        return Err(CoreError::safe("idempotency_conflict"));
    }
    Ok(IdempotencyRequest {
        operation,
        key,
        digest: format!(
            "sha256:{}",
            sha256_hex(
                &canonical_json(value).map_err(|_| CoreError::safe("idempotency_conflict"))?
            )
        ),
    })
}

fn save_idempotency(
    tx: &rusqlite::Transaction<'_>,
    run_id: &str,
    request: Option<&IdempotencyRequest<'_>>,
    response: &str,
) -> Result<(), CoreError> {
    if let Some(request) = request {
        tx.execute(
            "INSERT INTO idempotency(run_id,operation,key,request_digest,response)
             VALUES(?1,?2,?3,?4,?5)",
            params![
                run_id,
                request.operation,
                request.key,
                request.digest,
                response
            ],
        )?;
    }
    Ok(())
}

fn revoke_run_authority(tx: &rusqlite::Transaction<'_>, run_id: &str) -> Result<(), CoreError> {
    let contract: Option<String> = tx.query_row(
        "SELECT authority_contract FROM runs WHERE run_id=?1",
        params![run_id],
        |row| row.get(0),
    )?;
    if let Some(contract) = contract {
        let mut value = parse_strict_json(contract.as_bytes(), MAX_SAFE_JSON_BYTES)
            .map_err(|_| CoreError::safe("state_corrupt"))?;
        value["revoked"] = Value::Bool(true);
        tx.execute(
            "UPDATE runs SET authority_contract=?2 WHERE run_id=?1",
            params![run_id, canonical_text(&value)?],
        )?;
    }
    Ok(())
}

fn append_event(
    tx: &rusqlite::Transaction<'_>,
    run_id: &str,
    event_type: &str,
    payload: &Value,
    artifacts: &[String],
) -> Result<(), CoreError> {
    let next = tx.query_row(
        "SELECT last_sequence + 1 FROM runs WHERE run_id=?1",
        params![run_id],
        |row| row.get::<_, i64>(0),
    )?;
    tx.execute(
        "INSERT INTO events(event_id,run_id,sequence,occurred_at,type,payload,artifact_refs)
         VALUES(?1,?2,?3,?4,?5,?6,?7)",
        params![
            prefixed_id("evt"),
            run_id,
            next,
            now_rfc3339()?,
            event_type,
            payload.to_string(),
            json_text(&artifacts)?
        ],
    )?;
    tx.execute(
        "UPDATE runs SET last_sequence=?2 WHERE run_id=?1",
        params![run_id, next],
    )?;
    Ok(())
}

fn configure_sqlite(conn: &Connection) -> Result<(), CoreError> {
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_DQS_DDL, false)?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_DQS_DML, false)?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false)?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "FULL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "secure_delete", "ON")?;
    conn.pragma_update(None, "trusted_schema", "OFF")?;
    conn.execute_batch("PRAGMA temp_store=MEMORY; PRAGMA recursive_triggers=OFF;")?;
    let journal_mode: String = conn.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
    let foreign_keys: i64 = conn.pragma_query_value(None, "foreign_keys", |row| row.get(0))?;
    if journal_mode != "wal" || foreign_keys != 1 {
        return Err(CoreError::safe("state_unavailable"));
    }
    Ok(())
}

fn verify_sqlite_health(conn: &Connection, code: &str) -> Result<(), CoreError> {
    let mut statement = conn
        .prepare("PRAGMA integrity_check")
        .map_err(|_| CoreError::safe(code))?;
    let statuses = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|_| CoreError::safe(code))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| CoreError::safe(code))?;
    if statuses != ["ok"] {
        return Err(CoreError::safe(code));
    }
    let mut statement = conn
        .prepare("PRAGMA foreign_key_check")
        .map_err(|_| CoreError::safe(code))?;
    if statement
        .query([])
        .map_err(|_| CoreError::safe(code))?
        .next()
        .map_err(|_| CoreError::safe(code))?
        .is_some()
    {
        return Err(CoreError::safe(code));
    }
    Ok(())
}

fn open_validated_state(path: &Path, code: &str) -> Result<Connection, CoreError> {
    let conn = Connection::open(path).map_err(|_| CoreError::safe(code))?;
    require_sqlite_version(&conn).map_err(|_| CoreError::safe(code))?;
    configure_sqlite(&conn).map_err(|_| CoreError::safe(code))?;
    verify_rust_schema(&conn, true).map_err(|_| CoreError::safe(code))?;
    verify_sqlite_health(&conn, code)?;
    Ok(conn)
}

#[cfg(unix)]
fn sync_parent(path: &Path) -> Result<(), CoreError> {
    File::open(
        path.parent()
            .ok_or_else(|| CoreError::safe("state_unavailable"))?,
    )?
    .sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_parent(path: &Path) -> Result<(), CoreError> {
    let parent = path
        .parent()
        .ok_or_else(|| CoreError::safe("state_unavailable"))?;
    let metadata = fs::symlink_metadata(parent)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(CoreError::safe("state_unavailable"));
    }
    // Windows has no portable directory fsync. Callers flush each file before
    // this metadata check, and SQLite runs with synchronous=FULL.
    Ok(())
}

fn copy_private_synced(source: &Path, target: &Path, code: &str) -> Result<(), CoreError> {
    let mut source = File::open(source).map_err(|_| CoreError::safe(code))?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut target_file = options.open(target).map_err(|_| CoreError::safe(code))?;
    io::copy(&mut source, &mut target_file).map_err(|_| CoreError::safe(code))?;
    target_file.sync_all().map_err(|_| CoreError::safe(code))?;
    sync_parent(target).map_err(|_| CoreError::safe(code))
}

fn validate_quiescent_sqlite_source(db: &Path) -> Result<(), CoreError> {
    let name = db
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| CoreError::safe("import_invalid"))?;
    for suffix in ["-wal", "-shm", "-journal"] {
        let sidecar = db.with_file_name(format!("{name}{suffix}"));
        match fs::symlink_metadata(&sidecar) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Ok(_) | Err(_) => return Err(CoreError::safe("import_invalid")),
        }
    }
    Ok(())
}

fn cleanup_staged_sqlite(db: &Path) -> Result<(), CoreError> {
    remove_sqlite_sidecars(db, "import_invalid")?;
    match fs::symlink_metadata(db) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err(CoreError::safe("import_invalid"));
        }
        Ok(_) => fs::remove_file(db).map_err(|_| CoreError::safe("import_invalid"))?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(CoreError::safe("import_invalid")),
    }
    sync_parent(db).map_err(|_| CoreError::safe("import_invalid"))
}

fn remove_sqlite_sidecars(db: &Path, code: &str) -> Result<(), CoreError> {
    let name = db
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| CoreError::safe(code))?;
    for suffix in ["-wal", "-shm"] {
        let sidecar = db.with_file_name(format!("{name}{suffix}"));
        if sidecar.exists() {
            let metadata = fs::symlink_metadata(&sidecar).map_err(|_| CoreError::safe(code))?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(CoreError::safe(code));
            }
            fs::remove_file(&sidecar).map_err(|_| CoreError::safe(code))?;
        }
    }
    sync_parent(db).map_err(|_| CoreError::safe(code))
}

fn restore_state_connection(root: &Path, rollback: &Path) -> Result<Connection, CoreError> {
    let db = root.join("state.sqlite");
    remove_sqlite_sidecars(&db, "state_unavailable")?;
    let restore = root.join(format!(".rollback-{}.sqlite", Uuid::now_v7()));
    copy_private_synced(rollback, &restore, "state_unavailable")?;
    fs::rename(restore, &db)?;
    sync_parent(&db)?;
    open_validated_state(&db, "state_unavailable")
}

fn migrate(root: &Path, conn: &mut Connection) -> Result<(), CoreError> {
    let version: u32 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version > CURRENT_SCHEMA {
        return Err(CoreError::safe("migration_failed"));
    }
    let tables = schema_tables(conn)?;
    if version == 0 && tables.is_empty() {
        let tx = conn.transaction()?;
        create_rust_schema(&tx)?;
        tx.commit()
            .map_err(|_| CoreError::safe("migration_failed"))?;
        return Ok(());
    }
    if version == CURRENT_SCHEMA {
        verify_rust_schema(conn, true)?;
        return Ok(());
    }
    if version == 4 {
        verify_rust_v4_schema(conn)?;
        backup_database(root, conn, version)?;
        let tx = conn.transaction()?;
        tx.execute_batch(
            "ALTER TABLE runs ADD COLUMN authority_contract TEXT;
             ALTER TABLE runs ADD COLUMN legacy_report_only INTEGER NOT NULL DEFAULT 1;
             UPDATE runs SET authority_digest='',budgets='{\"wall_ms\":0,\"input_tokens\":0,\"output_tokens\":0,\"bytes\":0,\"attempts\":0}';
             UPDATE runs SET status='awaiting_authority',started_at=NULL,terminal_at=NULL
               WHERE status NOT IN ('completed','completed_no_findings','completed_with_unsupported','failed','cancelled');
             UPDATE stages SET state='interrupted',lease=NULL
               WHERE state NOT IN ('completed','failed','cancelled','interrupted');
             CREATE UNIQUE INDEX idempotency_operation_key ON idempotency(operation,key);
             PRAGMA user_version=5;",
        )
        .map_err(|_| CoreError::safe("migration_failed"))?;
        tx.commit()
            .map_err(|_| CoreError::safe("migration_failed"))?;
        verify_rust_schema(conn, true)?;
        return Ok(());
    }
    if version == 3 {
        verify_rust_schema(conn, false)?;
        backup_database(root, conn, version)?;
        let tx = conn.transaction()?;
        tx.execute_batch(
            "ALTER TABLE runs ADD COLUMN authority_id TEXT NOT NULL DEFAULT 'auth_00000000-0000-7000-8000-000000000000';
             ALTER TABLE runs ADD COLUMN authority_digest TEXT NOT NULL DEFAULT '';
             ALTER TABLE runs ADD COLUMN authority_contract TEXT;
             ALTER TABLE runs ADD COLUMN legacy_report_only INTEGER NOT NULL DEFAULT 1;
             ALTER TABLE artifacts ADD COLUMN retention_until_ms INTEGER;
             CREATE TABLE idempotency(
                run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
                operation TEXT NOT NULL,
                key TEXT NOT NULL,
                request_digest TEXT NOT NULL,
                response TEXT NOT NULL,
                PRIMARY KEY(run_id,operation,key)
             );
             CREATE UNIQUE INDEX idempotency_operation_key ON idempotency(operation,key);
             UPDATE runs SET budgets='{\"wall_ms\":0,\"input_tokens\":0,\"output_tokens\":0,\"bytes\":0,\"attempts\":0}';
             UPDATE runs SET status='awaiting_authority',started_at=NULL,terminal_at=NULL
               WHERE status NOT IN ('completed','completed_no_findings','completed_with_unsupported','failed','cancelled');
             UPDATE stages SET state='interrupted',lease=NULL
               WHERE state NOT IN ('completed','failed','cancelled','interrupted');
             PRAGMA user_version=5;",
        )
        .map_err(|_| CoreError::safe("migration_failed"))?;
        tx.commit()
            .map_err(|_| CoreError::safe("migration_failed"))?;
        verify_rust_schema(conn, true)?;
        return Ok(());
    }
    if version == 1 && is_python_v2_schema(conn) {
        backup_database(root, conn, version)?;
        migrate_python_v2_in_place(root, conn)?;
        verify_rust_schema(conn, true)?;
        return Ok(());
    }
    Err(CoreError::safe("migration_failed"))
}

fn create_rust_schema(tx: &rusqlite::Transaction<'_>) -> Result<(), CoreError> {
    tx.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS runs(
            run_id TEXT PRIMARY KEY,
            snapshot_id TEXT NOT NULL,
            mode TEXT NOT NULL,
            status TEXT NOT NULL,
            counters TEXT NOT NULL,
            budgets TEXT NOT NULL,
            cleanup_state TEXT NOT NULL,
            created_at TEXT NOT NULL,
            started_at TEXT,
            terminal_at TEXT,
            last_sequence INTEGER NOT NULL,
            receipt_id TEXT,
            authority_id TEXT NOT NULL,
            authority_digest TEXT NOT NULL,
            authority_contract TEXT,
            legacy_report_only INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS stages(
            stage_id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
            kind TEXT NOT NULL,
            state TEXT NOT NULL,
            attempt INTEGER NOT NULL,
            max_attempts INTEGER NOT NULL,
            retryable INTEGER NOT NULL,
            lease TEXT
        );
        CREATE TABLE IF NOT EXISTS events(
            event_id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
            sequence INTEGER NOT NULL,
            occurred_at TEXT NOT NULL,
            type TEXT NOT NULL,
            payload TEXT NOT NULL,
            artifact_refs TEXT NOT NULL,
            UNIQUE(run_id, sequence)
        );
        CREATE TABLE IF NOT EXISTS artifacts(
            artifact_id TEXT PRIMARY KEY,
            byte_count INTEGER NOT NULL,
            media_type TEXT NOT NULL,
            class TEXT NOT NULL,
            created_by TEXT NOT NULL,
            policy_digest TEXT NOT NULL,
            pinned INTEGER NOT NULL,
            complete INTEGER NOT NULL,
            quarantined INTEGER NOT NULL,
            retention_until_ms INTEGER
        );
        CREATE TABLE IF NOT EXISTS artifact_refs(
            artifact_id TEXT NOT NULL REFERENCES artifacts(artifact_id) ON DELETE RESTRICT,
            entity_id TEXT NOT NULL,
            purpose TEXT NOT NULL,
            PRIMARY KEY(artifact_id, entity_id, purpose)
        );
        CREATE TABLE IF NOT EXISTS idempotency(
            run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
            operation TEXT NOT NULL,
            key TEXT NOT NULL,
            request_digest TEXT NOT NULL,
            response TEXT NOT NULL,
            PRIMARY KEY(run_id,operation,key)
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idempotency_operation_key
            ON idempotency(operation,key);
        PRAGMA user_version=5;
        ",
    )?;
    Ok(())
}

fn backup_database(root: &Path, conn: &Connection, version: u32) -> Result<PathBuf, CoreError> {
    let backups = root.join("backups");
    ensure_private_dir(&backups)?;
    let target = backups.join(format!("migration-v{version}-{}.sqlite", Uuid::now_v7()));
    conn.execute("VACUUM INTO ?1", params![target.to_string_lossy().as_ref()])
        .map_err(|_| CoreError::safe("migration_failed"))?;
    #[cfg(unix)]
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600))?;
    OpenOptions::new().write(true).open(&target)?.sync_all()?;
    sync_parent(&target)?;
    Ok(target)
}

fn require_sqlite_version(conn: &Connection) -> Result<(), CoreError> {
    let text: String = conn.query_row("SELECT sqlite_version()", [], |row| row.get(0))?;
    let mut parts = text.split('.');
    let version = (
        parts.next().and_then(|value| value.parse().ok()),
        parts.next().and_then(|value| value.parse().ok()),
        parts.next().and_then(|value| value.parse().ok()),
    );
    if version
        .0
        .zip(version.1)
        .zip(version.2)
        .map(|((a, b), c)| (a, b, c))
        < Some(MINIMUM_SQLITE)
    {
        return Err(CoreError::safe("sqlite_too_old"));
    }
    Ok(())
}

fn open_writer_lock(root: &Path) -> Result<File, CoreError> {
    let path = root.join(".writer.lock");
    reject_symlink(&path)?;
    ensure_private_file(&path)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    options.mode(0o600);
    let file = options.open(path)?;
    file.try_lock()
        .map_err(|_| CoreError::safe("writer_conflict"))?;
    Ok(file)
}

fn schema_tables(conn: &Connection) -> Result<BTreeSet<String>, CoreError> {
    let mut statement = conn.prepare(
        "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
    )?;
    statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(CoreError::from)
}

fn table_columns(conn: &Connection, table: &str) -> Result<Vec<String>, CoreError> {
    if !table
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
    {
        return Err(CoreError::safe("migration_failed"));
    }
    let mut statement = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    statement
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(CoreError::from)
}

fn verify_columns(
    conn: &Connection,
    expected: &[(&str, &[&str])],
    code: &str,
) -> Result<(), CoreError> {
    let expected_tables = expected
        .iter()
        .map(|(table, _)| (*table).to_owned())
        .collect::<BTreeSet<_>>();
    if schema_tables(conn)? != expected_tables {
        return Err(CoreError::safe(code));
    }
    for (table, columns) in expected {
        if table_columns(conn, table)?
            != columns.iter().map(ToString::to_string).collect::<Vec<_>>()
        {
            return Err(CoreError::safe(code));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn verify_rust_schema(conn: &Connection, current: bool) -> Result<(), CoreError> {
    let run_v3 = [
        "run_id",
        "snapshot_id",
        "mode",
        "status",
        "counters",
        "budgets",
        "cleanup_state",
        "created_at",
        "started_at",
        "terminal_at",
        "last_sequence",
        "receipt_id",
    ];
    let run_v5 = [
        "run_id",
        "snapshot_id",
        "mode",
        "status",
        "counters",
        "budgets",
        "cleanup_state",
        "created_at",
        "started_at",
        "terminal_at",
        "last_sequence",
        "receipt_id",
        "authority_id",
        "authority_digest",
        "authority_contract",
        "legacy_report_only",
    ];
    let artifact_v3 = [
        "artifact_id",
        "byte_count",
        "media_type",
        "class",
        "created_by",
        "policy_digest",
        "pinned",
        "complete",
        "quarantined",
    ];
    let artifact_v4 = [
        "artifact_id",
        "byte_count",
        "media_type",
        "class",
        "created_by",
        "policy_digest",
        "pinned",
        "complete",
        "quarantined",
        "retention_until_ms",
    ];
    let stages = [
        "stage_id",
        "run_id",
        "kind",
        "state",
        "attempt",
        "max_attempts",
        "retryable",
        "lease",
    ];
    let events = [
        "event_id",
        "run_id",
        "sequence",
        "occurred_at",
        "type",
        "payload",
        "artifact_refs",
    ];
    let refs = ["artifact_id", "entity_id", "purpose"];
    let idempotency = ["run_id", "operation", "key", "request_digest", "response"];
    let mut expected = vec![
        (
            "runs",
            if current {
                run_v5.as_slice()
            } else {
                run_v3.as_slice()
            },
        ),
        ("stages", stages.as_slice()),
        ("events", events.as_slice()),
        (
            "artifacts",
            if current {
                artifact_v4.as_slice()
            } else {
                artifact_v3.as_slice()
            },
        ),
        ("artifact_refs", refs.as_slice()),
    ];
    if current {
        expected.push(("idempotency", idempotency.as_slice()));
    }
    verify_columns(conn, &expected, "migration_failed")?;
    if current {
        let columns = conn
            .prepare("PRAGMA index_info(idempotency_operation_key)")?
            .query_map([], |row| row.get::<_, String>(2))?
            .collect::<Result<Vec<_>, _>>()?;
        if columns != ["operation", "key"] {
            return Err(CoreError::safe("migration_failed"));
        }
    }
    Ok(())
}

fn verify_rust_v4_schema(conn: &Connection) -> Result<(), CoreError> {
    let runs = [
        "run_id",
        "snapshot_id",
        "mode",
        "status",
        "counters",
        "budgets",
        "cleanup_state",
        "created_at",
        "started_at",
        "terminal_at",
        "last_sequence",
        "receipt_id",
        "authority_id",
        "authority_digest",
    ];
    let stages = [
        "stage_id",
        "run_id",
        "kind",
        "state",
        "attempt",
        "max_attempts",
        "retryable",
        "lease",
    ];
    let events = [
        "event_id",
        "run_id",
        "sequence",
        "occurred_at",
        "type",
        "payload",
        "artifact_refs",
    ];
    let artifacts = [
        "artifact_id",
        "byte_count",
        "media_type",
        "class",
        "created_by",
        "policy_digest",
        "pinned",
        "complete",
        "quarantined",
        "retention_until_ms",
    ];
    let refs = ["artifact_id", "entity_id", "purpose"];
    let idempotency = ["run_id", "operation", "key", "request_digest", "response"];
    verify_columns(
        conn,
        &[
            ("runs", &runs),
            ("stages", &stages),
            ("events", &events),
            ("artifacts", &artifacts),
            ("artifact_refs", &refs),
            ("idempotency", &idempotency),
        ],
        "migration_failed",
    )
}

fn is_python_v2_schema(conn: &Connection) -> bool {
    let expected = [
        (
            "schema_migrations",
            &["version", "applied_at_microseconds", "application_version"][..],
        ),
        (
            "runs",
            &[
                "run_id",
                "status",
                "last_sequence",
                "entity_json",
                "updated_at_microseconds",
            ][..],
        ),
        (
            "events",
            &[
                "event_id",
                "run_id",
                "sequence",
                "event_type",
                "entity_json",
                "occurred_at",
            ][..],
        ),
        (
            "stages",
            &[
                "stage_id",
                "run_id",
                "state",
                "entity_json",
                "updated_at_microseconds",
            ][..],
        ),
        (
            "idempotency",
            &[
                "run_id",
                "operation",
                "key",
                "request_digest",
                "response_json",
                "created_at_microseconds",
            ][..],
        ),
        (
            "artifacts",
            &[
                "artifact_id",
                "class",
                "media_type",
                "byte_count",
                "relative_path",
                "complete",
                "quarantined",
                "pinned",
                "retention_until_microseconds",
                "created_at_microseconds",
            ][..],
        ),
        (
            "artifact_refs",
            &["artifact_id", "owner_type", "owner_id"][..],
        ),
    ];
    verify_columns(conn, &expected, "import_invalid").is_ok()
}

#[derive(Clone)]
struct PythonArtifact {
    artifact_id: String,
    class: ArtifactClass,
    media_type: String,
    byte_count: u64,
    relative_path: String,
    complete: bool,
    quarantined: bool,
    pinned: bool,
    retention_until_ms: Option<u64>,
}

struct PythonState {
    runs: Vec<Value>,
    events: Vec<Value>,
    stages: Vec<Value>,
    artifacts: Vec<PythonArtifact>,
    refs: Vec<(String, String, String)>,
}

fn validate_python_source(conn: &Connection) -> Result<(), CoreError> {
    let version: u32 = conn
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|_| CoreError::safe("import_invalid"))?;
    if version != 1 || !is_python_v2_schema(conn) {
        return Err(CoreError::safe("import_invalid"));
    }
    let integrity: String = conn
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(|_| CoreError::safe("import_invalid"))?;
    if integrity != "ok" {
        return Err(CoreError::safe("import_invalid"));
    }
    let foreign_violation: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM pragma_foreign_key_check LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| CoreError::safe("import_invalid"))?;
    if foreign_violation.is_some() {
        return Err(CoreError::safe("import_invalid"));
    }
    Ok(())
}

fn parse_python_contract(bytes: &[u8]) -> Result<Value, CoreError> {
    let value = parse_strict_json(bytes, MAX_SAFE_JSON_BYTES)
        .map_err(|_| CoreError::safe("import_invalid"))?;
    validate_contract(&value).map_err(|_| CoreError::safe("import_invalid"))?;
    Ok(value)
}

#[allow(clippy::too_many_lines)]
fn extract_python_state(conn: &Connection) -> Result<PythonState, CoreError> {
    let mut runs = Vec::new();
    let mut run_sequences = std::collections::BTreeMap::new();
    {
        let mut statement = conn
            .prepare("SELECT run_id,status,last_sequence,entity_json FROM runs ORDER BY run_id")
            .map_err(|_| CoreError::safe("import_invalid"))?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            })
            .map_err(|_| CoreError::safe("import_invalid"))?;
        for row in rows {
            let (run_id, status, sequence, bytes) =
                row.map_err(|_| CoreError::safe("import_invalid"))?;
            let sequence = sql_u64(sequence).map_err(|_| CoreError::safe("import_invalid"))?;
            let value = parse_python_contract(&bytes)?;
            if json_string(&value, "run_id")? != run_id
                || json_string(&value, "status")? != status
                || json_u64(&value, "last_sequence")? != sequence
            {
                return Err(CoreError::safe("import_invalid"));
            }
            validate_entity_id(&run_id, "run").map_err(|_| CoreError::safe("import_invalid"))?;
            run_sequences.insert(run_id, sequence);
            runs.push(value);
        }
    }
    let mut events = Vec::new();
    let mut seen_sequences = std::collections::BTreeMap::<String, u64>::new();
    {
        let mut statement = conn
            .prepare("SELECT event_id,run_id,sequence,event_type,entity_json,occurred_at FROM events ORDER BY run_id,sequence")
            .map_err(|_| CoreError::safe("import_invalid"))?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })
            .map_err(|_| CoreError::safe("import_invalid"))?;
        for row in rows {
            let (event_id, run_id, sequence, event_type, bytes, occurred_at) =
                row.map_err(|_| CoreError::safe("import_invalid"))?;
            let sequence = sql_u64(sequence).map_err(|_| CoreError::safe("import_invalid"))?;
            let expected = seen_sequences
                .get(&run_id)
                .copied()
                .unwrap_or(0)
                .checked_add(1)
                .ok_or_else(|| CoreError::safe("import_invalid"))?;
            let value = parse_python_contract(&bytes)?;
            if sequence != expected
                || json_string(&value, "event_id")? != event_id
                || json_string(&value, "run_id")? != run_id
                || json_string(&value, "type")? != event_type
                || json_string(&value, "occurred_at")? != occurred_at
                || json_u64(&value, "sequence")? != sequence
            {
                return Err(CoreError::safe("import_invalid"));
            }
            validate_entity_id(&event_id, "evt").map_err(|_| CoreError::safe("import_invalid"))?;
            seen_sequences.insert(run_id, sequence);
            events.push(value);
        }
    }
    for (run_id, last_sequence) in run_sequences {
        if seen_sequences.get(&run_id).copied().unwrap_or(0) != last_sequence {
            return Err(CoreError::safe("import_invalid"));
        }
    }
    let mut stages = Vec::new();
    {
        let mut statement = conn
            .prepare("SELECT stage_id,run_id,state,entity_json FROM stages ORDER BY stage_id")
            .map_err(|_| CoreError::safe("import_invalid"))?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            })
            .map_err(|_| CoreError::safe("import_invalid"))?;
        for row in rows {
            let (stage_id, run_id, state, bytes) =
                row.map_err(|_| CoreError::safe("import_invalid"))?;
            let value = parse_python_contract(&bytes)?;
            if json_string(&value, "stage_id")? != stage_id
                || json_string(&value, "run_id")? != run_id
                || json_string(&value, "state")? != state
            {
                return Err(CoreError::safe("import_invalid"));
            }
            validate_entity_id(&stage_id, "stage")
                .map_err(|_| CoreError::safe("import_invalid"))?;
            stages.push(value);
        }
    }
    let mut artifacts = Vec::new();
    {
        let mut statement = conn
            .prepare("SELECT artifact_id,class,media_type,byte_count,relative_path,complete,quarantined,pinned,retention_until_microseconds FROM artifacts ORDER BY artifact_id")
            .map_err(|_| CoreError::safe("import_invalid"))?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, Option<i64>>(8)?,
                ))
            })
            .map_err(|_| CoreError::safe("import_invalid"))?;
        for row in rows {
            let (id, class, media_type, bytes, relative, complete, quarantined, pinned, retention) =
                row.map_err(|_| CoreError::safe("import_invalid"))?;
            validate_artifact_id(&id).map_err(|_| CoreError::safe("import_invalid"))?;
            validate_relative_path(&relative).map_err(|_| CoreError::safe("import_invalid"))?;
            let bool_value = |value| match value {
                0 => Ok(false),
                1 => Ok(true),
                _ => Err(CoreError::safe("import_invalid")),
            };
            let retention_until_ms = retention
                .map(|value| sql_u64(value).map(|value| value / 1_000))
                .transpose()
                .map_err(|_| CoreError::safe("import_invalid"))?;
            artifacts.push(PythonArtifact {
                artifact_id: id,
                class: ArtifactClass::parse(&class)
                    .map_err(|_| CoreError::safe("import_invalid"))?,
                media_type,
                byte_count: sql_u64(bytes).map_err(|_| CoreError::safe("import_invalid"))?,
                relative_path: relative,
                complete: bool_value(complete)?,
                quarantined: bool_value(quarantined)?,
                pinned: bool_value(pinned)?,
                retention_until_ms,
            });
        }
    }
    let mut refs = Vec::new();
    {
        let mut statement = conn
            .prepare("SELECT artifact_id,owner_type,owner_id FROM artifact_refs ORDER BY artifact_id,owner_type,owner_id")
            .map_err(|_| CoreError::safe("import_invalid"))?;
        let rows = statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .map_err(|_| CoreError::safe("import_invalid"))?;
        for row in rows {
            refs.push(row.map_err(|_| CoreError::safe("import_invalid"))?);
        }
    }
    let state = PythonState {
        runs,
        events,
        stages,
        artifacts,
        refs,
    };
    validate_python_refs(&state)?;
    Ok(state)
}

fn validate_python_refs(state: &PythonState) -> Result<(), CoreError> {
    let run_ids = state
        .runs
        .iter()
        .map(|value| json_string(value, "run_id"))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let event_ids = state
        .events
        .iter()
        .map(|value| json_string(value, "event_id"))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let stage_ids = state
        .stages
        .iter()
        .map(|value| json_string(value, "stage_id"))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let artifact_ids = state
        .artifacts
        .iter()
        .map(|artifact| artifact.artifact_id.clone())
        .collect::<BTreeSet<_>>();
    let refs = state.refs.iter().cloned().collect::<BTreeSet<_>>();
    if refs.len() != state.refs.len() {
        return Err(CoreError::safe("import_invalid"));
    }
    for (artifact_id, owner_type, owner_id) in &refs {
        let valid_owner = match owner_type.as_str() {
            "run" | "report" => run_ids.contains(owner_id),
            "event" => event_ids.contains(owner_id),
            "stage" => stage_ids.contains(owner_id),
            _ => false,
        };
        if !artifact_ids.contains(artifact_id) || !valid_owner {
            return Err(CoreError::safe("import_invalid"));
        }
    }
    for event in &state.events {
        let event_id = json_string(event, "event_id")?;
        let event_refs = event
            .get("artifact_refs")
            .and_then(Value::as_array)
            .ok_or_else(|| CoreError::safe("import_invalid"))?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(ToOwned::to_owned)
                    .ok_or_else(|| CoreError::safe("import_invalid"))
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        if event_refs.iter().any(|artifact_id| {
            !refs.contains(&(artifact_id.clone(), "event".to_owned(), event_id.clone()))
        }) || refs.iter().any(|(artifact_id, owner_type, owner_id)| {
            owner_type == "event" && owner_id == &event_id && !event_refs.contains(artifact_id)
        }) {
            return Err(CoreError::safe("import_invalid"));
        }
    }
    Ok(())
}

fn json_string(value: &Value, key: &str) -> Result<String, CoreError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| CoreError::safe("import_invalid"))
}

fn json_u64(value: &Value, key: &str) -> Result<u64, CoreError> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| CoreError::safe("import_invalid"))
}

fn python_budget(value: Option<&Value>, counters: bool) -> BudgetLedger {
    let object = value.and_then(Value::as_object);
    let field = |name: &str| {
        object
            .and_then(|map| map.get(name))
            .and_then(Value::as_u64)
            .unwrap_or(0)
    };
    let mut result = BudgetLedger {
        wall_ms: field("wall_ms"),
        input_tokens: field("input_tokens"),
        output_tokens: field("output_tokens"),
        bytes: field("bytes"),
        attempts: field("attempts"),
    };
    if counters && result.attempts == 0 {
        result.attempts = field("performed");
    }
    if !counters {
        if result.wall_ms == 0 {
            result.wall_ms = u64::MAX;
        }
        if result.input_tokens == 0 {
            result.input_tokens = u64::MAX;
        }
        if result.output_tokens == 0 {
            result.output_tokens = u64::MAX;
        }
        if result.bytes == 0 {
            result.bytes = u64::MAX;
        }
        if result.attempts == 0 {
            result.attempts = u64::MAX;
        }
    }
    result
}

fn ensure_no_import_collisions(conn: &Connection, state: &PythonState) -> Result<(), CoreError> {
    for (table, key, values) in [
        (
            "runs",
            "run_id",
            state
                .runs
                .iter()
                .map(|value| json_string(value, "run_id"))
                .collect::<Result<Vec<_>, _>>()?,
        ),
        (
            "events",
            "event_id",
            state
                .events
                .iter()
                .map(|value| json_string(value, "event_id"))
                .collect::<Result<Vec<_>, _>>()?,
        ),
        (
            "stages",
            "stage_id",
            state
                .stages
                .iter()
                .map(|value| json_string(value, "stage_id"))
                .collect::<Result<Vec<_>, _>>()?,
        ),
        (
            "artifacts",
            "artifact_id",
            state
                .artifacts
                .iter()
                .map(|value| value.artifact_id.clone())
                .collect(),
        ),
    ] {
        let sql = format!("SELECT 1 FROM {table} WHERE {key}=?1");
        for value in values {
            if conn
                .query_row(&sql, params![value], |_| Ok(()))
                .optional()?
                .is_some()
            {
                return Err(CoreError::safe("import_invalid"));
            }
        }
    }
    Ok(())
}

fn copy_python_artifacts(
    source_root: &Path,
    target_root: &Path,
    artifacts: &[PythonArtifact],
) -> Result<Vec<PathBuf>, CoreError> {
    let artifact_root = source_root.join("artifacts");
    let needs_artifacts = artifacts
        .iter()
        .any(|artifact| artifact.complete && !artifact.quarantined);
    let canonical_root = if needs_artifacts {
        let source_root =
            fs::canonicalize(source_root).map_err(|_| CoreError::safe("import_invalid"))?;
        let metadata =
            fs::symlink_metadata(&artifact_root).map_err(|_| CoreError::safe("import_invalid"))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(CoreError::safe("import_invalid"));
        }
        let canonical =
            fs::canonicalize(&artifact_root).map_err(|_| CoreError::safe("import_invalid"))?;
        if canonical.parent() != Some(source_root.as_path()) {
            return Err(CoreError::safe("import_invalid"));
        }
        Some(canonical)
    } else {
        None
    };
    let mut copied = Vec::new();
    for artifact in artifacts {
        if !artifact.complete || artifact.quarantined {
            continue;
        }
        let result = (|| {
            let source = artifact_root.join(&artifact.relative_path);
            let mut walked = artifact_root.clone();
            for component in Path::new(&artifact.relative_path).components() {
                walked.push(component);
                let metadata =
                    fs::symlink_metadata(&walked).map_err(|_| CoreError::safe("import_invalid"))?;
                if metadata.file_type().is_symlink() {
                    return Err(CoreError::safe("import_invalid"));
                }
            }
            if !fs::symlink_metadata(&source)
                .map_err(|_| CoreError::safe("import_invalid"))?
                .is_file()
            {
                return Err(CoreError::safe("import_invalid"));
            }
            let resolved =
                fs::canonicalize(&source).map_err(|_| CoreError::safe("import_invalid"))?;
            if !canonical_root
                .as_ref()
                .is_some_and(|root| resolved.starts_with(root))
            {
                return Err(CoreError::safe("import_invalid"));
            }
            let bytes = fs::read(&source).map_err(|_| CoreError::safe("import_invalid"))?;
            verify_artifact_bytes(&artifact.artifact_id, &bytes, artifact.byte_count)
                .map_err(|_| CoreError::safe("import_invalid"))?;
            let hex = artifact
                .artifact_id
                .strip_prefix("sha256:")
                .ok_or_else(|| CoreError::safe("import_invalid"))?;
            let destination = target_root
                .join("cas")
                .join("sha256")
                .join(&hex[..2])
                .join(hex);
            let existed = destination.exists();
            write_cas_file(target_root, &destination, &bytes)
                .map_err(|_| CoreError::safe("import_invalid"))?;
            if !existed {
                copied.push(destination);
            }
            Ok(())
        })();
        if let Err(error) = result {
            cleanup_imported_files(&copied);
            return Err(error);
        }
    }
    Ok(copied)
}

fn cleanup_imported_files(paths: &[PathBuf]) {
    for path in paths {
        let _ = fs::remove_file(path);
    }
}

#[allow(clippy::too_many_lines)]
fn insert_python_state(
    tx: &rusqlite::Transaction<'_>,
    state: &PythonState,
) -> Result<(), CoreError> {
    for run in &state.runs {
        let authority_id = run
            .get("authority_ids")
            .and_then(Value::as_array)
            .and_then(|values| values.first())
            .and_then(Value::as_str)
            .ok_or_else(|| CoreError::safe("import_invalid"))?;
        validate_entity_id(authority_id, "auth").map_err(|_| CoreError::safe("import_invalid"))?;
        let snapshot_id = json_string(run, "snapshot_id")?;
        validate_snapshot_id(&snapshot_id).map_err(|_| CoreError::safe("import_invalid"))?;
        let mode = parse_mode(&json_string(run, "mode")?)
            .map_err(|_| CoreError::safe("import_invalid"))?;
        let imported_status = RunStatus::parse(&json_string(run, "status")?)
            .map_err(|_| CoreError::safe("import_invalid"))?;
        let status = if imported_status.is_terminal() {
            imported_status
        } else {
            RunStatus::AwaitingAuthority
        };
        let cleanup = parse_cleanup(&json_string(run, "cleanup_state")?)
            .map_err(|_| CoreError::safe("import_invalid"))?;
        let receipt = run.get("receipt_id").and_then(Value::as_str);
        tx.execute(
            "INSERT INTO runs(run_id,snapshot_id,mode,status,counters,budgets,cleanup_state,created_at,started_at,terminal_at,last_sequence,receipt_id,authority_id,authority_digest,authority_contract,legacy_report_only)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,NULL,?9,?10,?11,?12,'',NULL,1)",
            params![
                json_string(run, "run_id")?, snapshot_id, mode.as_str(), status.as_str(),
                json_text(&python_budget(run.get("counters"), true))?,
                json_text(&BudgetLedger::default())?, cleanup.as_str(),
                json_string(run, "created_at")?,
                run.get("terminal_at").and_then(Value::as_str),
                sql_i64(json_u64(run, "last_sequence")?)?,
                receipt, authority_id,
            ],
        )?;
    }
    for artifact in &state.artifacts {
        tx.execute(
            "INSERT INTO artifacts VALUES(?1,?2,?3,?4,'python_v2_import',?5,?6,?7,?8,?9)",
            params![
                artifact.artifact_id,
                sql_i64(artifact.byte_count)?,
                artifact.media_type,
                artifact.class.as_str(),
                format!("sha256:{}", sha256_hex(b"python-v2-import")),
                artifact.pinned,
                artifact.complete,
                artifact.quarantined,
                artifact.retention_until_ms.map(sql_i64).transpose()?,
            ],
        )?;
    }
    for stage in &state.stages {
        tx.execute(
            "INSERT INTO stages VALUES(?1,?2,?3,?4,?5,?6,?7,NULL)",
            params![
                json_string(stage, "stage_id")?,
                json_string(stage, "run_id")?,
                json_string(stage, "kind")?,
                {
                    let state = StageState::parse(&json_string(stage, "state")?)
                        .map_err(|_| CoreError::safe("import_invalid"))?;
                    if state.is_terminal() {
                        state
                    } else {
                        StageState::Interrupted
                    }
                    .as_str()
                },
                sql_i64(json_u64(stage, "attempt")?)?,
                sql_i64(json_u64(stage, "max_attempts")?)?,
                stage
                    .get("retryable")
                    .and_then(Value::as_bool)
                    .ok_or_else(|| CoreError::safe("import_invalid"))?,
            ],
        )?;
    }
    for event in &state.events {
        let refs = event
            .get("artifact_refs")
            .and_then(Value::as_array)
            .ok_or_else(|| CoreError::safe("import_invalid"))?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(ToOwned::to_owned)
                    .ok_or_else(|| CoreError::safe("import_invalid"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let event_id = json_string(event, "event_id")?;
        tx.execute(
            "INSERT INTO events VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![
                event_id,
                json_string(event, "run_id")?,
                sql_i64(json_u64(event, "sequence")?)?,
                json_string(event, "occurred_at")?,
                json_string(event, "type")?,
                json_text(event)?,
                json_text(&refs)?,
            ],
        )?;
    }
    for (artifact, owner_type, owner_id) in &state.refs {
        tx.execute(
            "INSERT INTO artifact_refs VALUES(?1,?2,?3)",
            params![artifact, owner_id, owner_type],
        )?;
    }
    Ok(())
}

fn migrate_python_v2_in_place(root: &Path, conn: &mut Connection) -> Result<(), CoreError> {
    conn.execute_batch("BEGIN")?;
    let extracted = validate_python_source(conn).and_then(|()| extract_python_state(conn));
    conn.execute_batch(if extracted.is_ok() {
        "COMMIT"
    } else {
        "ROLLBACK"
    })?;
    let state = extracted?;
    let copied = copy_python_artifacts(root, root, &state.artifacts)?;
    let tx = conn.transaction()?;
    tx.execute_batch(
        "DROP TABLE idempotency; DROP TABLE artifact_refs; DROP TABLE events; DROP TABLE stages;
         DROP TABLE artifacts; DROP TABLE runs; DROP TABLE schema_migrations;",
    )?;
    create_rust_schema(&tx)?;
    let migrated = insert_python_state(&tx, &state)
        .and_then(|()| tx.commit().map_err(|_| CoreError::safe("migration_failed")));
    if migrated.is_err() {
        cleanup_imported_files(&copied);
    }
    migrated
}

fn validate_entity_id(value: &str, prefix: &str) -> Result<(), CoreError> {
    let text = value
        .strip_prefix(&format!("{prefix}_"))
        .ok_or_else(|| CoreError::safe("state_corrupt"))?;
    let uuid = Uuid::parse_str(text).map_err(|_| CoreError::safe("state_corrupt"))?;
    if uuid.hyphenated().to_string() != text
        || uuid.get_version_num() != 7
        || uuid.get_variant() != Variant::RFC4122
    {
        return Err(CoreError::safe("state_corrupt"));
    }
    Ok(())
}

fn validate_snapshot_id(value: &str) -> Result<(), CoreError> {
    let digest = value
        .strip_prefix("snap_sha256_")
        .ok_or_else(|| CoreError::safe("state_corrupt"))?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CoreError::safe("state_corrupt"));
    }
    Ok(())
}

fn validate_digest(value: &str) -> Result<(), CoreError> {
    let digest = value
        .strip_prefix("sha256:")
        .ok_or_else(|| CoreError::safe("state_corrupt"))?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CoreError::safe("state_corrupt"));
    }
    Ok(())
}

fn validate_authority(authority: &AuthorityManifest) -> Result<(), CoreError> {
    let contract = authority.contract_value()?;
    validate_contract(&contract).map_err(|_| CoreError::safe("authority_denied"))?;
    validate_entity_id(&authority.authority_id, "auth")?;
    validate_digest(&authority.manifest_digest)?;
    validate_snapshot_id(&authority.snapshot_id)?;
    if authority.revoked
        || authority.subject_id != format!("action_{}", authority.snapshot_id)
        || matches!(
            authority.mode,
            AuthorityMode::Apply | AuthorityMode::Integrate
        )
    {
        return Err(CoreError::safe("authority_denied"));
    }
    let approved = OffsetDateTime::parse(&authority.approved_at, &Rfc3339)
        .map_err(|_| CoreError::safe("authority_denied"))?;
    if approved > OffsetDateTime::now_utc() {
        return Err(CoreError::safe("authority_denied"));
    }
    if let Some(expires) = &authority.expires_at
        && OffsetDateTime::parse(expires, &Rfc3339)
            .map_err(|_| CoreError::safe("authority_denied"))?
            <= OffsetDateTime::now_utc()
    {
        return Err(CoreError::safe("authority_denied"));
    }
    let canonical =
        canonical_json(&authority.manifest).map_err(|_| CoreError::safe("authority_denied"))?;
    let expected = format!("sha256:{}", sha256_hex(&canonical));
    if expected
        .as_bytes()
        .ct_eq(authority.manifest_digest.as_bytes())
        .unwrap_u8()
        != 1
    {
        return Err(CoreError::safe("authority_denied"));
    }
    let manifest = authority
        .manifest
        .as_object()
        .ok_or_else(|| CoreError::safe("authority_denied"))?;
    let strings = |name: &str| -> Result<Vec<&str>, CoreError> {
        manifest
            .get(name)
            .and_then(Value::as_array)
            .ok_or_else(|| CoreError::safe("authority_denied"))?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .ok_or_else(|| CoreError::safe("authority_denied"))
            })
            .collect()
    };
    let writes = strings("writes")?;
    let reads = strings("reads")?;
    let allowed_reads = match authority.mode {
        AuthorityMode::Inspect => ["selected_source_bytes"].as_slice(),
        AuthorityMode::Audit | AuthorityMode::Draft => {
            ["selected_source_bytes", "safe_artifacts"].as_slice()
        }
        AuthorityMode::Apply | AuthorityMode::Integrate => {
            return Err(CoreError::safe("authority_denied"));
        }
    };
    let allowed_writes = match authority.mode {
        AuthorityMode::Inspect | AuthorityMode::Audit => ["tool_owned_state"].as_slice(),
        AuthorityMode::Draft => [
            "tool_owned_state",
            "tool_owned_snapshot",
            "tool_owned_candidate",
        ]
        .as_slice(),
        AuthorityMode::Apply | AuthorityMode::Integrate => {
            return Err(CoreError::safe("authority_denied"));
        }
    };
    if !reads.contains(&"selected_source_bytes")
        || reads.iter().any(|read| !allowed_reads.contains(read))
        || !writes.contains(&"tool_owned_state")
        || writes.iter().any(|write| !allowed_writes.contains(write))
        || !strings("commands")?.is_empty()
        || manifest
            .get("executor")
            .is_some_and(|value| !value.is_null())
    {
        return Err(CoreError::safe("authority_denied"));
    }
    let network = strings("network_destinations")?;
    let egress = strings("egress_classes")?;
    let model = manifest.get("model").and_then(Value::as_str);
    if !network.is_empty() || model.is_some() || !egress.is_empty() {
        return Err(CoreError::safe("authority_denied"));
    }
    authority_budget(authority)?;
    Ok(())
}

fn authority_budget(authority: &AuthorityManifest) -> Result<BudgetLedger, CoreError> {
    let budget = authority
        .manifest
        .get("budget")
        .and_then(Value::as_object)
        .ok_or_else(|| CoreError::safe("authority_denied"))?;
    let expected = [
        "attempts",
        "bytes",
        "input_tokens",
        "output_tokens",
        "wall_ms",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    if budget.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected {
        return Err(CoreError::safe("authority_denied"));
    }
    let value = |key: &str| {
        budget
            .get(key)
            .and_then(Value::as_u64)
            .ok_or_else(|| CoreError::safe("authority_denied"))
    };
    Ok(BudgetLedger {
        wall_ms: value("wall_ms")?,
        input_tokens: value("input_tokens")?,
        output_tokens: value("output_tokens")?,
        bytes: value("bytes")?,
        attempts: value("attempts")?,
    })
}

fn is_safe_name(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && value.as_bytes()[0].is_ascii_lowercase()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_.-".contains(&byte)
        })
}

fn valid_idempotency_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.:-".contains(&byte))
}

fn valid_media_type(value: &str) -> bool {
    let Some((kind, subtype)) = value.split_once('/') else {
        return false;
    };
    let token = |part: &str| {
        !part.is_empty()
            && part.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'+' | b'-')
            })
    };
    token(kind) && token(subtype) && !subtype.contains('/')
}

fn ensure_private_dir(path: &Path) -> Result<(), CoreError> {
    if !path.is_absolute() {
        return Err(CoreError::safe("invalid_state_root"));
    }
    if path.exists() {
        let metadata =
            fs::symlink_metadata(path).map_err(|_| CoreError::safe("invalid_state_root"))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(CoreError::safe("invalid_state_root"));
        }
        #[cfg(unix)]
        {
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(CoreError::safe("invalid_state_root"));
            }
            if let Some(parent) = path.parent()
                && parent.exists()
                && fs::symlink_metadata(parent)?.uid() != metadata.uid()
            {
                return Err(CoreError::safe("invalid_state_root"));
            }
        }
    } else {
        fs::create_dir_all(path)?;
        #[cfg(unix)]
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn ensure_private_file(path: &Path) -> Result<(), CoreError> {
    if path.exists() {
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(CoreError::safe("invalid_state_root"));
        }
        #[cfg(unix)]
        {
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(CoreError::safe("invalid_state_root"));
            }
            if let Some(parent) = path.parent()
                && fs::symlink_metadata(parent)?.uid() != metadata.uid()
            {
                return Err(CoreError::safe("invalid_state_root"));
            }
        }
        return Ok(());
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    options.open(path)?;
    Ok(())
}

fn reject_symlink(path: &Path) -> Result<(), CoreError> {
    if path.exists() {
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() {
            return Err(CoreError::safe("invalid_state_root"));
        }
    }
    Ok(())
}

fn write_cas_file(root: &Path, destination: &Path, bytes: &[u8]) -> Result<(), CoreError> {
    if !destination.starts_with(root) {
        return Err(CoreError::safe("artifact_invalid"));
    }
    if let Some(parent) = destination.parent() {
        ensure_private_dir(parent)?;
    }
    let tmp_dir = root.join("tmp");
    ensure_private_dir(&tmp_dir)?;
    let tmp = tmp_dir.join(format!("artifact-{}", Uuid::now_v7()));
    {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    match fs::hard_link(&tmp, destination) {
        Ok(()) => {
            fs::remove_file(&tmp)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            fs::remove_file(&tmp)?;
            let existing =
                fs::read(destination).map_err(|_| CoreError::safe("artifact_invalid"))?;
            verify_artifact_bytes(
                &artifact_id(bytes),
                &existing,
                u64::try_from(bytes.len()).map_err(|_| CoreError::safe("artifact_invalid"))?,
            )?;
        }
        Err(_) => return Err(CoreError::safe("artifact_invalid")),
    }
    sync_parent(destination)?;
    Ok(())
}

fn verify_artifact_bytes(id: &str, bytes: &[u8], expected_len: u64) -> Result<(), CoreError> {
    let actual_len = u64::try_from(bytes.len()).map_err(|_| CoreError::safe("artifact_invalid"))?;
    if actual_len != expected_len {
        return Err(CoreError::safe("artifact_invalid"));
    }
    let expected = id
        .strip_prefix("sha256:")
        .ok_or_else(|| CoreError::safe("artifact_invalid"))?;
    let observed = sha256_hex(bytes);
    if observed.as_bytes().ct_eq(expected.as_bytes()).unwrap_u8() != 1 {
        return Err(CoreError::safe("artifact_invalid"));
    }
    Ok(())
}

fn validate_artifact_id(value: &str) -> Result<(), CoreError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(CoreError::safe("artifact_invalid"));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(CoreError::safe("artifact_invalid"));
    }
    Ok(())
}

fn prefixed_id(prefix: &str) -> String {
    format!("{prefix}_{}", Uuid::now_v7())
}

fn now_rfc3339() -> Result<String, CoreError> {
    OffsetDateTime::now_utc()
        .format(&format_description!(
            "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:6]Z"
        ))
        .map_err(|_| CoreError::safe("state_unavailable"))
}

fn json_text<T: Serialize>(value: &T) -> Result<String, CoreError> {
    serde_json::to_string(value).map_err(CoreError::from)
}

fn canonical_text(value: &Value) -> Result<String, CoreError> {
    String::from_utf8(canonical_json(value).map_err(|_| CoreError::safe("state_corrupt"))?)
        .map_err(|_| CoreError::safe("state_corrupt"))
}

fn parse_mode(value: &str) -> Result<AuthorityMode, CoreError> {
    match value {
        "inspect" => Ok(AuthorityMode::Inspect),
        "audit" => Ok(AuthorityMode::Audit),
        "draft" => Ok(AuthorityMode::Draft),
        "apply" => Ok(AuthorityMode::Apply),
        "integrate" => Ok(AuthorityMode::Integrate),
        _ => Err(CoreError::safe("state_corrupt")),
    }
}

fn parse_cleanup(value: &str) -> Result<CleanupState, CoreError> {
    match value {
        "not_required" => Ok(CleanupState::NotRequired),
        "pending" => Ok(CleanupState::Pending),
        "completed" => Ok(CleanupState::Completed),
        "failed" => Ok(CleanupState::Failed),
        _ => Err(CoreError::safe("state_corrupt")),
    }
}

fn file_digest(path: &Path) -> Result<String, CoreError> {
    let bytes = fs::read(path)?;
    Ok(sha256_hex(&bytes))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push(char::from(b"0123456789abcdef"[(byte >> 4) as usize]));
        output.push(char::from(b"0123456789abcdef"[(byte & 0x0f) as usize]));
    }
    output
}

fn sql_i64(value: u64) -> Result<i64, CoreError> {
    i64::try_from(value).map_err(|_| CoreError::safe("budget_exceeded"))
}

fn sql_u64(value: i64) -> Result<u64, CoreError> {
    u64::try_from(value).map_err(|_| CoreError::safe("state_corrupt"))
}

fn sql_bool(value: i64) -> Result<bool, CoreError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(CoreError::safe("state_corrupt")),
    }
}

fn push_fact(markdown: &mut String, key: &str, value: &str) {
    markdown.push_str("- `");
    markdown.push_str(key);
    markdown.push_str("`: `");
    markdown.push_str(value);
    markdown.push_str("`\n");
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn store() -> (TempDir, CoreStore) {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("state");
        let store = CoreStore::open(&root).unwrap();
        (tmp, store)
    }

    fn sqlite_family(path: &Path) -> Vec<(String, String)> {
        let prefix = path.file_name().unwrap().to_string_lossy();
        let mut files = fs::read_dir(path.parent().unwrap())
            .unwrap()
            .filter_map(Result::ok)
            .filter_map(|entry| {
                let name = entry.file_name().to_string_lossy().into_owned();
                name.starts_with(prefix.as_ref()).then(|| {
                    let digest = file_digest(&entry.path()).unwrap();
                    (name, digest)
                })
            })
            .collect::<Vec<_>>();
        files.sort();
        files
    }

    fn budget() -> BudgetLedger {
        BudgetLedger {
            wall_ms: 1_000,
            input_tokens: 100,
            output_tokens: 100,
            bytes: 1_000,
            attempts: 5,
        }
    }

    fn authority(mode: AuthorityMode) -> AuthorityManifest {
        let manifest = json!({
            "reads": match mode {
                AuthorityMode::Inspect => vec!["selected_source_bytes"],
                _ => vec!["selected_source_bytes", "safe_artifacts"],
            },
            "writes": match mode {
                AuthorityMode::Draft => vec!["tool_owned_state", "tool_owned_snapshot", "tool_owned_candidate"],
                _ => vec!["tool_owned_state"],
            },
            "commands": [],
            "executor": null,
            "network_destinations": [],
            "environment_names": [],
            "model": null,
            "budget": {
                "wall_ms": 1_000,
                "input_tokens": 100,
                "output_tokens": 100,
                "bytes": 1_000,
                "attempts": 5,
            },
            "egress_classes": [],
            "retention": {},
            "cancellation": "supervisor_verified",
            "cleanup": "tool_owned_state_only",
        });
        AuthorityManifest {
            schema_uri: format!("{SCHEMA_BASE}authority.schema.json"),
            schema_version: SCHEMA_VERSION.to_owned(),
            authority_id: "auth_019f0000-0000-7000-8000-000000000001".to_owned(),
            subject_id: format!("action_snap_sha256_{}", "b".repeat(64)),
            mode,
            manifest_digest: format!("sha256:{}", sha256_hex(&canonical_json(&manifest).unwrap())),
            manifest,
            approved_at: "2026-07-19T00:00:00.000000Z".to_owned(),
            expires_at: Some("2027-07-19T00:00:00.000000Z".to_owned()),
            approval_origin: "interactive_local".to_owned(),
            revoked: false,
            snapshot_id: format!("snap_sha256_{}", "b".repeat(64)),
        }
    }

    fn resign(authority: &mut AuthorityManifest) {
        authority.manifest_digest = format!(
            "sha256:{}",
            sha256_hex(&canonical_json(&authority.manifest).unwrap())
        );
    }

    fn create_python_v2(path: &Path) -> (String, String, String) {
        let run_id = "run_019f0000-0000-7000-8000-000000000010".to_owned();
        let event_one = "evt_019f0000-0000-7000-8000-000000000011".to_owned();
        let event_two = "evt_019f0000-0000-7000-8000-000000000012".to_owned();
        let stage_id = "stage_019f0000-0000-7000-8000-000000000013".to_owned();
        let timestamp = "2026-07-19T12:00:00.000000Z";
        let run = json!({
            "schema_uri": format!("{SCHEMA_BASE}run.schema.json"),
            "schema_version": SCHEMA_VERSION,
            "run_id": run_id,
            "snapshot_id": format!("snap_sha256_{}", "c".repeat(64)),
            "authority_ids": ["auth_019f0000-0000-7000-8000-000000000014"],
            "mode": "audit",
            "status": "created",
            "highest_support_level": "L0",
            "digests": {},
            "counters": {},
            "budgets": {},
            "cleanup_state": "not_required",
            "created_at": timestamp,
            "last_sequence": 2,
        });
        let event = |id: &str, sequence: u64, event_type: &str| {
            json!({
                "schema_uri": format!("{SCHEMA_BASE}event.schema.json"),
                "schema_version": SCHEMA_VERSION,
                "event_id": id,
                "run_id": run_id,
                "sequence": sequence,
                "occurred_at": timestamp,
                "type": event_type,
                "payload_schema": format!("{SCHEMA_BASE}events/{}.schema.json", event_type.replace('.', "-")),
                "payload_version": SCHEMA_VERSION,
                "payload": {"reason": event_type},
                "artifact_refs": [],
            })
        };
        let first = event(&event_one, 1, "run.created");
        let second = event(&event_two, 2, "stage.created");
        let stage = json!({
            "schema_uri": format!("{SCHEMA_BASE}stage.schema.json"),
            "schema_version": SCHEMA_VERSION,
            "stage_id": stage_id,
            "run_id": run_id,
            "kind": "scan",
            "state": "created",
            "attempt": 0,
            "max_attempts": 2,
            "retryable": true,
            "input_artifact_refs": [],
            "output_artifact_refs": [],
            "timing": {},
            "resources": {},
        });
        let conn = Connection::open(path).unwrap();
        conn.execute_batch(
            "CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY,applied_at_microseconds INTEGER NOT NULL,application_version TEXT NOT NULL) STRICT;
             CREATE TABLE runs(run_id TEXT PRIMARY KEY,status TEXT NOT NULL,last_sequence INTEGER NOT NULL CHECK(last_sequence>=0),entity_json BLOB NOT NULL,updated_at_microseconds INTEGER NOT NULL) STRICT;
             CREATE TABLE events(event_id TEXT PRIMARY KEY,run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE RESTRICT,sequence INTEGER NOT NULL CHECK(sequence>=1),event_type TEXT NOT NULL,entity_json BLOB NOT NULL,occurred_at TEXT NOT NULL,UNIQUE(run_id,sequence)) STRICT;
             CREATE TABLE stages(stage_id TEXT PRIMARY KEY,run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE RESTRICT,state TEXT NOT NULL,entity_json BLOB NOT NULL,updated_at_microseconds INTEGER NOT NULL) STRICT;
             CREATE TABLE idempotency(run_id TEXT NOT NULL,operation TEXT NOT NULL,key TEXT NOT NULL,request_digest TEXT NOT NULL,response_json BLOB NOT NULL,created_at_microseconds INTEGER NOT NULL,PRIMARY KEY(run_id,operation,key)) STRICT;
             CREATE TABLE artifacts(artifact_id TEXT PRIMARY KEY,class TEXT NOT NULL,media_type TEXT NOT NULL,byte_count INTEGER NOT NULL CHECK(byte_count>=0),relative_path TEXT NOT NULL UNIQUE,complete INTEGER NOT NULL CHECK(complete IN(0,1)),quarantined INTEGER NOT NULL CHECK(quarantined IN(0,1)),pinned INTEGER NOT NULL CHECK(pinned IN(0,1)),retention_until_microseconds INTEGER,created_at_microseconds INTEGER NOT NULL) STRICT;
             CREATE TABLE artifact_refs(artifact_id TEXT NOT NULL REFERENCES artifacts(artifact_id) ON DELETE RESTRICT,owner_type TEXT NOT NULL,owner_id TEXT NOT NULL,PRIMARY KEY(artifact_id,owner_type,owner_id)) STRICT;
             PRAGMA user_version=1;",
        )
        .unwrap();
        conn.execute("INSERT INTO schema_migrations VALUES(1,1,'0.1.0')", [])
            .unwrap();
        conn.execute(
            "INSERT INTO runs VALUES(?1,'created',2,?2,1)",
            params![run_id, serde_json::to_vec(&run).unwrap()],
        )
        .unwrap();
        for value in [&first, &second] {
            conn.execute(
                "INSERT INTO events VALUES(?1,?2,?3,?4,?5,?6)",
                params![
                    value["event_id"].as_str().unwrap(),
                    run_id,
                    i64::try_from(value["sequence"].as_u64().unwrap()).unwrap(),
                    value["type"].as_str().unwrap(),
                    serde_json::to_vec(value).unwrap(),
                    timestamp,
                ],
            )
            .unwrap();
        }
        conn.execute(
            "INSERT INTO stages VALUES(?1,?2,'created',?3,1)",
            params![stage_id, run_id, serde_json::to_vec(&stage).unwrap()],
        )
        .unwrap();
        drop(conn);
        #[cfg(unix)]
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        (run_id, event_one, stage_id)
    }

    fn replace_python_event_id(path: &Path, replacement: &str) {
        let conn = Connection::open(path).unwrap();
        let bytes: Vec<u8> = conn
            .query_row(
                "SELECT entity_json FROM events WHERE sequence=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let mut event: Value = serde_json::from_slice(&bytes).unwrap();
        event["event_id"] = json!(replacement);
        conn.execute(
            "UPDATE events SET event_id=?1,entity_json=?2 WHERE sequence=1",
            params![replacement, serde_json::to_vec(&event).unwrap()],
        )
        .unwrap();
    }

    #[test]
    fn authority_modes_are_explicit_and_do_not_fall_back_to_apply() {
        assert!(!AuthorityMode::Draft.permits_ceiling(AuthorityAction::ExternalModelEgress));
        assert!(!AuthorityMode::Inspect.permits_ceiling(AuthorityAction::ExternalModelEgress));
        let (_tmp, mut store) = store();
        let error = store
            .create_run(&authority(AuthorityMode::Apply), budget())
            .unwrap_err();
        assert_eq!(error.code, "invalid_authority_mode");
        assert!(!error.safe_message.contains("snap_sha256"));
    }

    #[test]
    fn authority_contract_rejects_forgery_expiry_revocation_and_escalation() {
        let valid = authority(AuthorityMode::Audit);
        assert!(!valid.permits(AuthorityAction::ExternalModelEgress));
        assert!(valid.permits(AuthorityAction::ReadSafeArtifacts));
        assert!(!valid.permits(AuthorityAction::WriteCandidateArtifacts));

        let mut narrow = valid.clone();
        narrow.manifest["reads"] = json!(["selected_source_bytes"]);
        resign(&mut narrow);
        assert!(validate_authority(&narrow).is_ok());
        assert!(!narrow.permits(AuthorityAction::ReadSafeArtifacts));

        let mut forged = valid.clone();
        forged.manifest_digest = format!("sha256:{}", "0".repeat(64));
        assert_eq!(
            validate_authority(&forged).unwrap_err().code,
            "authority_denied"
        );

        let mut revoked = valid.clone();
        revoked.revoked = true;
        assert_eq!(
            validate_authority(&revoked).unwrap_err().code,
            "authority_denied"
        );

        let mut expired = valid.clone();
        expired.expires_at = Some("2026-07-18T00:00:00.000000Z".to_owned());
        assert_eq!(
            validate_authority(&expired).unwrap_err().code,
            "authority_denied"
        );

        let mut write = valid.clone();
        write.manifest["writes"] = json!(["tool_owned_state", "target_repository"]);
        resign(&mut write);
        assert_eq!(
            validate_authority(&write).unwrap_err().code,
            "authority_denied"
        );

        let mut command = valid.clone();
        command.manifest["commands"] = json!(["cargo test"]);
        resign(&mut command);
        assert_eq!(
            validate_authority(&command).unwrap_err().code,
            "authority_denied"
        );

        let mut network = valid.clone();
        network.manifest["network_destinations"] = json!(["api.openai.com"]);
        network.manifest["model"] = json!("gpt-5");
        network.manifest["egress_classes"] = json!(["D1"]);
        resign(&mut network);
        assert_eq!(
            validate_authority(&network).unwrap_err().code,
            "authority_denied"
        );

        let mut read = valid.clone();
        read.manifest["reads"] = json!(["selected_source_bytes", "/etc/passwd"]);
        resign(&mut read);
        assert_eq!(
            validate_authority(&read).unwrap_err().code,
            "authority_denied"
        );

        let mut unknown = valid.contract_value().unwrap();
        unknown["unexpected"] = json!(true);
        assert_eq!(
            AuthorityManifest::from_contract_json(
                &valid.snapshot_id,
                &serde_json::to_vec(&unknown).unwrap(),
            )
            .unwrap_err()
            .code,
            "authority_denied"
        );

        let mut unknown_budget = valid.clone();
        unknown_budget.manifest["budget"]["cpu_ms"] = json!(1);
        resign(&mut unknown_budget);
        assert_eq!(
            validate_authority(&unknown_budget).unwrap_err().code,
            "authority_denied"
        );

        let (_tmp, mut store) = store();
        let mut over = budget();
        over.attempts = 6;
        assert_eq!(
            store.create_run(&valid, over).unwrap_err().code,
            "budget_exceeded"
        );
    }

    #[test]
    fn run_stage_transitions_lease_recovery_and_cancel_are_typed() {
        let (_tmp, mut store) = store();
        let run = store
            .create_run(&authority(AuthorityMode::Audit), budget())
            .unwrap();
        let stage = store.add_stage(&run.run_id, "discovery", 2).unwrap();
        let error = store
            .transition_stage(&stage.stage_id, StageState::Completed)
            .unwrap_err();
        assert_eq!(error.code, "invalid_transition");

        store
            .transition_run(&run.run_id, RunStatus::Queued)
            .unwrap();
        store
            .transition_run(&run.run_id, RunStatus::Running)
            .unwrap();
        store
            .transition_stage(&stage.stage_id, StageState::Queued)
            .unwrap();
        let leased = store
            .acquire_lease(&stage.stage_id, "worker-a", 100, 10)
            .unwrap();
        assert_eq!(leased.state, StageState::Running);
        assert_eq!(store.recover_expired_leases(111, true).unwrap(), 1);
        assert_eq!(
            store.stage(&stage.stage_id).unwrap().state,
            StageState::Interrupted
        );
        assert_eq!(
            store.run(&run.run_id).unwrap().status,
            RunStatus::Interrupted
        );

        let resumed = store
            .transition_run(&run.run_id, RunStatus::Queued)
            .unwrap();
        assert_eq!(resumed.status, RunStatus::Queued);
        let cancelling = store.request_cancel(&run.run_id).unwrap();
        assert_eq!(cancelling.status, RunStatus::Cancelling);
        store
            .mark_cleanup(&run.run_id, CleanupState::Completed)
            .unwrap();
        let cancelled = store.confirm_cancelled(&run.run_id, true).unwrap();
        assert_eq!(cancelled.status, RunStatus::Cancelled);
    }

    #[test]
    fn budget_accounting_fails_closed_without_mutating_counters() {
        let (_tmp, mut store) = store();
        let run = store
            .create_run(&authority(AuthorityMode::Inspect), budget())
            .unwrap();
        let ok = store
            .record_budget(
                &run.run_id,
                &BudgetLedger {
                    attempts: 1,
                    bytes: 10,
                    ..BudgetLedger::default()
                },
            )
            .unwrap();
        assert_eq!(ok.counters.attempts, 1);
        let error = store
            .record_budget(
                &run.run_id,
                &BudgetLedger {
                    attempts: 10,
                    ..BudgetLedger::default()
                },
            )
            .unwrap_err();
        assert_eq!(error.code, "budget_exceeded");
        assert_eq!(store.run(&run.run_id).unwrap().counters.attempts, 1);

        let delta = BudgetLedger {
            attempts: 1,
            ..BudgetLedger::default()
        };
        store
            .record_budget_idempotent(&run.run_id, &delta, "budget-0001")
            .unwrap();
        store
            .record_budget_idempotent(&run.run_id, &delta, "budget-0001")
            .unwrap();
        assert_eq!(store.run(&run.run_id).unwrap().counters.attempts, 2);
        assert_eq!(
            store
                .record_budget_idempotent(
                    &run.run_id,
                    &BudgetLedger {
                        attempts: 2,
                        ..BudgetLedger::default()
                    },
                    "budget-0001",
                )
                .unwrap_err()
                .code,
            "idempotency_conflict"
        );
    }

    #[test]
    fn cas_artifacts_are_confined_integrity_checked_and_access_controlled() {
        let (_tmp, mut store) = store();
        let safe = store
            .put_artifact(
                b"safe",
                "text/plain",
                ArtifactClass::Safe,
                "test",
                &format!("sha256:{}", "f".repeat(64)),
                false,
            )
            .unwrap();
        assert_eq!(
            store
                .read_artifact(&safe.artifact_id, ArtifactAccess::default())
                .unwrap(),
            b"safe"
        );

        let protected = store
            .put_artifact(
                b"secret-token",
                "text/plain",
                ArtifactClass::Protected,
                "test",
                &format!("sha256:{}", "f".repeat(64)),
                false,
            )
            .unwrap();
        let denied = store
            .read_artifact(&protected.artifact_id, ArtifactAccess::default())
            .unwrap_err();
        assert_eq!(denied.code, "artifact_forbidden");
        assert_eq!(
            store
                .read_artifact(
                    &protected.artifact_id,
                    ArtifactAccess {
                        protected: true,
                        executable: false
                    }
                )
                .unwrap(),
            b"secret-token"
        );

        let path = store.artifact_path(&safe.artifact_id).unwrap();
        fs::write(path, b"tampered").unwrap();
        assert_eq!(store.reconcile_artifacts().unwrap(), 1);
        assert!(store.artifact(&safe.artifact_id).unwrap().quarantined);
    }

    #[test]
    fn receipts_require_terminal_stages_cleanup_and_budget_evidence() {
        let (_tmp, mut store) = store();
        let run = store
            .create_run(&authority(AuthorityMode::Audit), budget())
            .unwrap();
        let stage = store.add_stage(&run.run_id, "audit", 1).unwrap();
        store
            .transition_run(&run.run_id, RunStatus::Queued)
            .unwrap();
        store
            .transition_run(&run.run_id, RunStatus::Running)
            .unwrap();
        assert_eq!(
            store
                .complete_run(&run.run_id, RunStatus::Completed)
                .unwrap_err()
                .code,
            "receipt_gate_unmet"
        );
        store
            .transition_stage(&stage.stage_id, StageState::Queued)
            .unwrap();
        store
            .acquire_lease(&stage.stage_id, "worker", 1, 100)
            .unwrap();
        store
            .transition_stage(&stage.stage_id, StageState::Completed)
            .unwrap();
        store
            .record_budget(
                &run.run_id,
                &BudgetLedger {
                    attempts: 1,
                    ..BudgetLedger::default()
                },
            )
            .unwrap();
        store
            .mark_cleanup(&run.run_id, CleanupState::Completed)
            .unwrap();
        let completed = store
            .complete_run_idempotent(&run.run_id, RunStatus::Completed, "complete-1")
            .unwrap();
        assert_eq!(
            store
                .complete_run_idempotent(&run.run_id, RunStatus::Completed, "complete-1")
                .unwrap()
                .receipt_id,
            completed.receipt_id
        );
        assert!(completed.receipt_id.unwrap().starts_with("receipt_sha256_"));
    }

    #[test]
    fn json_and_markdown_reports_share_one_projection() {
        let (_tmp, mut store) = store();
        let run = store
            .create_run(&authority(AuthorityMode::Inspect), budget())
            .unwrap();
        let stage = store.add_stage(&run.run_id, "inventory", 1).unwrap();
        store
            .transition_run(&run.run_id, RunStatus::Queued)
            .unwrap();
        store
            .transition_run(&run.run_id, RunStatus::Running)
            .unwrap();
        store
            .transition_stage(&stage.stage_id, StageState::Queued)
            .unwrap();
        store
            .acquire_lease(&stage.stage_id, "worker", 1, 100)
            .unwrap();
        store
            .transition_stage(&stage.stage_id, StageState::Completed)
            .unwrap();
        store
            .record_budget(
                &run.run_id,
                &BudgetLedger {
                    attempts: 1,
                    bytes: 5,
                    ..BudgetLedger::default()
                },
            )
            .unwrap();
        store
            .mark_cleanup(&run.run_id, CleanupState::Completed)
            .unwrap();
        let completed = store
            .complete_run(&run.run_id, RunStatus::CompletedNoFindings)
            .unwrap();
        let json_report = store.report_json(&run.run_id).unwrap();
        let markdown = store.report_markdown(&run.run_id).unwrap();
        let parsed: ReportProjection = serde_json::from_str(&json_report).unwrap();
        assert_eq!(parsed.run.run_id, completed.run_id);
        assert!(markdown.contains(&completed.run_id));
        assert!(markdown.contains("completed_no_findings"));
        assert_eq!(json_report, store.report_json(&run.run_id).unwrap());
    }

    #[test]
    fn migration_backup_import_and_rollback_are_supported() {
        let (tmp, mut store) = store();
        let run = store
            .create_run(&authority(AuthorityMode::Inspect), budget())
            .unwrap();
        let backup = store.backup().unwrap();
        store
            .create_run(&authority(AuthorityMode::Audit), budget())
            .unwrap();
        store.import_backup(&backup).unwrap();
        assert!(store.run(&run.run_id).is_ok());
        let missing = store
            .run("run_019f0000-0000-7000-8000-000000000000")
            .unwrap_err();
        assert_eq!(missing.code, "state_corrupt");

        let invalid = tmp.path().join("invalid.sqlite");
        fs::write(&invalid, b"not sqlite").unwrap();
        assert_eq!(
            store.import_backup(&invalid).unwrap_err().code,
            "backup_invalid"
        );
    }

    #[test]
    fn list_events_retained_floor_and_cancel_are_durable_and_idempotent() {
        let (tmp, mut store) = store();
        let first = store
            .create_run(&authority(AuthorityMode::Audit), budget())
            .unwrap();
        let second = store
            .create_run(&authority(AuthorityMode::Inspect), budget())
            .unwrap();
        assert_eq!(store.list_runs().unwrap()[0].run_id, second.run_id);
        let page = store.events_after(&first.run_id, 0, 100).unwrap();
        assert_eq!(page.retained_floor, 1);
        assert_eq!(page.events[0].event_type, "run.created");
        store.request_cancel(&first.run_id).unwrap();
        let sequence = store.run(&first.run_id).unwrap().last_sequence;
        store.request_cancel(&first.run_id).unwrap();
        assert_eq!(store.run(&first.run_id).unwrap().last_sequence, sequence);
        store
            .conn
            .execute(
                "DELETE FROM events WHERE run_id=?1 AND sequence=1",
                params![first.run_id],
            )
            .unwrap();
        assert_eq!(
            store.events_after(&first.run_id, 0, 100).unwrap_err().code,
            "event_cursor_expired"
        );
        let root = tmp.path().join("state");
        drop(store);
        let reopened = CoreStore::open(&root).unwrap();
        assert_eq!(reopened.run(&second.run_id).unwrap().run_id, second.run_id);
    }

    #[test]
    fn writer_lock_wal_reader_busy_and_verified_startup_recovery() {
        let (tmp, mut store) = store();
        let root = tmp.path().join("state");
        assert_eq!(
            CoreStore::open(&root).err().unwrap().code,
            "writer_conflict"
        );
        let run = store
            .create_run(&authority(AuthorityMode::Audit), budget())
            .unwrap();
        let reader = Connection::open_with_flags(
            root.join("state.sqlite"),
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        assert_eq!(
            reader
                .query_row("SELECT COUNT(*) FROM runs", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            1
        );
        let stage = store.add_stage(&run.run_id, "scan", 1).unwrap();
        store
            .transition_run(&run.run_id, RunStatus::Running)
            .unwrap();
        store
            .transition_stage(&stage.stage_id, StageState::Queued)
            .unwrap();
        store
            .acquire_lease(&stage.stage_id, "worker", 1, 1)
            .unwrap();
        assert_eq!(
            store.recover_startup_leases(3, false).unwrap_err().code,
            "lease_conflict"
        );
        drop(reader);
        drop(store);
        let mut reopened = CoreStore::open(&root).unwrap();
        assert_eq!(
            reopened.stage(&stage.stage_id).unwrap().state,
            StageState::Running
        );
        assert_eq!(reopened.recover_startup_leases(3, true).unwrap(), 1);

        let contender = Connection::open(root.join("state.sqlite")).unwrap();
        contender.execute_batch("BEGIN IMMEDIATE").unwrap();
        reopened
            .conn
            .busy_timeout(std::time::Duration::from_millis(1))
            .unwrap();
        assert_eq!(
            reopened
                .record_budget(&run.run_id, &BudgetLedger::default())
                .unwrap_err()
                .code,
            "state_unavailable"
        );
        contender.execute_batch("ROLLBACK").unwrap();
    }

    #[test]
    fn artifacts_are_run_scoped_and_gc_is_dry_run_class_reference_and_pin_safe() {
        let (_tmp, mut store) = store();
        let first = store
            .create_run(&authority(AuthorityMode::Audit), budget())
            .unwrap();
        let second = store
            .create_run(&authority(AuthorityMode::Audit), budget())
            .unwrap();
        let linked = store
            .put_run_artifact(
                &first.run_id,
                b"linked",
                "text/plain",
                ArtifactClass::Safe,
                "test",
                &format!("sha256:{}", "d".repeat(64)),
                false,
            )
            .unwrap();
        let other = store
            .put_run_artifact(
                &second.run_id,
                b"other",
                "text/plain",
                ArtifactClass::Safe,
                "test",
                &format!("sha256:{}", "d".repeat(64)),
                false,
            )
            .unwrap();
        let free = store
            .put_artifact(
                b"free",
                "text/plain",
                ArtifactClass::Safe,
                "test",
                &format!("sha256:{}", "d".repeat(64)),
                false,
            )
            .unwrap();
        store
            .put_artifact(
                b"pinned",
                "text/plain",
                ArtifactClass::Safe,
                "test",
                &format!("sha256:{}", "d".repeat(64)),
                true,
            )
            .unwrap();
        store
            .put_artifact(
                b"protected",
                "text/plain",
                ArtifactClass::Protected,
                "test",
                &format!("sha256:{}", "d".repeat(64)),
                false,
            )
            .unwrap();
        assert_eq!(
            store.artifacts_for_run(&first.run_id).unwrap(),
            vec![linked]
        );
        assert_eq!(
            store.artifacts_for_run(&second.run_id).unwrap(),
            vec![other]
        );
        let plan = store
            .garbage_collect(u64::try_from(i64::MAX).unwrap(), true)
            .unwrap();
        assert_eq!(plan.candidates, vec![free.artifact_id.clone()]);
        assert!(store.artifact_path(&free.artifact_id).unwrap().exists());
        assert_eq!(
            store
                .report_bytes(&first.run_id, ReportFormat::Json)
                .unwrap(),
            store.report_json(&first.run_id).unwrap().into_bytes()
        );
        assert_eq!(
            store
                .report_bytes(&first.run_id, ReportFormat::Markdown)
                .unwrap(),
            store.report_markdown(&first.run_id).unwrap().into_bytes()
        );
    }

    #[test]
    fn corrupt_negative_and_non_boolean_sql_values_fail_closed() {
        let (_tmp, mut store) = store();
        let run = store
            .create_run(&authority(AuthorityMode::Inspect), budget())
            .unwrap();
        store
            .conn
            .execute(
                "UPDATE runs SET last_sequence=-1 WHERE run_id=?1",
                params![run.run_id],
            )
            .unwrap();
        assert_eq!(store.run(&run.run_id).unwrap_err().code, "state_corrupt");
        let artifact = store
            .put_artifact(
                b"value",
                "text/plain",
                ArtifactClass::Safe,
                "test",
                &format!("sha256:{}", "e".repeat(64)),
                false,
            )
            .unwrap();
        store
            .conn
            .execute(
                "UPDATE artifacts SET pinned=2 WHERE artifact_id=?1",
                params![artifact.artifact_id],
            )
            .unwrap();
        assert_eq!(
            store.artifact(&artifact.artifact_id).unwrap_err().code,
            "state_corrupt"
        );
        assert_eq!(
            validate_entity_id("run_550e8400-e29b-41d4-a716-446655440000", "run")
                .unwrap_err()
                .code,
            "state_corrupt"
        );
        store
            .conn
            .execute(
                "UPDATE runs SET authority_id=upper(authority_id) WHERE run_id=?1",
                params![run.run_id],
            )
            .unwrap();
        assert_eq!(store.run(&run.run_id).unwrap_err().code, "state_corrupt");
    }

    #[test]
    fn python_v2_import_is_read_only_collision_safe_and_preserves_full_events() {
        let tmp = TempDir::new().unwrap();
        let source = tmp.path().join("python.sqlite");
        let (run_id, event_id, stage_id) = create_python_v2(&source);
        let source_before = sqlite_family(&source);
        let root = tmp.path().join("rust");
        let mut store = CoreStore::open(&root).unwrap();
        assert_eq!(store.import_python_v2(&source).unwrap(), 1);
        assert_eq!(sqlite_family(&source), source_before);
        let imported = store.run(&run_id).unwrap();
        assert_eq!(imported.last_sequence, 2);
        assert_eq!(imported.status, RunStatus::AwaitingAuthority);
        assert!(imported.legacy_report_only);
        assert_eq!(imported.budgets, BudgetLedger::default());
        assert!(imported.authority_digest.is_empty());
        assert_eq!(
            store.stage(&stage_id).unwrap().state,
            StageState::Interrupted
        );
        assert_eq!(
            store.add_stage(&run_id, "resume", 1).unwrap_err().code,
            "authority_denied"
        );
        let events = store.events_after(&run_id, 0, 100).unwrap().events;
        assert_eq!(events[0].event_id, event_id);
        assert_eq!(events[0].schema_version, SCHEMA_VERSION);
        assert_eq!(events[0].payload_version, SCHEMA_VERSION);
        assert_eq!(
            store.import_python_v2(&source).unwrap_err().code,
            "import_invalid"
        );
        assert_eq!(store.list_runs().unwrap().len(), 1);
        assert!(fs::read_dir(root.join("backups")).unwrap().next().is_some());
    }

    #[test]
    fn python_v2_import_rejects_uppercase_and_non_v7_entity_ids() {
        let tmp = TempDir::new().unwrap();
        let uppercase = tmp.path().join("uppercase.sqlite");
        create_python_v2(&uppercase);
        replace_python_event_id(&uppercase, "evt_019F0000-0000-7000-8000-000000000011");
        let v4 = tmp.path().join("v4.sqlite");
        create_python_v2(&v4);
        replace_python_event_id(&v4, "evt_550e8400-e29b-41d4-a716-446655440000");
        let mut store = CoreStore::open(&tmp.path().join("rust")).unwrap();
        assert_eq!(
            store.import_python_v2(&uppercase).unwrap_err().code,
            "import_invalid"
        );
        assert_eq!(
            store.import_python_v2(&v4).unwrap_err().code,
            "import_invalid"
        );
        assert!(store.list_runs().unwrap().is_empty());
    }

    #[test]
    fn python_v2_import_rejects_live_sidecars_without_mutating_them() {
        let tmp = TempDir::new().unwrap();
        let source = tmp.path().join("python.sqlite");
        create_python_v2(&source);
        fs::write(tmp.path().join("python.sqlite-wal"), b"synthetic-live-wal").unwrap();
        let source_before = sqlite_family(&source);
        let mut store = CoreStore::open(&tmp.path().join("rust")).unwrap();
        assert_eq!(
            store.import_python_v2(&source).unwrap_err().code,
            "import_invalid"
        );
        assert_eq!(sqlite_family(&source), source_before);
        assert!(store.list_runs().unwrap().is_empty());
    }

    #[test]
    fn open_fingerprints_and_migrates_python_v2_with_backup() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("state");
        fs::create_dir(&root).unwrap();
        #[cfg(unix)]
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let database = root.join("state.sqlite");
        let (run_id, _, _) = create_python_v2(&database);
        let store = CoreStore::open(&root).unwrap();
        assert_eq!(store.run(&run_id).unwrap().last_sequence, 2);
        let version: u32 = store
            .conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, CURRENT_SCHEMA);
        assert!(fs::read_dir(root.join("backups")).unwrap().next().is_some());
    }

    #[test]
    fn persisted_authority_is_revalidated_and_privileged_mutations_are_gated() {
        let (tmp, mut store) = store();
        let root = tmp.path().join("state");
        let run = store
            .create_run(&authority(AuthorityMode::Audit), budget())
            .unwrap();
        drop(store);
        let mut reopened = CoreStore::open(&root).unwrap();
        reopened.add_stage(&run.run_id, "scan", 1).unwrap();
        let contract: String = reopened
            .conn
            .query_row(
                "SELECT authority_contract FROM runs WHERE run_id=?1",
                params![run.run_id],
                |row| row.get(0),
            )
            .unwrap();
        let mut value: Value = serde_json::from_str(&contract).unwrap();
        assert_eq!(contract, canonical_text(&value).unwrap());
        value["revoked"] = json!(true);
        reopened
            .conn
            .execute(
                "UPDATE runs SET authority_contract=?2 WHERE run_id=?1",
                params![run.run_id, value.to_string()],
            )
            .unwrap();
        drop(reopened);
        let mut reopened = CoreStore::open(&root).unwrap();
        assert_eq!(
            reopened
                .add_stage(&run.run_id, "blocked", 1)
                .unwrap_err()
                .code,
            "authority_denied"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn orchestration_idempotency_is_durable_and_conflicts_on_changed_requests() {
        let (tmp, mut store) = store();
        let root = tmp.path().join("state");
        let approved = authority(AuthorityMode::Audit);
        let run = store
            .create_run_idempotent(&approved, budget(), "request-1")
            .unwrap();
        assert_eq!(
            store
                .create_run_idempotent(&approved, budget(), "request-1")
                .unwrap()
                .run_id,
            run.run_id
        );
        assert_eq!(store.list_runs().unwrap().len(), 1);
        let stage = store
            .add_stage_idempotent(&run.run_id, "scan", 1, "request-1")
            .unwrap();
        assert_eq!(
            store
                .add_stage_idempotent(&run.run_id, "scan", 1, "request-1")
                .unwrap()
                .stage_id,
            stage.stage_id
        );
        assert_eq!(
            store
                .add_stage_idempotent(&run.run_id, "other", 1, "request-1")
                .unwrap_err()
                .code,
            "idempotency_conflict"
        );
        let transitioned = store
            .transition_run_idempotent(&run.run_id, RunStatus::Preflight, "request-1")
            .unwrap();
        let sequence = transitioned.last_sequence;
        assert_eq!(
            store
                .transition_run_idempotent(&run.run_id, RunStatus::Preflight, "request-1")
                .unwrap()
                .last_sequence,
            sequence
        );
        drop(store);
        let mut reopened = CoreStore::open(&root).unwrap();
        assert_eq!(
            reopened
                .create_run_idempotent(&approved, budget(), "request-1")
                .unwrap()
                .run_id,
            run.run_id
        );
        assert_eq!(
            reopened
                .add_stage_idempotent(&run.run_id, "scan", 1, "request-1")
                .unwrap()
                .stage_id,
            stage.stage_id
        );
        reopened
            .transition_stage_idempotent(&stage.stage_id, StageState::Queued, "queue-1")
            .unwrap();
        let leased = reopened
            .acquire_lease_idempotent(&stage.stage_id, "worker", 1, 10, "lease-1")
            .unwrap();
        assert_eq!(
            reopened
                .acquire_lease_idempotent(&stage.stage_id, "worker", 1, 10, "lease-1")
                .unwrap(),
            leased
        );
        let counted = reopened
            .record_budget_idempotent(
                &run.run_id,
                &BudgetLedger {
                    attempts: 1,
                    ..BudgetLedger::default()
                },
                "budget-1",
            )
            .unwrap();
        assert_eq!(counted.counters.attempts, 1);
        assert_eq!(
            reopened
                .record_budget_idempotent(
                    &run.run_id,
                    &BudgetLedger {
                        attempts: 1,
                        ..BudgetLedger::default()
                    },
                    "budget-1",
                )
                .unwrap()
                .counters
                .attempts,
            1
        );
        reopened
            .mark_cleanup_idempotent(&run.run_id, CleanupState::Completed, "cleanup-1")
            .unwrap();
        reopened
            .request_cancel_idempotent(&run.run_id, "cancel-1")
            .unwrap();
        let cancel_sequence = reopened.run(&run.run_id).unwrap().last_sequence;
        assert_eq!(
            reopened
                .request_cancel_idempotent(&run.run_id, "cancel-1")
                .unwrap()
                .last_sequence,
            cancel_sequence
        );
        let cancelled = reopened
            .confirm_cancelled_idempotent(&run.run_id, true, "confirm-1")
            .unwrap();
        assert_eq!(cancelled.status, RunStatus::Cancelled);
        assert_eq!(
            reopened
                .confirm_cancelled_idempotent(&run.run_id, true, "confirm-1")
                .unwrap()
                .last_sequence,
            cancelled.last_sequence
        );
    }

    #[test]
    fn v4_migration_removes_resumable_authority_and_preserves_reports() {
        let (tmp, mut store) = store();
        let root = tmp.path().join("state");
        let run = store
            .create_run(&authority(AuthorityMode::Audit), budget())
            .unwrap();
        store
            .conn
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .unwrap();
        drop(store);
        let conn = Connection::open(root.join("state.sqlite")).unwrap();
        conn.execute_batch(
            "DROP INDEX idempotency_operation_key;
             ALTER TABLE runs DROP COLUMN legacy_report_only;
             ALTER TABLE runs DROP COLUMN authority_contract;
             PRAGMA user_version=4;",
        )
        .unwrap();
        drop(conn);
        let mut migrated = CoreStore::open(&root).unwrap();
        let imported = migrated.run(&run.run_id).unwrap();
        assert!(imported.legacy_report_only);
        assert_eq!(imported.status, RunStatus::AwaitingAuthority);
        assert_eq!(imported.budgets, BudgetLedger::default());
        assert!(imported.authority_digest.is_empty());
        assert!(migrated.report_json(&run.run_id).is_ok());
        assert_eq!(
            migrated
                .add_stage(&run.run_id, "resume", 1)
                .unwrap_err()
                .code,
            "authority_denied"
        );
        assert!(fs::read_dir(root.join("backups")).unwrap().next().is_some());
    }

    #[test]
    fn failed_v4_migration_rolls_back_without_partial_schema_changes() {
        let (tmp, mut store) = store();
        let root = tmp.path().join("state");
        let first = store
            .create_run(&authority(AuthorityMode::Audit), budget())
            .unwrap();
        let second = store
            .create_run(&authority(AuthorityMode::Inspect), budget())
            .unwrap();
        store
            .conn
            .execute_batch("DROP INDEX idempotency_operation_key")
            .unwrap();
        for run_id in [&first.run_id, &second.run_id] {
            store
                .conn
                .execute(
                    "INSERT INTO idempotency VALUES(?1,'legacy','same-key',?2,'ok')",
                    params![run_id, format!("sha256:{}", "d".repeat(64))],
                )
                .unwrap();
        }
        store
            .conn
            .execute_batch(
                "PRAGMA wal_checkpoint(TRUNCATE);
                 ALTER TABLE runs DROP COLUMN legacy_report_only;
                 ALTER TABLE runs DROP COLUMN authority_contract;
                 PRAGMA user_version=4;",
            )
            .unwrap();
        drop(store);
        assert_eq!(
            CoreStore::open(&root).err().unwrap().code,
            "migration_failed"
        );
        let conn = Connection::open_with_flags(
            root.join("state.sqlite"),
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let version: u32 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, 4);
        assert!(
            !table_columns(&conn, "runs")
                .unwrap()
                .contains(&"authority_contract".to_owned())
        );
        assert!(fs::read_dir(root.join("backups")).unwrap().next().is_some());
    }

    #[test]
    fn python_import_rejects_duplicate_json_and_invalid_reference_graphs() {
        let tmp = TempDir::new().unwrap();
        let duplicate = tmp.path().join("duplicate.sqlite");
        create_python_v2(&duplicate);
        let conn = Connection::open(&duplicate).unwrap();
        let bytes: Vec<u8> = conn
            .query_row("SELECT entity_json FROM runs", [], |row| row.get(0))
            .unwrap();
        let text = String::from_utf8(bytes).unwrap();
        let duplicate_json = format!("{{\"run_id\":\"duplicate\",{}", &text[1..]);
        conn.execute(
            "UPDATE runs SET entity_json=?1",
            params![duplicate_json.into_bytes()],
        )
        .unwrap();
        drop(conn);

        let invalid_ref = tmp.path().join("invalid-ref.sqlite");
        create_python_v2(&invalid_ref);
        let artifact_id = format!("sha256:{}", "a".repeat(64));
        let conn = Connection::open(&invalid_ref).unwrap();
        conn.execute(
            "INSERT INTO artifacts VALUES(?1,'safe','text/plain',0,'unused',0,0,0,NULL,1)",
            params![artifact_id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO artifact_refs VALUES(?1,'event','evt_019f0000-0000-7000-8000-000000000099')",
            params![artifact_id],
        )
        .unwrap();
        drop(conn);

        let mut store = CoreStore::open(&tmp.path().join("rust")).unwrap();
        assert_eq!(
            store.import_python_v2(&duplicate).unwrap_err().code,
            "import_invalid"
        );
        assert_eq!(
            store.import_python_v2(&invalid_ref).unwrap_err().code,
            "import_invalid"
        );
        assert!(store.list_runs().unwrap().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn python_import_rejects_symlinked_artifact_ancestors() {
        use std::os::unix::fs::symlink;

        let tmp = TempDir::new().unwrap();
        let source = tmp.path().join("python.sqlite");
        create_python_v2(&source);
        let bytes = b"protected";
        let id = artifact_id(bytes);
        let conn = Connection::open(&source).unwrap();
        conn.execute(
            "INSERT INTO artifacts VALUES(?1,'safe','text/plain',?2,'nested/value',1,0,0,NULL,1)",
            params![id, i64::try_from(bytes.len()).unwrap()],
        )
        .unwrap();
        drop(conn);
        let artifact_root = tmp.path().join("artifacts");
        let outside = tmp.path().join("outside");
        fs::create_dir(&artifact_root).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("value"), bytes).unwrap();
        symlink(&outside, artifact_root.join("nested")).unwrap();
        let mut store = CoreStore::open(&tmp.path().join("rust")).unwrap();
        assert_eq!(
            store.import_python_v2(&source).unwrap_err().code,
            "import_invalid"
        );
    }

    #[test]
    fn sqlite_open_checks_wal_foreign_keys_and_private_restore_files() {
        let (tmp, mut store) = store();
        let root = tmp.path().join("state");
        assert_eq!(
            store
                .conn
                .pragma_query_value::<String, _>(None, "journal_mode", |row| row.get(0))
                .unwrap(),
            "wal"
        );
        assert_eq!(
            store
                .conn
                .pragma_query_value::<i64, _>(None, "foreign_keys", |row| row.get(0))
                .unwrap(),
            1
        );
        let backup = store.backup().unwrap();
        #[cfg(unix)]
        assert_eq!(
            fs::symlink_metadata(&backup).unwrap().permissions().mode() & 0o077,
            0
        );
        let run = store
            .create_run(&authority(AuthorityMode::Inspect), budget())
            .unwrap();
        let old = std::mem::replace(&mut store.conn, Connection::open_in_memory().unwrap());
        drop(old);
        store.conn = restore_state_connection(&root, &backup).unwrap();
        assert!(store.run(&run.run_id).is_err());
        drop(store);

        let conn = Connection::open(root.join("state.sqlite")).unwrap();
        conn.pragma_update(None, "foreign_keys", "OFF").unwrap();
        conn.execute(
            "INSERT INTO stages VALUES('stage_019f0000-0000-7000-8000-000000000099','run_019f0000-0000-7000-8000-000000000099','scan','created',0,1,1,NULL)",
            [],
        )
        .unwrap();
        drop(conn);
        assert_eq!(CoreStore::open(&root).err().unwrap().code, "state_corrupt");
    }
}
