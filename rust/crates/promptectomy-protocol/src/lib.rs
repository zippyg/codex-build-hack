use std::collections::BTreeSet;

use promptectomy_contracts::{ContractError, parse_strict_json};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

mod supervisor;

pub use supervisor::{
    AdapterCancellation, AdapterSupervisor, SafeStderr, SupervisorConfig, SupervisorError,
};

pub const PROTOCOL_NAME: &str = "promptectomy.out_of_process";
pub const PROTOCOL_MAJOR: u16 = 1;
pub const PROTOCOL_MINOR: u16 = 0;
pub const MESSAGE_SCHEMA_VERSION: &str = "promptectomy.protocol.message.v1";
pub const MESSAGE_SCHEMA_PREFIX: &str = "promptectomy.protocol.message.v";
pub const DEFAULT_MAX_FRAME_BYTES: u32 = 1_048_576;
pub const DEFAULT_MAX_STRING_BYTES: u32 = 16_384;
pub const DEFAULT_MAX_ARRAY_ITEMS: u32 = 256;
pub const DEFAULT_MAX_OBJECT_MEMBERS: u32 = 256;
pub const DEFAULT_MAX_JSON_DEPTH: u16 = 32;

const HEADER_BYTES: usize = 4;
const HEADER_BYTES_U32: u32 = 4;
const MAX_WALL_TIME_MS: u64 = 86_400_000;
const MAX_CPU_MILLIS: u64 = 86_400_000;
const MAX_MEMORY_BYTES: u64 = 1_099_511_627_776;
const MAX_OUTPUT_BYTES: u64 = 1_073_741_824;
const MAX_ARTIFACT_BYTES: u64 = 268_435_456;
const MAX_TOKEN_BUDGET: u64 = 10_000_000;
const MAX_ATTEMPTS: u64 = 32;

pub type ProtocolResult<T> = Result<T, ProtocolError>;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("protocol frame exceeds {max} bytes: {actual}")]
    FrameTooLarge { max: usize, actual: usize },
    #[error("protocol frame was truncated: expected {expected} bytes, got {actual}")]
    TruncatedFrame { expected: usize, actual: usize },
    #[error("protocol frame contains duplicate JSON members")]
    DuplicateMember,
    #[error("protocol frame is not strict JSON")]
    InvalidJson,
    #[error("protocol frame contains an unknown field")]
    UnknownField,
    #[error("protocol frame uses an unknown message kind")]
    UnknownMessageKind,
    #[error("protocol major version is not supported: {major}")]
    UnknownMajor { major: u16 },
    #[error("protocol identity does not match")]
    ProtocolMismatch,
    #[error("protocol value exceeds bound: {field}")]
    BoundViolation { field: &'static str },
    #[error("protocol request operation is incompatible with endpoint")]
    IncompatibleOperation,
    #[error("protocol I/O failed")]
    Io,
}

impl From<std::io::Error> for ProtocolError {
    fn from(_: std::io::Error) -> Self {
        Self::Io
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ProtocolMessage {
    pub schema_version: String,
    pub message_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    pub body: MessageBody,
}

impl ProtocolMessage {
    pub fn hello(message_id: impl Into<String>, body: HelloBody) -> Self {
        Self {
            schema_version: MESSAGE_SCHEMA_VERSION.to_owned(),
            message_id: message_id.into(),
            request_id: None,
            body: MessageBody::Hello(body),
        }
    }

    pub const fn kind(&self) -> MessageKind {
        self.body.kind()
    }

    fn validate(&self, limits: &ProtocolLimits) -> ProtocolResult<()> {
        validate_message_schema(&self.schema_version)?;
        validate_safe_string(&self.message_id, "message_id", limits)?;
        if let Some(request_id) = &self.request_id {
            validate_safe_string(request_id, "request_id", limits)?;
        }
        self.body.validate(limits)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageKind {
    Hello,
    Ready,
    Request,
    Result,
    Cancel,
    Failure,
}

impl MessageKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Hello => "hello",
            Self::Ready => "ready",
            Self::Request => "request",
            Self::Result => "result",
            Self::Cancel => "cancel",
            Self::Failure => "failure",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(untagged)]
pub enum MessageBody {
    Hello(HelloBody),
    Ready(ReadyBody),
    Request(RequestBody),
    Result(ResultBody),
    Cancel(CancelBody),
    Failure(FailureBody),
}

impl MessageBody {
    pub const fn kind(&self) -> MessageKind {
        match self {
            Self::Hello(_) => MessageKind::Hello,
            Self::Ready(_) => MessageKind::Ready,
            Self::Request(_) => MessageKind::Request,
            Self::Result(_) => MessageKind::Result,
            Self::Cancel(_) => MessageKind::Cancel,
            Self::Failure(_) => MessageKind::Failure,
        }
    }

    fn validate(&self, limits: &ProtocolLimits) -> ProtocolResult<()> {
        match self {
            Self::Hello(value) => value.validate(limits),
            Self::Ready(value) => value.validate(limits),
            Self::Request(value) => value.validate(limits),
            Self::Result(value) => value.validate(limits),
            Self::Cancel(value) => value.validate(limits),
            Self::Failure(value) => value.validate(limits),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointKind {
    ControlPlane,
    PythonAdapter,
    TypeScriptAdapter,
    OciExecutor,
    AgentConnector,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    DiscoverPython,
    DiscoverTypeScript,
    NormalizeEvidence,
    ExecuteOci,
    AcceptOciBackend,
    RunAgentTask,
    CancelAgentTask,
}

impl OperationKind {
    const fn is_allowed_for(self, endpoint: EndpointKind) -> bool {
        match endpoint {
            EndpointKind::ControlPlane => false,
            EndpointKind::PythonAdapter => {
                matches!(self, Self::DiscoverPython | Self::NormalizeEvidence)
            }
            EndpointKind::TypeScriptAdapter => {
                matches!(self, Self::DiscoverTypeScript | Self::NormalizeEvidence)
            }
            EndpointKind::OciExecutor => matches!(self, Self::ExecuteOci | Self::AcceptOciBackend),
            EndpointKind::AgentConnector => {
                matches!(self, Self::RunAgentTask | Self::CancelAgentTask)
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolLimits {
    pub max_frame_bytes: u32,
    pub max_string_bytes: u32,
    pub max_array_items: u32,
    pub max_object_members: u32,
    pub max_json_depth: u16,
}

impl Default for ProtocolLimits {
    fn default() -> Self {
        Self {
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
            max_string_bytes: DEFAULT_MAX_STRING_BYTES,
            max_array_items: DEFAULT_MAX_ARRAY_ITEMS,
            max_object_members: DEFAULT_MAX_OBJECT_MEMBERS,
            max_json_depth: DEFAULT_MAX_JSON_DEPTH,
        }
    }
}

impl ProtocolLimits {
    pub fn validate(&self) -> ProtocolResult<()> {
        if self.max_frame_bytes < HEADER_BYTES_U32 || self.max_frame_bytes > DEFAULT_MAX_FRAME_BYTES
        {
            return Err(ProtocolError::BoundViolation {
                field: "max_frame_bytes",
            });
        }
        if self.max_string_bytes == 0 || self.max_string_bytes > DEFAULT_MAX_STRING_BYTES {
            return Err(ProtocolError::BoundViolation {
                field: "max_string_bytes",
            });
        }
        if self.max_array_items == 0 || self.max_array_items > DEFAULT_MAX_ARRAY_ITEMS {
            return Err(ProtocolError::BoundViolation {
                field: "max_array_items",
            });
        }
        if self.max_object_members == 0 || self.max_object_members > DEFAULT_MAX_OBJECT_MEMBERS {
            return Err(ProtocolError::BoundViolation {
                field: "max_object_members",
            });
        }
        if self.max_json_depth == 0 || self.max_json_depth > DEFAULT_MAX_JSON_DEPTH {
            return Err(ProtocolError::BoundViolation {
                field: "max_json_depth",
            });
        }
        Ok(())
    }

    fn intersect(&self, peer: &Self) -> ProtocolResult<Self> {
        let value = Self {
            max_frame_bytes: self.max_frame_bytes.min(peer.max_frame_bytes),
            max_string_bytes: self.max_string_bytes.min(peer.max_string_bytes),
            max_array_items: self.max_array_items.min(peer.max_array_items),
            max_object_members: self.max_object_members.min(peer.max_object_members),
            max_json_depth: self.max_json_depth.min(peer.max_json_depth),
        };
        value.validate()?;
        Ok(value)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HelloBody {
    pub protocol: String,
    pub major: u16,
    pub minor: u16,
    pub endpoint: EndpointKind,
    pub implementation: String,
    pub capabilities: Vec<String>,
    pub limits: ProtocolLimits,
}

impl HelloBody {
    pub fn new(
        endpoint: EndpointKind,
        implementation: impl Into<String>,
        capabilities: Vec<String>,
    ) -> Self {
        Self {
            protocol: PROTOCOL_NAME.to_owned(),
            major: PROTOCOL_MAJOR,
            minor: PROTOCOL_MINOR,
            endpoint,
            implementation: implementation.into(),
            capabilities,
            limits: ProtocolLimits::default(),
        }
    }

    fn validate(&self, limits: &ProtocolLimits) -> ProtocolResult<()> {
        if self.protocol != PROTOCOL_NAME {
            return Err(ProtocolError::ProtocolMismatch);
        }
        if self.major != PROTOCOL_MAJOR {
            return Err(ProtocolError::UnknownMajor { major: self.major });
        }
        validate_safe_string(&self.implementation, "implementation", limits)?;
        validate_string_vec(&self.capabilities, "capabilities", limits)?;
        self.limits.validate()
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NegotiatedProtocol {
    pub protocol: String,
    pub major: u16,
    pub minor: u16,
    pub local_endpoint: EndpointKind,
    pub peer_endpoint: EndpointKind,
    pub capabilities: Vec<String>,
    pub limits: ProtocolLimits,
}

impl NegotiatedProtocol {
    fn validate(&self, limits: &ProtocolLimits) -> ProtocolResult<()> {
        if self.protocol != PROTOCOL_NAME {
            return Err(ProtocolError::ProtocolMismatch);
        }
        if self.major != PROTOCOL_MAJOR {
            return Err(ProtocolError::UnknownMajor { major: self.major });
        }
        validate_string_vec(&self.capabilities, "capabilities", limits)?;
        self.limits.validate()
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReadyBody {
    pub negotiated: NegotiatedProtocol,
}

impl ReadyBody {
    fn validate(&self, limits: &ProtocolLimits) -> ProtocolResult<()> {
        self.negotiated.validate(limits)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Deadline {
    pub unix_epoch_ms: u64,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetLimits {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wall_time_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_millis: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_budget: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempts: Option<u64>,
}

impl BudgetLimits {
    fn validate(&self) -> ProtocolResult<()> {
        validate_optional_budget(self.wall_time_ms, MAX_WALL_TIME_MS, "wall_time_ms")?;
        validate_optional_budget(self.cpu_millis, MAX_CPU_MILLIS, "cpu_millis")?;
        validate_optional_budget(self.memory_bytes, MAX_MEMORY_BYTES, "memory_bytes")?;
        validate_optional_budget(self.output_bytes, MAX_OUTPUT_BYTES, "output_bytes")?;
        validate_optional_budget(self.artifact_bytes, MAX_ARTIFACT_BYTES, "artifact_bytes")?;
        validate_optional_budget(self.token_budget, MAX_TOKEN_BUDGET, "token_budget")?;
        validate_optional_budget(self.attempts, MAX_ATTEMPTS, "attempts")
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CancellationPolicy {
    pub cancel_token: String,
    pub poll_interval_ms: u64,
}

impl CancellationPolicy {
    fn validate(&self, limits: &ProtocolLimits) -> ProtocolResult<()> {
        validate_safe_string(&self.cancel_token, "cancel_token", limits)?;
        if self.poll_interval_ms == 0 || self.poll_interval_ms > 60_000 {
            return Err(ProtocolError::BoundViolation {
                field: "poll_interval_ms",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequestBody {
    pub endpoint: EndpointKind,
    pub operation: OperationKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline: Option<Deadline>,
    pub budgets: BudgetLimits,
    pub cancellation: CancellationPolicy,
    pub payload: Value,
}

impl RequestBody {
    fn validate(&self, limits: &ProtocolLimits) -> ProtocolResult<()> {
        if !self.operation.is_allowed_for(self.endpoint) {
            return Err(ProtocolError::IncompatibleOperation);
        }
        self.budgets.validate()?;
        self.cancellation.validate(limits)?;
        validate_json_bounds(&self.payload, limits)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultStatus {
    Completed,
    Failed,
    Unsupported,
    Cancelled,
    Interrupted,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SafeDiagnostic {
    pub code: String,
    pub safe_message: String,
}

impl SafeDiagnostic {
    fn validate(&self, limits: &ProtocolLimits) -> ProtocolResult<()> {
        validate_safe_string(&self.code, "diagnostic_code", limits)?;
        validate_safe_string(&self.safe_message, "diagnostic_message", limits)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResultBody {
    pub status: ResultStatus,
    pub payload: Value,
    pub artifact_refs: Vec<String>,
    pub budgets_used: BudgetLimits,
    pub diagnostics: Vec<SafeDiagnostic>,
}

impl ResultBody {
    fn validate(&self, limits: &ProtocolLimits) -> ProtocolResult<()> {
        validate_string_vec(&self.artifact_refs, "artifact_refs", limits)?;
        self.budgets_used.validate()?;
        if self.diagnostics.len() > usize::try_from(limits.max_array_items).unwrap_or(usize::MAX) {
            return Err(ProtocolError::BoundViolation {
                field: "diagnostics",
            });
        }
        for diagnostic in &self.diagnostics {
            diagnostic.validate(limits)?;
        }
        validate_json_bounds(&self.payload, limits)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CancelBody {
    pub target_request_id: String,
    pub reason: String,
}

impl CancelBody {
    fn validate(&self, limits: &ProtocolLimits) -> ProtocolResult<()> {
        validate_safe_string(&self.target_request_id, "target_request_id", limits)?;
        validate_safe_string(&self.reason, "cancel_reason", limits)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureCategory {
    Protocol,
    Unsupported,
    Policy,
    Budget,
    Adapter,
    Executor,
    Agent,
    Cancel,
    Internal,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureCode {
    ProtocolVersionMismatch,
    FrameTooLarge,
    InvalidJson,
    UnknownField,
    UnsupportedOperation,
    DeadlineExceeded,
    BudgetExceeded,
    Cancelled,
    AdapterFailed,
    ExecutorFailed,
    AgentFailed,
    Internal,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FailureBody {
    pub code: FailureCode,
    pub category: FailureCategory,
    pub retryable: bool,
    pub safe_message: String,
    pub next_action: String,
}

impl FailureBody {
    fn validate(&self, limits: &ProtocolLimits) -> ProtocolResult<()> {
        validate_safe_string(&self.safe_message, "safe_message", limits)?;
        validate_safe_string(&self.next_action, "next_action", limits)
    }
}

pub fn negotiate(local: &HelloBody, peer: &HelloBody) -> ProtocolResult<NegotiatedProtocol> {
    let default_limits = ProtocolLimits::default();
    local.validate(&default_limits)?;
    peer.validate(&default_limits)?;

    let local_caps = local.capabilities.iter().cloned().collect::<BTreeSet<_>>();
    let peer_caps = peer.capabilities.iter().cloned().collect::<BTreeSet<_>>();
    let capabilities = local_caps
        .intersection(&peer_caps)
        .cloned()
        .collect::<Vec<_>>();

    Ok(NegotiatedProtocol {
        protocol: PROTOCOL_NAME.to_owned(),
        major: PROTOCOL_MAJOR,
        minor: local.minor.min(peer.minor),
        local_endpoint: local.endpoint,
        peer_endpoint: peer.endpoint,
        capabilities,
        limits: local.limits.intersect(&peer.limits)?,
    })
}

pub async fn read_frame<R>(
    reader: &mut R,
    limits: &ProtocolLimits,
) -> ProtocolResult<ProtocolMessage>
where
    R: AsyncRead + Unpin,
{
    limits.validate()?;
    let mut header = [0_u8; HEADER_BYTES];
    read_exact_bounded(reader, &mut header).await?;
    let frame_len = u32::from_be_bytes(header);
    let max = usize::try_from(limits.max_frame_bytes).unwrap_or(usize::MAX);
    let actual = usize::try_from(frame_len).unwrap_or(usize::MAX);
    if actual > max {
        return Err(ProtocolError::FrameTooLarge { max, actual });
    }
    let mut payload = vec![0_u8; actual];
    read_exact_bounded(reader, &mut payload).await?;
    decode_message(&payload, limits)
}

pub async fn write_frame<W>(
    writer: &mut W,
    limits: &ProtocolLimits,
    message: &ProtocolMessage,
) -> ProtocolResult<()>
where
    W: AsyncWrite + Unpin,
{
    let payload = encode_message(message, limits)?;
    let frame_len = u32::try_from(payload.len()).map_err(|_| ProtocolError::FrameTooLarge {
        max: usize::try_from(limits.max_frame_bytes).unwrap_or(usize::MAX),
        actual: payload.len(),
    })?;
    writer.write_all(&frame_len.to_be_bytes()).await?;
    writer.write_all(&payload).await?;
    writer.flush().await?;
    Ok(())
}

pub fn encode_message(
    message: &ProtocolMessage,
    limits: &ProtocolLimits,
) -> ProtocolResult<Vec<u8>> {
    limits.validate()?;
    message.validate(limits)?;
    let body = serde_json::to_value(&message.body).map_err(|_| ProtocolError::InvalidJson)?;
    let envelope = RawEnvelopeOut {
        schema_version: MESSAGE_SCHEMA_VERSION,
        message_id: &message.message_id,
        request_id: message.request_id.as_deref(),
        kind: message.kind().as_str(),
        body,
    };
    let payload = serde_json::to_vec(&envelope).map_err(|_| ProtocolError::InvalidJson)?;
    let max = usize::try_from(limits.max_frame_bytes).unwrap_or(usize::MAX);
    if payload.len() > max {
        return Err(ProtocolError::FrameTooLarge {
            max,
            actual: payload.len(),
        });
    }
    let value = parse_json(&payload, limits)?;
    validate_json_bounds(&value, limits)?;
    Ok(payload)
}

pub fn decode_message(payload: &[u8], limits: &ProtocolLimits) -> ProtocolResult<ProtocolMessage> {
    limits.validate()?;
    let max = usize::try_from(limits.max_frame_bytes).unwrap_or(usize::MAX);
    if payload.len() > max {
        return Err(ProtocolError::FrameTooLarge {
            max,
            actual: payload.len(),
        });
    }
    let value = parse_json(payload, limits)?;
    validate_json_bounds(&value, limits)?;
    let raw = decode_value::<RawEnvelope>(value)?;
    validate_message_schema(&raw.schema_version)?;
    validate_safe_string(&raw.message_id, "message_id", limits)?;
    if let Some(request_id) = &raw.request_id {
        validate_safe_string(request_id, "request_id", limits)?;
    }
    let body = match raw.kind.as_str() {
        "hello" => MessageBody::Hello(decode_value(raw.body)?),
        "ready" => MessageBody::Ready(decode_value(raw.body)?),
        "request" => MessageBody::Request(decode_value(raw.body)?),
        "result" => MessageBody::Result(decode_value(raw.body)?),
        "cancel" => MessageBody::Cancel(decode_value(raw.body)?),
        "failure" => MessageBody::Failure(decode_value(raw.body)?),
        _ => return Err(ProtocolError::UnknownMessageKind),
    };
    let message = ProtocolMessage {
        schema_version: raw.schema_version,
        message_id: raw.message_id,
        request_id: raw.request_id,
        body,
    };
    message.validate(limits)?;
    Ok(message)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEnvelope {
    schema_version: String,
    message_id: String,
    #[serde(default)]
    request_id: Option<String>,
    kind: String,
    body: Value,
}

#[derive(Serialize)]
struct RawEnvelopeOut<'a> {
    schema_version: &'static str,
    message_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<&'a str>,
    kind: &'static str,
    body: Value,
}

async fn read_exact_bounded<R>(reader: &mut R, buffer: &mut [u8]) -> ProtocolResult<()>
where
    R: AsyncRead + Unpin,
{
    let mut read = 0;
    while read < buffer.len() {
        let amount = reader.read(&mut buffer[read..]).await?;
        if amount == 0 {
            return Err(ProtocolError::TruncatedFrame {
                expected: buffer.len(),
                actual: read,
            });
        }
        read += amount;
    }
    Ok(())
}

fn parse_json(payload: &[u8], limits: &ProtocolLimits) -> ProtocolResult<Value> {
    parse_strict_json(
        payload,
        usize::try_from(limits.max_frame_bytes).unwrap_or(usize::MAX),
    )
    .map_err(|error| map_contract_error(&error))
}

fn map_contract_error(error: &ContractError) -> ProtocolError {
    match error {
        ContractError::TooLarge(max) => ProtocolError::FrameTooLarge {
            max: *max,
            actual: max.saturating_add(1),
        },
        ContractError::DuplicateMember => ProtocolError::DuplicateMember,
        _ => ProtocolError::InvalidJson,
    }
}

fn decode_value<T>(value: Value) -> ProtocolResult<T>
where
    T: DeserializeOwned,
{
    serde_json::from_value(value).map_err(|error| {
        let message = error.to_string();
        if message.contains("unknown field") {
            ProtocolError::UnknownField
        } else {
            ProtocolError::InvalidJson
        }
    })
}

fn validate_message_schema(value: &str) -> ProtocolResult<()> {
    if value == MESSAGE_SCHEMA_VERSION {
        return Ok(());
    }
    let Some(version) = value.strip_prefix(MESSAGE_SCHEMA_PREFIX) else {
        return Err(ProtocolError::ProtocolMismatch);
    };
    let major = version
        .parse::<u16>()
        .map_err(|_| ProtocolError::ProtocolMismatch)?;
    Err(ProtocolError::UnknownMajor { major })
}

fn validate_json_bounds(value: &Value, limits: &ProtocolLimits) -> ProtocolResult<()> {
    validate_json_bounds_at(value, limits, 0)
}

fn validate_json_bounds_at(
    value: &Value,
    limits: &ProtocolLimits,
    depth: u16,
) -> ProtocolResult<()> {
    if depth > limits.max_json_depth {
        return Err(ProtocolError::BoundViolation { field: "depth" });
    }
    match value {
        Value::String(text) => validate_safe_string(text, "string", limits),
        Value::Array(items) => {
            if items.len() > usize::try_from(limits.max_array_items).unwrap_or(usize::MAX) {
                return Err(ProtocolError::BoundViolation { field: "array" });
            }
            for item in items {
                validate_json_bounds_at(item, limits, depth.saturating_add(1))?;
            }
            Ok(())
        }
        Value::Object(items) => {
            if items.len() > usize::try_from(limits.max_object_members).unwrap_or(usize::MAX) {
                return Err(ProtocolError::BoundViolation { field: "object" });
            }
            for (key, item) in items {
                validate_safe_string(key, "object_key", limits)?;
                validate_json_bounds_at(item, limits, depth.saturating_add(1))?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn validate_safe_string(
    value: &str,
    field: &'static str,
    limits: &ProtocolLimits,
) -> ProtocolResult<()> {
    if value.is_empty()
        || value.len() > usize::try_from(limits.max_string_bytes).unwrap_or(usize::MAX)
        || value.chars().any(char::is_control)
    {
        return Err(ProtocolError::BoundViolation { field });
    }
    Ok(())
}

fn validate_string_vec(
    values: &[String],
    field: &'static str,
    limits: &ProtocolLimits,
) -> ProtocolResult<()> {
    if values.len() > usize::try_from(limits.max_array_items).unwrap_or(usize::MAX) {
        return Err(ProtocolError::BoundViolation { field });
    }
    for value in values {
        validate_safe_string(value, field, limits)?;
    }
    Ok(())
}

fn validate_optional_budget(
    value: Option<u64>,
    max: u64,
    field: &'static str,
) -> ProtocolResult<()> {
    if value.is_some_and(|amount| amount == 0 || amount > max) {
        return Err(ProtocolError::BoundViolation { field });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use tokio::io::{AsyncWriteExt, duplex};

    use super::*;

    fn limits() -> ProtocolLimits {
        ProtocolLimits::default()
    }

    fn hello_message() -> ProtocolMessage {
        ProtocolMessage::hello(
            "msg_1",
            HelloBody::new(
                EndpointKind::PythonAdapter,
                "python-adapter 0.1.0",
                vec!["discover".to_owned(), "evidence".to_owned()],
            ),
        )
    }

    fn request_message() -> ProtocolMessage {
        ProtocolMessage {
            schema_version: MESSAGE_SCHEMA_VERSION.to_owned(),
            message_id: "msg_2".to_owned(),
            request_id: Some("req_1".to_owned()),
            body: MessageBody::Request(RequestBody {
                endpoint: EndpointKind::OciExecutor,
                operation: OperationKind::ExecuteOci,
                deadline: Some(Deadline {
                    unix_epoch_ms: 1_805_000_000_000,
                }),
                budgets: BudgetLimits {
                    wall_time_ms: Some(5_000),
                    cpu_millis: Some(2_000),
                    memory_bytes: Some(268_435_456),
                    output_bytes: Some(1_048_576),
                    artifact_bytes: Some(1_048_576),
                    token_budget: None,
                    attempts: Some(1),
                },
                cancellation: CancellationPolicy {
                    cancel_token: "cancel_1".to_owned(),
                    poll_interval_ms: 100,
                },
                payload: json!({"manifest_ref": "artifact_sha256_abc"}),
            }),
        }
    }

    #[tokio::test]
    async fn framed_async_round_trip_preserves_message() {
        let message = request_message();
        let (mut writer, mut reader) = duplex(8_192);

        write_frame(&mut writer, &limits(), &message).await.unwrap();
        let decoded = read_frame(&mut reader, &limits()).await.unwrap();

        assert_eq!(decoded, message);
    }

    #[tokio::test]
    async fn oversized_frame_is_rejected_before_body_read() {
        let mut small = limits();
        small.max_frame_bytes = 16;
        let (mut writer, mut reader) = duplex(64);
        writer.write_all(&17_u32.to_be_bytes()).await.unwrap();

        assert_eq!(
            read_frame(&mut reader, &small).await.unwrap_err(),
            ProtocolError::FrameTooLarge {
                max: 16,
                actual: 17
            }
        );
    }

    #[tokio::test]
    async fn truncated_header_and_body_are_typed() {
        let (mut writer, mut reader) = duplex(64);
        writer.write_all(&[0, 1]).await.unwrap();
        drop(writer);
        assert_eq!(
            read_frame(&mut reader, &limits()).await.unwrap_err(),
            ProtocolError::TruncatedFrame {
                expected: 4,
                actual: 2
            }
        );

        let (mut writer, mut reader) = duplex(64);
        writer.write_all(&10_u32.to_be_bytes()).await.unwrap();
        writer.write_all(b"{}").await.unwrap();
        drop(writer);
        assert_eq!(
            read_frame(&mut reader, &limits()).await.unwrap_err(),
            ProtocolError::TruncatedFrame {
                expected: 10,
                actual: 2
            }
        );
    }

    #[test]
    fn duplicate_members_unknown_fields_and_unknown_kind_are_typed() {
        let duplicate = br#"{"schema_version":"promptectomy.protocol.message.v1","message_id":"m","kind":"hello","body":{"protocol":"promptectomy.out_of_process","major":1,"major":1,"minor":0,"endpoint":"python_adapter","implementation":"x","capabilities":[],"limits":{"max_frame_bytes":1024,"max_string_bytes":64,"max_array_items":8,"max_object_members":8,"max_json_depth":8}}}"#;
        assert_eq!(
            decode_message(duplicate, &limits()).unwrap_err(),
            ProtocolError::DuplicateMember
        );

        let mut top_unknown = encoded_value(&hello_message());
        top_unknown["extra"] = json!(true);
        assert_eq!(
            decode_message(&serde_json::to_vec(&top_unknown).unwrap(), &limits()).unwrap_err(),
            ProtocolError::UnknownField
        );

        let mut body_unknown = encoded_value(&hello_message());
        body_unknown["body"]["extra"] = json!(true);
        assert_eq!(
            decode_message(&serde_json::to_vec(&body_unknown).unwrap(), &limits()).unwrap_err(),
            ProtocolError::UnknownField
        );

        let mut unknown_kind = encoded_value(&hello_message());
        unknown_kind["kind"] = json!("surprise");
        assert_eq!(
            decode_message(&serde_json::to_vec(&unknown_kind).unwrap(), &limits()).unwrap_err(),
            ProtocolError::UnknownMessageKind
        );
    }

    #[test]
    fn unknown_major_is_rejected_for_envelope_and_negotiation() {
        let mut message = encoded_value(&hello_message());
        message["schema_version"] = json!("promptectomy.protocol.message.v2");
        assert_eq!(
            decode_message(&serde_json::to_vec(&message).unwrap(), &limits()).unwrap_err(),
            ProtocolError::UnknownMajor { major: 2 }
        );

        let mut peer = HelloBody::new(EndpointKind::AgentConnector, "agent 0.1.0", vec![]);
        peer.major = 2;
        assert_eq!(
            negotiate(
                &HelloBody::new(EndpointKind::PythonAdapter, "python 0.1.0", vec![]),
                &peer
            )
            .unwrap_err(),
            ProtocolError::UnknownMajor { major: 2 }
        );
    }

    #[test]
    fn negotiation_intersects_capabilities_and_limits_exactly() {
        let mut local = HelloBody::new(
            EndpointKind::PythonAdapter,
            "local",
            vec!["discover".to_owned(), "evidence".to_owned()],
        );
        local.minor = 3;
        local.limits.max_frame_bytes = 4_096;
        local.limits.max_json_depth = 12;

        let mut peer = HelloBody::new(
            EndpointKind::AgentConnector,
            "peer",
            vec!["agent".to_owned(), "discover".to_owned()],
        );
        peer.minor = 1;
        peer.limits.max_frame_bytes = 2_048;
        peer.limits.max_json_depth = 10;

        let negotiated = negotiate(&local, &peer).unwrap();

        assert_eq!(negotiated.major, PROTOCOL_MAJOR);
        assert_eq!(negotiated.minor, 1);
        assert_eq!(negotiated.local_endpoint, EndpointKind::PythonAdapter);
        assert_eq!(negotiated.peer_endpoint, EndpointKind::AgentConnector);
        assert_eq!(negotiated.capabilities, vec!["discover"]);
        assert_eq!(negotiated.limits.max_frame_bytes, 2_048);
        assert_eq!(negotiated.limits.max_json_depth, 10);
    }

    #[test]
    fn string_array_depth_budget_and_operation_bounds_are_enforced() {
        let mut small = limits();
        small.max_string_bytes = 8;
        let mut message = hello_message();
        if let MessageBody::Hello(body) = &mut message.body {
            body.implementation = "this string is too long".to_owned();
        }
        assert_eq!(
            encode_message(&message, &small).unwrap_err(),
            ProtocolError::BoundViolation {
                field: "implementation"
            }
        );

        let mut array_limited = limits();
        array_limited.max_array_items = 1;
        let message = hello_message();
        assert_eq!(
            encode_message(&message, &array_limited).unwrap_err(),
            ProtocolError::BoundViolation {
                field: "capabilities"
            }
        );

        let mut depth_limited = limits();
        depth_limited.max_json_depth = 2;
        let mut request = request_message();
        if let MessageBody::Request(body) = &mut request.body {
            body.payload = json!({"a": {"b": {"c": true}}});
        }
        assert_eq!(
            encode_message(&request, &depth_limited).unwrap_err(),
            ProtocolError::BoundViolation { field: "depth" }
        );

        let mut incompatible = request_message();
        if let MessageBody::Request(body) = &mut incompatible.body {
            body.endpoint = EndpointKind::PythonAdapter;
            body.operation = OperationKind::ExecuteOci;
        }
        assert_eq!(
            encode_message(&incompatible, &limits()).unwrap_err(),
            ProtocolError::IncompatibleOperation
        );

        let mut over_budget = request_message();
        if let MessageBody::Request(body) = &mut over_budget.body {
            body.budgets.wall_time_ms = Some(MAX_WALL_TIME_MS + 1);
        }
        assert_eq!(
            encode_message(&over_budget, &limits()).unwrap_err(),
            ProtocolError::BoundViolation {
                field: "wall_time_ms"
            }
        );
    }

    #[test]
    fn strict_json_rejects_floats_and_large_integers() {
        let mut value = encoded_value(&request_message());
        value["body"]["payload"] = json!({"float": 1.5});
        assert_eq!(
            decode_message(&serde_json::to_vec(&value).unwrap(), &limits()).unwrap_err(),
            ProtocolError::InvalidJson
        );

        let text = br#"{"schema_version":"promptectomy.protocol.message.v1","message_id":"m","kind":"cancel","body":{"target_request_id":"r","reason":9007199254740992}}"#;
        assert_eq!(
            decode_message(text, &limits()).unwrap_err(),
            ProtocolError::InvalidJson
        );
    }

    #[test]
    fn deterministic_protocol_decode_fuzz_corpus_is_typed() {
        let original = encode_message(&request_message(), &limits()).unwrap();
        let mut seed = 0xd6e8_feb8_6659_fd93_u64;
        for _ in 0..2_048 {
            let mut candidate = original.clone();
            for _ in 0..=(seed % 4) {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                let index = usize::try_from(seed).unwrap_or(usize::MAX) % candidate.len();
                candidate[index] ^= u8::try_from(seed >> 56).unwrap_or(0) | 1;
            }
            if let Ok(message) = decode_message(&candidate, &limits()) {
                let encoded = encode_message(&message, &limits()).unwrap();
                assert_eq!(decode_message(&encoded, &limits()).unwrap(), message);
            }
        }
    }

    fn encoded_value(message: &ProtocolMessage) -> Value {
        serde_json::from_slice(&encode_message(message, &limits()).unwrap()).unwrap()
    }
}
