use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[cfg(unix)]
use std::collections::VecDeque;
#[cfg(unix)]
use std::convert::Infallible;
#[cfg(unix)]
use std::sync::Arc;
#[cfg(unix)]
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use bytes::Bytes;
#[cfg(unix)]
use http_body_util::{BodyExt, Full, Limited};
#[cfg(unix)]
use hyper::body::{Body, Incoming};
#[cfg(unix)]
use hyper::header::{
    AUTHORIZATION, CACHE_CONTROL, CONNECTION, CONTENT_LENGTH, CONTENT_SECURITY_POLICY,
    CONTENT_TYPE, HOST, ORIGIN, REFERRER_POLICY, TRANSFER_ENCODING, UPGRADE,
    X_CONTENT_TYPE_OPTIONS,
};
#[cfg(unix)]
use hyper::service::service_fn;
#[cfg(unix)]
use hyper::{Method, Request, Response, StatusCode};
#[cfg(unix)]
use hyper_util::rt::TokioIo;
#[cfg(unix)]
use promptectomy_contracts::SCHEMA_SHA256;
use promptectomy_contracts::{SCHEMA_VERSION, artifact_id};
use promptectomy_core::{CoreError, CoreStore};
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[cfg(unix)]
use serde_json::json;
#[cfg(unix)]
use subtle::ConstantTimeEq;
use thiserror::Error;
#[cfg(unix)]
use tokio::sync::{Mutex, Semaphore};
#[cfg(unix)]
use uuid::Uuid;

pub const PROTOCOL_VERSION: &str = "phase3-daemon-1";
pub const DEFAULT_HOST: &str = "promptectomy.local";
pub const MAX_BODY_BYTES: usize = 2_000_000;
pub const RATE_WINDOW: Duration = Duration::from_secs(60);
pub const RATE_LIMIT: usize = 120;
pub const MAX_CONNECTIONS: usize = 64;
pub const MAX_METADATA_BYTES: u64 = 16_384;
pub const CONNECTION_DEADLINE: Duration = Duration::from_secs(10);
#[cfg(unix)]
const MAX_SOCKET_PATH_BYTES: usize = 95;
pub const DEFAULT_ALLOWED_ORIGINS: [&str; 4] = [
    "http://127.0.0.1",
    "http://localhost",
    "https://127.0.0.1",
    "https://localhost",
];

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointMetadata {
    pub schema_version: String,
    pub protocol_version: String,
    pub transport: String,
    pub private: bool,
    pub socket_path: String,
    pub token: String,
    pub host: String,
    pub allowed_origins: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SafeError {
    pub code: String,
    pub category: String,
    pub retryable: bool,
    pub safe_message: String,
    pub next_action: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApiEnvelope {
    pub schema_version: String,
    pub protocol_version: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<SafeError>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClientResponse {
    pub status: u16,
    pub envelope: ApiEnvelope,
}

#[derive(Clone, Debug)]
pub struct DaemonConfig {
    root: PathBuf,
}

impl DaemonConfig {
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: normalize_root(root.into()),
        }
    }

    #[must_use]
    pub fn socket_path(&self) -> PathBuf {
        socket_path_for_root(&self.root)
    }

    #[must_use]
    pub fn metadata_path(&self) -> PathBuf {
        self.root.join("endpoint.json")
    }

    #[must_use]
    pub fn state_path(&self) -> PathBuf {
        self.root.join("state")
    }
}

#[cfg(unix)]
fn socket_path_for_root(root: &Path) -> PathBuf {
    use std::os::unix::ffi::OsStrExt;

    let direct = root.join("promptectomy.sock");
    if direct.as_os_str().as_bytes().len() <= MAX_SOCKET_PATH_BYTES {
        return direct;
    }
    let base = PathBuf::from("/tmp")
        .canonicalize()
        .unwrap_or_else(|_| PathBuf::from("/tmp"));
    let digest = artifact_id(root.as_os_str().as_bytes());
    let key = digest
        .strip_prefix("sha256:")
        .expect("artifact IDs have a fixed prefix")
        .chars()
        .take(32)
        .collect::<String>();
    base.join(format!(".promptectomy-{key}")).join("p.sock")
}

#[cfg(not(unix))]
fn socket_path_for_root(root: &Path) -> PathBuf {
    root.join("promptectomy.sock")
}

fn normalize_root(path: PathBuf) -> PathBuf {
    if !path.is_absolute() {
        return path;
    }
    if let Ok(canonical) = path.canonicalize() {
        return canonical;
    }
    let mut ancestor = path.as_path();
    let mut suffix = Vec::new();
    while fs::symlink_metadata(ancestor).is_err() {
        let Some(name) = ancestor.file_name() else {
            return path;
        };
        suffix.push(name.to_owned());
        let Some(parent) = ancestor.parent() else {
            return path;
        };
        ancestor = parent;
    }
    let Ok(mut normalized) = ancestor.canonicalize() else {
        return path;
    };
    for component in suffix.iter().rev() {
        normalized.push(component);
    }
    normalized
}

#[derive(Debug, Error)]
pub enum DaemonError {
    #[error("local daemon transport is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("daemon root is not private")]
    UnsafeRoot,
    #[error("daemon endpoint path is unsafe")]
    UnsafeEndpoint,
    #[error("a daemon is already listening on this endpoint")]
    AlreadyRunning,
    #[error("daemon I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("daemon JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("daemon response is invalid")]
    InvalidResponse,
    #[error("trusted core rejected daemon state: {0}")]
    Core(#[from] CoreError),
}

#[cfg(unix)]
#[derive(Debug)]
struct RateState {
    accepted: VecDeque<Instant>,
}

#[cfg(unix)]
struct DaemonState {
    metadata: EndpointMetadata,
    store: Mutex<CoreStore>,
    rate: Mutex<RateState>,
    state_path: PathBuf,
    state_owner: u32,
}

#[cfg(unix)]
struct EndpointCleanup {
    metadata_path: PathBuf,
    socket_path: PathBuf,
    socket_directory: Option<PathBuf>,
}

#[cfg(unix)]
impl Drop for EndpointCleanup {
    fn drop(&mut self) {
        for (path, socket) in [(&self.metadata_path, false), (&self.socket_path, true)] {
            if verify_private_endpoint(path, socket).is_ok() {
                let _ = fs::remove_file(path);
            }
        }
        for root in [self.metadata_path.parent(), self.socket_path.parent()]
            .into_iter()
            .flatten()
        {
            let _ = fs::File::open(root).and_then(|directory| directory.sync_all());
        }
        if let Some(directory) = &self.socket_directory
            && fs::remove_dir(directory).is_ok()
            && let Some(parent) = directory.parent()
        {
            let _ = fs::File::open(parent).and_then(|value| value.sync_all());
        }
    }
}

#[cfg(unix)]
impl DaemonState {
    fn new(
        metadata: EndpointMetadata,
        store: CoreStore,
        state_path: PathBuf,
        state_owner: u32,
    ) -> Self {
        Self {
            metadata,
            store: Mutex::new(store),
            rate: Mutex::new(RateState {
                accepted: VecDeque::new(),
            }),
            state_path,
            state_owner,
        }
    }

    async fn accept_rate(&self, now: Instant) -> bool {
        let mut rate = self.rate.lock().await;
        while rate
            .accepted
            .front()
            .is_some_and(|seen| now.duration_since(*seen) > RATE_WINDOW)
        {
            rate.accepted.pop_front();
        }
        if rate.accepted.len() >= RATE_LIMIT {
            return false;
        }
        rate.accepted.push_back(now);
        true
    }
}

#[must_use]
pub fn default_root() -> PathBuf {
    std::env::var_os("PROMPTECTOMY_DAEMON_DIR").map_or_else(
        || {
            let temporary = std::env::temp_dir();
            let base = temporary.canonicalize().unwrap_or(temporary);
            base.join(format!("promptectomy-{}", current_user_hint()))
        },
        PathBuf::from,
    )
}

#[must_use]
pub fn default_config() -> DaemonConfig {
    DaemonConfig::new(default_root())
}

#[cfg(unix)]
pub fn open_core_store(config: &DaemonConfig) -> Result<CoreStore, DaemonError> {
    prepare_private_root(&config.root)?;
    prepare_private_state(&config.state_path())?;
    let store = CoreStore::open(&config.state_path())?;
    let owner = private_directory_owner(&config.state_path())?;
    enforce_state_permissions(&config.state_path(), owner)?;
    Ok(store)
}

#[cfg(windows)]
pub fn open_core_store(_: &DaemonConfig) -> Result<CoreStore, DaemonError> {
    Err(DaemonError::UnsupportedPlatform)
}

#[cfg(unix)]
pub async fn serve(config: DaemonConfig) -> Result<(), DaemonError> {
    use std::os::unix::fs::PermissionsExt;
    use tokio::net::UnixListener;

    let store = open_core_store(&config)?;
    let socket_path = config.socket_path();
    let socket_directory = socket_path.parent().ok_or(DaemonError::UnsafeEndpoint)?;
    prepare_private_root(socket_directory)?;
    remove_stale_socket(&socket_path).await?;
    let token = generate_token()?;
    let metadata = EndpointMetadata {
        schema_version: SCHEMA_VERSION.to_owned(),
        protocol_version: PROTOCOL_VERSION.to_owned(),
        transport: "unix-domain-socket".to_owned(),
        private: true,
        socket_path: socket_path.to_string_lossy().into_owned(),
        token,
        host: DEFAULT_HOST.to_owned(),
        allowed_origins: DEFAULT_ALLOWED_ORIGINS
            .iter()
            .map(ToString::to_string)
            .collect(),
    };
    let listener = UnixListener::bind(&socket_path)?;
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;
    verify_private_endpoint(&socket_path, true)?;
    let _cleanup = EndpointCleanup {
        metadata_path: config.metadata_path(),
        socket_path: socket_path.clone(),
        socket_directory: (socket_directory != config.root).then(|| socket_directory.to_path_buf()),
    };
    write_private_metadata(&config.metadata_path(), &metadata)?;
    let state_path = config.state_path();
    let state_owner = private_directory_owner(&state_path)?;
    let state = Arc::new(DaemonState::new(metadata, store, state_path, state_owner));
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let (stream, _) = listener.accept().await?;
        let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
            drop(stream);
            continue;
        };
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let _permit = permit;
            let _ =
                tokio::time::timeout(CONNECTION_DEADLINE, serve_connection(stream, state)).await;
        });
    }
}

#[cfg(windows)]
pub async fn serve(_: DaemonConfig) -> Result<(), DaemonError> {
    std::future::ready(Err(DaemonError::UnsupportedPlatform)).await
}

#[cfg(unix)]
pub fn read_metadata(config: &DaemonConfig) -> Result<EndpointMetadata, DaemonError> {
    validate_private_root(&config.root)?;
    verify_private_endpoint(&config.metadata_path(), false)?;
    let file_size = fs::symlink_metadata(config.metadata_path())?.len();
    if file_size == 0 || file_size > MAX_METADATA_BYTES {
        return Err(DaemonError::UnsafeEndpoint);
    }
    let content = fs::read(config.metadata_path())?;
    let metadata: EndpointMetadata = serde_json::from_slice(&content)?;
    if metadata.schema_version != SCHEMA_VERSION
        || metadata.protocol_version != PROTOCOL_VERSION
        || metadata.socket_path != config.socket_path().to_string_lossy()
        || metadata.host != DEFAULT_HOST
        || !valid_allowed_origins(&metadata.allowed_origins)
        || !metadata.private
        || metadata.transport != "unix-domain-socket"
        || !valid_token(&metadata.token)
    {
        return Err(DaemonError::UnsafeEndpoint);
    }
    verify_private_endpoint(Path::new(&metadata.socket_path), true)?;
    Ok(metadata)
}

#[cfg(windows)]
pub fn read_metadata(_: &DaemonConfig) -> Result<EndpointMetadata, DaemonError> {
    Err(DaemonError::UnsupportedPlatform)
}

#[cfg(unix)]
pub async fn request(
    metadata: &EndpointMetadata,
    method: &str,
    path: &str,
    body: Option<&Value>,
) -> Result<ClientResponse, DaemonError> {
    use tokio::net::UnixStream;

    let stream = UnixStream::connect(&metadata.socket_path).await?;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|_| DaemonError::InvalidResponse)?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let body_bytes = match body {
        Some(value) => serde_json::to_vec(value)?,
        None => Vec::new(),
    };
    let method = Method::from_bytes(method.as_bytes()).map_err(|_| DaemonError::InvalidResponse)?;
    let request = Request::builder()
        .method(method)
        .uri(path)
        .header(HOST, &metadata.host)
        .header(AUTHORIZATION, format!("Bearer {}", metadata.token))
        .header(CONTENT_TYPE, "application/json")
        .header(CONTENT_LENGTH, body_bytes.len())
        .body(Full::new(Bytes::from(body_bytes)))
        .map_err(|_| DaemonError::InvalidResponse)?;
    let response = sender
        .send_request(request)
        .await
        .map_err(|_| DaemonError::InvalidResponse)?;
    let status = response.status().as_u16();
    let collected = Limited::new(response.into_body(), MAX_BODY_BYTES)
        .collect()
        .await
        .map_err(|_| DaemonError::InvalidResponse)?;
    let envelope = serde_json::from_slice(&collected.to_bytes())?;
    Ok(ClientResponse { status, envelope })
}

#[cfg(windows)]
pub async fn request(
    _: &EndpointMetadata,
    _: &str,
    _: &str,
    _: Option<&Value>,
) -> Result<ClientResponse, DaemonError> {
    std::future::ready(Err(DaemonError::UnsupportedPlatform)).await
}

pub fn unavailable(code: &str, next_action: &str) -> ApiEnvelope {
    error(
        code,
        "unsupported",
        false,
        "This command is unavailable in the current Phase 3 Rust slice.",
        next_action,
    )
}

#[must_use]
pub fn sanitize_terminal(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();
    while let Some(character) = chars.next() {
        if character == '\u{1b}' {
            match chars.peek().copied() {
                Some('[') => {
                    chars.next();
                    for next in chars.by_ref() {
                        if ('@'..='~').contains(&next) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    chars.next();
                    let mut previous_escape = false;
                    for next in chars.by_ref() {
                        if next == '\u{7}' || (previous_escape && next == '\\') {
                            break;
                        }
                        previous_escape = next == '\u{1b}';
                    }
                }
                _ => {}
            }
            continue;
        }
        if is_bidi_control(character) {
            continue;
        }
        if character == '\n' || character == '\t' || !character.is_control() {
            output.push(character);
        }
    }
    output
}

#[cfg(unix)]
fn ok(data: Value) -> ApiEnvelope {
    ApiEnvelope {
        schema_version: SCHEMA_VERSION.to_owned(),
        protocol_version: PROTOCOL_VERSION.to_owned(),
        status: "ok".to_owned(),
        data: Some(data),
        error: None,
    }
}

fn error(
    code: &str,
    category: &str,
    retryable: bool,
    safe_message: &str,
    next_action: &str,
) -> ApiEnvelope {
    ApiEnvelope {
        schema_version: SCHEMA_VERSION.to_owned(),
        protocol_version: PROTOCOL_VERSION.to_owned(),
        status: "error".to_owned(),
        data: None,
        error: Some(SafeError {
            code: code.to_owned(),
            category: category.to_owned(),
            retryable,
            safe_message: sanitize_terminal(safe_message),
            next_action: sanitize_terminal(next_action),
        }),
    }
}

#[cfg(unix)]
async fn serve_connection(
    stream: tokio::net::UnixStream,
    state: Arc<DaemonState>,
) -> Result<(), hyper::Error> {
    hyper::server::conn::http1::Builder::new()
        .keep_alive(false)
        .half_close(true)
        .max_headers(64)
        .max_buf_size(16_384)
        .serve_connection(
            TokioIo::new(stream),
            service_fn(move |request| {
                let state = Arc::clone(&state);
                async move { Ok::<_, Infallible>(handle_request(request, state).await) }
            }),
        )
        .await
}

#[cfg(unix)]
async fn handle_request(
    request: Request<Incoming>,
    state: Arc<DaemonState>,
) -> Response<Full<Bytes>> {
    let (parts, body) = request.into_parts();
    if let Some(response) = validate_request(&parts, &state) {
        return response;
    }
    if !state.accept_rate(Instant::now()).await {
        return response(
            StatusCode::TOO_MANY_REQUESTS,
            error(
                "rate_limited",
                "policy",
                true,
                "The local API request limit was reached.",
                "Retry after the rate window resets.",
            ),
        );
    }
    if enforce_state_permissions(&state.state_path, state.state_owner).is_err() {
        let (status, envelope) = invalid_state_permissions();
        return response(
            StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            envelope,
        );
    }
    if body
        .size_hint()
        .upper()
        .is_some_and(|length| length > MAX_BODY_BYTES as u64)
    {
        return response(StatusCode::PAYLOAD_TOO_LARGE, body_too_large());
    }
    let body = match Limited::new(body, MAX_BODY_BYTES).collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => return response(StatusCode::PAYLOAD_TOO_LARGE, body_too_large()),
    };
    let (status, envelope) = route(
        parts.method.as_str(),
        parts
            .uri
            .path_and_query()
            .map_or("/", |value| value.as_str()),
        &body,
        state,
    )
    .await;
    response(
        StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        envelope,
    )
}

#[cfg(unix)]
fn validate_request(
    parts: &hyper::http::request::Parts,
    state: &DaemonState,
) -> Option<Response<Full<Bytes>>> {
    if parts.method == Method::CONNECT
        || parts.headers.contains_key(TRANSFER_ENCODING)
        || parts.headers.contains_key(UPGRADE)
        || parts
            .headers
            .get(CONNECTION)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
            })
    {
        return Some(response(
            StatusCode::BAD_REQUEST,
            error(
                "unsupported_http_framing",
                "input",
                false,
                "The local API request uses unsupported HTTP framing.",
                "Use a single HTTP/1.1 request with Content-Length framing.",
            ),
        ));
    }
    if parts.headers.get_all(CONTENT_LENGTH).iter().count() > 1 {
        return Some(response(
            StatusCode::BAD_REQUEST,
            error(
                "ambiguous_content_length",
                "input",
                false,
                "The request contains duplicate Content-Length headers.",
                "Send exactly one Content-Length header.",
            ),
        ));
    }
    if !valid_host(single_header(&parts.headers, HOST), &state.metadata.host) {
        return Some(response(
            StatusCode::BAD_REQUEST,
            error(
                "invalid_host",
                "policy",
                false,
                "The request Host is not accepted.",
                "Use the private endpoint metadata host value.",
            ),
        ));
    }
    if !valid_origin(
        single_header(&parts.headers, ORIGIN),
        &state.metadata.allowed_origins,
    ) {
        return Some(response(
            StatusCode::FORBIDDEN,
            error(
                "invalid_origin",
                "policy",
                false,
                "The request Origin is not accepted.",
                "Use an exact configured local origin or omit Origin for non-browser clients.",
            ),
        ));
    }
    let provided = single_header(&parts.headers, AUTHORIZATION)
        .and_then(|value| value.strip_prefix("Bearer "));
    if !constant_time_eq(provided.unwrap_or_default(), &state.metadata.token) {
        return Some(response(
            StatusCode::UNAUTHORIZED,
            error(
                "invalid_capability",
                "policy",
                false,
                "A valid local capability is required.",
                "Read private endpoint metadata for this OS user.",
            ),
        ));
    }
    None
}

#[cfg(unix)]
fn single_header(headers: &hyper::HeaderMap, name: hyper::header::HeaderName) -> Option<&str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    values.next().is_none().then_some(value)
}

#[cfg(unix)]
fn body_too_large() -> ApiEnvelope {
    error(
        "request_body_too_large",
        "input",
        false,
        "The request body is too large.",
        "Send a bounded Phase 3 request.",
    )
}

#[allow(clippy::needless_pass_by_value)]
#[cfg(unix)]
fn response(status: StatusCode, envelope: ApiEnvelope) -> Response<Full<Bytes>> {
    let body = serde_json::to_vec(&envelope).expect("API envelope serialization cannot fail");
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .header(CACHE_CONTROL, "no-store")
        .header(X_CONTENT_TYPE_OPTIONS, "nosniff")
        .header(REFERRER_POLICY, "no-referrer")
        .header(CONTENT_SECURITY_POLICY, "default-src 'none'")
        .header(CONNECTION, "close")
        .body(Full::new(Bytes::from(body)))
        .expect("static response headers are valid")
}

#[cfg(unix)]
async fn route(
    method: &str,
    path: &str,
    body: &[u8],
    state: Arc<DaemonState>,
) -> (u16, ApiEnvelope) {
    let (path, query) = split_query(path);
    if method == "GET" && !body.is_empty() {
        return (400, *unexpected_body());
    }
    match (method, path) {
        ("GET", "/v2/health") => {
            if query.is_some() {
                return invalid_query();
            }
            (
                200,
                ok(json!({
                    "service": "promptectomy-daemon",
                    "transport": state.metadata.transport,
                    "private": state.metadata.private,
                    "schema_version": SCHEMA_VERSION,
                    "schema_sha256": SCHEMA_SHA256,
                    "protocol_version": PROTOCOL_VERSION,
                })),
            )
        }
        ("GET", "/v2/status") => {
            if query.is_some() {
                return invalid_query();
            }
            status(state).await
        }
        ("POST", "/v2/gc") => {
            if query.is_some() {
                return invalid_query();
            }
            if let Err(envelope) = reject_unexpected_body(body) {
                return (400, *envelope);
            }
            garbage_collect(state).await
        }
        _ => route_run(method, path, query, body, state).await,
    }
}

#[cfg(unix)]
async fn status(state: Arc<DaemonState>) -> (u16, ApiEnvelope) {
    let store = state.store.lock().await;
    let result = store.list_runs();
    drop(store);
    match result {
        Ok(runs) => {
            let run_count = runs.len();
            (
                200,
                ok(json!({"daemon": "running", "runs": runs, "run_count": run_count})),
            )
        }
        Err(error) => core_error(&error),
    }
}

#[cfg(unix)]
async fn garbage_collect(state: Arc<DaemonState>) -> (u16, ApiEnvelope) {
    let now_ms = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => u64::try_from(duration.as_millis()).unwrap_or(u64::MAX),
        Err(_) => {
            return (
                500,
                error(
                    "clock_unavailable",
                    "internal",
                    false,
                    "The system clock is unavailable.",
                    "Repair the local system clock before retrying.",
                ),
            );
        }
    };
    let mut store = state.store.lock().await;
    let result = store.garbage_collect(now_ms, true);
    drop(store);
    match result {
        Ok(plan) => (200, ok(json!(plan))),
        Err(error) => core_error(&error),
    }
}

#[cfg(unix)]
async fn route_run(
    method: &str,
    path: &str,
    query: Option<&str>,
    body: &[u8],
    state: Arc<DaemonState>,
) -> (u16, ApiEnvelope) {
    let parts: Vec<&str> = path.trim_matches('/').split('/').collect();
    if parts.len() < 3 || parts[0] != "v2" || parts[1] != "runs" {
        return (
            404,
            error(
                "endpoint_unavailable",
                "unsupported",
                false,
                "The requested endpoint is unavailable in Phase 3.",
                "Use doctor, status, watch, report, cancel, daemon, or gc.",
            ),
        );
    }
    let run_id = parts[2];
    match (method, parts.as_slice()) {
        ("GET", ["v2", "runs", _]) => {
            if query.is_some() {
                return invalid_query();
            }
            get_run(run_id, state).await
        }
        ("GET", ["v2", "runs", _, "events"]) => match parse_event_query(query) {
            Ok((cursor, limit)) => get_events(run_id, cursor, limit, state).await,
            Err(envelope) => (400, *envelope),
        },
        ("POST", ["v2", "runs", _, "report"]) => {
            if let Err(envelope) = reject_unexpected_body(body) {
                return (400, *envelope);
            }
            match parse_report_query(query) {
                Ok(format) => report(run_id, format, state).await,
                Err(envelope) => (400, *envelope),
            }
        }
        ("POST", ["v2", "runs", _, "cancel"]) => {
            if query.is_some() {
                return invalid_query();
            }
            if let Err(envelope) = reject_unexpected_body(body) {
                return (400, *envelope);
            }
            cancel(run_id, state).await
        }
        _ => (
            404,
            error(
                "endpoint_unavailable",
                "unsupported",
                false,
                "The requested endpoint is unavailable in Phase 3.",
                "Use doctor, status, watch, report, cancel, daemon, or gc.",
            ),
        ),
    }
}

#[cfg(unix)]
async fn get_run(run_id: &str, state: Arc<DaemonState>) -> (u16, ApiEnvelope) {
    let store = state.store.lock().await;
    let result = store.run(run_id);
    drop(store);
    match result {
        Ok(run) => (200, ok(json!(run))),
        Err(error) => core_error(&error),
    }
}

#[cfg(unix)]
async fn get_events(
    run_id: &str,
    cursor: u64,
    limit: u64,
    state: Arc<DaemonState>,
) -> (u16, ApiEnvelope) {
    let store = state.store.lock().await;
    let result = store.events_after(run_id, cursor, limit);
    drop(store);
    match result {
        Ok(page) => {
            let next_cursor = page.events.last().map_or(cursor, |event| event.sequence);
            (
                200,
                ok(json!({
                    "events": page.events,
                    "next_cursor": next_cursor,
                    "retained_floor": page.retained_floor,
                    "gap": false,
                })),
            )
        }
        Err(error) => core_error(&error),
    }
}

#[cfg(unix)]
async fn report(run_id: &str, format: Option<&str>, state: Arc<DaemonState>) -> (u16, ApiEnvelope) {
    let format = format.unwrap_or("json");
    let store = state.store.lock().await;
    let result = match format {
        "json" => store.report_json(run_id),
        "md" | "markdown" => store.report_markdown(run_id),
        _ => {
            return (
                400,
                error(
                    "invalid_report_format",
                    "input",
                    false,
                    "The requested report format is not supported.",
                    "Use json or md.",
                ),
            );
        }
    };
    drop(store);
    match result {
        Ok(content) => (200, ok(json!({"format": format, "content": content}))),
        Err(error) => core_error(&error),
    }
}

#[cfg(unix)]
async fn cancel(run_id: &str, state: Arc<DaemonState>) -> (u16, ApiEnvelope) {
    let mut store = state.store.lock().await;
    let result = store.request_cancel(run_id);
    drop(store);
    match result {
        Ok(run) => (200, ok(json!(run))),
        Err(error) => core_error(&error),
    }
}

#[cfg(unix)]
fn invalid_state_permissions() -> (u16, ApiEnvelope) {
    (
        500,
        error(
            "state_permissions_invalid",
            "storage",
            false,
            "Private state permissions are invalid.",
            "Repair the owner-only daemon state directory before retrying.",
        ),
    )
}

#[cfg(unix)]
fn core_error(core_error: &CoreError) -> (u16, ApiEnvelope) {
    let safe = core_error.safe_error();
    if matches!(safe.code.as_str(), "cursor_gap" | "event_cursor_expired") {
        return (
            410,
            error(
                "event_cursor_expired",
                &safe.category,
                safe.retryable,
                &safe.safe_message,
                &safe.next_action,
            ),
        );
    }
    let status = match safe.category.as_str() {
        "input" => 400,
        "policy" => 403,
        "state" | "storage" => 409,
        _ => 500,
    };
    (
        status,
        error(
            &safe.code,
            &safe.category,
            safe.retryable,
            &safe.safe_message,
            &safe.next_action,
        ),
    )
}

#[cfg(unix)]
fn reject_unexpected_body(body: &[u8]) -> Result<(), Box<ApiEnvelope>> {
    if body.is_empty() {
        Ok(())
    } else {
        Err(unexpected_body())
    }
}

#[cfg(unix)]
fn unexpected_body() -> Box<ApiEnvelope> {
    Box::new(error(
        "unexpected_body",
        "input",
        false,
        "This endpoint does not accept a request body.",
        "Send the request without a body.",
    ))
}

#[cfg(unix)]
fn split_query(path: &str) -> (&str, Option<&str>) {
    path.split_once('?')
        .map_or((path, None), |(path, query)| (path, Some(query)))
}

#[cfg(unix)]
fn parse_event_query(query: Option<&str>) -> Result<(u64, u64), Box<ApiEnvelope>> {
    let pairs = parse_query(query, &["cursor", "limit"])?;
    let parse = |key: &str, default: u64| -> Result<u64, Box<ApiEnvelope>> {
        pairs
            .iter()
            .find_map(|(name, value)| (*name == key).then_some(*value))
            .map_or(Ok(default), |value| {
                value.parse::<u64>().map_err(|_| invalid_query_envelope())
            })
    };
    let cursor = parse("cursor", 0)?;
    let limit = parse("limit", 100)?;
    if !(1..=1_000).contains(&limit) {
        return Err(invalid_query_envelope());
    }
    Ok((cursor, limit))
}

#[cfg(unix)]
fn parse_report_query(query: Option<&str>) -> Result<Option<&str>, Box<ApiEnvelope>> {
    let pairs = parse_query(query, &["format"])?;
    Ok(pairs
        .iter()
        .find_map(|(name, value)| (*name == "format").then_some(*value)))
}

#[cfg(unix)]
fn parse_query<'a>(
    query: Option<&'a str>,
    allowed: &[&str],
) -> Result<Vec<(&'a str, &'a str)>, Box<ApiEnvelope>> {
    let Some(query) = query else {
        return Ok(Vec::new());
    };
    if query.is_empty() {
        return Err(invalid_query_envelope());
    }
    let mut pairs = Vec::new();
    for part in query.split('&') {
        let Some((name, value)) = part.split_once('=') else {
            return Err(invalid_query_envelope());
        };
        if name.is_empty()
            || value.is_empty()
            || !allowed.contains(&name)
            || pairs.iter().any(|(seen, _)| seen == &name)
        {
            return Err(invalid_query_envelope());
        }
        pairs.push((name, value));
    }
    Ok(pairs)
}

#[cfg(unix)]
fn invalid_query() -> (u16, ApiEnvelope) {
    (400, *invalid_query_envelope())
}

#[cfg(unix)]
fn invalid_query_envelope() -> Box<ApiEnvelope> {
    Box::new(error(
        "invalid_query",
        "input",
        false,
        "The request query is invalid.",
        "Use each documented query parameter at most once with a valid value.",
    ))
}

#[cfg(unix)]
fn valid_host(value: Option<&str>, expected: &str) -> bool {
    let Some(value) = value else {
        return false;
    };
    let hostname = if let Some(ipv6) = value.strip_prefix('[') {
        let Some((host, remainder)) = ipv6.split_once(']') else {
            return false;
        };
        if !valid_port_suffix(remainder) {
            return false;
        }
        host
    } else {
        if value.matches(':').count() > 1 {
            return false;
        }
        match value.split_once(':') {
            Some((host, port)) if !port.is_empty() && port.parse::<u16>().is_ok() => host,
            Some(_) => return false,
            None => value,
        }
    };
    matches!(hostname, "127.0.0.1" | "::1" | "localhost") || hostname == expected
}

#[cfg(unix)]
fn valid_port_suffix(value: &str) -> bool {
    value.is_empty()
        || value
            .strip_prefix(':')
            .is_some_and(|port| !port.is_empty() && port.parse::<u16>().is_ok())
}

#[cfg(unix)]
fn valid_origin(value: Option<&str>, allowed: &[String]) -> bool {
    match value {
        None => true,
        Some(origin) => allowed.iter().any(|candidate| candidate == origin),
    }
}

#[cfg(unix)]
fn valid_allowed_origins(origins: &[String]) -> bool {
    origins.len() == DEFAULT_ALLOWED_ORIGINS.len()
        && origins
            .iter()
            .zip(DEFAULT_ALLOWED_ORIGINS)
            .all(|(origin, expected)| origin == expected)
}

#[cfg(unix)]
fn constant_time_eq(provided: &str, expected: &str) -> bool {
    provided.as_bytes().ct_eq(expected.as_bytes()).into()
}

#[cfg(unix)]
fn valid_token(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(unix)]
fn prepare_private_root(root: &Path) -> Result<(), DaemonError> {
    reject_symlink_components(root)?;
    fs::create_dir_all(root)?;
    reject_symlink_components(root)?;
    set_private_directory(root)?;
    verify_private_directory(root)
}

#[cfg(unix)]
fn validate_private_root(root: &Path) -> Result<(), DaemonError> {
    reject_symlink_components(root)?;
    verify_private_directory(root)
}

#[cfg(unix)]
fn prepare_private_state(state: &Path) -> Result<(), DaemonError> {
    reject_symlink_components(state)?;
    match fs::create_dir(state) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    reject_symlink_components(state)?;
    set_private_directory(state)?;
    verify_private_directory(state)
}

#[cfg(unix)]
fn reject_symlink_components(path: &Path) -> Result<(), DaemonError> {
    use std::path::Component;

    if !path.is_absolute() {
        return Err(DaemonError::UnsafeRoot);
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::Normal(_) => current.push(component),
            _ => return Err(DaemonError::UnsafeRoot),
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(DaemonError::UnsafeRoot);
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn set_private_directory(path: &Path) -> Result<(), DaemonError> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(unix)]
fn verify_private_directory(path: &Path) -> Result<(), DaemonError> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(DaemonError::UnsafeRoot);
    }
    let probe = path.join(format!(".owner-probe-{}", Uuid::now_v7()));
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&probe)?;
    let owner = file.metadata()?.uid();
    drop(file);
    fs::remove_file(&probe)?;
    if metadata.uid() != owner {
        return Err(DaemonError::UnsafeRoot);
    }
    Ok(())
}

#[cfg(unix)]
#[allow(clippy::verbose_bit_mask)]
fn enforce_state_permissions(state: &Path, owner: u32) -> Result<(), DaemonError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata = fs::symlink_metadata(state)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.uid() != owner
    {
        return Err(DaemonError::UnsafeRoot);
    }
    for name in [
        ".writer.lock",
        "state.sqlite",
        "state.sqlite-wal",
        "state.sqlite-shm",
    ] {
        let path = state.join(name);
        match fs::symlink_metadata(&path) {
            Ok(metadata)
                if !metadata.file_type().is_symlink()
                    && metadata.is_file()
                    && metadata.uid() == owner
                    && metadata.permissions().mode() & 0o077 == 0 => {}
            Ok(_) => return Err(DaemonError::UnsafeEndpoint),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn private_directory_owner(path: &Path) -> Result<u32, DaemonError> {
    use std::os::unix::fs::MetadataExt;

    Ok(fs::symlink_metadata(path)?.uid())
}

#[cfg(unix)]
async fn remove_stale_socket(path: &Path) -> Result<(), DaemonError> {
    match fs::symlink_metadata(path) {
        Ok(_) => verify_private_endpoint(path, true)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    }
    if tokio::net::UnixStream::connect(path).await.is_ok() {
        return Err(DaemonError::AlreadyRunning);
    }
    fs::remove_file(path)?;
    Ok(())
}

#[cfg(unix)]
fn verify_private_endpoint(path: &Path, socket: bool) -> Result<(), DaemonError> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};

    let parent = path.parent().ok_or(DaemonError::UnsafeEndpoint)?;
    validate_private_root(parent)?;
    let owner = fs::symlink_metadata(parent)?.uid();
    let metadata = fs::symlink_metadata(path)?;
    let expected_type = if socket {
        metadata.file_type().is_socket()
    } else {
        metadata.is_file()
    };
    if metadata.file_type().is_symlink()
        || !expected_type
        || metadata.uid() != owner
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(DaemonError::UnsafeEndpoint);
    }
    Ok(())
}

#[cfg(unix)]
fn write_private_metadata(path: &Path, metadata: &EndpointMetadata) -> Result<(), DaemonError> {
    use std::os::unix::fs::OpenOptionsExt;

    match fs::symlink_metadata(path) {
        Ok(_) => verify_private_endpoint(path, false)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let temporary = path.with_extension(format!("{}.tmp", Uuid::now_v7()));
    let content = serde_json::to_vec(metadata)?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    io::Write::write_all(&mut file, &content)?;
    file.sync_all()?;
    fs::rename(temporary, path)?;
    fs::File::open(path.parent().ok_or(DaemonError::UnsafeEndpoint)?)?.sync_all()?;
    verify_private_endpoint(path, false)?;
    Ok(())
}

#[cfg(unix)]
fn generate_token() -> Result<String, DaemonError> {
    use std::io::Read;

    let mut bytes = [0_u8; 32];
    fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    let mut token = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write as _;

        write!(&mut token, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(token)
}

fn current_user_hint() -> String {
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| std::env::temp_dir().to_string_lossy().into_owned());
    digest_hint(user.as_bytes())
}

fn digest_hint(value: &[u8]) -> String {
    artifact_id(value)
        .strip_prefix("sha256:")
        .expect("artifact IDs have a fixed prefix")
        .chars()
        .take(12)
        .collect()
}

fn is_bidi_control(character: char) -> bool {
    matches!(
        character,
        '\u{061c}'
            | '\u{200e}'
            | '\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2066}'..='\u{2069}'
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use promptectomy_core::{AuthorityManifest, BudgetLedger};

    #[test]
    fn sanitizer_removes_ansi_osc_controls_and_bidi() {
        let value = "ok\u{1b}[31mred\u{1b}[0m\u{1b}]8;;https://x\u{7}x\u{1b}]8;;\u{7}\u{202e}\u{0}";
        assert_eq!(sanitize_terminal(value), "okredx");
    }

    #[test]
    fn unavailable_error_is_safe_and_typed() {
        let envelope = unavailable("draft_unavailable", "Wait for Phase 5.");
        assert_eq!(envelope.status, "error");
        let error = envelope.error.unwrap();
        assert_eq!(error.category, "unsupported");
        assert!(!error.retryable);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_transport_is_typed_unsupported() {
        let config = DaemonConfig::new(PathBuf::from(r"C:\promptectomy-test"));
        let metadata = EndpointMetadata {
            schema_version: SCHEMA_VERSION.to_owned(),
            protocol_version: PROTOCOL_VERSION.to_owned(),
            transport: "unsupported".to_owned(),
            private: true,
            socket_path: String::new(),
            token: String::new(),
            host: DEFAULT_HOST.to_owned(),
            allowed_origins: Vec::new(),
        };

        assert!(matches!(
            open_core_store(&config),
            Err(DaemonError::UnsupportedPlatform)
        ));
        assert!(matches!(
            read_metadata(&config),
            Err(DaemonError::UnsupportedPlatform)
        ));
        assert!(matches!(
            serve(config).await,
            Err(DaemonError::UnsupportedPlatform)
        ));
        assert!(matches!(
            request(&metadata, "GET", "/v2/health", None).await,
            Err(DaemonError::UnsupportedPlatform)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn host_parser_rejects_ipv6_suffix_confusion() {
        assert!(valid_host(Some("[::1]:4319"), DEFAULT_HOST));
        assert!(!valid_host(Some("[::1]evil"), DEFAULT_HOST));
        assert!(!valid_host(Some("localhost:"), DEFAULT_HOST));
        assert!(valid_allowed_origins(
            &DEFAULT_ALLOWED_ORIGINS
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        ));
        assert!(!valid_allowed_origins(&["https://example.test".to_owned()]));
    }

    #[cfg(unix)]
    #[test]
    fn metadata_read_is_bounded() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().unwrap();
        let config = DaemonConfig::new(root.path());
        prepare_private_root(&config.root).unwrap();
        fs::write(
            config.metadata_path(),
            vec![b'x'; usize::try_from(MAX_METADATA_BYTES + 1).unwrap()],
        )
        .unwrap();
        fs::set_permissions(config.metadata_path(), fs::Permissions::from_mode(0o600)).unwrap();
        let result = read_metadata(&config);
        assert!(
            matches!(result, Err(DaemonError::UnsafeEndpoint)),
            "unexpected metadata result: {result:?}"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn long_state_root_uses_a_private_bounded_socket_path() {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::PermissionsExt;

        let base = tempfile::tempdir().unwrap();
        let config = DaemonConfig::new(base.path().join("x".repeat(140)));
        let socket = config.socket_path();
        assert!(socket.as_os_str().as_bytes().len() <= MAX_SOCKET_PATH_BYTES);
        assert_ne!(socket.parent(), Some(config.root.as_path()));

        let (handle, metadata) = start_daemon(&config).await;
        assert_eq!(metadata.socket_path, socket.to_string_lossy());
        let directory = socket.parent().unwrap().to_path_buf();
        assert_eq!(
            fs::symlink_metadata(&directory)
                .unwrap()
                .permissions()
                .mode()
                & 0o077,
            0
        );
        assert_eq!(
            request(&metadata, "GET", "/v2/health", None)
                .await
                .unwrap()
                .status,
            200
        );
        handle.abort();
        let _ = handle.await;
        for _ in 0..100 {
            if !directory.exists() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("short socket directory was not cleaned up");
    }

    #[cfg(unix)]
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn daemon_uses_durable_core_state_across_restart() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().unwrap();
        let config = DaemonConfig::new(root.path());
        prepare_private_root(&config.root).unwrap();
        prepare_private_state(&config.state_path()).unwrap();
        let mut store = CoreStore::open(&config.state_path()).unwrap();
        let authority = test_authority();
        let run = store
            .create_run(&authority, BudgetLedger::default())
            .unwrap();
        drop(store);

        let (first_handle, first_metadata) = start_daemon(&config).await;
        let status = request(&first_metadata, "GET", "/v2/status", None)
            .await
            .unwrap();
        assert_eq!(status.envelope.data.unwrap()["run_count"], 1);

        let events = request(
            &first_metadata,
            "GET",
            &format!("/v2/runs/{}/events?cursor=0&limit=100", run.run_id),
            None,
        )
        .await
        .unwrap();
        assert_eq!(events.envelope.data.unwrap()["next_cursor"], 1);

        for format in ["json", "md"] {
            let report = request(
                &first_metadata,
                "POST",
                &format!("/v2/runs/{}/report?format={format}", run.run_id),
                None,
            )
            .await
            .unwrap();
            assert_eq!(report.status, 200);
            let content = report.envelope.data.unwrap()["content"]
                .as_str()
                .unwrap()
                .to_owned();
            assert!(content.contains(&run.run_id));
        }

        let gap = request(
            &first_metadata,
            "GET",
            &format!(
                "/v2/runs/{}/events?cursor={}&limit=100",
                run.run_id,
                u64::MAX
            ),
            None,
        )
        .await
        .unwrap();
        assert_eq!(gap.status, 410);
        assert_eq!(gap.envelope.error.unwrap().code, "event_cursor_expired");

        fs::set_permissions(config.state_path(), fs::Permissions::from_mode(0o755)).unwrap();
        let mut missing_capability = first_metadata.clone();
        missing_capability.token.clear();
        let unauthenticated = request(&missing_capability, "GET", "/v2/health", None)
            .await
            .unwrap();
        assert_eq!(unauthenticated.status, 401);
        assert_eq!(
            unauthenticated.envelope.error.unwrap().code,
            "invalid_capability"
        );
        let insecure_directory = request(&first_metadata, "GET", "/v2/health", None)
            .await
            .unwrap();
        assert_eq!(insecure_directory.status, 500);
        assert_eq!(
            insecure_directory.envelope.error.unwrap().code,
            "state_permissions_invalid"
        );
        fs::set_permissions(config.state_path(), fs::Permissions::from_mode(0o700)).unwrap();

        let database = config.state_path().join("state.sqlite");
        fs::set_permissions(&database, fs::Permissions::from_mode(0o644)).unwrap();
        let blocked = request(
            &first_metadata,
            "POST",
            &format!("/v2/runs/{}/cancel", run.run_id),
            None,
        )
        .await
        .unwrap();
        assert_eq!(blocked.status, 500);
        assert_eq!(
            blocked.envelope.error.unwrap().code,
            "state_permissions_invalid"
        );
        fs::set_permissions(&database, fs::Permissions::from_mode(0o600)).unwrap();
        let unmutated = request(
            &first_metadata,
            "GET",
            &format!("/v2/runs/{}", run.run_id),
            None,
        )
        .await
        .unwrap();
        assert_eq!(unmutated.envelope.data.unwrap()["status"], "created");

        let cancelled = request(
            &first_metadata,
            "POST",
            &format!("/v2/runs/{}/cancel", run.run_id),
            None,
        )
        .await
        .unwrap();
        assert_eq!(cancelled.envelope.data.unwrap()["status"], "cancelling");
        let gc = request(&first_metadata, "POST", "/v2/gc", None)
            .await
            .unwrap();
        assert_eq!(gc.envelope.data.unwrap()["dry_run"], true);

        first_handle.abort();
        let _ = first_handle.await;
        let (second_handle, second_metadata) = start_daemon(&config).await;
        assert_ne!(first_metadata.token, second_metadata.token);
        let persisted = request(
            &second_metadata,
            "GET",
            &format!("/v2/runs/{}", run.run_id),
            None,
        )
        .await
        .unwrap();
        assert_eq!(persisted.envelope.data.unwrap()["status"], "cancelling");
        second_handle.abort();
    }

    #[cfg(unix)]
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn daemon_rejects_ambiguous_and_unsupported_http_framing() {
        let root = tempfile::tempdir().unwrap();
        let config = DaemonConfig::new(root.path());
        let (handle, metadata) = start_daemon(&config).await;
        let auth = format!("Authorization: Bearer {}\r\n", metadata.token);

        let duplicate = raw_request(
            &metadata,
            &format!(
                "GET /v2/health HTTP/1.1\r\nHost: {}\r\n{auth}Content-Length: 0\r\nContent-Length: 1\r\n\r\nx",
                metadata.host
            ),
        )
        .await;
        assert!(
            status_or_disconnect(&duplicate, 400),
            "duplicate response: {:?}",
            String::from_utf8_lossy(&duplicate)
        );

        let transfer = raw_request(
            &metadata,
            &format!(
                "POST /v2/gc HTTP/1.1\r\nHost: {}\r\n{auth}Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
                metadata.host
            ),
        )
        .await;
        assert!(status_or_disconnect(&transfer, 400));

        let malformed = raw_request(
            &metadata,
            &format!(
                "POST /v2/gc HTTP/1.1\r\nHost: {}\r\n{auth}Content-Length: nope\r\n\r\n",
                metadata.host
            ),
        )
        .await;
        assert!(status_or_disconnect(&malformed, 400));

        let oversized = raw_request(
            &metadata,
            &format!(
                "POST /v2/gc HTTP/1.1\r\nHost: {}\r\n{auth}Content-Length: {}\r\n\r\n",
                metadata.host,
                MAX_BODY_BYTES + 1
            ),
        )
        .await;
        assert!(String::from_utf8_lossy(&oversized).starts_with("HTTP/1.1 413"));

        let pipelined = raw_request(
            &metadata,
            &format!(
                "GET /v2/health HTTP/1.1\r\nHost: {}\r\n{auth}Content-Length: 0\r\n\r\nGET /v2/health HTTP/1.1\r\nHost: {}\r\n{auth}Content-Length: 0\r\n\r\n",
                metadata.host, metadata.host
            ),
        )
        .await;
        assert_eq!(
            String::from_utf8_lossy(&pipelined)
                .matches("HTTP/1.1")
                .count(),
            1
        );

        let null_origin = raw_request(
            &metadata,
            &format!(
                "GET /v2/health HTTP/1.1\r\nHost: {}\r\nOrigin: null\r\n{auth}Content-Length: 0\r\n\r\n",
                metadata.host
            ),
        )
        .await;
        assert!(String::from_utf8_lossy(&null_origin).starts_with("HTTP/1.1 403"));

        let confused_host = raw_request(
            &metadata,
            &format!(
                "GET /v2/health HTTP/1.1\r\nHost: [::1]evil\r\n{auth}Content-Length: 0\r\n\r\n"
            ),
        )
        .await;
        assert!(String::from_utf8_lossy(&confused_host).starts_with("HTTP/1.1 400"));

        let get_body = request(
            &metadata,
            "GET",
            "/v2/health",
            Some(&json!({"unexpected": true})),
        )
        .await
        .unwrap();
        assert_eq!(get_body.status, 400);
        assert_eq!(get_body.envelope.error.unwrap().code, "unexpected_body");

        let run_id = "run_019f0000-0000-7000-8000-000000000001";
        for (method, path) in [
            ("GET", "/v2/health?unknown=1".to_owned()),
            (
                "GET",
                format!("/v2/runs/{run_id}/events?cursor=nope&limit=100"),
            ),
            ("GET", format!("/v2/runs/{run_id}/events?cursor=0&cursor=1")),
            ("GET", format!("/v2/runs/{run_id}/events?cursor=0&limit=0")),
            (
                "POST",
                format!("/v2/runs/{run_id}/report?format=json&format=md"),
            ),
        ] {
            let rejected = request(&metadata, method, &path, None).await.unwrap();
            assert_eq!(rejected.status, 400, "path {path}");
            assert_eq!(rejected.envelope.error.unwrap().code, "invalid_query");
        }

        let health = request(&metadata, "GET", "/v2/health", None).await.unwrap();
        assert_eq!(health.status, 200);
        let mut missing = metadata.clone();
        missing.token.clear();
        assert_eq!(
            request(&missing, "GET", "/v2/health", None)
                .await
                .unwrap()
                .status,
            401
        );
        handle.abort();
    }

    #[cfg(unix)]
    async fn start_daemon(
        config: &DaemonConfig,
    ) -> (
        tokio::task::JoinHandle<Result<(), DaemonError>>,
        EndpointMetadata,
    ) {
        let handle = tokio::spawn(serve(config.clone()));
        for _ in 0..400 {
            if let Ok(metadata) = read_metadata(config)
                && request(&metadata, "GET", "/v2/health", None)
                    .await
                    .is_ok_and(|response| response.status == 200)
            {
                return (handle, metadata);
            }
            assert!(
                !handle.is_finished(),
                "daemon exited before publishing metadata"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("daemon did not publish endpoint metadata");
    }

    #[cfg(unix)]
    async fn raw_request(metadata: &EndpointMetadata, request: &str) -> Vec<u8> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut stream = tokio::net::UnixStream::connect(&metadata.socket_path)
            .await
            .unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        stream.shutdown().await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        response
    }

    #[cfg(unix)]
    fn status_or_disconnect(response: &[u8], expected: u16) -> bool {
        response.is_empty()
            || String::from_utf8_lossy(response).starts_with(&format!("HTTP/1.1 {expected}"))
    }

    #[cfg(unix)]
    fn test_authority() -> AuthorityManifest {
        let manifest = json!({
            "reads": ["selected_source_bytes"],
            "writes": ["tool_owned_state"],
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
        let digest = artifact_id(&promptectomy_contracts::canonical_json(&manifest).unwrap());
        let value = json!({
            "schema_uri": format!("{}authority.schema.json", promptectomy_contracts::SCHEMA_BASE),
            "schema_version": SCHEMA_VERSION,
            "authority_id": format!("auth_{}", Uuid::now_v7()),
            "subject_id": format!("action_snap_sha256_{}", "b".repeat(64)),
            "mode": "inspect",
            "manifest": manifest,
            "manifest_digest": digest,
            "approved_at": "2026-07-19T00:00:00.000000Z",
            "expires_at": "2027-07-19T00:00:00.000000Z",
            "approval_origin": "interactive_local",
            "revoked": false,
        });
        AuthorityManifest::from_contract_json(
            &format!("snap_sha256_{}", "b".repeat(64)),
            &serde_json::to_vec(&value).unwrap(),
        )
        .unwrap()
    }
}
