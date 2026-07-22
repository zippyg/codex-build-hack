#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::Read as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream, lookup_host};
use tokio::sync::{Mutex, Semaphore};
use tokio::task::JoinSet;
use tokio::time::Instant;

pub const REQUEST_PATH: &str = "/work/input/proxy-request.json";
pub const OBSERVATIONS_PATH: &str = "/work/output/observations.json";
pub const WORKER_DONE_PATH: &str = "/work/input/worker-done.json";
pub const LISTEN_ADDRESS: &str = "0.0.0.0:8080";
const REQUEST_VERSION: &str = "promptectomy.egress-proxy-request.v1";
const OBSERVATIONS_VERSION: &str = "promptectomy.egress-proxy.v2";
const WORKER_DONE_VERSION: &str = "promptectomy.remote-worker-done.v1";
const MAX_REQUEST_FILE_BYTES: u64 = 64 * 1024;
const HARD_MAX_CONNECTIONS: usize = 16;
const HARD_MAX_REQUEST_BYTES: usize = 16 * 1024;
const HARD_MAX_HEADERS: usize = 64;
const HARD_MAX_TUNNEL_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const HARD_MAX_CONNECTION_SECONDS: u64 = 300;
const HARD_MAX_WALL_SECONDS: u64 = 600;
const INPUT_WAIT_SECONDS: u64 = 10;
const ALLOWED_HOSTS: [&str; 5] = [
    "bitbucket.org",
    "codeberg.org",
    "git.sr.ht",
    "github.com",
    "gitlab.com",
];

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("request_unavailable")]
    RequestUnavailable,
    #[error("invalid_request")]
    InvalidRequest,
    #[error("resolution_denied")]
    ResolutionDenied,
    #[error("listen_failed")]
    ListenFailed,
    #[error("observation_write_failed")]
    ObservationWriteFailed,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyRequest {
    pub schema_version: String,
    pub manifest_digest: String,
    pub destination: Destination,
    pub max_connections: usize,
    pub max_request_bytes: usize,
    pub max_headers: usize,
    pub max_tunnel_bytes: u64,
    pub max_connection_seconds: u64,
    pub wall_time_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Destination {
    pub host: String,
    pub port: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyObservations {
    pub schema_version: &'static str,
    pub manifest_digest: String,
    pub observed_destinations: Vec<Destination>,
    pub enforcement: &'static str,
    pub resolved_ip: String,
    pub accepted_connections: u64,
    pub rejected_connections: u64,
    pub bytes_client_to_upstream: u64,
    pub bytes_upstream_to_client: u64,
    pub byte_limit_exceeded: bool,
    pub terminal: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WorkerDone {
    schema_version: String,
    manifest_digest: String,
}

#[derive(Debug)]
struct ObservationState {
    value: ProxyObservations,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConnectionError {
    Denied,
    Io,
    TimedOut,
    ByteLimit,
}

impl ProxyRequest {
    pub fn validate(&self) -> Result<(), ProxyError> {
        if self.schema_version != REQUEST_VERSION
            || !is_digest(&self.manifest_digest)
            || !matches!(self.destination.port, 22 | 443)
            || !ALLOWED_HOSTS.contains(&self.destination.host.as_str())
            || self.max_connections == 0
            || self.max_connections > HARD_MAX_CONNECTIONS
            || self.max_request_bytes < 64
            || self.max_request_bytes > HARD_MAX_REQUEST_BYTES
            || self.max_headers == 0
            || self.max_headers > HARD_MAX_HEADERS
            || self.max_tunnel_bytes == 0
            || self.max_tunnel_bytes > HARD_MAX_TUNNEL_BYTES
            || self.max_connection_seconds == 0
            || self.max_connection_seconds > HARD_MAX_CONNECTION_SECONDS
            || self.wall_time_seconds == 0
            || self.wall_time_seconds > HARD_MAX_WALL_SECONDS
        {
            return Err(ProxyError::InvalidRequest);
        }
        validate_host(&self.destination.host)?;
        Ok(())
    }
}

pub async fn execute() -> Result<(), ProxyError> {
    let request = wait_for_request().await?;
    let resolved_ip = resolve_once(&request.destination).await?;
    let observations = Arc::new(Mutex::new(ObservationState {
        value: ProxyObservations {
            schema_version: OBSERVATIONS_VERSION,
            manifest_digest: request.manifest_digest.clone(),
            observed_destinations: Vec::new(),
            enforcement: "application_connect_proxy",
            resolved_ip: resolved_ip.to_string(),
            accepted_connections: 0,
            rejected_connections: 0,
            bytes_client_to_upstream: 0,
            bytes_upstream_to_client: 0,
            byte_limit_exceeded: false,
            terminal: false,
        },
    }));
    let listener = bind_and_publish(
        LISTEN_ADDRESS,
        &observations,
        Path::new(OBSERVATIONS_PATH),
        Path::new("/work/output/observations.tmp"),
    )
    .await?;
    serve(
        request,
        resolved_ip,
        observations,
        listener,
        Path::new(WORKER_DONE_PATH),
    )
    .await
}

async fn wait_for_request() -> Result<ProxyRequest, ProxyError> {
    let deadline = Instant::now() + Duration::from_secs(INPUT_WAIT_SECONDS);
    loop {
        if let Ok(bytes) = read_bounded(Path::new(REQUEST_PATH), MAX_REQUEST_FILE_BYTES)
            && let Ok(request) = serde_json::from_slice::<ProxyRequest>(&bytes)
            && request.validate().is_ok()
        {
            return Ok(request);
        }
        if Instant::now() >= deadline {
            return Err(ProxyError::RequestUnavailable);
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn bind_and_publish(
    address: &str,
    observations: &Arc<Mutex<ObservationState>>,
    path: &Path,
    temporary: &Path,
) -> Result<TcpListener, ProxyError> {
    let listener = TcpListener::bind(address)
        .await
        .map_err(|_| ProxyError::ListenFailed)?;
    write_observations_to(observations, path, temporary).await?;
    Ok(listener)
}

async fn serve(
    request: ProxyRequest,
    resolved_ip: IpAddr,
    observations: Arc<Mutex<ObservationState>>,
    listener: TcpListener,
    worker_done_path: &Path,
) -> Result<(), ProxyError> {
    let permits = Arc::new(Semaphore::new(request.max_connections));
    let tunnel_bytes = Arc::new(AtomicU64::new(0));
    let mut connections = JoinSet::new();
    let deadline = Instant::now() + Duration::from_secs(request.wall_time_seconds);
    loop {
        while let Some(result) = connections.try_join_next() {
            result.map_err(|_| ProxyError::ListenFailed)??;
        }
        if worker_done(worker_done_path, &request.manifest_digest) {
            break;
        }
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            connections.abort_all();
            return Err(ProxyError::ListenFailed);
        };
        let accepted =
            tokio::time::timeout(remaining.min(Duration::from_millis(10)), listener.accept()).await;
        let (mut client, _) = match accepted {
            Ok(Ok(connection)) => connection,
            Ok(Err(_)) => return Err(ProxyError::ListenFailed),
            Err(_) => continue,
        };
        let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
            let _ = client
                .write_all(b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n")
                .await;
            record_rejection(&observations).await?;
            continue;
        };
        let connection_request = request.clone();
        let connection_observations = Arc::clone(&observations);
        let connection_tunnel_bytes = Arc::clone(&tunnel_bytes);
        connections.spawn(async move {
            let _permit = permit;
            let result = Box::pin(tokio::time::timeout(
                Duration::from_secs(connection_request.max_connection_seconds),
                handle_connection(
                    &mut client,
                    &connection_request,
                    resolved_ip,
                    connection_tunnel_bytes,
                ),
            ))
            .await;
            let outcome = match result {
                Ok(value) => value,
                Err(_) => Err(ConnectionError::TimedOut),
            };
            record_outcome(&connection_observations, &connection_request, outcome).await
        });
    }
    drop(listener);
    quiesce_connections(&mut connections, &observations, deadline).await?;
    write_observations(&observations).await
}

fn worker_done(path: &Path, expected_manifest_digest: &str) -> bool {
    read_bounded(path, MAX_REQUEST_FILE_BYTES)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<WorkerDone>(&bytes).ok())
        .is_some_and(|signal| {
            signal.schema_version == WORKER_DONE_VERSION
                && signal.manifest_digest == expected_manifest_digest
        })
}

async fn drain_connections(
    connections: &mut JoinSet<Result<(), ProxyError>>,
    deadline: Instant,
) -> Result<(), ProxyError> {
    while !connections.is_empty() {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(ProxyError::ListenFailed)?;
        let result = tokio::time::timeout(remaining, connections.join_next())
            .await
            .map_err(|_| ProxyError::ListenFailed)?
            .ok_or(ProxyError::ListenFailed)?;
        result.map_err(|_| ProxyError::ListenFailed)??;
    }
    Ok(())
}

async fn quiesce_connections(
    connections: &mut JoinSet<Result<(), ProxyError>>,
    observations: &Arc<Mutex<ObservationState>>,
    deadline: Instant,
) -> Result<(), ProxyError> {
    drain_connections(connections, deadline).await?;
    observations.lock().await.value.terminal = true;
    Ok(())
}

async fn handle_connection(
    client: &mut TcpStream,
    request: &ProxyRequest,
    resolved_ip: IpAddr,
    total: Arc<AtomicU64>,
) -> Result<(u64, u64), ConnectionError> {
    read_connect_request(client, request).await?;
    let upstream_address = SocketAddr::new(resolved_ip, request.destination.port);
    let mut upstream = TcpStream::connect(upstream_address)
        .await
        .map_err(|_| ConnectionError::Io)?;
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .map_err(|_| ConnectionError::Io)?;
    let client_to_upstream = Arc::new(AtomicU64::new(0));
    let upstream_to_client = Arc::new(AtomicU64::new(0));
    let (client_read, client_write) = client.split();
    let (upstream_read, upstream_write) = upstream.split();
    let forward = copy_limited(
        client_read,
        upstream_write,
        Arc::clone(&total),
        Arc::clone(&client_to_upstream),
        request.max_tunnel_bytes,
    );
    let backward = copy_limited(
        upstream_read,
        client_write,
        total,
        Arc::clone(&upstream_to_client),
        request.max_tunnel_bytes,
    );
    tokio::try_join!(forward, backward)?;
    Ok((
        client_to_upstream.load(Ordering::Relaxed),
        upstream_to_client.load(Ordering::Relaxed),
    ))
}

async fn copy_limited<R, W>(
    mut reader: R,
    mut writer: W,
    total: Arc<AtomicU64>,
    direction: Arc<AtomicU64>,
    max_bytes: u64,
) -> Result<(), ConnectionError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let count = reader
            .read(&mut buffer)
            .await
            .map_err(|_| ConnectionError::Io)?;
        if count == 0 {
            writer.shutdown().await.map_err(|_| ConnectionError::Io)?;
            return Ok(());
        }
        reserve_bytes(&total, &direction, count, max_bytes)?;
        writer
            .write_all(&buffer[..count])
            .await
            .map_err(|_| ConnectionError::Io)?;
    }
}

fn reserve_bytes(
    total: &AtomicU64,
    direction: &AtomicU64,
    count: usize,
    max_bytes: u64,
) -> Result<(), ConnectionError> {
    let count = u64::try_from(count).map_err(|_| ConnectionError::ByteLimit)?;
    let mut current = total.load(Ordering::Relaxed);
    loop {
        let next = current
            .checked_add(count)
            .ok_or(ConnectionError::ByteLimit)?;
        if next > max_bytes {
            return Err(ConnectionError::ByteLimit);
        }
        match total.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(observed) => current = observed,
        }
    }
    direction.fetch_add(count, Ordering::Relaxed);
    Ok(())
}

async fn read_connect_request(
    stream: &mut TcpStream,
    request: &ProxyRequest,
) -> Result<(), ConnectionError> {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        if bytes.len() >= request.max_request_bytes {
            return Err(ConnectionError::Denied);
        }
        let byte = stream.read_u8().await.map_err(|_| ConnectionError::Io)?;
        bytes.push(byte);
    }
    parse_connect_request(&bytes, request)
}

fn parse_connect_request(bytes: &[u8], request: &ProxyRequest) -> Result<(), ConnectionError> {
    if bytes.len() > request.max_request_bytes || !bytes.ends_with(b"\r\n\r\n") || !bytes.is_ascii()
    {
        return Err(ConnectionError::Denied);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| ConnectionError::Denied)?;
    let mut lines = text[..text.len() - 4].split("\r\n");
    let request_line = lines.next().ok_or(ConnectionError::Denied)?;
    let authority = format!("{}:{}", request.destination.host, request.destination.port);
    if request_line != format!("CONNECT {authority} HTTP/1.1") {
        return Err(ConnectionError::Denied);
    }
    let mut header_count = 0_usize;
    let mut host_count = 0_usize;
    for line in lines {
        header_count += 1;
        if header_count > request.max_headers || line.is_empty() {
            return Err(ConnectionError::Denied);
        }
        let (name, value) = line.split_once(':').ok_or(ConnectionError::Denied)?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || value
                .bytes()
                .any(|byte| byte.is_ascii_control() && byte != b'\t')
        {
            return Err(ConnectionError::Denied);
        }
        let value = value.trim();
        if name.eq_ignore_ascii_case("host") {
            host_count += 1;
            if value != authority {
                return Err(ConnectionError::Denied);
            }
        }
        if name.eq_ignore_ascii_case("proxy-authorization")
            || name.eq_ignore_ascii_case("authorization")
            || name.eq_ignore_ascii_case("transfer-encoding")
            || (name.eq_ignore_ascii_case("content-length") && value != "0")
        {
            return Err(ConnectionError::Denied);
        }
    }
    if host_count != 1 {
        return Err(ConnectionError::Denied);
    }
    Ok(())
}

async fn resolve_once(destination: &Destination) -> Result<IpAddr, ProxyError> {
    let resolved = lookup_host((destination.host.as_str(), destination.port))
        .await
        .map_err(|_| ProxyError::ResolutionDenied)?;
    let mut addresses = BTreeSet::new();
    for address in resolved {
        if !is_global_ip(address.ip()) {
            return Err(ProxyError::ResolutionDenied);
        }
        addresses.insert(address.ip());
    }
    addresses
        .into_iter()
        .next()
        .ok_or(ProxyError::ResolutionDenied)
}

fn is_global_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_global_v4(ip),
        IpAddr::V6(ip) => is_global_v6(ip),
    }
}

fn is_global_v4(ip: Ipv4Addr) -> bool {
    let value = u32::from(ip);
    ![
        (0x0000_0000, 8),
        (0x0a00_0000, 8),
        (0x6440_0000, 10),
        (0x7f00_0000, 8),
        (0xa9fe_0000, 16),
        (0xac10_0000, 12),
        (0xc000_0000, 24),
        (0xc000_0200, 24),
        (0xc058_6300, 24),
        (0xc0a8_0000, 16),
        (0xc612_0000, 15),
        (0xc633_6400, 24),
        (0xcb00_7100, 24),
        (0xe000_0000, 3),
    ]
    .iter()
    .any(|(network, prefix)| in_v4_prefix(value, *network, *prefix))
}

fn in_v4_prefix(value: u32, network: u32, prefix: u8) -> bool {
    let mask = u32::MAX << (32 - prefix);
    value & mask == network
}

fn is_global_v6(ip: Ipv6Addr) -> bool {
    let value = u128::from(ip);
    in_v6_prefix(value, 0x2000_0000_0000_0000_0000_0000_0000_0000, 3)
        && ![
            (0x2001_0000_0000_0000_0000_0000_0000_0000, 23),
            (0x2001_0db8_0000_0000_0000_0000_0000_0000, 32),
            (0x3fff_0000_0000_0000_0000_0000_0000_0000, 20),
        ]
        .iter()
        .any(|(network, prefix)| in_v6_prefix(value, *network, *prefix))
}

fn in_v6_prefix(value: u128, network: u128, prefix: u8) -> bool {
    let mask = u128::MAX << (128 - prefix);
    value & mask == network
}

async fn record_rejection(observations: &Arc<Mutex<ObservationState>>) -> Result<(), ProxyError> {
    {
        let mut state = observations.lock().await;
        state.value.rejected_connections = state.value.rejected_connections.saturating_add(1);
    }
    write_observations(observations).await
}

async fn record_outcome(
    observations: &Arc<Mutex<ObservationState>>,
    request: &ProxyRequest,
    outcome: Result<(u64, u64), ConnectionError>,
) -> Result<(), ProxyError> {
    {
        let mut state = observations.lock().await;
        apply_outcome(&mut state.value, request, outcome);
    }
    write_observations(observations).await
}

fn apply_outcome(
    observations: &mut ProxyObservations,
    request: &ProxyRequest,
    outcome: Result<(u64, u64), ConnectionError>,
) {
    match outcome {
        Ok((sent, received)) => {
            observations.accepted_connections = observations.accepted_connections.saturating_add(1);
            observations.bytes_client_to_upstream =
                observations.bytes_client_to_upstream.saturating_add(sent);
            observations.bytes_upstream_to_client = observations
                .bytes_upstream_to_client
                .saturating_add(received);
            if observations.observed_destinations.is_empty() {
                observations
                    .observed_destinations
                    .push(request.destination.clone());
            }
        }
        Err(ConnectionError::ByteLimit) => {
            observations.rejected_connections = observations.rejected_connections.saturating_add(1);
            observations.byte_limit_exceeded = true;
        }
        Err(ConnectionError::Denied | ConnectionError::Io | ConnectionError::TimedOut) => {
            observations.rejected_connections = observations.rejected_connections.saturating_add(1);
        }
    }
}

async fn write_observations(observations: &Arc<Mutex<ObservationState>>) -> Result<(), ProxyError> {
    write_observations_to(
        observations,
        Path::new(OBSERVATIONS_PATH),
        Path::new("/work/output/observations.tmp"),
    )
    .await
}

async fn write_observations_to(
    observations: &Arc<Mutex<ObservationState>>,
    path: &Path,
    temporary: &Path,
) -> Result<(), ProxyError> {
    let state = observations.lock().await;
    let bytes = serde_json::to_vec(&state.value).map_err(|_| ProxyError::ObservationWriteFailed)?;
    tokio::fs::write(temporary, bytes)
        .await
        .map_err(|_| ProxyError::ObservationWriteFailed)?;
    tokio::fs::rename(temporary, path)
        .await
        .map_err(|_| ProxyError::ObservationWriteFailed)
}

fn validate_host(host: &str) -> Result<(), ProxyError> {
    if host.is_empty()
        || host.len() > 253
        || host.parse::<IpAddr>().is_ok()
        || host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(ProxyError::InvalidRequest);
    }
    Ok(())
}

fn read_bounded(path: &Path, max_bytes: u64) -> Result<Vec<u8>, ProxyError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ProxyError::RequestUnavailable)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > max_bytes
    {
        return Err(ProxyError::RequestUnavailable);
    }
    let file = File::open(path).map_err(|_| ProxyError::RequestUnavailable)?;
    let mut bytes = Vec::new();
    file.take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ProxyError::RequestUnavailable)?;
    if u64::try_from(bytes.len()).map_err(|_| ProxyError::RequestUnavailable)? > max_bytes {
        return Err(ProxyError::RequestUnavailable);
    }
    Ok(bytes)
}

fn is_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> ProxyRequest {
        ProxyRequest {
            schema_version: REQUEST_VERSION.to_owned(),
            manifest_digest: format!("sha256:{}", "a".repeat(64)),
            destination: Destination {
                host: "github.com".to_owned(),
                port: 443,
            },
            max_connections: 2,
            max_request_bytes: 4096,
            max_headers: 16,
            max_tunnel_bytes: 1024 * 1024,
            max_connection_seconds: 5,
            wall_time_seconds: 10,
        }
    }

    fn observations() -> Arc<Mutex<ObservationState>> {
        Arc::new(Mutex::new(ObservationState {
            value: ProxyObservations {
                schema_version: OBSERVATIONS_VERSION,
                manifest_digest: format!("sha256:{}", "a".repeat(64)),
                observed_destinations: Vec::new(),
                enforcement: "application_connect_proxy",
                resolved_ip: "8.8.8.8".to_owned(),
                accepted_connections: 0,
                rejected_connections: 0,
                bytes_client_to_upstream: 0,
                bytes_upstream_to_client: 0,
                byte_limit_exceeded: false,
                terminal: false,
            },
        }))
    }

    #[test]
    fn proxy_request_is_strict_and_bounded() {
        let request = request();
        request.validate().expect("valid request");
        let mut value = serde_json::to_value(&request).expect("request value");
        value["unknown"] = serde_json::json!(true);
        assert!(serde_json::from_value::<ProxyRequest>(value).is_err());

        let mut excessive = request;
        excessive.max_connections = HARD_MAX_CONNECTIONS + 1;
        assert!(excessive.validate().is_err());
    }

    #[test]
    fn exact_destination_policy_accepts_ssh_and_rejects_arbitrary_ports() {
        let mut ssh = request();
        ssh.destination.port = 22;
        ssh.validate().expect("bounded SSH destination");

        for denied in [0, 21, 23, 80, 8443] {
            ssh.destination.port = denied;
            assert!(matches!(ssh.validate(), Err(ProxyError::InvalidRequest)));
        }
    }

    #[test]
    fn connect_parser_allows_only_exact_destination() {
        let request = request();
        let valid =
            b"CONNECT github.com:443 HTTP/1.1\r\nHost: github.com:443\r\nUser-Agent: git/2\r\n\r\n";
        parse_connect_request(valid, &request).expect("valid connect");
        for denied in [
            b"GET https://github.com/ HTTP/1.1\r\nHost: github.com:443\r\n\r\n".as_slice(),
            b"CONNECT attacker.example:443 HTTP/1.1\r\nHost: attacker.example:443\r\n\r\n".as_slice(),
            b"CONNECT github.com:443 HTTP/1.1\r\nHost: github.com:443\r\nProxy-Authorization: secret\r\n\r\n".as_slice(),
            b"CONNECT github.com:443 HTTP/1.1\r\nHost: github.com:443\r\nContent-Length: 1\r\n\r\n".as_slice(),
            b"CONNECT github.com:443 HTTP/1.1\r\nHost: github.com:443\r\nHost: github.com:443\r\n\r\n".as_slice(),
        ] {
            assert!(parse_connect_request(denied, &request).is_err());
        }
    }

    #[test]
    fn non_global_addresses_are_denied() {
        for denied in [
            "0.0.0.0",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "172.16.0.1",
            "192.168.0.1",
            "198.18.0.1",
            "192.0.2.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "::1",
            "fc00::1",
            "fe80::1",
            "2001:db8::1",
        ] {
            assert!(!is_global_ip(denied.parse().expect("IP")), "{denied}");
        }
        for allowed in ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"] {
            assert!(is_global_ip(allowed.parse().expect("IP")), "{allowed}");
        }
    }

    #[test]
    fn byte_reservation_never_crosses_total_cap() {
        let total = AtomicU64::new(0);
        let first = AtomicU64::new(0);
        let second = AtomicU64::new(0);
        reserve_bytes(&total, &first, 7, 10).expect("first reservation");
        assert_eq!(
            reserve_bytes(&total, &second, 4, 10),
            Err(ConnectionError::ByteLimit)
        );
        assert_eq!(total.load(Ordering::Relaxed), 7);
        assert_eq!(first.load(Ordering::Relaxed), 7);
        assert_eq!(second.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn worker_done_signal_is_strict_and_manifest_bound() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("worker-done.json");
        let digest = format!("sha256:{}", "a".repeat(64));
        fs::write(
            &path,
            serde_json::to_vec(&WorkerDone {
                schema_version: WORKER_DONE_VERSION.to_owned(),
                manifest_digest: digest.clone(),
            })
            .expect("signal"),
        )
        .expect("write signal");
        assert!(worker_done(&path, &digest));
        assert!(!worker_done(&path, &format!("sha256:{}", "b".repeat(64))));
        fs::write(
            &path,
            br#"{"schema_version":"promptectomy.remote-worker-done.v1","manifest_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","unknown":true}"#,
        )
        .expect("write hostile signal");
        assert!(!worker_done(&path, &digest));
    }

    #[tokio::test]
    async fn failed_bind_never_publishes_readiness() {
        let occupied = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("occupied listener");
        let address = occupied.local_addr().expect("listener address").to_string();
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("observations.json");
        let temporary = temp.path().join("observations.tmp");
        let result = bind_and_publish(&address, &observations(), &path, &temporary).await;
        assert!(matches!(result, Err(ProxyError::ListenFailed)));
        assert!(!path.exists());
        assert!(!temporary.exists());
    }

    #[tokio::test]
    async fn terminal_state_waits_for_late_connection_outcome() {
        let observations = observations();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let mut connections = JoinSet::new();
        let task_observations = Arc::clone(&observations);
        let task_request = request();
        connections.spawn(async move {
            release_rx.await.map_err(|_| ProxyError::ListenFailed)?;
            apply_outcome(
                &mut task_observations.lock().await.value,
                &task_request,
                Err(ConnectionError::ByteLimit),
            );
            Ok(())
        });

        assert!(!observations.lock().await.value.terminal);
        release_tx.send(()).expect("release connection");
        quiesce_connections(
            &mut connections,
            &observations,
            Instant::now() + Duration::from_secs(1),
        )
        .await
        .expect("quiescent report");
        let state = observations.lock().await;
        assert!(state.value.terminal);
        assert_eq!(state.value.rejected_connections, 1);
        assert!(state.value.byte_limit_exceeded);
    }
}
