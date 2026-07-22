use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::digest::digest_string;
use crate::git::{canonical_https_host, validate_https};
use crate::remote::{
    ControlAttestation, RemoteBackendProfile, RemoteCredentialPolicy, RemoteDestinationEnforcement,
    RemoteGitManifest,
};
use crate::{AcquisitionError, SourceKind, is_digest, read_bounded};

const REQUEST_SCHEMA: &str = "promptectomy.remote-git-runner-request.v2";
const PROXY_REQUEST_SCHEMA: &str = "promptectomy.egress-proxy-request.v1";
const WORKER_SCHEMA: &str = "promptectomy.remote-worker.v1";
const PROXY_SCHEMA: &str = "promptectomy.egress-proxy.v2";
const WORKER_BINARY: &str = "/usr/local/bin/promptectomy-remote-git-runner";
const PROXY_BINARY: &str = "/usr/local/bin/promptectomy-egress-proxy";
const RELAY_BINARY: &str = "/usr/local/bin/promptectomy-ssh-agent-relay";
const REQUEST_PATH: &str = "/work/input/request.json";
const PROXY_REQUEST_PATH: &str = "/work/input/proxy-request.json";
const BUNDLE_PATH: &str = "/work/output/source-bundle.json";
const WORKER_REPORT_PATH: &str = "/work/output/result.json";
const PROXY_REPORT_PATH: &str = "/work/output/observations.json";
const PROC_NET_ROUTE_PATH: &str = "/proc/net/route";
const RELAY_SOCKET_PATH: &str = "/work/relay/agent.sock";
const RELAY_GRANT_PATH: &str = "/work/input/grant.json";
const RELAY_RECEIPT_PATH: &str = "/work/output/receipt.json";
const RELAY_UPSTREAM_PATH: &str = "/work/upstream/agent.sock";
const ORBSTACK_HOST_AGENT_SOCKET: &str = "/run/host-services/ssh-auth.sock";
const WORKER_DONE_PATH: &str = "/work/input/worker-done.json";
const WORKER_DONE_SCHEMA: &str = "promptectomy.remote-worker-done.v1";
const MAX_BINARY_BYTES: u64 = 16 * 1024 * 1024;
const MAX_INSPECT_BYTES: usize = 256 * 1024;
const MAX_REQUEST_BYTES: usize = 128 * 1024;
const DEFAULT_COMMAND_SECONDS: u64 = 30;
const CONTAINER_UID: &str = "65532:65532";
const DOCKER_CONTEXT: &str = "orbstack";
const SERVER_OS: &str = "linux";
const SERVER_ARCH: &str = "arm64";
const MIN_DOCKER_SERVER_MAJOR: u64 = 28;
const INPUT_TMPFS_BYTES: u64 = 256 * 1024;
const MIN_CONTAINER_MEMORY_BYTES: u64 = 256 * 1024 * 1024;
#[cfg(not(test))]
const PROXY_TERMINAL_WAIT: Duration = Duration::from_secs(10);
#[cfg(test)]
const PROXY_TERMINAL_WAIT: Duration = Duration::from_millis(100);

static SESSION_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CommandPlan {
    pub program: PathBuf,
    pub arguments: Vec<OsString>,
    pub environment: Vec<(OsString, OsString)>,
    pub stdin: Vec<u8>,
    pub max_output_bytes: usize,
    pub timeout: Duration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CommandOutput {
    pub success: bool,
    pub stdout: Vec<u8>,
}

pub(crate) trait CommandRunner: Send + Sync {
    fn run(
        &self,
        plan: &CommandPlan,
        cancelled: &AtomicBool,
    ) -> Result<CommandOutput, OciRemoteError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    fn run(
        &self,
        plan: &CommandPlan,
        cancelled: &AtomicBool,
    ) -> Result<CommandOutput, OciRemoteError> {
        if cancelled.load(Ordering::Acquire) {
            return Err(OciRemoteError::Cancelled);
        }
        let mut command = Command::new(&plan.program);
        command
            .args(&plan.arguments)
            .env_clear()
            .envs(plan.environment.iter().cloned())
            .stdin(if plan.stdin.is_empty() {
                Stdio::null()
            } else {
                Stdio::piped()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt as _;
            command.process_group(0);
        }
        let mut child = command.spawn().map_err(|_| OciRemoteError::CommandStart)?;
        if !plan.stdin.is_empty() {
            let mut stdin = child.stdin.take().ok_or(OciRemoteError::CommandStart)?;
            if stdin.write_all(&plan.stdin).is_err() {
                terminate_child(&mut child);
                return Err(OciRemoteError::CommandFailed);
            }
        }
        let stdout = child.stdout.take().ok_or(OciRemoteError::CommandStart)?;
        let stderr = child.stderr.take().ok_or(OciRemoteError::CommandStart)?;
        let output_limit = plan.max_output_bytes;
        let stdout_reader = thread::spawn(move || read_pipe(stdout, output_limit, true));
        let stderr_reader = thread::spawn(move || read_pipe(stderr, output_limit, false));
        let deadline = Instant::now()
            .checked_add(plan.timeout)
            .ok_or(OciRemoteError::InvalidConfiguration)?;
        let status = loop {
            if cancelled.load(Ordering::Acquire) {
                terminate_child(&mut child);
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                return Err(OciRemoteError::Cancelled);
            }
            if Instant::now() >= deadline {
                terminate_child(&mut child);
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                return Err(OciRemoteError::CommandTimedOut);
            }
            if let Some(status) = child
                .try_wait()
                .map_err(|_| OciRemoteError::CommandFailed)?
            {
                break status;
            }
            thread::sleep(Duration::from_millis(10));
        };
        let (stdout, stdout_exceeded) = stdout_reader
            .join()
            .map_err(|_| OciRemoteError::CommandFailed)??;
        let (_, stderr_exceeded) = stderr_reader
            .join()
            .map_err(|_| OciRemoteError::CommandFailed)??;
        if stdout_exceeded || stderr_exceeded {
            return Err(OciRemoteError::CommandOutputExceeded);
        }
        Ok(CommandOutput {
            success: status.success(),
            stdout,
        })
    }
}

fn terminate_child(child: &mut Child) {
    #[cfg(unix)]
    {
        use rustix::process::{Pid, Signal, kill_process_group};

        if let Some(pid) = Pid::from_raw(child.id().cast_signed()) {
            let _ = kill_process_group(pid, Signal::KILL);
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

fn read_pipe(
    mut pipe: impl Read,
    limit: usize,
    retain: bool,
) -> Result<(Vec<u8>, bool), OciRemoteError> {
    let mut kept = Vec::with_capacity(limit.min(64 * 1024));
    let mut exceeded = false;
    let mut total = 0_usize;
    let mut buffer = [0_u8; 8192];
    loop {
        let count = pipe
            .read(&mut buffer)
            .map_err(|_| OciRemoteError::CommandFailed)?;
        if count == 0 {
            break;
        }
        total = total.saturating_add(count);
        exceeded |= total > limit;
        if retain && kept.len() < limit {
            let take = count.min(limit - kept.len());
            kept.extend_from_slice(&buffer[..take]);
        }
    }
    Ok((kept, exceeded))
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct OciRemoteConfig {
    pub docker_program: PathBuf,
    pub image_reference: String,
    pub user: String,
    pub pids_limit: u32,
    pub memory_bytes: u64,
    pub nano_cpus: u64,
    pub output_tmpfs_bytes: u64,
    pub temp_tmpfs_bytes: u64,
    pub relay_upstream: Option<RelayUpstream>,
}

#[cfg_attr(
    not(unix),
    allow(
        dead_code,
        reason = "the reviewed relay backend is unavailable on this platform"
    )
)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RelayUpstream {
    OrbstackHost,
    #[cfg(test)]
    TestVolume(String),
}

impl std::fmt::Debug for OciRemoteConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OciRemoteConfig")
            .field("image_reference", &self.image_reference)
            .field("user", &self.user)
            .field("pids_limit", &self.pids_limit)
            .field("memory_bytes", &self.memory_bytes)
            .field("nano_cpus", &self.nano_cpus)
            .field("output_tmpfs_bytes", &self.output_tmpfs_bytes)
            .field("temp_tmpfs_bytes", &self.temp_tmpfs_bytes)
            .field("relay_upstream_configured", &self.relay_upstream.is_some())
            .finish_non_exhaustive()
    }
}

impl OciRemoteConfig {
    fn validate(&self, manifest: &RemoteGitManifest) -> Result<(), OciRemoteError> {
        let minimum_output = manifest
            .max_bundle_bytes
            .checked_add(
                u64::try_from(manifest.max_output_bytes)
                    .map_err(|_| OciRemoteError::InvalidConfiguration)?,
            )
            .ok_or(OciRemoteError::InvalidConfiguration)?;
        if !self.docker_program.is_absolute()
            || self.image_reference.len() > 512
            || self
                .image_reference
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
            || self.user != CONTAINER_UID
            || !(16..=256).contains(&self.pids_limit)
            || !(MIN_CONTAINER_MEMORY_BYTES..=2 * 1024 * 1024 * 1024).contains(&self.memory_bytes)
            || !(100_000_000..=2_000_000_000).contains(&self.nano_cpus)
            || self.output_tmpfs_bytes < minimum_output
            || self.output_tmpfs_bytes > 1024 * 1024 * 1024
            || !(4 * 1024 * 1024..=64 * 1024 * 1024).contains(&self.temp_tmpfs_bytes)
            || manifest.max_remote_work_bytes > 1024 * 1024 * 1024
            || self
                .image_reference
                .rsplit_once('@')
                .is_none_or(|(_, digest)| digest != manifest.backend.image_digest)
            || match manifest.source_kind {
                SourceKind::HttpsRemote => self.relay_upstream.is_some(),
                SourceKind::SshBrokered => self
                    .relay_upstream
                    .as_ref()
                    .is_none_or(|upstream| !valid_relay_upstream(upstream)),
                _ => true,
            }
        {
            return Err(OciRemoteError::InvalidConfiguration);
        }
        Ok(())
    }
}

fn valid_relay_upstream(upstream: &RelayUpstream) -> bool {
    match upstream {
        RelayUpstream::OrbstackHost => true,
        #[cfg(test)]
        RelayUpstream::TestVolume(name) => valid_resource_name(name),
    }
}

#[cfg(test)]
fn valid_resource_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OciControlEvidence {
    pub backend_profile: RemoteBackendProfile,
    pub image_digest: String,
    pub runner_digest: String,
    pub proxy_digest: String,
    pub root_read_only: ControlAttestation,
    pub no_new_privileges: ControlAttestation,
    pub capabilities_dropped: ControlAttestation,
    pub resource_limits: ControlAttestation,
    pub remote_work_tmpfs_bytes: u64,
    pub input_tmpfs_bytes: u64,
    pub output_tmpfs_bytes: u64,
    pub temporary_tmpfs_bytes: u64,
    pub worker_internal_network_only: ControlAttestation,
    pub proxy_dual_homed: ControlAttestation,
    pub credentials_isolated: ControlAttestation,
    pub destination_enforcement: RemoteDestinationEnforcement,
    pub kernel_exact_destination_enforced: bool,
    pub worker_default_route_absent: ControlAttestation,
    pub proxy_gateway_and_host_reachability_kernel_blocked: bool,
    pub cleanup_complete: ControlAttestation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OciRemoteResult {
    pub source_bundle: Vec<u8>,
    pub resolved_commit: String,
    pub git_binary_digest: String,
    pub observed_destination_host: String,
    pub observed_destination_port: u16,
    pub controls: OciControlEvidence,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(crate) enum OciRemoteError {
    #[error("the OCI remote configuration is invalid")]
    InvalidConfiguration,
    #[error("the OCI remote request is invalid")]
    InvalidRequest,
    #[error("the OCI runtime command could not be started")]
    CommandStart,
    #[error("the OCI runtime command failed without exposing process output")]
    CommandFailed,
    #[error("the OCI runtime command exceeded its output bound")]
    CommandOutputExceeded,
    #[error("the OCI runtime command exceeded its time bound")]
    CommandTimedOut,
    #[error("the OCI remote acquisition was cancelled")]
    Cancelled,
    #[error("the accepted OCI image digest did not match")]
    ImageDigestMismatch,
    #[error("an accepted OCI binary digest did not match")]
    BinaryDigestMismatch,
    #[error("an OCI runtime control was absent or substituted")]
    ControlMismatch,
    #[error("an untrusted OCI output was malformed or inconsistent")]
    InvalidOutput,
    #[error("the OCI resources could not be proven removed")]
    CleanupFailed,
}

impl From<AcquisitionError> for OciRemoteError {
    fn from(_: AcquisitionError) -> Self {
        Self::InvalidRequest
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct WorkerRequest<'a> {
    schema_version: &'static str,
    manifest: &'a RemoteGitManifest,
    https_url: Option<&'a str>,
    ssh: Option<WorkerSshRequest<'a>>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct WorkerSshRequest<'a> {
    repository: &'a str,
    host_key_type: &'a str,
    host_key_base64: &'a str,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ProxyRequest<'a> {
    schema_version: &'static str,
    manifest_digest: &'a str,
    destination: &'a crate::remote::EgressDestination,
    max_connections: usize,
    max_request_bytes: usize,
    max_headers: usize,
    max_tunnel_bytes: u64,
    max_connection_seconds: u64,
    wall_time_seconds: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerReport {
    schema_version: String,
    manifest_digest: String,
    resolved_commit: String,
    source_bundle_digest: String,
    git_binary_digest: String,
    git_execution_neutralized: bool,
    credentials_isolated: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProxyDestination {
    host: String,
    port: u16,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProxyReport {
    schema_version: String,
    manifest_digest: String,
    observed_destinations: Vec<ProxyDestination>,
    enforcement: RemoteDestinationEnforcement,
    resolved_ip: String,
    accepted_connections: u64,
    rejected_connections: u64,
    bytes_client_to_upstream: u64,
    bytes_upstream_to_client: u64,
    byte_limit_exceeded: bool,
    terminal: bool,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct WorkerDone<'a> {
    schema_version: &'static str,
    manifest_digest: &'a str,
}

pub(crate) fn acquire_public_https(
    runner: &dyn CommandRunner,
    config: &OciRemoteConfig,
    manifest: &RemoteGitManifest,
    locator: &str,
    cancelled: &AtomicBool,
) -> Result<OciRemoteResult, OciRemoteError> {
    manifest.validate()?;
    config.validate(manifest)?;
    validate_public_request(manifest, locator)?;
    acquire_remote(
        runner,
        config,
        manifest,
        &WorkerRequest {
            schema_version: REQUEST_SCHEMA,
            manifest,
            https_url: Some(locator),
            ssh: None,
        },
        None,
        cancelled,
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "the trust boundary keeps every validated SSH binding explicit"
)]
#[cfg(unix)]
pub(crate) fn acquire_brokered_ssh(
    runner: &dyn CommandRunner,
    config: &OciRemoteConfig,
    manifest: &RemoteGitManifest,
    repository: &str,
    host_key_type: &str,
    host_key_base64: &str,
    relay_grant: &[u8],
    cancelled: &AtomicBool,
) -> Result<OciRemoteResult, OciRemoteError> {
    manifest.validate()?;
    config.validate(manifest)?;
    validate_ssh_request(manifest, repository, host_key_type, host_key_base64)?;
    acquire_remote(
        runner,
        config,
        manifest,
        &WorkerRequest {
            schema_version: REQUEST_SCHEMA,
            manifest,
            https_url: None,
            ssh: Some(WorkerSshRequest {
                repository,
                host_key_type,
                host_key_base64,
            }),
        },
        Some(relay_grant),
        cancelled,
    )
}

fn acquire_remote(
    runner: &dyn CommandRunner,
    config: &OciRemoteConfig,
    manifest: &RemoteGitManifest,
    worker_request: &WorkerRequest<'_>,
    relay_grant: Option<&[u8]>,
    cancelled: &AtomicBool,
) -> Result<OciRemoteResult, OciRemoteError> {
    if cancelled.load(Ordering::Acquire) {
        return Err(OciRemoteError::Cancelled);
    }
    let request = serde_jcs::to_vec(&worker_request).map_err(|_| OciRemoteError::InvalidRequest)?;
    if request.len() > MAX_REQUEST_BYTES {
        return Err(OciRemoteError::InvalidRequest);
    }
    if relay_grant.is_some_and(|grant| grant.is_empty() || grant.len() > MAX_REQUEST_BYTES)
        || (worker_request.ssh.is_some() != relay_grant.is_some())
    {
        return Err(OciRemoteError::InvalidRequest);
    }
    let proxy_request = serde_jcs::to_vec(&ProxyRequest {
        schema_version: PROXY_REQUEST_SCHEMA,
        manifest_digest: &manifest.manifest_digest,
        destination: &manifest.destination,
        max_connections: 16,
        max_request_bytes: 16 * 1024,
        max_headers: 64,
        max_tunnel_bytes: manifest
            .max_remote_work_bytes
            .saturating_mul(2)
            .min(2 * 1024 * 1024 * 1024),
        max_connection_seconds: manifest.wall_time_seconds.min(300),
        wall_time_seconds: manifest.wall_time_seconds.saturating_add(15).min(600),
    })
    .map_err(|_| OciRemoteError::InvalidRequest)?;
    if proxy_request.len() > MAX_REQUEST_BYTES {
        return Err(OciRemoteError::InvalidRequest);
    }

    let workspace = tempfile::Builder::new()
        .prefix("promptectomy-oci-")
        .tempdir()
        .map_err(|_| OciRemoteError::InvalidRequest)?;
    let request_path = workspace.path().join("request.json");
    let proxy_request_path = workspace.path().join("proxy-request.json");
    let relay_grant_path = workspace.path().join("relay-grant.json");
    write_private_request(&request_path, &request)?;
    write_private_request(&proxy_request_path, &proxy_request)?;
    if let Some(relay_grant) = relay_grant {
        write_private_request(&relay_grant_path, relay_grant)?;
    }
    let names = ResourceNames::new();
    let docker = DockerSession {
        runner,
        config,
        manifest,
        names,
    };

    verify_runtime(&docker, cancelled)?;
    verify_image(&docker, cancelled)?;
    let body = run_session(
        &docker,
        &request_path,
        &proxy_request_path,
        relay_grant.map(|_| relay_grant_path.as_path()),
        workspace.path(),
        cancelled,
    );
    let cleanup = cleanup_session(&docker);
    match (body, cleanup) {
        (Ok(mut result), Ok(())) => {
            result.controls.cleanup_complete = ControlAttestation::Passed;
            Ok(result)
        }
        (_, Err(_)) => Err(OciRemoteError::CleanupFailed),
        (Err(error), Ok(())) => Err(error),
    }
}

#[cfg(unix)]
fn validate_ssh_request(
    manifest: &RemoteGitManifest,
    repository: &str,
    host_key_type: &str,
    host_key_base64: &str,
) -> Result<(), OciRemoteError> {
    let broker = manifest
        .broker
        .as_ref()
        .ok_or(OciRemoteError::InvalidRequest)?;
    if manifest.source_kind != SourceKind::SshBrokered
        || manifest.credential_policy != RemoteCredentialPolicy::SshAgentBrokerGrant
        || manifest.destination.port != 22
        || manifest.backend.profile != RemoteBackendProfile::OrbstackMacosArm64V1
        || domain_digest("ssh-repository", repository.as_bytes()) != broker.repository_digest
        || domain_digest(
            "ssh-host-key",
            format!("{host_key_type} {host_key_base64}").as_bytes(),
        ) != broker.host_key_digest
    {
        return Err(OciRemoteError::InvalidRequest);
    }
    Ok(())
}

fn validate_public_request(
    manifest: &RemoteGitManifest,
    locator: &str,
) -> Result<(), OciRemoteError> {
    if manifest.source_kind != SourceKind::HttpsRemote
        || manifest.credential_policy != RemoteCredentialPolicy::None
        || manifest.broker.is_some()
        || manifest.backend.profile != RemoteBackendProfile::OrbstackMacosArm64V1
    {
        return Err(OciRemoteError::InvalidRequest);
    }
    validate_https(locator)?;
    if canonical_https_host(locator)? != manifest.destination.host
        || domain_digest("remote-locator", locator.as_bytes()) != manifest.locator_digest
    {
        return Err(OciRemoteError::InvalidRequest);
    }
    Ok(())
}

fn write_private_request(path: &Path, request: &[u8]) -> Result<(), OciRemoteError> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o644);
    }
    let mut file = options
        .open(path)
        .map_err(|_| OciRemoteError::InvalidRequest)?;
    file.write_all(request)
        .map_err(|_| OciRemoteError::InvalidRequest)?;
    file.sync_all().map_err(|_| OciRemoteError::InvalidRequest)
}

struct DockerSession<'a> {
    runner: &'a dyn CommandRunner,
    config: &'a OciRemoteConfig,
    manifest: &'a RemoteGitManifest,
    names: ResourceNames,
}

#[derive(Clone, Debug)]
struct ResourceNames {
    label: String,
    internal_network: String,
    outbound_network: String,
    worker: String,
    proxy: String,
    relay: String,
    relay_volume: String,
}

impl ResourceNames {
    fn new() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let counter = SESSION_COUNTER.fetch_add(1, Ordering::Relaxed);
        let token = format!("{}-{nanos:x}-{counter:x}", std::process::id());
        Self {
            label: format!("promptectomy.session={token}"),
            internal_network: format!("pt-{token}-internal"),
            outbound_network: format!("pt-{token}-outbound"),
            worker: format!("pt-{token}-worker"),
            proxy: format!("pt-{token}-proxy"),
            relay: format!("pt-{token}-relay"),
            relay_volume: format!("pt-{token}-relay"),
        }
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the security-critical OCI lifecycle is kept as one auditable linear transaction"
)]
fn run_session(
    docker: &DockerSession<'_>,
    request_path: &Path,
    proxy_request_path: &Path,
    relay_grant_path: Option<&Path>,
    output_root: &Path,
    cancelled: &AtomicBool,
) -> Result<OciRemoteResult, OciRemoteError> {
    docker.required(
        [
            "network",
            "create",
            "--driver",
            "bridge",
            "--internal",
            "--ipv6=false",
            "--opt",
            "com.docker.network.bridge.gateway_mode_ipv4=isolated",
            "--label",
            &docker.names.label,
            &docker.names.internal_network,
        ],
        DEFAULT_COMMAND_SECONDS,
        cancelled,
    )?;
    docker.required(
        [
            "network",
            "create",
            "--label",
            &docker.names.label,
            &docker.names.outbound_network,
        ],
        DEFAULT_COMMAND_SECONDS,
        cancelled,
    )?;
    verify_network(docker, &docker.names.internal_network, true, cancelled)?;
    verify_network(docker, &docker.names.outbound_network, false, cancelled)?;

    if let Some(relay_grant_path) = relay_grant_path {
        docker.required(
            [
                "volume",
                "create",
                "--label",
                &docker.names.label,
                &docker.names.relay_volume,
            ],
            DEFAULT_COMMAND_SECONDS,
            cancelled,
        )?;
        create_relay(docker, cancelled)?;
        verify_binary(
            docker,
            &docker.names.relay,
            RELAY_BINARY,
            &docker.manifest.backend.ssh_agent_relay_digest,
            output_root,
            "relay-bin",
            cancelled,
        )?;
        verify_relay_container(docker, cancelled)?;
        docker.required(
            ["start", &docker.names.relay],
            DEFAULT_COMMAND_SECONDS,
            cancelled,
        )?;
        copy_request(
            docker,
            relay_grant_path,
            &docker.names.relay,
            RELAY_GRANT_PATH,
            "0:0",
            cancelled,
        )?;
        await_relay_ready(docker, cancelled)?;
    }

    create_proxy(docker, cancelled)?;
    verify_binary(
        docker,
        &docker.names.proxy,
        PROXY_BINARY,
        &docker.manifest.backend.egress_proxy_digest,
        output_root,
        "proxy-bin",
        cancelled,
    )?;
    docker.required(
        [
            "network",
            "connect",
            &docker.names.outbound_network,
            &docker.names.proxy,
        ],
        DEFAULT_COMMAND_SECONDS,
        cancelled,
    )?;
    verify_container(docker, ContainerRole::Proxy, cancelled)?;
    docker.required(
        ["start", &docker.names.proxy],
        DEFAULT_COMMAND_SECONDS,
        cancelled,
    )?;
    copy_request(
        docker,
        proxy_request_path,
        &docker.names.proxy,
        PROXY_REQUEST_PATH,
        CONTAINER_UID,
        cancelled,
    )?;
    await_proxy_ready(docker, cancelled)?;

    create_worker(docker, cancelled)?;
    verify_binary(
        docker,
        &docker.names.worker,
        WORKER_BINARY,
        &docker.manifest.backend.runner_digest,
        output_root,
        "worker-bin",
        cancelled,
    )?;
    verify_container(docker, ContainerRole::Worker, cancelled)?;
    docker.required(
        ["start", &docker.names.worker],
        DEFAULT_COMMAND_SECONDS,
        cancelled,
    )?;
    verify_worker_default_route_absent(docker, cancelled)?;
    copy_request(
        docker,
        request_path,
        &docker.names.worker,
        REQUEST_PATH,
        CONTAINER_UID,
        cancelled,
    )?;
    let worker_report_bytes = await_worker_report(docker, cancelled)?;
    let source_bundle = docker.read_from(
        &docker.names.worker,
        BUNDLE_PATH,
        usize::try_from(docker.manifest.max_bundle_bytes)
            .map_err(|_| OciRemoteError::InvalidConfiguration)?,
        cancelled,
    )?;
    docker.required(
        ["stop", "--time", "2", &docker.names.worker],
        DEFAULT_COMMAND_SECONDS,
        cancelled,
    )?;
    if relay_grant_path.is_some() {
        await_relay_receipt(docker, cancelled)?;
    }
    let worker_done = serde_jcs::to_vec(&WorkerDone {
        schema_version: WORKER_DONE_SCHEMA,
        manifest_digest: &docker.manifest.manifest_digest,
    })
    .map_err(|_| OciRemoteError::InvalidRequest)?;
    docker.required_with_input(
        [
            OsString::from("exec"),
            OsString::from("--interactive"),
            OsString::from("--user"),
            OsString::from(CONTAINER_UID),
            OsString::from(&docker.names.proxy),
            OsString::from("/usr/bin/dd"),
            OsString::from(format!("of={WORKER_DONE_PATH}")),
            OsString::from("status=none"),
        ],
        worker_done,
        DEFAULT_COMMAND_SECONDS,
        cancelled,
    )?;
    let proxy_report_bytes = await_proxy_terminal(docker, cancelled)?;
    docker.required(
        ["stop", "--time", "2", &docker.names.proxy],
        DEFAULT_COMMAND_SECONDS,
        cancelled,
    )?;

    validate_outputs(
        docker,
        source_bundle,
        &worker_report_bytes,
        &proxy_report_bytes,
    )
}

fn verify_worker_default_route_absent(
    docker: &DockerSession<'_>,
    cancelled: &AtomicBool,
) -> Result<(), OciRemoteError> {
    let routes = docker.read_from(
        &docker.names.worker,
        PROC_NET_ROUTE_PATH,
        64 * 1024,
        cancelled,
    )?;
    if worker_default_route_absent(&routes)? {
        Ok(())
    } else {
        Err(OciRemoteError::ControlMismatch)
    }
}

fn worker_default_route_absent(routes: &[u8]) -> Result<bool, OciRemoteError> {
    let text = std::str::from_utf8(routes).map_err(|_| OciRemoteError::ControlMismatch)?;
    let mut lines = text.lines();
    let header = lines
        .next()
        .ok_or(OciRemoteError::ControlMismatch)?
        .split_ascii_whitespace()
        .collect::<Vec<_>>();
    if header
        != [
            "Iface",
            "Destination",
            "Gateway",
            "Flags",
            "RefCnt",
            "Use",
            "Metric",
            "Mask",
            "MTU",
            "Window",
            "IRTT",
        ]
    {
        return Err(OciRemoteError::ControlMismatch);
    }
    for line in lines {
        let columns = line.split_ascii_whitespace().collect::<Vec<_>>();
        if columns.len() != 11
            || columns[1].len() != 8
            || columns[3].len() != 4
            || columns[7].len() != 8
        {
            return Err(OciRemoteError::ControlMismatch);
        }
        let destination =
            u32::from_str_radix(columns[1], 16).map_err(|_| OciRemoteError::ControlMismatch)?;
        u32::from_str_radix(columns[2], 16).map_err(|_| OciRemoteError::ControlMismatch)?;
        u16::from_str_radix(columns[3], 16).map_err(|_| OciRemoteError::ControlMismatch)?;
        let mask =
            u32::from_str_radix(columns[7], 16).map_err(|_| OciRemoteError::ControlMismatch)?;
        if destination == 0 && mask == 0 {
            return Ok(false);
        }
    }
    Ok(true)
}

fn await_proxy_terminal(
    docker: &DockerSession<'_>,
    cancelled: &AtomicBool,
) -> Result<Vec<u8>, OciRemoteError> {
    let deadline = Instant::now()
        .checked_add(PROXY_TERMINAL_WAIT)
        .ok_or(OciRemoteError::InvalidConfiguration)?;
    loop {
        if cancelled.load(Ordering::Acquire) {
            return Err(OciRemoteError::Cancelled);
        }
        if Instant::now() >= deadline {
            return Err(OciRemoteError::InvalidOutput);
        }
        if let Ok(bytes) = docker.read_from(
            &docker.names.proxy,
            PROXY_REPORT_PATH,
            docker.manifest.max_output_bytes,
            cancelled,
        ) && serde_json::from_slice::<ProxyReport>(&bytes).is_ok_and(|report| {
            report.schema_version == PROXY_SCHEMA
                && report.manifest_digest == docker.manifest.manifest_digest
                && report.terminal
        }) {
            return Ok(bytes);
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn await_proxy_ready(
    docker: &DockerSession<'_>,
    cancelled: &AtomicBool,
) -> Result<(), OciRemoteError> {
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(10))
        .ok_or(OciRemoteError::InvalidConfiguration)?;
    loop {
        if cancelled.load(Ordering::Acquire) {
            return Err(OciRemoteError::Cancelled);
        }
        if Instant::now() >= deadline {
            return Err(OciRemoteError::InvalidOutput);
        }
        if docker
            .read_from(
                &docker.names.proxy,
                PROXY_REPORT_PATH,
                docker.manifest.max_output_bytes,
                cancelled,
            )
            .ok()
            .and_then(|bytes| serde_json::from_slice::<ProxyReport>(&bytes).ok())
            .is_some_and(|report| {
                report.schema_version == PROXY_SCHEMA
                    && report.manifest_digest == docker.manifest.manifest_digest
                    && report.enforcement == RemoteDestinationEnforcement::ApplicationConnectProxy
                    && public_ip_text(&report.resolved_ip)
                    && report.observed_destinations.is_empty()
                    && report.accepted_connections == 0
                    && report.rejected_connections == 0
                    && report.bytes_client_to_upstream == 0
                    && report.bytes_upstream_to_client == 0
                    && !report.byte_limit_exceeded
                    && !report.terminal
            })
        {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn await_worker_report(
    docker: &DockerSession<'_>,
    cancelled: &AtomicBool,
) -> Result<Vec<u8>, OciRemoteError> {
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(
            docker.manifest.wall_time_seconds.saturating_add(10),
        ))
        .ok_or(OciRemoteError::InvalidConfiguration)?;
    loop {
        if cancelled.load(Ordering::Acquire) {
            return Err(OciRemoteError::Cancelled);
        }
        if Instant::now() >= deadline {
            return Err(OciRemoteError::CommandTimedOut);
        }
        if let Ok(bytes) = docker.read_from(
            &docker.names.worker,
            WORKER_REPORT_PATH,
            docker.manifest.max_output_bytes,
            cancelled,
        ) {
            if serde_json::from_slice::<WorkerReport>(&bytes).is_ok() {
                return Ok(bytes);
            }
            if !bytes.is_empty() {
                return Err(OciRemoteError::InvalidOutput);
            }
        }
        thread::sleep(Duration::from_millis(25));
    }
}

impl DockerSession<'_> {
    fn run<I, S>(
        &self,
        arguments: I,
        seconds: u64,
        max_output_bytes: usize,
        cancelled: &AtomicBool,
    ) -> Result<CommandOutput, OciRemoteError>
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        let mut command_arguments =
            vec![OsString::from("--context"), OsString::from(DOCKER_CONTEXT)];
        command_arguments.extend(arguments.into_iter().map(Into::into));
        let plan = CommandPlan {
            program: self.config.docker_program.clone(),
            arguments: command_arguments,
            environment: Vec::new(),
            stdin: Vec::new(),
            max_output_bytes,
            timeout: Duration::from_secs(seconds),
        };
        self.runner.run(&plan, cancelled)
    }

    fn required<I, S>(
        &self,
        arguments: I,
        seconds: u64,
        cancelled: &AtomicBool,
    ) -> Result<Vec<u8>, OciRemoteError>
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        let output = self.run(arguments, seconds, MAX_INSPECT_BYTES, cancelled)?;
        if !output.success {
            return Err(OciRemoteError::CommandFailed);
        }
        Ok(output.stdout)
    }

    fn required_with_input<I, S>(
        &self,
        arguments: I,
        input: Vec<u8>,
        seconds: u64,
        cancelled: &AtomicBool,
    ) -> Result<Vec<u8>, OciRemoteError>
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        if input.is_empty() || input.len() > MAX_REQUEST_BYTES {
            return Err(OciRemoteError::InvalidRequest);
        }
        let mut command_arguments =
            vec![OsString::from("--context"), OsString::from(DOCKER_CONTEXT)];
        command_arguments.extend(arguments.into_iter().map(Into::into));
        let output = self.runner.run(
            &CommandPlan {
                program: self.config.docker_program.clone(),
                arguments: command_arguments,
                environment: Vec::new(),
                stdin: input,
                max_output_bytes: MAX_INSPECT_BYTES,
                timeout: Duration::from_secs(seconds),
            },
            cancelled,
        )?;
        if !output.success {
            return Err(OciRemoteError::CommandFailed);
        }
        Ok(output.stdout)
    }

    fn copy_from(
        &self,
        container: &str,
        source: &str,
        destination: &Path,
        cancelled: &AtomicBool,
    ) -> Result<(), OciRemoteError> {
        let source = format!("{container}:{source}");
        let output = self.run(
            [
                OsString::from("cp"),
                OsString::from(source),
                destination.as_os_str().to_owned(),
            ],
            DEFAULT_COMMAND_SECONDS,
            MAX_INSPECT_BYTES,
            cancelled,
        )?;
        if !output.success {
            return Err(OciRemoteError::CommandFailed);
        }
        Ok(())
    }

    fn read_from(
        &self,
        container: &str,
        source: &str,
        max_output_bytes: usize,
        cancelled: &AtomicBool,
    ) -> Result<Vec<u8>, OciRemoteError> {
        if max_output_bytes == 0 {
            return Err(OciRemoteError::InvalidConfiguration);
        }
        let output = self.run(
            [
                OsString::from("exec"),
                OsString::from("--user"),
                OsString::from(CONTAINER_UID),
                OsString::from(container),
                OsString::from("/usr/bin/cat"),
                OsString::from(source),
            ],
            DEFAULT_COMMAND_SECONDS,
            max_output_bytes,
            cancelled,
        )?;
        if !output.success {
            return Err(OciRemoteError::CommandFailed);
        }
        Ok(output.stdout)
    }
}

fn verify_image(docker: &DockerSession<'_>, cancelled: &AtomicBool) -> Result<(), OciRemoteError> {
    let image = docker.config.image_reference.as_str();
    let output = docker.required(
        ["image", "inspect", "--format", "{{.Id}}", image],
        DEFAULT_COMMAND_SECONDS,
        cancelled,
    )?;
    let digest = parse_single_line(&output)?;
    if digest != docker.manifest.backend.image_digest {
        return Err(OciRemoteError::ImageDigestMismatch);
    }
    Ok(())
}

fn verify_runtime(
    docker: &DockerSession<'_>,
    cancelled: &AtomicBool,
) -> Result<(), OciRemoteError> {
    let context = docker.required(["context", "show"], DEFAULT_COMMAND_SECONDS, cancelled)?;
    if parse_single_line(&context)? != DOCKER_CONTEXT {
        return Err(OciRemoteError::ControlMismatch);
    }
    let server = docker.required(
        ["version", "--format", "{{json .Server}}"],
        DEFAULT_COMMAND_SECONDS,
        cancelled,
    )?;
    let document: Value =
        serde_json::from_slice(&server).map_err(|_| OciRemoteError::ControlMismatch)?;
    let version = document
        .get("Version")
        .and_then(Value::as_str)
        .ok_or(OciRemoteError::ControlMismatch)?;
    let major = version
        .split_once('.')
        .map_or(version, |(major, _)| major)
        .parse::<u64>()
        .map_err(|_| OciRemoteError::ControlMismatch)?;
    if document.get("Os").and_then(Value::as_str) != Some(SERVER_OS)
        || document.get("Arch").and_then(Value::as_str) != Some(SERVER_ARCH)
        || major < MIN_DOCKER_SERVER_MAJOR
    {
        return Err(OciRemoteError::ControlMismatch);
    }
    Ok(())
}

fn verify_network(
    docker: &DockerSession<'_>,
    network: &str,
    expected_internal: bool,
    cancelled: &AtomicBool,
) -> Result<(), OciRemoteError> {
    let output = docker.required(
        ["network", "inspect", "--format", "{{json .}}", network],
        DEFAULT_COMMAND_SECONDS,
        cancelled,
    )?;
    let document: Value =
        serde_json::from_slice(&output).map_err(|_| OciRemoteError::ControlMismatch)?;
    if document.get("Internal").and_then(Value::as_bool) != Some(expected_internal)
        || document.get("Driver").and_then(Value::as_str) != Some("bridge")
        || (expected_internal
            && (document.get("EnableIPv6").and_then(Value::as_bool) != Some(false)
                || document
                    .get("Options")
                    .and_then(Value::as_object)
                    .and_then(|options| options.get("com.docker.network.bridge.gateway_mode_ipv4"))
                    .and_then(Value::as_str)
                    != Some("isolated")))
    {
        return Err(OciRemoteError::ControlMismatch);
    }
    Ok(())
}

fn common_create_arguments(docker: &DockerSession<'_>, name: &str) -> Vec<OsString> {
    vec![
        "create".into(),
        "--name".into(),
        name.into(),
        "--label".into(),
        docker.names.label.clone().into(),
        "--pull".into(),
        "never".into(),
        "--read-only".into(),
        "--user".into(),
        docker.config.user.clone().into(),
        "--cap-drop".into(),
        "ALL".into(),
        "--security-opt".into(),
        "no-new-privileges".into(),
        "--pids-limit".into(),
        docker.config.pids_limit.to_string().into(),
        "--memory".into(),
        docker.config.memory_bytes.to_string().into(),
        "--cpus".into(),
        format!(
            "{}.{:03}",
            docker.config.nano_cpus / 1_000_000_000,
            docker.config.nano_cpus % 1_000_000_000 / 1_000_000
        )
        .into(),
        "--network".into(),
        docker.names.internal_network.clone().into(),
        "--env".into(),
        "PATH=/usr/bin".into(),
        "--tmpfs".into(),
        format!(
            "/work/input:rw,noexec,nosuid,nodev,size={INPUT_TMPFS_BYTES},mode=0700,uid=65532,gid=65532"
        )
        .into(),
        "--tmpfs".into(),
        format!(
            "/work/output:rw,noexec,nosuid,nodev,size={},mode=0700,uid=65532,gid=65532",
            docker.config.output_tmpfs_bytes
        )
        .into(),
        "--tmpfs".into(),
        format!(
            "/tmp:rw,noexec,nosuid,nodev,size={},mode=1777,uid=65532,gid=65532",
            docker.config.temp_tmpfs_bytes
        )
        .into(),
    ]
}

fn create_proxy(docker: &DockerSession<'_>, cancelled: &AtomicBool) -> Result<(), OciRemoteError> {
    let mut arguments = common_create_arguments(docker, &docker.names.proxy);
    arguments.extend([
        "--network-alias".into(),
        "promptectomy-egress-proxy".into(),
        "--network-alias".into(),
        "proxy".into(),
        "--entrypoint".into(),
        PROXY_BINARY.into(),
        docker.config.image_reference.clone().into(),
    ]);
    let output = docker.run(
        arguments,
        DEFAULT_COMMAND_SECONDS,
        MAX_INSPECT_BYTES,
        cancelled,
    )?;
    if !output.success {
        return Err(OciRemoteError::CommandFailed);
    }
    Ok(())
}

fn create_relay(docker: &DockerSession<'_>, cancelled: &AtomicBool) -> Result<(), OciRemoteError> {
    let upstream = docker
        .config
        .relay_upstream
        .as_ref()
        .ok_or(OciRemoteError::InvalidConfiguration)?;
    let upstream_mount = match upstream {
        RelayUpstream::OrbstackHost => {
            format!("type=bind,source={ORBSTACK_HOST_AGENT_SOCKET},target={RELAY_UPSTREAM_PATH}")
        }
        #[cfg(test)]
        RelayUpstream::TestVolume(volume) => {
            format!("type=volume,source={volume},target=/work/upstream,volume-nocopy")
        }
    };
    let arguments: Vec<OsString> = vec![
        "create".into(),
        "--name".into(),
        docker.names.relay.clone().into(),
        "--label".into(),
        docker.names.label.clone().into(),
        "--pull".into(),
        "never".into(),
        "--read-only".into(),
        "--user".into(),
        "0:0".into(),
        "--cap-drop".into(),
        "ALL".into(),
        "--security-opt".into(),
        "no-new-privileges".into(),
        "--pids-limit".into(),
        "32".into(),
        "--memory".into(),
        (128 * 1024 * 1024).to_string().into(),
        "--cpus".into(),
        "0.250".into(),
        "--network".into(),
        "none".into(),
        "--env".into(),
        "PATH=/usr/bin".into(),
        "--tmpfs".into(),
        format!(
            "/work/input:rw,noexec,nosuid,nodev,size={INPUT_TMPFS_BYTES},mode=0700,uid=0,gid=0"
        )
        .into(),
        "--tmpfs".into(),
        "/work/output:rw,noexec,nosuid,nodev,size=262144,mode=0700,uid=0,gid=0".into(),
        "--tmpfs".into(),
        "/tmp:rw,noexec,nosuid,nodev,size=4194304,mode=1777,uid=0,gid=0".into(),
        "--mount".into(),
        format!(
            "type=volume,source={},target=/work/relay,volume-nocopy",
            docker.names.relay_volume
        )
        .into(),
        "--mount".into(),
        upstream_mount.into(),
        "--entrypoint".into(),
        RELAY_BINARY.into(),
        docker.config.image_reference.clone().into(),
    ];
    let output = docker.run(
        arguments,
        DEFAULT_COMMAND_SECONDS,
        MAX_INSPECT_BYTES,
        cancelled,
    )?;
    if output.success {
        Ok(())
    } else {
        Err(OciRemoteError::CommandFailed)
    }
}

fn await_relay_ready(
    docker: &DockerSession<'_>,
    cancelled: &AtomicBool,
) -> Result<(), OciRemoteError> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if cancelled.load(Ordering::Acquire) {
            return Err(OciRemoteError::Cancelled);
        }
        if Instant::now() >= deadline {
            return Err(OciRemoteError::InvalidOutput);
        }
        let output = docker.run(
            [
                "exec",
                "--user",
                "0:0",
                &docker.names.relay,
                "/usr/bin/test",
                "-S",
                RELAY_SOCKET_PATH,
            ],
            DEFAULT_COMMAND_SECONDS,
            MAX_INSPECT_BYTES,
            cancelled,
        );
        if matches!(output, Ok(CommandOutput { success: true, .. })) {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn await_relay_receipt(
    docker: &DockerSession<'_>,
    cancelled: &AtomicBool,
) -> Result<(), OciRemoteError> {
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(
            docker.manifest.wall_time_seconds.saturating_add(5),
        ))
        .ok_or(OciRemoteError::InvalidConfiguration)?;
    loop {
        if cancelled.load(Ordering::Acquire) {
            return Err(OciRemoteError::Cancelled);
        }
        if Instant::now() >= deadline {
            return Err(OciRemoteError::InvalidOutput);
        }
        verify_relay_running(docker, cancelled)?;
        if let Ok(output) = docker.run(
            [
                "exec",
                "--user",
                "0:0",
                &docker.names.relay,
                "/usr/bin/cat",
                RELAY_RECEIPT_PATH,
            ],
            DEFAULT_COMMAND_SECONDS,
            MAX_INSPECT_BYTES,
            cancelled,
        ) && output.success
            && serde_json::from_slice::<promptectomy_ssh_agent_relay::RelayReceiptDocument>(
                &output.stdout,
            )
            .is_ok_and(|receipt| {
                receipt.schema_version == promptectomy_ssh_agent_relay::RECEIPT_VERSION
                    && receipt.manifest_digest == docker.manifest.manifest_digest
                    && receipt.session_bound
                    && receipt.signatures > 0
                    && receipt.signatures <= 4
            })
        {
            verify_relay_running(docker, cancelled)?;
            return Ok(());
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn verify_relay_running(
    docker: &DockerSession<'_>,
    cancelled: &AtomicBool,
) -> Result<(), OciRemoteError> {
    let state = docker.required(
        [
            "inspect",
            "--format",
            "{{json .State}}",
            &docker.names.relay,
        ],
        DEFAULT_COMMAND_SECONDS,
        cancelled,
    )?;
    let state: Value =
        serde_json::from_slice(&state).map_err(|_| OciRemoteError::ControlMismatch)?;
    if state.get("Running").and_then(Value::as_bool) != Some(true)
        || state.get("Dead").and_then(Value::as_bool) != Some(false)
        || state.get("Restarting").and_then(Value::as_bool) != Some(false)
        || state.get("OOMKilled").and_then(Value::as_bool) != Some(false)
        || state.get("ExitCode").and_then(Value::as_i64) != Some(0)
        || state.get("Error").and_then(Value::as_str) != Some("")
    {
        return Err(OciRemoteError::ControlMismatch);
    }
    Ok(())
}

fn create_worker(docker: &DockerSession<'_>, cancelled: &AtomicBool) -> Result<(), OciRemoteError> {
    let mut arguments = common_create_arguments(docker, &docker.names.worker);
    arguments.extend([
        "--tmpfs".into(),
        format!(
            "/work/run:rw,noexec,nosuid,nodev,size={},mode=0700,uid=65532,gid=65532",
            docker.manifest.max_remote_work_bytes
        )
        .into(),
    ]);
    for (name, value) in [
        ("HTTPS_PROXY", "http://proxy:8080"),
        ("HTTP_PROXY", "http://proxy:8080"),
        ("ALL_PROXY", "http://proxy:8080"),
        ("NO_PROXY", ""),
        ("GIT_CONFIG_NOSYSTEM", "1"),
        ("HOME", "/nonexistent"),
    ] {
        arguments.extend(["--env".into(), format!("{name}={value}").into()]);
    }
    if docker.config.relay_upstream.is_some() {
        arguments.extend([
            "--mount".into(),
            format!(
                "type=volume,source={},target=/work/relay,readonly,volume-nocopy",
                docker.names.relay_volume
            )
            .into(),
        ]);
    }
    arguments.extend([
        "--entrypoint".into(),
        WORKER_BINARY.into(),
        docker.config.image_reference.clone().into(),
    ]);
    let output = docker.run(
        arguments,
        DEFAULT_COMMAND_SECONDS,
        MAX_INSPECT_BYTES,
        cancelled,
    )?;
    if !output.success {
        return Err(OciRemoteError::CommandFailed);
    }
    Ok(())
}

fn copy_request(
    docker: &DockerSession<'_>,
    request: &Path,
    container: &str,
    target: &str,
    user: &str,
    cancelled: &AtomicBool,
) -> Result<(), OciRemoteError> {
    let request = read_bounded(
        request,
        u64::try_from(MAX_REQUEST_BYTES).map_err(|_| OciRemoteError::InvalidConfiguration)?,
        AcquisitionError::InvalidRemoteManifest,
    )?;
    let output = docker.required_with_input(
        [
            OsString::from("exec"),
            OsString::from("--interactive"),
            OsString::from("--user"),
            OsString::from(user),
            OsString::from(container),
            OsString::from("/usr/bin/dd"),
            OsString::from(format!("of={target}")),
            OsString::from("status=none"),
        ],
        request,
        DEFAULT_COMMAND_SECONDS,
        cancelled,
    )?;
    if !output.iter().all(u8::is_ascii_whitespace) {
        return Err(OciRemoteError::CommandFailed);
    }
    Ok(())
}

fn verify_binary(
    docker: &DockerSession<'_>,
    container: &str,
    binary: &str,
    expected_digest: &str,
    output_root: &Path,
    local_name: &str,
    cancelled: &AtomicBool,
) -> Result<(), OciRemoteError> {
    let local_path = output_root.join(local_name);
    docker.copy_from(container, binary, &local_path, cancelled)?;
    let bytes = read_bounded(
        &local_path,
        MAX_BINARY_BYTES,
        AcquisitionError::InvalidRemoteAttestation,
    )?;
    if digest_string(&bytes) != expected_digest {
        return Err(OciRemoteError::BinaryDigestMismatch);
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum ContainerRole {
    Worker,
    Proxy,
}

fn verify_relay_container(
    docker: &DockerSession<'_>,
    cancelled: &AtomicBool,
) -> Result<(), OciRemoteError> {
    let host = docker.required(
        [
            "inspect",
            "--format",
            "{{json .HostConfig}}",
            &docker.names.relay,
        ],
        DEFAULT_COMMAND_SECONDS,
        cancelled,
    )?;
    let config = docker.required(
        [
            "inspect",
            "--format",
            "{{json .Config}}",
            &docker.names.relay,
        ],
        DEFAULT_COMMAND_SECONDS,
        cancelled,
    )?;
    let mounts = docker.required(
        [
            "inspect",
            "--format",
            "{{json .Mounts}}",
            &docker.names.relay,
        ],
        DEFAULT_COMMAND_SECONDS,
        cancelled,
    )?;
    let host: Value = serde_json::from_slice(&host).map_err(|_| OciRemoteError::ControlMismatch)?;
    let host = host.as_object().ok_or(OciRemoteError::ControlMismatch)?;
    let tmpfs = host
        .get("Tmpfs")
        .and_then(Value::as_object)
        .ok_or(OciRemoteError::ControlMismatch)?;
    if host.get("ReadonlyRootfs") != Some(&Value::Bool(true))
        || strings(host.get("CapDrop"))? != ["ALL"]
        || !strings(host.get("SecurityOpt"))?
            .iter()
            .any(|value| value.starts_with("no-new-privileges"))
        || host.get("Privileged") != Some(&Value::Bool(false))
        || host.get("PidsLimit").and_then(Value::as_u64) != Some(32)
        || host.get("Memory").and_then(Value::as_u64) != Some(128 * 1024 * 1024)
        || host.get("NanoCpus").and_then(Value::as_u64) != Some(250_000_000)
        || host.get("NetworkMode").and_then(Value::as_str) != Some("none")
        || !empty_runtime_field(host.get("Binds"))
        || tmpfs.len() != 3
        || !valid_root_tmpfs(tmpfs.get("/work/input"), "size=262144", "mode=0700")
        || !valid_root_tmpfs(tmpfs.get("/work/output"), "size=262144", "mode=0700")
        || !valid_root_tmpfs(tmpfs.get("/tmp"), "size=4194304", "mode=1777")
    {
        return Err(OciRemoteError::ControlMismatch);
    }
    let config: Value =
        serde_json::from_slice(&config).map_err(|_| OciRemoteError::ControlMismatch)?;
    if config.get("User").and_then(Value::as_str) != Some("0:0")
        || config
            .get("Entrypoint")
            .and_then(Value::as_array)
            .is_none_or(|entrypoint| {
                entrypoint.len() != 1 || entrypoint[0].as_str() != Some(RELAY_BINARY)
            })
        || strings(config.get("Env"))? != ["PATH=/usr/bin"]
    {
        return Err(OciRemoteError::ControlMismatch);
    }
    let mounts: Value =
        serde_json::from_slice(&mounts).map_err(|_| OciRemoteError::ControlMismatch)?;
    let mounts = mounts.as_array().ok_or(OciRemoteError::ControlMismatch)?;
    if mounts.len() != 2
        || !mounts.iter().any(|mount| {
            mount.get("Type").and_then(Value::as_str) == Some("volume")
                && mount.get("Name").and_then(Value::as_str)
                    == Some(docker.names.relay_volume.as_str())
                && mount.get("Destination").and_then(Value::as_str) == Some("/work/relay")
                && mount.get("RW").and_then(Value::as_bool) == Some(true)
        })
        || !mounts
            .iter()
            .any(|mount| valid_relay_upstream_mount(docker, mount))
    {
        return Err(OciRemoteError::ControlMismatch);
    }
    Ok(())
}

fn valid_relay_upstream_mount(docker: &DockerSession<'_>, mount: &Value) -> bool {
    match docker.config.relay_upstream.as_ref() {
        Some(RelayUpstream::OrbstackHost) => {
            mount.get("Type").and_then(Value::as_str) == Some("bind")
                && mount.get("Source").and_then(Value::as_str) == Some(ORBSTACK_HOST_AGENT_SOCKET)
                && mount.get("Destination").and_then(Value::as_str) == Some(RELAY_UPSTREAM_PATH)
                && mount.get("RW").and_then(Value::as_bool) == Some(true)
        }
        #[cfg(test)]
        Some(RelayUpstream::TestVolume(volume)) => {
            mount.get("Type").and_then(Value::as_str) == Some("volume")
                && mount.get("Name").and_then(Value::as_str) == Some(volume.as_str())
                && mount.get("Destination").and_then(Value::as_str) == Some("/work/upstream")
                && mount.get("RW").and_then(Value::as_bool) == Some(true)
        }
        None => false,
    }
}

fn verify_container(
    docker: &DockerSession<'_>,
    role: ContainerRole,
    cancelled: &AtomicBool,
) -> Result<(), OciRemoteError> {
    let (container, binary, networks) = match role {
        ContainerRole::Worker => (
            docker.names.worker.as_str(),
            WORKER_BINARY,
            BTreeSet::from([docker.names.internal_network.as_str()]),
        ),
        ContainerRole::Proxy => (
            docker.names.proxy.as_str(),
            PROXY_BINARY,
            BTreeSet::from([
                docker.names.internal_network.as_str(),
                docker.names.outbound_network.as_str(),
            ]),
        ),
    };
    let host = docker.required(
        ["inspect", "--format", "{{json .HostConfig}}", container],
        DEFAULT_COMMAND_SECONDS,
        cancelled,
    )?;
    let config = docker.required(
        ["inspect", "--format", "{{json .Config}}", container],
        DEFAULT_COMMAND_SECONDS,
        cancelled,
    )?;
    let network = docker.required(
        [
            "inspect",
            "--format",
            "{{json .NetworkSettings.Networks}}",
            container,
        ],
        DEFAULT_COMMAND_SECONDS,
        cancelled,
    )?;
    let mounts = docker.required(
        ["inspect", "--format", "{{json .Mounts}}", container],
        DEFAULT_COMMAND_SECONDS,
        cancelled,
    )?;
    validate_host_config(docker, role, &host)?;
    validate_container_config(docker, role, binary, &config)?;
    validate_container_mounts(docker, role, &mounts)?;
    let document: Value =
        serde_json::from_slice(&network).map_err(|_| OciRemoteError::ControlMismatch)?;
    let observed = document
        .as_object()
        .ok_or(OciRemoteError::ControlMismatch)?
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if observed != networks {
        return Err(OciRemoteError::ControlMismatch);
    }
    Ok(())
}

fn validate_host_config(
    docker: &DockerSession<'_>,
    role: ContainerRole,
    bytes: &[u8],
) -> Result<(), OciRemoteError> {
    let document: Value =
        serde_json::from_slice(bytes).map_err(|_| OciRemoteError::ControlMismatch)?;
    let object = document
        .as_object()
        .ok_or(OciRemoteError::ControlMismatch)?;
    let cap_drop = strings(object.get("CapDrop"))?;
    let security_opt = strings(object.get("SecurityOpt"))?;
    let tmpfs = object
        .get("Tmpfs")
        .and_then(Value::as_object)
        .ok_or(OciRemoteError::ControlMismatch)?;
    let host_binds_valid = validate_host_binds(docker, role, object.get("Binds"));
    let host_mounts_valid = validate_host_mounts(docker, role, object.get("Mounts"));
    let no_ports = object.get("PortBindings").is_none_or(|value| {
        value.is_null() || value.as_object().is_some_and(serde_json::Map::is_empty)
    });
    let output_size = format!("size={}", docker.config.output_tmpfs_bytes);
    let temp_size = format!("size={}", docker.config.temp_tmpfs_bytes);
    let input_size = format!("size={INPUT_TMPFS_BYTES}");
    let work_size = format!("size={}", docker.manifest.max_remote_work_bytes);
    let work_tmpfs_valid = match role {
        ContainerRole::Worker => {
            tmpfs.len() == 4 && valid_tmpfs(tmpfs.get("/work/run"), &work_size, "mode=0700")
        }
        ContainerRole::Proxy => tmpfs.len() == 3 && !tmpfs.contains_key("/work/run"),
    };
    if object.get("ReadonlyRootfs") != Some(&Value::Bool(true))
        || cap_drop != ["ALL"]
        || security_opt.len() != 1
        || !matches!(
            security_opt.first().map(String::as_str),
            Some("no-new-privileges" | "no-new-privileges:true")
        )
        || object.get("Privileged") != Some(&Value::Bool(false))
        || object.get("AutoRemove") != Some(&Value::Bool(false))
        || object.get("PublishAllPorts") != Some(&Value::Bool(false))
        || !empty_runtime_field(object.get("CapAdd"))
        || !empty_runtime_field(object.get("Devices"))
        || !empty_runtime_field(object.get("DeviceRequests"))
        || !empty_runtime_field(object.get("DeviceCgroupRules"))
        || !host_binds_valid
        || !host_mounts_valid
        || !empty_runtime_field(object.get("PortBindings"))
        || !empty_runtime_field(object.get("Links"))
        || !empty_runtime_field(object.get("VolumesFrom"))
        || !empty_runtime_field(object.get("Dns"))
        || !empty_runtime_field(object.get("DnsOptions"))
        || !empty_runtime_field(object.get("DnsSearch"))
        || !empty_runtime_field(object.get("ExtraHosts"))
        || !empty_runtime_field(object.get("GroupAdd"))
        || !empty_runtime_field(object.get("PidMode"))
        || !empty_runtime_field(object.get("UTSMode"))
        || !empty_runtime_field(object.get("UsernsMode"))
        || !safe_private_namespace(object.get("IpcMode"))
        || !safe_private_namespace(object.get("CgroupnsMode"))
        || object.get("PidsLimit").and_then(Value::as_u64)
            != Some(u64::from(docker.config.pids_limit))
        || object.get("Memory").and_then(Value::as_u64) != Some(docker.config.memory_bytes)
        || object.get("NanoCpus").and_then(Value::as_u64) != Some(docker.config.nano_cpus)
        || object.get("NetworkMode").and_then(Value::as_str)
            != Some(docker.names.internal_network.as_str())
        || !no_ports
        || !valid_tmpfs(tmpfs.get("/work/output"), &output_size, "mode=0700")
        || !valid_tmpfs(tmpfs.get("/work/input"), &input_size, "mode=0700")
        || !valid_tmpfs(tmpfs.get("/tmp"), &temp_size, "mode=1777")
        || !work_tmpfs_valid
    {
        return Err(OciRemoteError::ControlMismatch);
    }
    Ok(())
}

fn validate_host_mounts(
    docker: &DockerSession<'_>,
    role: ContainerRole,
    value: Option<&Value>,
) -> bool {
    if !matches!(role, ContainerRole::Worker) || docker.config.relay_upstream.is_none() {
        return empty_runtime_field(value);
    }
    value.and_then(Value::as_array).is_some_and(|mounts| {
        mounts.len() == 1
            && mounts[0].get("Type").and_then(Value::as_str) == Some("volume")
            && mounts[0].get("Source").and_then(Value::as_str)
                == Some(docker.names.relay_volume.as_str())
            && mounts[0].get("Target").and_then(Value::as_str) == Some("/work/relay")
            && mounts[0].get("ReadOnly").and_then(Value::as_bool) == Some(true)
    })
}

fn validate_host_binds(
    docker: &DockerSession<'_>,
    role: ContainerRole,
    value: Option<&Value>,
) -> bool {
    let _ = (docker, role);
    empty_runtime_field(value)
}

fn validate_container_mounts(
    docker: &DockerSession<'_>,
    role: ContainerRole,
    bytes: &[u8],
) -> Result<(), OciRemoteError> {
    let document: Value =
        serde_json::from_slice(bytes).map_err(|_| OciRemoteError::ControlMismatch)?;
    let mounts = document.as_array().ok_or(OciRemoteError::ControlMismatch)?;
    let valid = if matches!(role, ContainerRole::Worker) && docker.config.relay_upstream.is_some() {
        mounts.len() == 1
            && mounts[0].get("Type").and_then(Value::as_str) == Some("volume")
            && mounts[0].get("Name").and_then(Value::as_str)
                == Some(docker.names.relay_volume.as_str())
            && mounts[0].get("Destination").and_then(Value::as_str) == Some("/work/relay")
            && mounts[0].get("RW").and_then(Value::as_bool) == Some(false)
    } else {
        mounts.is_empty()
    };
    if valid {
        Ok(())
    } else {
        Err(OciRemoteError::ControlMismatch)
    }
}

fn empty_runtime_field(value: Option<&Value>) -> bool {
    value.is_none_or(|value| {
        value.is_null()
            || value.as_str() == Some("")
            || value.as_array().is_some_and(Vec::is_empty)
            || value.as_object().is_some_and(serde_json::Map::is_empty)
    })
}

fn safe_private_namespace(value: Option<&Value>) -> bool {
    value.is_none_or(|value| matches!(value.as_str(), Some("" | "private")))
}

fn valid_tmpfs(value: Option<&Value>, size: &str, mode: &str) -> bool {
    valid_tmpfs_owner(value, size, mode, "uid=65532", "gid=65532")
}

fn valid_root_tmpfs(value: Option<&Value>, size: &str, mode: &str) -> bool {
    valid_tmpfs_owner(value, size, mode, "uid=0", "gid=0")
}

fn valid_tmpfs_owner(value: Option<&Value>, size: &str, mode: &str, uid: &str, gid: &str) -> bool {
    let Some(options) = value.and_then(Value::as_str) else {
        return false;
    };
    let expected = BTreeSet::from(["rw", "noexec", "nosuid", "nodev", size, mode, uid, gid]);
    let actual = options.split(',').collect::<Vec<_>>();
    actual.len() == expected.len()
        && actual.iter().copied().collect::<BTreeSet<_>>().len() == actual.len()
        && actual.into_iter().collect::<BTreeSet<_>>() == expected
}

fn validate_container_config(
    docker: &DockerSession<'_>,
    role: ContainerRole,
    binary: &str,
    bytes: &[u8],
) -> Result<(), OciRemoteError> {
    let document: Value =
        serde_json::from_slice(bytes).map_err(|_| OciRemoteError::ControlMismatch)?;
    let object = document
        .as_object()
        .ok_or(OciRemoteError::ControlMismatch)?;
    let entrypoint = strings(object.get("Entrypoint"))?;
    let environment = strings(object.get("Env"))?;
    let no_declared_volumes = object.get("Volumes").is_none_or(|value| {
        value.is_null() || value.as_object().is_some_and(serde_json::Map::is_empty)
    });
    let expected_environment = match role {
        ContainerRole::Proxy => BTreeSet::from(["PATH=/usr/bin"]),
        ContainerRole::Worker => BTreeSet::from([
            "ALL_PROXY=http://proxy:8080",
            "GIT_CONFIG_NOSYSTEM=1",
            "HOME=/nonexistent",
            "HTTPS_PROXY=http://proxy:8080",
            "HTTP_PROXY=http://proxy:8080",
            "NO_PROXY=",
            "PATH=/usr/bin",
        ]),
    };
    let observed_environment = environment
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if object.get("User").and_then(Value::as_str) != Some(docker.config.user.as_str())
        || entrypoint != [binary]
        || contains_credential_environment(&environment)
        || environment.len() != expected_environment.len()
        || observed_environment != expected_environment
        || !no_declared_volumes
    {
        return Err(OciRemoteError::ControlMismatch);
    }
    Ok(())
}

fn contains_credential_environment(environment: &[String]) -> bool {
    environment.iter().any(|entry| {
        let key = entry.split_once('=').map_or(entry.as_str(), |(key, _)| key);
        let upper = key.to_ascii_uppercase();
        upper.contains("TOKEN")
            || upper.contains("SECRET")
            || upper.contains("PASSWORD")
            || upper.contains("CREDENTIAL")
            || upper.contains("SSH_AUTH_SOCK")
            || upper.contains("AWS_")
            || upper.contains("GOOGLE_APPLICATION_CREDENTIALS")
            || upper.contains("GITHUB_")
            || upper.contains("GITLAB_")
            || upper.contains("OPENAI_")
    })
}

fn strings(value: Option<&Value>) -> Result<Vec<String>, OciRemoteError> {
    value
        .and_then(Value::as_array)
        .ok_or(OciRemoteError::ControlMismatch)?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or(OciRemoteError::ControlMismatch)
        })
        .collect()
}

fn validate_outputs(
    docker: &DockerSession<'_>,
    source_bundle: Vec<u8>,
    worker_bytes: &[u8],
    proxy_bytes: &[u8],
) -> Result<OciRemoteResult, OciRemoteError> {
    let worker: WorkerReport =
        serde_json::from_slice(worker_bytes).map_err(|_| OciRemoteError::InvalidOutput)?;
    let proxy: ProxyReport =
        serde_json::from_slice(proxy_bytes).map_err(|_| OciRemoteError::InvalidOutput)?;
    let resolved_ip = proxy
        .resolved_ip
        .parse()
        .map_err(|_| OciRemoteError::InvalidOutput)?;
    let tunnel_bytes = proxy
        .bytes_client_to_upstream
        .checked_add(proxy.bytes_upstream_to_client)
        .ok_or(OciRemoteError::InvalidOutput)?;
    let tunnel_limit = docker
        .manifest
        .max_remote_work_bytes
        .saturating_mul(2)
        .min(2 * 1024 * 1024 * 1024);
    if worker.schema_version != WORKER_SCHEMA
        || worker.manifest_digest != docker.manifest.manifest_digest
        || !valid_object_id(&worker.resolved_commit)
        || !is_digest(&worker.git_binary_digest)
        || !worker.git_execution_neutralized
        || !worker.credentials_isolated
        || worker.source_bundle_digest != domain_digest("remote-source-bundle", &source_bundle)
        || proxy.schema_version != PROXY_SCHEMA
        || proxy.manifest_digest != docker.manifest.manifest_digest
        || proxy.enforcement != RemoteDestinationEnforcement::ApplicationConnectProxy
        || proxy.observed_destinations.len() != 1
        || proxy.observed_destinations[0].host != docker.manifest.destination.host
        || proxy.observed_destinations[0].port != docker.manifest.destination.port
        || !public_ip(resolved_ip)
        || proxy.accepted_connections == 0
        || proxy.bytes_client_to_upstream == 0
        || proxy.bytes_upstream_to_client == 0
        || tunnel_bytes > tunnel_limit
        || proxy.rejected_connections != 0
        || proxy.byte_limit_exceeded
        || !proxy.terminal
    {
        return Err(OciRemoteError::InvalidOutput);
    }
    Ok(OciRemoteResult {
        source_bundle,
        resolved_commit: worker.resolved_commit,
        git_binary_digest: worker.git_binary_digest,
        observed_destination_host: proxy.observed_destinations[0].host.clone(),
        observed_destination_port: proxy.observed_destinations[0].port,
        controls: OciControlEvidence {
            backend_profile: docker.manifest.backend.profile,
            image_digest: docker.manifest.backend.image_digest.clone(),
            runner_digest: docker.manifest.backend.runner_digest.clone(),
            proxy_digest: docker.manifest.backend.egress_proxy_digest.clone(),
            root_read_only: ControlAttestation::Passed,
            no_new_privileges: ControlAttestation::Passed,
            capabilities_dropped: ControlAttestation::Passed,
            resource_limits: ControlAttestation::Passed,
            remote_work_tmpfs_bytes: docker.manifest.max_remote_work_bytes,
            input_tmpfs_bytes: INPUT_TMPFS_BYTES,
            output_tmpfs_bytes: docker.config.output_tmpfs_bytes,
            temporary_tmpfs_bytes: docker.config.temp_tmpfs_bytes,
            worker_internal_network_only: ControlAttestation::Passed,
            proxy_dual_homed: ControlAttestation::Passed,
            credentials_isolated: ControlAttestation::Passed,
            destination_enforcement: RemoteDestinationEnforcement::ApplicationConnectProxy,
            kernel_exact_destination_enforced: false,
            worker_default_route_absent: ControlAttestation::Passed,
            proxy_gateway_and_host_reachability_kernel_blocked: false,
            cleanup_complete: ControlAttestation::Failed,
        },
    })
}

fn cleanup_session(docker: &DockerSession<'_>) -> Result<(), OciRemoteError> {
    let never_cancel = AtomicBool::new(false);
    for container in [
        &docker.names.worker,
        &docker.names.proxy,
        &docker.names.relay,
    ] {
        let _ = docker.run(
            ["rm", "--force", "--volumes", container],
            DEFAULT_COMMAND_SECONDS,
            MAX_INSPECT_BYTES,
            &never_cancel,
        );
    }
    let _ = docker.run(
        ["volume", "rm", &docker.names.relay_volume],
        DEFAULT_COMMAND_SECONDS,
        MAX_INSPECT_BYTES,
        &never_cancel,
    );
    for network in [
        &docker.names.internal_network,
        &docker.names.outbound_network,
    ] {
        let _ = docker.run(
            ["network", "rm", network],
            DEFAULT_COMMAND_SECONDS,
            MAX_INSPECT_BYTES,
            &never_cancel,
        );
    }
    let containers = docker.run(
        [
            "ps",
            "-aq",
            "--filter",
            &format!("label={}", docker.names.label),
        ],
        DEFAULT_COMMAND_SECONDS,
        MAX_INSPECT_BYTES,
        &never_cancel,
    )?;
    let networks = docker.run(
        [
            "network",
            "ls",
            "-q",
            "--filter",
            &format!("label={}", docker.names.label),
        ],
        DEFAULT_COMMAND_SECONDS,
        MAX_INSPECT_BYTES,
        &never_cancel,
    )?;
    let volumes = docker.run(
        [
            "volume",
            "ls",
            "-q",
            "--filter",
            &format!("label={}", docker.names.label),
        ],
        DEFAULT_COMMAND_SECONDS,
        MAX_INSPECT_BYTES,
        &never_cancel,
    )?;
    if !containers.success
        || !networks.success
        || !volumes.success
        || !containers.stdout.iter().all(u8::is_ascii_whitespace)
        || !networks.stdout.iter().all(u8::is_ascii_whitespace)
        || !volumes.stdout.iter().all(u8::is_ascii_whitespace)
    {
        return Err(OciRemoteError::CleanupFailed);
    }
    Ok(())
}

fn parse_single_line(bytes: &[u8]) -> Result<String, OciRemoteError> {
    let text = std::str::from_utf8(bytes).map_err(|_| OciRemoteError::ControlMismatch)?;
    let trimmed = text.trim();
    if trimmed.is_empty()
        || trimmed
            .bytes()
            .any(|byte| byte.is_ascii_control() && !byte.is_ascii_whitespace())
        || trimmed.lines().count() != 1
    {
        return Err(OciRemoteError::ControlMismatch);
    }
    Ok(trimmed.to_owned())
}

fn valid_object_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn public_ip(address: std::net::IpAddr) -> bool {
    match address {
        std::net::IpAddr::V4(value) => {
            !value.is_private()
                && !value.is_loopback()
                && !value.is_link_local()
                && !value.is_broadcast()
                && !value.is_documentation()
                && !value.is_unspecified()
                && !value.is_multicast()
                && !matches!(
                    value.octets(),
                    [0 | 240..=255, ..]
                        | [100, 64..=127, ..]
                        | [192, 0, 0, ..]
                        | [198, 18..=19, ..]
                )
        }
        std::net::IpAddr::V6(value) => {
            let octets = value.octets();
            !(value.is_loopback()
                || value.is_unspecified()
                || value.is_multicast()
                || (octets[0] & 0xfe) == 0xfc
                || (octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80))
                && !(octets[0] == 0x20
                    && octets[1] == 0x01
                    && octets[2] == 0x0d
                    && octets[3] == 0xb8)
        }
    }
}

fn public_ip_text(value: &str) -> bool {
    value.parse().is_ok_and(public_ip)
}

fn domain_digest(domain: &str, value: &[u8]) -> String {
    let mut payload = Vec::with_capacity(domain.len() + value.len() + 1);
    payload.extend_from_slice(domain.as_bytes());
    payload.push(0);
    payload.extend_from_slice(value);
    digest_string(&payload)
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::process::Stdio;
    use std::sync::Mutex;

    use super::*;
    use crate::remote::{EgressDestination, RemoteBackendPolicy};

    const LOCATOR: &str = "https://github.com/example/private-path.git";
    const BUNDLE: &[u8] = b"bounded-source-bundle";
    const WORKER_BINARY_BYTES: &[u8] = b"worker-binary";
    const PROXY_BINARY_BYTES: &[u8] = b"proxy-binary";
    const RELAY_BINARY_BYTES: &[u8] = b"relay-binary";
    #[cfg(unix)]
    const SYNTHETIC_HOST_KEY_BASE64: &str = concat!(
        "AAAAC3NzaC1l",
        "ZDI1NTE5AAAA",
        "IHN5bnRoZXRp",
        "Yy1ob3N0LWtleQ"
    );

    #[allow(
        clippy::struct_excessive_bools,
        reason = "independent fault-injection switches keep transcript cases explicit"
    )]
    struct TranscriptRunner {
        plans: Mutex<Vec<CommandPlan>>,
        manifest_digest: String,
        image_digest: String,
        destination: ProxyDestination,
        control_substitution: bool,
        environment_substitution: bool,
        fail_worker_start: Option<OciRemoteError>,
        malformed_worker_output: bool,
        nonterminal_proxy_output: bool,
        default_route_present: bool,
        binary_substitution: bool,
        runtime_substitution: bool,
        server_os: &'static str,
        server_arch: &'static str,
        server_version: &'static str,
        worker_started: AtomicBool,
        worker_done: AtomicBool,
        relay_enabled: bool,
        relay_failed: bool,
    }

    impl TranscriptRunner {
        fn accepted(manifest: &RemoteGitManifest) -> Self {
            Self {
                plans: Mutex::new(Vec::new()),
                manifest_digest: manifest.manifest_digest.clone(),
                image_digest: manifest.backend.image_digest.clone(),
                destination: ProxyDestination {
                    host: manifest.destination.host.clone(),
                    port: manifest.destination.port,
                },
                control_substitution: false,
                environment_substitution: false,
                fail_worker_start: None,
                malformed_worker_output: false,
                nonterminal_proxy_output: false,
                default_route_present: false,
                binary_substitution: false,
                runtime_substitution: false,
                server_os: SERVER_OS,
                server_arch: SERVER_ARCH,
                server_version: "29.4.0",
                worker_started: AtomicBool::new(false),
                worker_done: AtomicBool::new(false),
                relay_enabled: false,
                relay_failed: false,
            }
        }

        fn plans(&self) -> Vec<CommandPlan> {
            self.plans.lock().expect("plans lock").clone()
        }
    }

    impl CommandRunner for TranscriptRunner {
        #[allow(
            clippy::too_many_lines,
            reason = "the fake runtime mirrors one complete ordered Docker transcript"
        )]
        fn run(&self, plan: &CommandPlan, _: &AtomicBool) -> Result<CommandOutput, OciRemoteError> {
            self.plans.lock().expect("plans lock").push(plan.clone());
            let all_args = plan
                .arguments
                .iter()
                .map(|value| value.to_string_lossy().into_owned())
                .collect::<Vec<_>>();
            assert_eq!(&all_args[..2], ["--context", DOCKER_CONTEXT]);
            let args = &all_args[2..];
            if args == ["context", "show"] {
                return ok(if self.runtime_substitution {
                    "default\n".to_owned()
                } else {
                    format!("{DOCKER_CONTEXT}\n")
                });
            }
            if args == ["version", "--format", "{{json .Server}}"] {
                return ok(serde_json::json!({
                    "Os": self.server_os,
                    "Arch": self.server_arch,
                    "Version": self.server_version,
                })
                .to_string());
            }
            if args.first().is_some_and(|value| value == "image") {
                return ok(format!("{}\n", self.image_digest));
            }
            if args.first().is_some_and(|value| value == "network")
                && args.get(1).is_some_and(|value| value == "inspect")
            {
                let internal = args
                    .last()
                    .is_some_and(|value| value.ends_with("-internal"));
                return ok(serde_json::json!({
                    "Internal": internal,
                    "Driver": "bridge",
                    "EnableIPv6": false,
                    "Options": if internal {
                        serde_json::json!({"com.docker.network.bridge.gateway_mode_ipv4": if self.control_substitution { "nat" } else { "isolated" }})
                    } else {
                        serde_json::json!({})
                    },
                }).to_string());
            }
            if args.first().is_some_and(|value| value == "inspect") {
                let container = args.last().expect("container");
                if container.ends_with("-relay") {
                    let prefix = container.strip_suffix("-relay").expect("relay suffix");
                    if args.iter().any(|value| value == "{{json .State}}") {
                        return ok(serde_json::json!({
                            "Running": !self.relay_failed,
                            "Dead": false,
                            "Restarting": false,
                            "OOMKilled": false,
                            "ExitCode": i32::from(self.relay_failed),
                            "Error": "",
                        })
                        .to_string());
                    }
                    if args.iter().any(|value| value.contains("HostConfig")) {
                        return ok(serde_json::json!({
                            "ReadonlyRootfs": true,
                            "CapDrop": ["ALL"],
                            "SecurityOpt": ["no-new-privileges"],
                            "Privileged": false,
                            "PidsLimit": 32,
                            "Memory": 134_217_728_u64,
                            "NanoCpus": 250_000_000_u64,
                            "NetworkMode": "none",
                            "Binds": null,
                            "Tmpfs": {
                                "/work/input": "rw,noexec,nosuid,nodev,size=262144,mode=0700,uid=0,gid=0",
                                "/work/output": "rw,noexec,nosuid,nodev,size=262144,mode=0700,uid=0,gid=0",
                                "/tmp": "rw,noexec,nosuid,nodev,size=4194304,mode=1777,uid=0,gid=0",
                            },
                        }).to_string());
                    }
                    if args.iter().any(|value| value == "{{json .Config}}") {
                        return ok(serde_json::json!({
                            "User": "0:0",
                            "Entrypoint": [RELAY_BINARY],
                            "Env": ["PATH=/usr/bin"],
                        })
                        .to_string());
                    }
                    if args.iter().any(|value| value == "{{json .Mounts}}") {
                        return ok(serde_json::json!([
                            {
                                "Type": "volume",
                                "Name": format!("{prefix}-relay"),
                                "Destination": "/work/relay",
                                "RW": true,
                            },
                            {
                                "Type": "volume",
                                "Name": "controlled-upstream",
                                "Destination": "/work/upstream",
                                "RW": true,
                            },
                        ])
                        .to_string());
                    }
                }
                let internal = container
                    .strip_suffix(if container.ends_with("-worker") {
                        "-worker"
                    } else {
                        "-proxy"
                    })
                    .expect("container suffix")
                    .to_owned()
                    + "-internal";
                let outbound = container
                    .strip_suffix("-proxy")
                    .map(|prefix| format!("{prefix}-outbound"));
                if args.iter().any(|value| value.contains("HostConfig")) {
                    let readonly = !self.control_substitution;
                    let mut tmpfs = serde_json::Map::from_iter([
                        (
                            "/work/input".to_owned(),
                            Value::String("rw,noexec,nosuid,nodev,size=262144,mode=0700,uid=65532,gid=65532".to_owned()),
                        ),
                        (
                            "/work/output".to_owned(),
                            Value::String("rw,noexec,nosuid,nodev,size=68157440,mode=0700,uid=65532,gid=65532".to_owned()),
                        ),
                        (
                            "/tmp".to_owned(),
                            Value::String("rw,noexec,nosuid,nodev,size=16777216,mode=1777,uid=65532,gid=65532".to_owned()),
                        ),
                    ]);
                    if container.ends_with("-worker") {
                        tmpfs.insert(
                            "/work/run".to_owned(),
                            Value::String("rw,noexec,nosuid,nodev,size=134217728,mode=0700,uid=65532,gid=65532".to_owned()),
                        );
                    }
                    let mounts = if container.ends_with("-worker") && self.relay_enabled {
                        let prefix = container.strip_suffix("-worker").expect("worker suffix");
                        vec![serde_json::json!({
                            "Type": "volume",
                            "Source": format!("{prefix}-relay"),
                            "Target": "/work/relay",
                            "ReadOnly": true,
                        })]
                    } else {
                        Vec::new()
                    };
                    return ok(serde_json::json!({
                        "ReadonlyRootfs": readonly,
                        "CapDrop": ["ALL"],
                        "CapAdd": null,
                        "SecurityOpt": ["no-new-privileges"],
                        "Privileged": false,
                        "AutoRemove": false,
                        "PublishAllPorts": false,
                        "Devices": [],
                        "DeviceRequests": [],
                        "DeviceCgroupRules": null,
                        "Links": null,
                        "VolumesFrom": null,
                        "Dns": [],
                        "DnsOptions": [],
                        "DnsSearch": [],
                        "ExtraHosts": null,
                        "GroupAdd": null,
                        "PidMode": "",
                        "IpcMode": "private",
                        "UTSMode": "",
                        "UsernsMode": "",
                        "CgroupnsMode": "private",
                        "PidsLimit": 64,
                        "Memory": 536_870_912_u64,
                        "NanoCpus": 500_000_000_u64,
                        "NetworkMode": internal,
                        "Binds": null,
                        "Mounts": mounts,
                        "PortBindings": {},
                        "Tmpfs": tmpfs,
                    })
                    .to_string());
                }
                if args.iter().any(|value| value == "{{json .Config}}") {
                    let worker = container.ends_with("-worker");
                    let mut env = vec!["PATH=/usr/bin".to_owned()];
                    if worker {
                        env.extend([
                            "HTTPS_PROXY=http://proxy:8080".to_owned(),
                            "HTTP_PROXY=http://proxy:8080".to_owned(),
                            "ALL_PROXY=http://proxy:8080".to_owned(),
                            "NO_PROXY=".to_owned(),
                            "GIT_CONFIG_NOSYSTEM=1".to_owned(),
                            "HOME=/nonexistent".to_owned(),
                        ]);
                    }
                    if self.environment_substitution {
                        env.push("LANG=C".to_owned());
                    }
                    return ok(serde_json::json!({
                        "User": CONTAINER_UID,
                        "Entrypoint": [if worker { WORKER_BINARY } else { PROXY_BINARY }],
                        "Env": env,
                        "Volumes": null,
                    })
                    .to_string());
                }
                if args.iter().any(|value| value == "{{json .Mounts}}") {
                    let mounts = if container.ends_with("-worker") && self.relay_enabled {
                        let prefix = container.strip_suffix("-worker").expect("worker suffix");
                        vec![serde_json::json!({
                            "Type": "volume",
                            "Name": format!("{prefix}-relay"),
                            "Destination": "/work/relay",
                            "RW": false,
                        })]
                    } else {
                        Vec::new()
                    };
                    return ok(serde_json::to_vec(&mounts).expect("mounts"));
                }
                let mut networks = serde_json::Map::new();
                networks.insert(internal, serde_json::json!({}));
                if let Some(outbound) = outbound {
                    networks.insert(outbound, serde_json::json!({}));
                }
                return ok(Value::Object(networks).to_string());
            }
            if args.first().is_some_and(|value| value == "start")
                && args.last().is_some_and(|value| value.ends_with("-worker"))
            {
                if let Some(error) = self.fail_worker_start {
                    return Err(error);
                }
                self.worker_started.store(true, Ordering::Release);
            }
            if args.first().is_some_and(|value| value == "wait") {
                return ok("0\n");
            }
            if args.first().is_some_and(|value| value == "exec")
                && args.iter().any(|value| value == "/usr/bin/cat")
            {
                let source = args.last().expect("container source");
                if source == BUNDLE_PATH {
                    return ok(BUNDLE);
                }
                if source == WORKER_REPORT_PATH {
                    if self.malformed_worker_output {
                        return ok(b"not-json".as_slice());
                    }
                    return ok(serde_json::to_vec(&serde_json::json!({
                        "schema_version": WORKER_SCHEMA,
                        "manifest_digest": self.manifest_digest,
                        "resolved_commit": "0123456789abcdef0123456789abcdef01234567",
                        "source_bundle_digest": domain_digest("remote-source-bundle", BUNDLE),
                        "git_binary_digest": digest_string(b"git"),
                        "git_execution_neutralized": true,
                        "credentials_isolated": true,
                    }))
                    .expect("worker report"));
                }
                if source == RELAY_RECEIPT_PATH {
                    return ok(serde_json::to_vec(
                        &promptectomy_ssh_agent_relay::RelayReceiptDocument {
                            schema_version: promptectomy_ssh_agent_relay::RECEIPT_VERSION
                                .to_owned(),
                            manifest_digest: self.manifest_digest.clone(),
                            session_bound: true,
                            signatures: 1,
                        },
                    )
                    .expect("relay receipt"));
                }
                if source == PROC_NET_ROUTE_PATH {
                    let destination = if self.default_route_present {
                        "00000000"
                    } else {
                        "0000000A"
                    };
                    let mask = if self.default_route_present {
                        "00000000"
                    } else {
                        "000000FF"
                    };
                    return ok(format!(
                        "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\neth0 {destination} 00000000 0001 0 0 0 {mask} 0 0 0\n"
                    ));
                }
                if source == PROXY_REPORT_PATH {
                    let worker_started = self.worker_started.load(Ordering::Acquire);
                    let worker_done = self.worker_done.load(Ordering::Acquire);
                    let destinations = if worker_started {
                        serde_json::json!([{
                            "host": self.destination.host,
                            "port": self.destination.port,
                        }])
                    } else {
                        serde_json::json!([])
                    };
                    return ok(serde_json::to_vec(&serde_json::json!({
                        "schema_version": PROXY_SCHEMA,
                        "manifest_digest": self.manifest_digest,
                        "observed_destinations": destinations,
                        "enforcement": "application_connect_proxy",
                        "resolved_ip": "140.82.121.3",
                        "accepted_connections": u64::from(worker_started),
                        "rejected_connections": 0,
                        "bytes_client_to_upstream": if worker_started { 128 } else { 0 },
                        "bytes_upstream_to_client": if worker_started { 512 } else { 0 },
                        "byte_limit_exceeded": false,
                        "terminal": worker_done && !self.nonterminal_proxy_output,
                    }))
                    .expect("proxy report"));
                }
            }
            if args.first().is_some_and(|value| value == "cp")
                && let Some(source) = args.get(1).filter(|value| value.contains(':'))
            {
                let destination = PathBuf::from(args.get(2).expect("copy destination"));
                if source.ends_with(WORKER_BINARY) {
                    fs::write(
                        destination,
                        if self.binary_substitution {
                            b"wrong"
                        } else {
                            WORKER_BINARY_BYTES
                        },
                    )
                    .expect("worker binary");
                } else if source.ends_with(PROXY_BINARY) {
                    fs::write(destination, PROXY_BINARY_BYTES).expect("proxy binary");
                } else if source.ends_with(RELAY_BINARY) {
                    fs::write(destination, RELAY_BINARY_BYTES).expect("relay binary");
                } else if source.ends_with(RELAY_RECEIPT_PATH) {
                    fs::write(
                        destination,
                        serde_json::to_vec(&promptectomy_ssh_agent_relay::RelayReceiptDocument {
                            schema_version: promptectomy_ssh_agent_relay::RECEIPT_VERSION
                                .to_owned(),
                            manifest_digest: self.manifest_digest.clone(),
                            session_bound: true,
                            signatures: 1,
                        })
                        .expect("relay receipt"),
                    )
                    .expect("relay receipt");
                } else if source.ends_with(BUNDLE_PATH) {
                    fs::write(destination, BUNDLE).expect("bundle");
                } else if source.ends_with(WORKER_REPORT_PATH) {
                    let bytes = if self.malformed_worker_output {
                        b"not-json".to_vec()
                    } else {
                        serde_json::to_vec(&serde_json::json!({
                            "schema_version": WORKER_SCHEMA,
                            "manifest_digest": self.manifest_digest,
                            "resolved_commit": "0123456789abcdef0123456789abcdef01234567",
                            "source_bundle_digest": domain_digest("remote-source-bundle", BUNDLE),
                            "git_binary_digest": digest_string(b"git"),
                            "git_execution_neutralized": true,
                            "credentials_isolated": true,
                        }))
                        .expect("worker report")
                    };
                    fs::write(destination, bytes).expect("worker report");
                } else if source.ends_with(PROXY_REPORT_PATH) {
                    let worker_started = self.worker_started.load(Ordering::Acquire);
                    let destinations = if worker_started {
                        serde_json::json!([{
                            "host": self.destination.host,
                            "port": self.destination.port,
                        }])
                    } else {
                        serde_json::json!([])
                    };
                    fs::write(
                        destination,
                        serde_json::to_vec(&serde_json::json!({
                            "schema_version": PROXY_SCHEMA,
                            "manifest_digest": self.manifest_digest,
                            "observed_destinations": destinations,
                            "enforcement": "application_connect_proxy",
                            "resolved_ip": "140.82.121.3",
                            "accepted_connections": u64::from(worker_started),
                            "rejected_connections": 0,
                            "bytes_client_to_upstream": if worker_started { 128 } else { 0 },
                            "bytes_upstream_to_client": if worker_started { 512 } else { 0 },
                            "byte_limit_exceeded": false,
                            "terminal": !self.nonterminal_proxy_output,
                        }))
                        .expect("proxy report"),
                    )
                    .expect("proxy report");
                }
            }
            if args.first().is_some_and(|value| value == "exec")
                && args
                    .iter()
                    .any(|value| value == &format!("of={WORKER_DONE_PATH}"))
            {
                self.worker_done.store(true, Ordering::Release);
            }
            ok(Vec::new())
        }
    }

    struct CancelOnWorkerStartRunner;

    impl CommandRunner for CancelOnWorkerStartRunner {
        fn run(
            &self,
            plan: &CommandPlan,
            cancelled: &AtomicBool,
        ) -> Result<CommandOutput, OciRemoteError> {
            let args = docker_args(plan);
            if args.first().is_some_and(|value| value == "start")
                && args
                    .last()
                    .is_some_and(|value| value.to_string_lossy().ends_with("-worker"))
            {
                return Err(OciRemoteError::Cancelled);
            }
            SystemCommandRunner.run(plan, cancelled)
        }
    }

    #[cfg(unix)]
    struct ControlledSshRunner {
        fixture_container: String,
        relay_receipt: Mutex<Option<promptectomy_ssh_agent_relay::RelayReceiptDocument>>,
        worker_error: Mutex<Option<String>>,
    }

    #[cfg(unix)]
    impl CommandRunner for ControlledSshRunner {
        fn run(
            &self,
            plan: &CommandPlan,
            cancelled: &AtomicBool,
        ) -> Result<CommandOutput, OciRemoteError> {
            let args = docker_args(plan);
            let outbound_network = args
                .first()
                .is_some_and(|value| value == "network")
                .then(|| args.last()?.to_str())
                .flatten()
                .filter(|name| name.ends_with("-outbound"));
            if args.get(1).is_some_and(|value| value == "create")
                && let Some(network) = outbound_network
            {
                let mut bounded = plan.clone();
                bounded.arguments.splice(
                    4..4,
                    [OsString::from("--subnet"), OsString::from("8.8.8.0/24")],
                );
                let output = SystemCommandRunner.run(&bounded, cancelled)?;
                if !output.success {
                    return Ok(output);
                }
                run_fixture_docker(
                    &plan.program,
                    [
                        "network",
                        "connect",
                        "--alias",
                        "github.com",
                        "--ip",
                        "8.8.8.8",
                        network,
                        &self.fixture_container,
                    ],
                )?;
                run_fixture_docker(
                    &plan.program,
                    ["network", "disconnect", "bridge", &self.fixture_container],
                )?;
                run_fixture_docker(&plan.program, ["start", self.fixture_container.as_str()])?;
                return Ok(output);
            }
            if args.get(1).is_some_and(|value| value == "rm")
                && let Some(network) = outbound_network
            {
                run_fixture_docker(
                    &plan.program,
                    [
                        "network",
                        "disconnect",
                        network,
                        self.fixture_container.as_str(),
                    ],
                )?;
            }
            let output = SystemCommandRunner.run(plan, cancelled)?;
            if output.success
                && args.last().is_some_and(|value| value == RELAY_RECEIPT_PATH)
                && let Ok(receipt) = serde_json::from_slice(&output.stdout)
            {
                *self.relay_receipt.lock().expect("relay receipt lock") = Some(receipt);
            }
            if output.success
                && args.last().is_some_and(|value| value == WORKER_REPORT_PATH)
                && let Ok(report) = serde_json::from_slice::<Value>(&output.stdout)
                && let Some(error) = report.get("error_code").and_then(Value::as_str)
            {
                *self.worker_error.lock().expect("worker error lock") = Some(error.to_owned());
            }
            if output.success
                && args.first().is_some_and(|value| value == "cp")
                && args
                    .get(1)
                    .is_some_and(|value| value.to_string_lossy().ends_with(RELAY_RECEIPT_PATH))
                && let Some(destination) = args.get(2)
                && let Ok(bytes) = fs::read(destination)
                && let Ok(receipt) = serde_json::from_slice(&bytes)
            {
                *self.relay_receipt.lock().expect("relay receipt lock") = Some(receipt);
            }
            Ok(output)
        }
    }

    #[cfg(unix)]
    fn fixture_docker<const N: usize>(
        program: &Path,
        args: [&str; N],
    ) -> Result<CommandOutput, OciRemoteError> {
        let mut arguments = vec![OsString::from("--context"), OsString::from(DOCKER_CONTEXT)];
        arguments.extend(args.into_iter().map(OsString::from));
        SystemCommandRunner.run(
            &CommandPlan {
                program: program.to_owned(),
                arguments,
                environment: Vec::new(),
                stdin: Vec::new(),
                max_output_bytes: MAX_INSPECT_BYTES,
                timeout: Duration::from_secs(DEFAULT_COMMAND_SECONDS),
            },
            &AtomicBool::new(false),
        )
    }

    #[cfg(unix)]
    fn run_fixture_docker<const N: usize>(
        program: &Path,
        args: [&str; N],
    ) -> Result<(), OciRemoteError> {
        let output = fixture_docker(program, args)?;
        if output.success {
            Ok(())
        } else {
            Err(OciRemoteError::CommandFailed)
        }
    }

    #[cfg(unix)]
    struct FixtureResources {
        docker: PathBuf,
        label: String,
        sshd: String,
        agent: String,
        agent_volume: String,
    }

    #[cfg(unix)]
    impl FixtureResources {
        fn cleanup(&self) -> Result<(), OciRemoteError> {
            for container in [&self.sshd, &self.agent] {
                let _ = fixture_docker(
                    &self.docker,
                    ["rm", "--force", "--volumes", container.as_str()],
                );
            }
            let _ = fixture_docker(&self.docker, ["volume", "rm", self.agent_volume.as_str()]);
            self.assert_empty()
        }

        fn assert_empty(&self) -> Result<(), OciRemoteError> {
            let outputs = [
                fixture_docker(&self.docker, ["ps", "-aq", "--filter", self.label.as_str()])?,
                fixture_docker(
                    &self.docker,
                    ["network", "ls", "-q", "--filter", self.label.as_str()],
                )?,
                fixture_docker(
                    &self.docker,
                    ["volume", "ls", "-q", "--filter", self.label.as_str()],
                )?,
            ];
            for output in outputs {
                if !output.success || !output.stdout.iter().all(u8::is_ascii_whitespace) {
                    return Err(OciRemoteError::CleanupFailed);
                }
            }
            Ok(())
        }
    }

    #[cfg(unix)]
    impl Drop for FixtureResources {
        fn drop(&mut self) {
            let _ = self.cleanup();
        }
    }

    #[allow(
        clippy::unnecessary_wraps,
        reason = "the helper matches the CommandRunner result type at transcript return sites"
    )]
    fn ok(bytes: impl Into<Vec<u8>>) -> Result<CommandOutput, OciRemoteError> {
        Ok(CommandOutput {
            success: true,
            stdout: bytes.into(),
        })
    }

    fn fixture() -> (RemoteGitManifest, OciRemoteConfig) {
        let image = digest_string(b"image");
        let backend = RemoteBackendPolicy {
            profile: RemoteBackendProfile::OrbstackMacosArm64V1,
            image_digest: image.clone(),
            runner_digest: digest_string(WORKER_BINARY_BYTES),
            egress_proxy_digest: digest_string(PROXY_BINARY_BYTES),
            ssh_agent_relay_digest: digest_string(RELAY_BINARY_BYTES),
        };
        let mut manifest = RemoteGitManifest {
            schema_version: crate::REMOTE_GIT_MANIFEST_VERSION.to_owned(),
            source_kind: SourceKind::HttpsRemote,
            manifest_digest: String::new(),
            authority_digest: digest_string(b"authority"),
            locator_digest: domain_digest("remote-locator", LOCATOR.as_bytes()),
            redacted_locator: "https://github.com/<redacted>".to_owned(),
            destination: EgressDestination {
                host: "github.com".to_owned(),
                port: 443,
            },
            revision: "main".to_owned(),
            selected_roots: Vec::new(),
            max_files: 10,
            max_total_bytes: 1024,
            max_file_bytes: 1024,
            max_path_bytes: 256,
            max_remote_work_bytes: 128 * 1024 * 1024,
            max_bundle_bytes: 64 * 1024 * 1024,
            max_output_bytes: 64 * 1024,
            wall_time_seconds: 10,
            checkout_policy: "no_checkout".to_owned(),
            egress_policy: "application_connect_proxy_exact_destination".to_owned(),
            credential_policy: RemoteCredentialPolicy::None,
            broker: None,
            backend,
        };
        manifest.manifest_digest = manifest.computed_digest();
        let config = OciRemoteConfig {
            docker_program: PathBuf::from("/usr/bin/docker"),
            image_reference: format!("promptectomy-remote@{image}"),
            user: CONTAINER_UID.to_owned(),
            pids_limit: 64,
            memory_bytes: 512 * 1024 * 1024,
            nano_cpus: 500_000_000,
            output_tmpfs_bytes: 65 * 1024 * 1024,
            temp_tmpfs_bytes: 16 * 1024 * 1024,
            relay_upstream: None,
        };
        (manifest, config)
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the test audits one complete ordered container transcript"
    )]
    fn accepted_transcript_never_places_locator_in_arguments_or_environment() {
        let (manifest, config) = fixture();
        let runner = TranscriptRunner::accepted(&manifest);
        let result = acquire_public_https(
            &runner,
            &config,
            &manifest,
            LOCATOR,
            &AtomicBool::new(false),
        )
        .expect("accepted acquisition");
        assert_eq!(result.source_bundle, BUNDLE);
        assert!(!result.controls.kernel_exact_destination_enforced);
        assert_eq!(
            result.controls.worker_default_route_absent,
            ControlAttestation::Passed
        );
        assert!(
            !result
                .controls
                .proxy_gateway_and_host_reachability_kernel_blocked
        );
        let plans = runner.plans();
        assert!(plans.iter().all(|plan| {
            plan.arguments
                .iter()
                .chain(
                    plan.environment
                        .iter()
                        .flat_map(|(key, value)| [key, value]),
                )
                .all(|value| !value.to_string_lossy().contains(LOCATOR))
        }));
        let worker_create = plans
            .iter()
            .find(|plan| {
                docker_args(plan)
                    .first()
                    .is_some_and(|value| value == "create")
                    && docker_args(plan)
                        .iter()
                        .any(|value| value.to_string_lossy().ends_with("-worker"))
            })
            .expect("worker create");
        for required in [
            "--read-only",
            "--pull",
            "--cap-drop",
            "--security-opt",
            "--pids-limit",
            "--memory",
            "--cpus",
            "--tmpfs",
        ] {
            assert!(
                worker_create
                    .arguments
                    .iter()
                    .any(|value| value == required)
            );
        }
        let internal_network = plans
            .iter()
            .find(|plan| {
                docker_args(plan)
                    .first()
                    .is_some_and(|value| value == "network")
                    && docker_args(plan)
                        .get(1)
                        .is_some_and(|value| value == "create")
                    && docker_args(plan).iter().any(|value| value == "--internal")
            })
            .expect("internal network create");
        assert!(
            internal_network
                .arguments
                .iter()
                .any(|value| value == "com.docker.network.bridge.gateway_mode_ipv4=isolated")
        );
        let proxy_create = plans
            .iter()
            .find(|plan| {
                docker_args(plan)
                    .first()
                    .is_some_and(|value| value == "create")
                    && docker_args(plan)
                        .iter()
                        .any(|value| value.to_string_lossy().ends_with("-proxy"))
            })
            .expect("proxy create");
        for alias in ["promptectomy-egress-proxy", "proxy"] {
            assert!(proxy_create.arguments.iter().any(|value| value == alias));
        }
        let readiness_read = plans
            .iter()
            .position(|plan| {
                docker_args(plan)
                    .first()
                    .is_some_and(|value| value == "exec")
                    && docker_args(plan)
                        .last()
                        .is_some_and(|value| value.to_string_lossy().ends_with(PROXY_REPORT_PATH))
            })
            .expect("readiness read");
        let worker_create_position = plans
            .iter()
            .position(|plan| std::ptr::eq(plan, worker_create))
            .expect("worker create position");
        assert!(readiness_read < worker_create_position);
        let bundle_read = plans
            .iter()
            .position(|plan| {
                docker_args(plan)
                    .first()
                    .is_some_and(|value| value == "exec")
                    && docker_args(plan)
                        .last()
                        .is_some_and(|value| value.to_string_lossy().ends_with(BUNDLE_PATH))
            })
            .expect("bundle read");
        let worker_stop = plans
            .iter()
            .position(|plan| {
                docker_args(plan)
                    .first()
                    .is_some_and(|value| value == "stop")
                    && docker_args(plan)
                        .last()
                        .is_some_and(|value| value.to_string_lossy().ends_with("-worker"))
            })
            .expect("worker stop");
        assert!(bundle_read < worker_stop);
        let worker_done = plans
            .iter()
            .position(|plan| {
                docker_args(plan)
                    .first()
                    .is_some_and(|value| value == "exec")
                    && docker_args(plan)
                        .iter()
                        .any(|value| value.to_string_lossy() == format!("of={WORKER_DONE_PATH}"))
            })
            .expect("worker done signal");
        let terminal_report_read = plans
            .iter()
            .rposition(|plan| {
                docker_args(plan)
                    .first()
                    .is_some_and(|value| value == "exec")
                    && docker_args(plan)
                        .last()
                        .is_some_and(|value| value.to_string_lossy().ends_with(PROXY_REPORT_PATH))
            })
            .expect("terminal proxy report read");
        let proxy_stop = plans
            .iter()
            .position(|plan| {
                docker_args(plan)
                    .first()
                    .is_some_and(|value| value == "stop")
                    && docker_args(plan)
                        .last()
                        .is_some_and(|value| value.to_string_lossy().ends_with("-proxy"))
            })
            .expect("proxy stop");
        assert!(worker_stop < worker_done);
        assert!(worker_done < terminal_report_read);
        assert!(terminal_report_read < proxy_stop);
    }

    #[test]
    fn substituted_runtime_control_fails_closed_and_cleans_up() {
        let (manifest, config) = fixture();
        let mut runner = TranscriptRunner::accepted(&manifest);
        runner.control_substitution = true;
        assert_eq!(
            acquire_public_https(
                &runner,
                &config,
                &manifest,
                LOCATOR,
                &AtomicBool::new(false)
            ),
            Err(OciRemoteError::ControlMismatch)
        );
        assert_cleanup_attempted(&runner.plans());
    }

    #[test]
    fn unexpected_environment_fails_closed_and_cleans_up() {
        let (manifest, config) = fixture();
        let mut runner = TranscriptRunner::accepted(&manifest);
        runner.environment_substitution = true;
        assert_eq!(
            acquire_public_https(
                &runner,
                &config,
                &manifest,
                LOCATOR,
                &AtomicBool::new(false)
            ),
            Err(OciRemoteError::ControlMismatch)
        );
        assert_cleanup_attempted(&runner.plans());
    }

    #[test]
    fn worker_failure_and_cancel_both_clean_up() {
        for error in [OciRemoteError::CommandFailed, OciRemoteError::Cancelled] {
            let (manifest, config) = fixture();
            let mut runner = TranscriptRunner::accepted(&manifest);
            runner.fail_worker_start = Some(error);
            assert_eq!(
                acquire_public_https(
                    &runner,
                    &config,
                    &manifest,
                    LOCATOR,
                    &AtomicBool::new(false)
                ),
                Err(error)
            );
            assert_cleanup_attempted(&runner.plans());
        }
    }

    #[test]
    fn malformed_untrusted_output_fails_after_cleanup() {
        let (manifest, config) = fixture();
        let mut runner = TranscriptRunner::accepted(&manifest);
        runner.malformed_worker_output = true;
        assert_eq!(
            acquire_public_https(
                &runner,
                &config,
                &manifest,
                LOCATOR,
                &AtomicBool::new(false)
            ),
            Err(OciRemoteError::InvalidOutput)
        );
        assert_cleanup_attempted(&runner.plans());
    }

    #[test]
    fn host_rejects_a_proxy_report_that_is_not_terminal() {
        let (manifest, config) = fixture();
        let mut runner = TranscriptRunner::accepted(&manifest);
        runner.nonterminal_proxy_output = true;
        assert_eq!(
            acquire_public_https(
                &runner,
                &config,
                &manifest,
                LOCATOR,
                &AtomicBool::new(false)
            ),
            Err(OciRemoteError::InvalidOutput)
        );
        assert_cleanup_attempted(&runner.plans());
    }

    #[test]
    fn binary_substitution_fails_before_execution_and_cleans_up() {
        let (manifest, config) = fixture();
        let mut runner = TranscriptRunner::accepted(&manifest);
        runner.binary_substitution = true;
        assert_eq!(
            acquire_public_https(
                &runner,
                &config,
                &manifest,
                LOCATOR,
                &AtomicBool::new(false)
            ),
            Err(OciRemoteError::BinaryDigestMismatch)
        );
        assert_cleanup_attempted(&runner.plans());
    }

    #[test]
    fn runtime_context_substitution_fails_before_resource_creation() {
        let (manifest, config) = fixture();
        let mut runner = TranscriptRunner::accepted(&manifest);
        runner.runtime_substitution = true;
        assert_eq!(
            acquire_public_https(
                &runner,
                &config,
                &manifest,
                LOCATOR,
                &AtomicBool::new(false)
            ),
            Err(OciRemoteError::ControlMismatch)
        );
        assert!(
            runner
                .plans()
                .iter()
                .all(|plan| { !docker_args(plan).iter().any(|value| value == "create") })
        );
    }

    #[test]
    fn runtime_server_identity_and_minimum_version_fail_closed() {
        let (manifest, config) = fixture();
        let mut runners = Vec::new();
        let mut runner = TranscriptRunner::accepted(&manifest);
        runner.server_os = "darwin";
        runners.push(runner);
        let mut runner = TranscriptRunner::accepted(&manifest);
        runner.server_arch = "amd64";
        runners.push(runner);
        let mut runner = TranscriptRunner::accepted(&manifest);
        runner.server_version = "27.5.1";
        runners.push(runner);
        for runner in runners {
            assert_eq!(
                acquire_public_https(
                    &runner,
                    &config,
                    &manifest,
                    LOCATOR,
                    &AtomicBool::new(false)
                ),
                Err(OciRemoteError::ControlMismatch)
            );
            assert!(
                runner
                    .plans()
                    .iter()
                    .all(|plan| { !docker_args(plan).iter().any(|value| value == "create") })
            );
        }
    }

    #[test]
    fn every_resource_bound_is_checked_before_runtime_use() {
        let (manifest, config) = fixture();
        let mut invalid = Vec::new();
        let mut value = config.clone();
        value.pids_limit = 15;
        invalid.push(value);
        let mut value = config.clone();
        value.pids_limit = 257;
        invalid.push(value);
        let mut value = config.clone();
        value.memory_bytes = MIN_CONTAINER_MEMORY_BYTES - 1;
        invalid.push(value);
        let mut value = config.clone();
        value.memory_bytes = 2 * 1024 * 1024 * 1024 + 1;
        invalid.push(value);
        let mut value = config.clone();
        value.nano_cpus = 99_999_999;
        invalid.push(value);
        let mut value = config.clone();
        value.nano_cpus = 2_000_000_001;
        invalid.push(value);
        let mut value = config.clone();
        value.output_tmpfs_bytes = manifest.max_bundle_bytes;
        invalid.push(value);
        let mut value = config.clone();
        value.output_tmpfs_bytes = 1024 * 1024 * 1024 + 1;
        invalid.push(value);
        let mut value = config.clone();
        value.temp_tmpfs_bytes = 3 * 1024 * 1024;
        invalid.push(value);
        let mut value = config;
        value.temp_tmpfs_bytes = 64 * 1024 * 1024 + 1;
        invalid.push(value);
        for config in invalid {
            let runner = TranscriptRunner::accepted(&manifest);
            assert_eq!(
                acquire_public_https(
                    &runner,
                    &config,
                    &manifest,
                    LOCATOR,
                    &AtomicBool::new(false)
                ),
                Err(OciRemoteError::InvalidConfiguration)
            );
            assert!(runner.plans().is_empty());
        }
    }

    #[test]
    fn tmpfs_validation_rejects_duplicate_conflicting_and_unknown_options() {
        let accepted = Value::String(
            "rw,noexec,nosuid,nodev,size=1048576,mode=0700,uid=65532,gid=65532".to_owned(),
        );
        assert!(valid_tmpfs(Some(&accepted), "size=1048576", "mode=0700"));
        for rejected in [
            "rw,rw,noexec,nosuid,nodev,size=1048576,mode=0700,uid=65532,gid=65532",
            "rw,noexec,nosuid,nodev,size=1048576,size=2097152,mode=0700,uid=65532,gid=65532",
            "rw,noexec,nosuid,nodev,size=1048576,mode=0700,mode=0777,uid=65532,gid=65532",
            "rw,noexec,nosuid,nodev,size=1048576,mode=0700,uid=65532,gid=65532,exec",
        ] {
            assert!(!valid_tmpfs(
                Some(&Value::String(rejected.to_owned())),
                "size=1048576",
                "mode=0700"
            ));
        }
    }

    #[test]
    #[ignore = "requires the accepted local OrbStack backend and pinned image"]
    #[allow(
        clippy::too_many_lines,
        reason = "the ignored test keeps one disposable hostile OCI lifecycle linear and auditable"
    )]
    fn orbstack_worker_has_no_default_route_rejects_direct_and_wrong_destination_egress() {
        let (manifest, config) = live_fixture();
        let runner = SystemCommandRunner;
        let docker = DockerSession {
            runner: &runner,
            config: &config,
            manifest: &manifest,
            names: ResourceNames::new(),
        };
        let cancelled = AtomicBool::new(false);
        let result = (|| {
            verify_runtime(&docker, &cancelled)?;
            verify_image(&docker, &cancelled)?;
            docker.required(
                [
                    "network",
                    "create",
                    "--driver",
                    "bridge",
                    "--internal",
                    "--ipv6=false",
                    "--opt",
                    "com.docker.network.bridge.gateway_mode_ipv4=isolated",
                    "--label",
                    &docker.names.label,
                    &docker.names.internal_network,
                ],
                DEFAULT_COMMAND_SECONDS,
                &cancelled,
            )?;
            docker.required(
                [
                    "network",
                    "create",
                    "--label",
                    &docker.names.label,
                    &docker.names.outbound_network,
                ],
                DEFAULT_COMMAND_SECONDS,
                &cancelled,
            )?;
            verify_network(&docker, &docker.names.internal_network, true, &cancelled)?;
            verify_network(&docker, &docker.names.outbound_network, false, &cancelled)?;

            create_proxy(&docker, &cancelled)?;
            docker.required(
                [
                    "network",
                    "connect",
                    &docker.names.outbound_network,
                    &docker.names.proxy,
                ],
                DEFAULT_COMMAND_SECONDS,
                &cancelled,
            )?;
            verify_container(&docker, ContainerRole::Proxy, &cancelled)?;
            docker.required(
                ["start", &docker.names.proxy],
                DEFAULT_COMMAND_SECONDS,
                &cancelled,
            )?;
            let proxy_request = serde_jcs::to_vec(&ProxyRequest {
                schema_version: PROXY_REQUEST_SCHEMA,
                manifest_digest: &manifest.manifest_digest,
                destination: &manifest.destination,
                max_connections: 16,
                max_request_bytes: 16 * 1024,
                max_headers: 64,
                max_tunnel_bytes: manifest.max_remote_work_bytes.saturating_mul(2),
                max_connection_seconds: manifest.wall_time_seconds,
                wall_time_seconds: manifest.wall_time_seconds,
            })
            .map_err(|_| OciRemoteError::InvalidRequest)?;
            docker.required_with_input(
                [
                    OsString::from("exec"),
                    OsString::from("--interactive"),
                    OsString::from("--user"),
                    OsString::from(CONTAINER_UID),
                    OsString::from(&docker.names.proxy),
                    OsString::from("/usr/bin/dd"),
                    OsString::from(format!("of={PROXY_REQUEST_PATH}")),
                    OsString::from("status=none"),
                ],
                proxy_request,
                DEFAULT_COMMAND_SECONDS,
                &cancelled,
            )?;
            await_proxy_ready(&docker, &cancelled)?;

            create_worker(&docker, &cancelled)?;
            verify_container(&docker, ContainerRole::Worker, &cancelled)?;
            docker.required(
                ["start", &docker.names.worker],
                DEFAULT_COMMAND_SECONDS,
                &cancelled,
            )?;
            let route = docker.read_from(
                &docker.names.worker,
                "/proc/net/route",
                64 * 1024,
                &cancelled,
            )?;
            let route = std::str::from_utf8(&route).map_err(|_| OciRemoteError::ControlMismatch)?;
            if route.lines().skip(1).any(|line| {
                let mut fields = line.split_ascii_whitespace();
                let _interface = fields.next();
                fields.next() == Some("00000000")
            }) {
                return Err(OciRemoteError::ControlMismatch);
            }

            let wrong_destination = docker.run(
                [
                    "exec",
                    "--user",
                    CONTAINER_UID,
                    &docker.names.worker,
                    "/usr/bin/git",
                    "ls-remote",
                    "https://example.com/forbidden.git",
                ],
                5,
                MAX_INSPECT_BYTES,
                &cancelled,
            )?;
            if wrong_destination.success {
                return Err(OciRemoteError::ControlMismatch);
            }
            let deadline = Instant::now()
                .checked_add(Duration::from_secs(5))
                .ok_or(OciRemoteError::InvalidConfiguration)?;
            loop {
                if Instant::now() >= deadline {
                    return Err(OciRemoteError::ControlMismatch);
                }
                if docker
                    .read_from(
                        &docker.names.proxy,
                        PROXY_REPORT_PATH,
                        manifest.max_output_bytes,
                        &cancelled,
                    )
                    .ok()
                    .and_then(|bytes| serde_json::from_slice::<ProxyReport>(&bytes).ok())
                    .is_some_and(|report| {
                        report.accepted_connections == 0
                            && report.rejected_connections > 0
                            && report.observed_destinations.is_empty()
                    })
                {
                    break;
                }
                thread::sleep(Duration::from_millis(25));
            }

            let direct = docker.run(
                [
                    "exec",
                    "--user",
                    CONTAINER_UID,
                    "--env",
                    "HTTPS_PROXY=",
                    "--env",
                    "HTTP_PROXY=",
                    "--env",
                    "ALL_PROXY=",
                    "--env",
                    "NO_PROXY=*",
                    &docker.names.worker,
                    "/usr/bin/git",
                    "ls-remote",
                    LOCATOR,
                ],
                5,
                MAX_INSPECT_BYTES,
                &cancelled,
            );
            if matches!(direct, Ok(CommandOutput { success: true, .. })) {
                return Err(OciRemoteError::ControlMismatch);
            }
            Ok(())
        })();
        let cleanup = cleanup_session(&docker);
        assert_eq!(cleanup, Ok(()));
        result.expect("hostile network controls");
    }

    #[test]
    #[ignore = "requires the accepted local OrbStack backend and pinned image"]
    fn orbstack_cancel_after_resource_creation_removes_every_session_resource() {
        let (manifest, config) = live_fixture();
        assert_eq!(
            acquire_public_https(
                &CancelOnWorkerStartRunner,
                &config,
                &manifest,
                LOCATOR,
                &AtomicBool::new(false),
            ),
            Err(OciRemoteError::Cancelled)
        );
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "requires an explicit pinned synthetic SSH fixture image and accepted OrbStack backend"]
    #[allow(
        clippy::too_many_lines,
        reason = "the ignored test owns one isolated real agent, SSH server, proxy, and worker lifecycle"
    )]
    fn orbstack_brokered_ssh_uses_real_agent_and_pinned_host_key_end_to_end() {
        use base64::Engine as _;
        use base64::engine::general_purpose::STANDARD_NO_PAD;
        use sha2::{Digest as _, Sha256};

        let fixture_image = std::env::var("PROMPTECTOMY_SSH_FIXTURE_IMAGE")
            .expect("set PROMPTECTOMY_SSH_FIXTURE_IMAGE to an explicit fixture image digest");
        assert!(
            fixture_image.starts_with("promptectomy-ssh-fixture@sha256:")
                && fixture_image.len() == "promptectomy-ssh-fixture@sha256:".len() + 64
                && fixture_image
                    .rsplit_once(':')
                    .is_some_and(|(_, digest)| digest.bytes().all(|byte| byte.is_ascii_hexdigit()))
        );

        let root = tempfile::Builder::new()
            .prefix("promptectomy-ssh-live-")
            .tempdir()
            .expect("fixture root");
        let client_key = root.path().join("client-key");
        let host_key = root.path().join("host-key");
        checked(
            Command::new("/usr/bin/ssh-keygen")
                .args(["-q", "-t", "ed25519", "-N", "", "-f"])
                .arg(&client_key)
                .stdout(Stdio::null())
                .stderr(Stdio::null()),
            "generate client key",
        );
        checked(
            Command::new("/usr/bin/ssh-keygen")
                .args(["-q", "-t", "ed25519", "-N", "", "-f"])
                .arg(&host_key)
                .stdout(Stdio::null())
                .stderr(Stdio::null()),
            "generate host key",
        );
        let (_, selected_public_key_base64, _) = read_public_key(&client_key.with_extension("pub"));
        let (host_key_type, host_key_base64, host_key_blob) =
            read_public_key(&host_key.with_extension("pub"));
        let host_key_sha256 = format!(
            "SHA256:{}",
            STANDARD_NO_PAD.encode(Sha256::digest(&host_key_blob))
        );

        let source = root.path().join("source");
        let bare = root.path().join("repo.git");
        checked(
            Command::new("/opt/homebrew/bin/git")
                .args(["init", "--initial-branch=main", "--quiet"])
                .arg(&source)
                .stdout(Stdio::null())
                .stderr(Stdio::null()),
            "initialize source repository",
        );
        fs::write(source.join("README.md"), b"controlled ssh fixture\n")
            .expect("write fixture content");
        for (key, value) in [
            ("user.name", "PROMPTECTOMY fixture"),
            ("user.email", "fixture@invalid.example"),
        ] {
            checked(
                Command::new("/opt/homebrew/bin/git")
                    .arg("-C")
                    .arg(&source)
                    .args(["config", key, value])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null()),
                "configure fixture repository",
            );
        }
        checked(
            Command::new("/opt/homebrew/bin/git")
                .arg("-C")
                .arg(&source)
                .args(["add", "README.md"])
                .stdout(Stdio::null())
                .stderr(Stdio::null()),
            "stage fixture content",
        );
        checked(
            Command::new("/opt/homebrew/bin/git")
                .arg("-C")
                .arg(&source)
                .args(["commit", "--quiet", "-m", "fixture"])
                .stdout(Stdio::null())
                .stderr(Stdio::null()),
            "commit fixture content",
        );
        checked(
            Command::new("/opt/homebrew/bin/git")
                .args(["clone", "--bare", "--quiet"])
                .arg(&source)
                .arg(&bare)
                .stdout(Stdio::null())
                .stderr(Stdio::null()),
            "create bare fixture repository",
        );

        fs::copy(
            client_key.with_extension("pub"),
            root.path().join("authorized_keys"),
        )
        .expect("write authorized keys");
        fs::write(
            root.path().join("sshd_config"),
            "Port 22\nListenAddress 0.0.0.0\nHostKey /fixture/host-key\nAuthorizedKeysFile /fixture/authorized_keys\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nChallengeResponseAuthentication no\nPermitRootLogin no\nUsePAM no\nAllowUsers git\nStrictModes no\nAllowTcpForwarding no\nPermitTunnel no\nX11Forwarding no\nPermitTTY no\nPidFile /tmp/sshd.pid\nLogLevel ERROR\n",
        )
        .expect("write sshd config");
        fs::write(
            root.path().join("agent-entrypoint.sh"),
            "#!/bin/sh\nset -eu\nrm -f /agent/agent.sock\n/usr/bin/ssh-agent -D -a /agent/agent.sock >/dev/null 2>&1 &\nagent_pid=$!\ntrap 'kill \"$agent_pid\" 2>/dev/null || true; wait \"$agent_pid\" 2>/dev/null || true' EXIT TERM INT\nremaining=500\nwhile [ ! -S /agent/agent.sock ]; do\n  remaining=$((remaining - 1))\n  [ \"$remaining\" -gt 0 ] || exit 1\n  sleep 0.01\ndone\nSSH_AUTH_SOCK=/agent/agent.sock /usr/bin/ssh-add /fixture/client-key >/dev/null 2>&1\nwait \"$agent_pid\"\n",
        )
        .expect("write agent entrypoint");

        let docker = std::env::var_os("PROMPTECTOMY_DOCKER_PROGRAM")
            .map_or_else(|| PathBuf::from("/opt/homebrew/bin/docker"), PathBuf::from);
        let image = SystemCommandRunner
            .run(
                &CommandPlan {
                    program: docker.clone(),
                    arguments: vec![
                        "--context".into(),
                        DOCKER_CONTEXT.into(),
                        "image".into(),
                        "inspect".into(),
                        "--format".into(),
                        "{{.Id}}".into(),
                        fixture_image.clone().into(),
                    ],
                    environment: Vec::new(),
                    stdin: Vec::new(),
                    max_output_bytes: MAX_INSPECT_BYTES,
                    timeout: Duration::from_secs(DEFAULT_COMMAND_SECONDS),
                },
                &AtomicBool::new(false),
            )
            .expect("inspect fixture image");
        assert!(image.success);
        assert_eq!(
            parse_single_line(&image.stdout).expect("fixture image id"),
            fixture_image.rsplit_once('@').expect("fixture digest").1
        );

        let fixture_token = format!(
            "{}-{}",
            std::process::id(),
            SESSION_COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let fixture_label = format!("promptectomy.fixture={fixture_token}");
        let fixture_filter = format!("label={fixture_label}");
        let fixture_name = format!("promptectomy-ssh-fixture-{fixture_token}");
        let agent_name = format!("promptectomy-agent-fixture-{fixture_token}");
        let agent_volume = format!("promptectomy-agent-fixture-{fixture_token}");
        let fixture_mount = format!(
            "type=bind,source={},target=/fixture,readonly",
            root.path().to_str().expect("fixture path")
        );
        let repository_mount = format!(
            "type=bind,source={},target=/srv/repo.git,readonly",
            bare.to_str().expect("repository path")
        );
        run_fixture_docker(
            &docker,
            [
                "volume",
                "create",
                "--label",
                fixture_label.as_str(),
                agent_volume.as_str(),
            ],
        )
        .expect("create agent fixture volume");
        let fixture = FixtureResources {
            docker: docker.clone(),
            label: fixture_filter,
            sshd: fixture_name.clone(),
            agent: agent_name.clone(),
            agent_volume: agent_volume.clone(),
        };
        let agent_mount = format!("type=volume,source={agent_volume},target=/agent,volume-nocopy");
        run_fixture_docker(
            &docker,
            [
                "create",
                "--name",
                agent_name.as_str(),
                "--label",
                fixture_label.as_str(),
                "--pull",
                "never",
                "--read-only",
                "--network",
                "none",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--pids-limit",
                "32",
                "--memory",
                "134217728",
                "--cpus",
                "0.250",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,nodev,size=4194304,mode=1777",
                "--mount",
                fixture_mount.as_str(),
                "--mount",
                agent_mount.as_str(),
                "--entrypoint",
                "/bin/sh",
                fixture_image.as_str(),
                "/fixture/agent-entrypoint.sh",
            ],
        )
        .expect("create Linux agent fixture");
        run_fixture_docker(&docker, ["start", agent_name.as_str()])
            .expect("start Linux agent fixture");
        let agent_deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let ready = fixture_docker(
                &docker,
                [
                    "exec",
                    agent_name.as_str(),
                    "/usr/bin/test",
                    "-S",
                    "/agent/agent.sock",
                ],
            )
            .expect("inspect Linux agent fixture");
            if ready.success {
                break;
            }
            assert!(
                Instant::now() < agent_deadline,
                "Linux agent socket timeout"
            );
            thread::sleep(Duration::from_millis(10));
        }
        let identities = fixture_docker(
            &docker,
            [
                "exec",
                "--env",
                "SSH_AUTH_SOCK=/agent/agent.sock",
                agent_name.as_str(),
                "/usr/bin/ssh-add",
                "-L",
            ],
        )
        .expect("read Linux agent identities");
        assert!(identities.success);
        let identities = std::str::from_utf8(&identities.stdout).expect("agent identities utf8");
        assert_eq!(identities.lines().count(), 1);
        assert!(identities.contains(&selected_public_key_base64));

        let created = SystemCommandRunner
            .run(
                &CommandPlan {
                    program: docker.clone(),
                    arguments: vec![
                        "--context".into(),
                        DOCKER_CONTEXT.into(),
                        "create".into(),
                        "--name".into(),
                        fixture_name.clone().into(),
                        "--label".into(),
                        fixture_label.clone().into(),
                        "--mount".into(),
                        fixture_mount.into(),
                        "--mount".into(),
                        repository_mount.into(),
                        fixture_image.into(),
                    ],
                    environment: Vec::new(),
                    stdin: Vec::new(),
                    max_output_bytes: MAX_INSPECT_BYTES,
                    timeout: Duration::from_secs(DEFAULT_COMMAND_SECONDS),
                },
                &AtomicBool::new(false),
            )
            .expect("create SSH fixture");
        assert!(created.success);

        let opaque_handle = "synthetic-fixture-grant";
        let repository = "srv/repo.git";
        let (mut manifest, mut config) = live_fixture();
        manifest.source_kind = SourceKind::SshBrokered;
        manifest.locator_digest = domain_digest("remote-locator", opaque_handle.as_bytes());
        manifest.redacted_locator = "ssh://github.com/<redacted>".to_owned();
        manifest.destination.port = 22;
        manifest.revision = "main".to_owned();
        manifest.credential_policy = RemoteCredentialPolicy::SshAgentBrokerGrant;
        manifest.broker = Some(crate::remote::BrokerBinding {
            handle_digest: domain_digest("ssh-broker-handle", opaque_handle.as_bytes()),
            executable_digest: digest_string(b"controlled-fixture-broker"),
            request_digest: digest_string(b"controlled-fixture-request"),
            repository_digest: domain_digest("ssh-repository", repository.as_bytes()),
            host_key_digest: domain_digest(
                "ssh-host-key",
                format!("{host_key_type} {host_key_base64}").as_bytes(),
            ),
            selected_public_key_digest: domain_digest(
                "ssh-selected-public-key",
                selected_public_key_base64.as_bytes(),
            ),
        });
        manifest.wall_time_seconds = 30;
        manifest.manifest_digest = manifest.computed_digest();
        config.relay_upstream = Some(RelayUpstream::TestVolume(agent_volume));
        let grant = promptectomy_ssh_agent_relay::RelayGrant {
            schema_version: promptectomy_ssh_agent_relay::GRANT_VERSION.to_owned(),
            opaque_handle: opaque_handle.to_owned(),
            display_host: "github.com".to_owned(),
            port: 22,
            username: "git".to_owned(),
            repository: repository.to_owned(),
            revision: "main".to_owned(),
            host_key_type: host_key_type.clone(),
            host_key_base64: host_key_base64.clone(),
            host_key_sha256,
            selected_public_key_base64,
            manifest_digest: manifest.manifest_digest.clone(),
            credential_source: "selected_ssh_agent".to_owned(),
            wall_time_seconds: manifest.wall_time_seconds,
            max_connections: 1,
            max_frame_bytes: 256 * 1024,
            max_signatures: 4,
        }
        .validate()
        .expect("validate relay grant");
        let relay_grant = grant.canonical_bytes().expect("canonical relay grant");
        let runner = ControlledSshRunner {
            fixture_container: fixture_name,
            relay_receipt: Mutex::new(None),
            worker_error: Mutex::new(None),
        };
        let result = acquire_brokered_ssh(
            &runner,
            &config,
            &manifest,
            repository,
            &host_key_type,
            &host_key_base64,
            &relay_grant,
            &AtomicBool::new(false),
        );
        assert!(
            result.is_ok(),
            "brokered SSH acquisition failed: {result:?}; worker={:?}",
            runner.worker_error.lock().expect("worker error lock")
        );
        let result = result.expect("brokered SSH acquisition");
        let receipt = runner
            .relay_receipt
            .lock()
            .expect("relay receipt lock")
            .clone()
            .expect("relay receipt");
        assert_eq!(receipt.manifest_digest, manifest.manifest_digest);
        assert!(receipt.session_bound);
        assert!((1..=4).contains(&receipt.signatures));
        let bundle: Value = serde_json::from_slice(&result.source_bundle).expect("source bundle");
        assert_eq!(bundle["files"][0]["path"], "README.md");
        assert_eq!(
            bundle["files"][0]["content_hex"],
            "636f6e74726f6c6c65642073736820666978747572650a"
        );
        assert_eq!(result.controls.cleanup_complete, ControlAttestation::Passed);
        fixture.cleanup().expect("clean fixture resources");
        fixture.assert_empty().expect("fixture resources removed");
    }

    #[cfg(unix)]
    fn checked(command: &mut Command, action: &str) {
        assert!(
            command.status().is_ok_and(|status| status.success()),
            "failed to {action}"
        );
    }

    #[cfg(unix)]
    fn read_public_key(path: &Path) -> (String, String, Vec<u8>) {
        use base64::Engine as _;
        use base64::engine::general_purpose::STANDARD_NO_PAD;

        let text = fs::read_to_string(path).expect("read public key");
        let mut fields = text.split_ascii_whitespace();
        let key_type = fields.next().expect("public key type").to_owned();
        let base64 = fields.next().expect("public key body").to_owned();
        let blob = STANDARD_NO_PAD
            .decode(&base64)
            .expect("decode public key body");
        (key_type, base64, blob)
    }

    fn live_fixture() -> (RemoteGitManifest, OciRemoteConfig) {
        let (mut manifest, mut config) = fixture();
        manifest.backend = RemoteBackendPolicy::reviewed_orbstack_macos_arm64_v1();
        manifest.wall_time_seconds = 20;
        manifest.manifest_digest = manifest.computed_digest();
        config.docker_program = std::env::var_os("PROMPTECTOMY_DOCKER_PROGRAM")
            .map_or_else(|| PathBuf::from("/opt/homebrew/bin/docker"), PathBuf::from);
        config.image_reference = crate::ORBSTACK_PUBLIC_GIT_IMAGE_REFERENCE.to_owned();
        (manifest, config)
    }

    fn assert_cleanup_attempted(plans: &[CommandPlan]) {
        assert!(plans.iter().any(|plan| {
            docker_args(plan).first().is_some_and(|value| value == "rm")
                && plan.arguments.iter().any(|value| value == "--force")
        }));
        assert!(plans.iter().any(|plan| {
            docker_args(plan)
                .first()
                .is_some_and(|value| value == "network")
                && docker_args(plan).get(1).is_some_and(|value| value == "rm")
        }));
        assert!(plans.iter().any(|plan| {
            docker_args(plan).first().is_some_and(|value| value == "ps")
                && plan.arguments.iter().any(|value| value == "-aq")
        }));
    }

    #[test]
    fn route_parser_rejects_default_and_malformed_routes() {
        let isolated = b"Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\neth0 0000000A 00000000 0001 0 0 0 000000FF 0 0 0\n";
        let default_route = b"Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\neth0 00000000 0100000A 0003 0 0 0 00000000 0 0 0\n";
        assert_eq!(worker_default_route_absent(isolated), Ok(true));
        assert_eq!(worker_default_route_absent(default_route), Ok(false));
        assert_eq!(
            worker_default_route_absent(b"Iface Destination\neth0 bad\n"),
            Err(OciRemoteError::ControlMismatch)
        );
    }

    #[test]
    fn default_route_fails_before_worker_request_is_copied() {
        let (manifest, config) = fixture();
        let mut runner = TranscriptRunner::accepted(&manifest);
        runner.default_route_present = true;
        assert_eq!(
            acquire_public_https(
                &runner,
                &config,
                &manifest,
                LOCATOR,
                &AtomicBool::new(false)
            ),
            Err(OciRemoteError::ControlMismatch)
        );
        assert!(runner.plans().iter().all(|plan| {
            let args = docker_args(plan);
            !(args.first().is_some_and(|value| value == "cp")
                && args
                    .get(2)
                    .is_some_and(|value| value.to_string_lossy().ends_with(REQUEST_PATH)))
        }));
        assert_cleanup_attempted(&runner.plans());
    }

    #[cfg(unix)]
    #[test]
    fn ssh_transcript_mounts_only_the_filtered_relay_and_never_copies_the_handle() {
        let (mut manifest, mut config) = fixture();
        let repository = "owner/private.git";
        let host_key_type = "ssh-ed25519";
        let host_key_base64 = SYNTHETIC_HOST_KEY_BASE64;
        let opaque_handle = "private_grant_canary";
        manifest.source_kind = SourceKind::SshBrokered;
        manifest.locator_digest = domain_digest("remote-locator", opaque_handle.as_bytes());
        manifest.redacted_locator = "ssh://github.com/<redacted>".to_owned();
        manifest.destination.port = 22;
        manifest.credential_policy = RemoteCredentialPolicy::SshAgentBrokerGrant;
        manifest.broker = Some(crate::remote::BrokerBinding {
            handle_digest: domain_digest("ssh-broker-handle", opaque_handle.as_bytes()),
            executable_digest: digest_string(b"broker"),
            request_digest: digest_string(b"request"),
            repository_digest: domain_digest("ssh-repository", repository.as_bytes()),
            host_key_digest: domain_digest(
                "ssh-host-key",
                format!("{host_key_type} {host_key_base64}").as_bytes(),
            ),
            selected_public_key_digest: digest_string(b"selected-key"),
        });
        manifest.manifest_digest = manifest.computed_digest();
        config.relay_upstream = Some(RelayUpstream::TestVolume("controlled-upstream".to_owned()));
        let mut runner = TranscriptRunner::accepted(&manifest);
        runner.relay_enabled = true;
        let result = acquire_brokered_ssh(
            &runner,
            &config,
            &manifest,
            repository,
            host_key_type,
            host_key_base64,
            b"validated synthetic relay grant",
            &AtomicBool::new(false),
        )
        .expect("accepted SSH transcript");
        assert_eq!(result.source_bundle, BUNDLE);
        let plans = runner.plans();
        let creates = plans
            .iter()
            .filter(|plan| {
                docker_args(plan)
                    .first()
                    .is_some_and(|value| value == "create")
            })
            .collect::<Vec<_>>();
        assert_eq!(creates.len(), 3);
        let worker = creates
            .iter()
            .find(|plan| {
                docker_args(plan)
                    .iter()
                    .any(|value| value.to_string_lossy().ends_with("-worker"))
            })
            .expect("worker create");
        let proxy = creates
            .iter()
            .find(|plan| {
                docker_args(plan)
                    .iter()
                    .any(|value| value.to_string_lossy().ends_with("-proxy"))
            })
            .expect("proxy create");
        let relay = creates
            .iter()
            .find(|plan| docker_args(plan).iter().any(|value| value == RELAY_BINARY))
            .expect("relay create");
        assert!(worker.arguments.iter().any(|value| {
            let value = value.to_string_lossy();
            value.contains("type=volume")
                && value.contains("target=/work/relay")
                && value.contains("readonly")
        }));
        assert!(
            relay
                .arguments
                .iter()
                .any(|value| { value.to_string_lossy().contains("target=/work/upstream") })
        );
        assert!(relay.arguments.iter().any(|value| value == "none"));
        assert!(proxy.arguments.iter().all(|value| value != "--mount"));
        assert!(plans.iter().all(|plan| {
            plan.arguments
                .iter()
                .chain(
                    plan.environment
                        .iter()
                        .flat_map(|(key, value)| [key, value]),
                )
                .all(|value| !value.to_string_lossy().contains(opaque_handle))
        }));
    }

    #[cfg(unix)]
    #[test]
    fn stale_receipt_from_a_failed_relay_is_rejected() {
        let (mut manifest, mut config) = fixture();
        let repository = "owner/private.git";
        let host_key_type = "ssh-ed25519";
        let host_key_base64 = SYNTHETIC_HOST_KEY_BASE64;
        let opaque_handle = "private_grant_canary";
        manifest.source_kind = SourceKind::SshBrokered;
        manifest.locator_digest = domain_digest("remote-locator", opaque_handle.as_bytes());
        manifest.redacted_locator = "ssh://github.com/<redacted>".to_owned();
        manifest.destination.port = 22;
        manifest.credential_policy = RemoteCredentialPolicy::SshAgentBrokerGrant;
        manifest.broker = Some(crate::remote::BrokerBinding {
            handle_digest: domain_digest("ssh-broker-handle", opaque_handle.as_bytes()),
            executable_digest: digest_string(b"broker"),
            request_digest: digest_string(b"request"),
            repository_digest: domain_digest("ssh-repository", repository.as_bytes()),
            host_key_digest: domain_digest(
                "ssh-host-key",
                format!("{host_key_type} {host_key_base64}").as_bytes(),
            ),
            selected_public_key_digest: digest_string(b"selected-key"),
        });
        manifest.manifest_digest = manifest.computed_digest();
        config.relay_upstream = Some(RelayUpstream::TestVolume("controlled-upstream".to_owned()));
        let mut runner = TranscriptRunner::accepted(&manifest);
        runner.relay_enabled = true;
        runner.relay_failed = true;
        assert_eq!(
            acquire_brokered_ssh(
                &runner,
                &config,
                &manifest,
                repository,
                host_key_type,
                host_key_base64,
                b"validated synthetic relay grant",
                &AtomicBool::new(false),
            ),
            Err(OciRemoteError::ControlMismatch)
        );
        assert_cleanup_attempted(&runner.plans());
    }

    fn docker_args(plan: &CommandPlan) -> &[OsString] {
        assert_eq!(plan.arguments[0], "--context");
        assert_eq!(plan.arguments[1], DOCKER_CONTEXT);
        &plan.arguments[2..]
    }
}
