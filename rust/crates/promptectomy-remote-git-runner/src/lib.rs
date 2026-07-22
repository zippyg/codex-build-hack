#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;
use tokio::time::Instant;

pub const REQUEST_PATH: &str = "/work/input/request.json";
pub const BUNDLE_PATH: &str = "/work/output/source-bundle.json";
pub const RESULT_PATH: &str = "/work/output/result.json";
const RUN_ROOT: &str = "/work/run";
const GIT_PROGRAM: &str = "/usr/bin/git";
const PROXY_URL: &str = "http://proxy:8080";
const PLACEHOLDER_URL: &str = "https://promptectomy.invalid/source";
const SSH_AGENT_PATH: &str = "/work/relay/agent.sock";
const SSH_COMMAND: &str = "/usr/bin/ssh -F /work/run/neutral/ssh-config";
const SSH_CONNECT_PROGRAM: &str = "/usr/local/bin/promptectomy-ssh-connect";
const SSH_KNOWN_HOSTS_PATH: &str = "/work/run/neutral/known-hosts";
const REQUEST_VERSION: &str = "promptectomy.remote-git-runner-request.v2";
const RESULT_VERSION: &str = "promptectomy.remote-worker.v1";
const MANIFEST_VERSION: &str = "promptectomy.remote-git-manifest.v2";
#[cfg(test)]
const BUNDLE_VERSION: &str = "promptectomy-source-bundle-1";
const BUNDLE_PREFIX: &[u8] = br#"{"files":["#;
const BUNDLE_SUFFIX: &[u8] = br#"],"version":"promptectomy-source-bundle-1"}"#;
const MAX_REQUEST_BYTES: u64 = 64 * 1024;
const MAX_FILES: usize = 100_000;
const MAX_TOTAL_BYTES: u64 = 32 * 1024 * 1024;
const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_PATH_BYTES: usize = 1024;
const MAX_WORK_BYTES: u64 = 256 * 1024 * 1024;
const MAX_BUNDLE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
const MAX_WALL_SECONDS: u64 = 300;
const INPUT_WAIT_SECONDS: u64 = 10;
const MAX_WORK_ENTRIES: usize = 250_000;
const MAX_BATCH_HEADER_BYTES: usize = 256;
const ALLOWED_HOSTS: [&str; 5] = [
    "bitbucket.org",
    "codeberg.org",
    "git.sr.ht",
    "github.com",
    "gitlab.com",
];
const WINDOWS_DEVICES: [&str; 22] = [
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

#[derive(Debug, Error)]
pub enum RunnerError {
    #[error("request_unavailable")]
    RequestUnavailable,
    #[error("invalid_request")]
    InvalidRequest,
    #[error("invalid_manifest")]
    InvalidManifest,
    #[error("locator_denied")]
    LocatorDenied,
    #[error("workspace_unavailable")]
    WorkspaceUnavailable,
    #[error("git_unavailable")]
    GitUnavailable,
    #[error("ssh_relay_unavailable")]
    SshRelayUnavailable,
    #[error("git_failed")]
    GitFailed,
    #[error("git_timed_out")]
    GitTimedOut,
    #[error("git_output_exceeded")]
    GitOutputExceeded,
    #[error("invalid_git_output")]
    InvalidGitOutput,
    #[error("unsafe_path")]
    UnsafePath,
    #[error("path_collision")]
    PathCollision,
    #[error("file_count_exceeded")]
    FileCountExceeded,
    #[error("file_bytes_exceeded")]
    FileBytesExceeded,
    #[error("total_bytes_exceeded")]
    TotalBytesExceeded,
    #[error("work_bytes_exceeded")]
    WorkBytesExceeded,
    #[error("bundle_bytes_exceeded")]
    BundleBytesExceeded,
    #[error("empty_selection")]
    EmptySelection,
    #[error("output_unavailable")]
    OutputUnavailable,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerRequest {
    pub schema_version: String,
    pub manifest: RemoteGitManifest,
    pub https_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh: Option<SshInput>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SshInput {
    pub repository: String,
    pub host_key_type: String,
    pub host_key_base64: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteGitManifest {
    pub schema_version: String,
    pub source_kind: SourceKind,
    pub manifest_digest: String,
    pub authority_digest: String,
    pub locator_digest: String,
    pub redacted_locator: String,
    pub destination: Destination,
    pub revision: String,
    pub selected_roots: Vec<String>,
    pub max_files: usize,
    pub max_total_bytes: u64,
    pub max_file_bytes: u64,
    pub max_path_bytes: usize,
    pub max_remote_work_bytes: u64,
    pub max_bundle_bytes: u64,
    pub max_output_bytes: usize,
    pub wall_time_seconds: u64,
    pub checkout_policy: String,
    pub egress_policy: String,
    pub credential_policy: CredentialPolicy,
    pub broker: Option<BrokerBinding>,
    pub backend: BackendPolicy,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    LocalPath,
    HttpsRemote,
    SshBrokered,
    Archive,
    Bundle,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialPolicy {
    None,
    SshAgentBrokerGrant,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Destination {
    pub host: String,
    pub port: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerBinding {
    pub handle_digest: String,
    pub executable_digest: String,
    pub request_digest: String,
    pub repository_digest: String,
    pub host_key_digest: String,
    pub selected_public_key_digest: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackendPolicy {
    pub profile: BackendProfile,
    pub image_digest: String,
    pub runner_digest: String,
    pub egress_proxy_digest: String,
    pub ssh_agent_relay_digest: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendProfile {
    OrbstackMacosArm64V1,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuccessResult {
    pub schema_version: &'static str,
    pub manifest_digest: String,
    pub resolved_commit: String,
    pub source_bundle_digest: String,
    pub git_binary_digest: String,
    pub git_execution_neutralized: bool,
    pub credentials_isolated: bool,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FailureResult<'a> {
    pub schema_version: &'static str,
    pub status: &'static str,
    pub manifest_digest: Option<&'a str>,
    pub error_code: String,
}

#[cfg(test)]
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct BundleDocument {
    version: &'static str,
    files: Vec<BundleFile>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct BundleFile {
    path: String,
    executable: bool,
    content_hex: String,
    digest: String,
}

#[derive(Clone, Debug)]
struct TreeEntry {
    path: String,
    object: String,
    size: u64,
    executable: bool,
    submodule: bool,
}

#[derive(Debug)]
struct GitOutput {
    stdout: Vec<u8>,
}

#[derive(Debug)]
struct GitPlan {
    neutral: std::path::PathBuf,
    remote_config: std::path::PathBuf,
    repository: std::path::PathBuf,
    ssh_destination: Option<String>,
}

pub async fn execute() -> Result<SuccessResult, RunnerError> {
    let request = wait_for_request().await?;
    execute_request(request, Path::new(RUN_ROOT)).await
}

async fn wait_for_request() -> Result<RunnerRequest, RunnerError> {
    let deadline = Instant::now() + Duration::from_secs(INPUT_WAIT_SECONDS);
    loop {
        if let Ok(bytes) = read_bounded(Path::new(REQUEST_PATH), MAX_REQUEST_BYTES)
            && let Ok(request) = serde_json::from_slice::<RunnerRequest>(&bytes)
            && request.validate().is_ok()
        {
            return Ok(request);
        }
        if Instant::now() >= deadline {
            return Err(RunnerError::RequestUnavailable);
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

impl RunnerRequest {
    pub fn validate(&self) -> Result<(), RunnerError> {
        if self.schema_version != REQUEST_VERSION {
            return Err(RunnerError::InvalidRequest);
        }
        self.manifest.validate()?;
        match (
            self.manifest.source_kind,
            self.https_url.as_deref(),
            &self.ssh,
        ) {
            (SourceKind::HttpsRemote, Some(url), None) => {
                let (host, canonical) = validate_url(url)?;
                if host != self.manifest.destination.host
                    || domain_digest("remote-locator", url.as_bytes())
                        != self.manifest.locator_digest
                    || canonical != url
                {
                    return Err(RunnerError::LocatorDenied);
                }
            }
            (SourceKind::SshBrokered, None, Some(ssh)) => {
                let broker = self
                    .manifest
                    .broker
                    .as_ref()
                    .ok_or(RunnerError::InvalidManifest)?;
                let host_key = format!("{} {}", ssh.host_key_type, ssh.host_key_base64);
                if domain_digest("ssh-repository", ssh.repository.as_bytes())
                    != broker.repository_digest
                    || domain_digest("ssh-host-key", host_key.as_bytes()) != broker.host_key_digest
                    || !is_digest(&broker.selected_public_key_digest)
                {
                    return Err(RunnerError::LocatorDenied);
                }
                validate_repository(&ssh.repository)?;
                validate_host_key(&ssh.host_key_type, &ssh.host_key_base64)?;
            }
            _ => return Err(RunnerError::InvalidRequest),
        }
        Ok(())
    }
}

impl RemoteGitManifest {
    fn validate(&self) -> Result<(), RunnerError> {
        let mut unsigned = self.clone();
        unsigned.manifest_digest.clear();
        let encoded = serde_jcs::to_vec(&unsigned).map_err(|_| RunnerError::InvalidManifest)?;
        if self.schema_version != MANIFEST_VERSION
            || self.manifest_digest != domain_digest("remote-git-manifest", &encoded)
            || !is_digest(&self.authority_digest)
            || !is_digest(&self.locator_digest)
            || !ALLOWED_HOSTS.contains(&self.destination.host.as_str())
            || self.max_files == 0
            || self.max_files > MAX_FILES
            || self.max_total_bytes == 0
            || self.max_total_bytes > MAX_TOTAL_BYTES
            || self.max_file_bytes == 0
            || self.max_file_bytes > self.max_total_bytes
            || self.max_file_bytes > MAX_FILE_BYTES
            || self.max_path_bytes == 0
            || self.max_path_bytes > MAX_PATH_BYTES
            || self.max_remote_work_bytes < self.max_total_bytes
            || self.max_remote_work_bytes > MAX_WORK_BYTES
            || self.max_bundle_bytes == 0
            || self.max_bundle_bytes > self.max_remote_work_bytes
            || self.max_bundle_bytes > MAX_BUNDLE_BYTES
            || self.max_output_bytes == 0
            || self.max_output_bytes > MAX_OUTPUT_BYTES
            || self.wall_time_seconds == 0
            || self.wall_time_seconds > MAX_WALL_SECONDS
            || self.checkout_policy != "no_checkout"
            || self.egress_policy != "application_connect_proxy_exact_destination"
            || !is_digest(&self.backend.image_digest)
            || !is_digest(&self.backend.runner_digest)
            || !is_digest(&self.backend.egress_proxy_digest)
            || !is_digest(&self.backend.ssh_agent_relay_digest)
        {
            return Err(RunnerError::InvalidManifest);
        }
        match (self.source_kind, self.credential_policy, &self.broker) {
            (SourceKind::HttpsRemote, CredentialPolicy::None, None)
                if self.destination.port == 443
                    && self.redacted_locator
                        == format!("https://{}/<redacted>", self.destination.host) => {}
            (SourceKind::SshBrokered, CredentialPolicy::SshAgentBrokerGrant, Some(broker))
                if self.destination.port == 22
                    && self.redacted_locator
                        == format!("ssh://{}/<redacted>", self.destination.host)
                    && is_digest(&broker.handle_digest)
                    && is_digest(&broker.executable_digest)
                    && is_digest(&broker.request_digest)
                    && is_digest(&broker.repository_digest)
                    && is_digest(&broker.host_key_digest)
                    && is_digest(&broker.selected_public_key_digest) => {}
            _ => return Err(RunnerError::InvalidManifest),
        }
        validate_revision(&self.revision)?;
        let mut prior = None;
        let mut collision_keys = BTreeSet::new();
        for root in &self.selected_roots {
            let normalized = normalize_path(root.as_bytes(), self.max_path_bytes)?;
            if normalized != *root
                || prior.as_ref().is_some_and(|value: &String| value >= root)
                || !collision_keys.insert(root.to_ascii_lowercase())
            {
                return Err(RunnerError::InvalidManifest);
            }
            prior = Some(root.clone());
        }
        Ok(())
    }
}

async fn execute_request(
    request: RunnerRequest,
    run_root: &Path,
) -> Result<SuccessResult, RunnerError> {
    let deadline = Instant::now() + Duration::from_secs(request.manifest.wall_time_seconds);
    if request.ssh.is_some() {
        verify_ssh_agent_socket(Path::new(SSH_AGENT_PATH))?;
    }
    let plan = prepare_workspace(&request, run_root)?;
    let (commit, entries) = fetch_inventory(&request.manifest, run_root, &plan, deadline).await?;
    let source_bundle_digest = materialize_bundle(
        entries,
        &request.manifest,
        &plan,
        Path::new(BUNDLE_PATH),
        deadline,
    )
    .await?;
    Ok(SuccessResult {
        schema_version: RESULT_VERSION,
        manifest_digest: request.manifest.manifest_digest,
        resolved_commit: commit,
        source_bundle_digest,
        git_binary_digest: digest_file(Path::new(GIT_PROGRAM), 32 * 1024 * 1024)?,
        git_execution_neutralized: true,
        credentials_isolated: true,
    })
}

fn prepare_workspace(request: &RunnerRequest, run_root: &Path) -> Result<GitPlan, RunnerError> {
    match fs::symlink_metadata(run_root) {
        Ok(metadata) => {
            if !metadata.file_type().is_dir()
                || fs::read_dir(run_root)
                    .map_err(|_| RunnerError::WorkspaceUnavailable)?
                    .next()
                    .is_some()
            {
                return Err(RunnerError::WorkspaceUnavailable);
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(run_root).map_err(|_| RunnerError::WorkspaceUnavailable)?;
        }
        Err(_) => return Err(RunnerError::WorkspaceUnavailable),
    }
    let neutral = run_root.join("neutral");
    fs::create_dir(&neutral).map_err(|_| RunnerError::WorkspaceUnavailable)?;
    fs::create_dir(neutral.join("empty-hooks")).map_err(|_| RunnerError::WorkspaceUnavailable)?;
    for name in ["empty-config", "empty-attributes", "empty-excludes"] {
        create_private_file(&neutral.join(name), &[])?;
    }
    let (locator, ssh_destination) = match &request.ssh {
        None => (
            request
                .https_url
                .clone()
                .ok_or(RunnerError::InvalidRequest)?,
            None,
        ),
        Some(ssh) => {
            let ssh_config = format!(
                "Host {}\n\tBatchMode yes\n\tCanonicalizeHostname no\n\tCheckHostIP no\n\tClearAllForwardings yes\n\tCompression no\n\tConnectionAttempts 1\n\tConnectTimeout 10\n\tEnableEscapeCommandline no\n\tForwardAgent no\n\tForwardX11 no\n\tGlobalKnownHostsFile /dev/null\n\tHostKeyAlgorithms {}\n\tHostName {}\n\tIdentitiesOnly no\n\tIdentityAgent {}\n\tIdentityFile none\n\tKbdInteractiveAuthentication no\n\tPasswordAuthentication no\n\tPermitLocalCommand no\n\tPort 22\n\tPreferredAuthentications publickey\n\tProxyCommand {} %h %p\n\tPubkeyAuthentication yes\n\tRequestTTY no\n\tStrictHostKeyChecking yes\n\tUpdateHostKeys no\n\tUser git\n\tUserKnownHostsFile {}\n\tVerifyHostKeyDNS no\n",
                request.manifest.destination.host,
                ssh.host_key_type,
                request.manifest.destination.host,
                SSH_AGENT_PATH,
                SSH_CONNECT_PROGRAM,
                SSH_KNOWN_HOSTS_PATH,
            );
            create_private_file(&neutral.join("ssh-config"), ssh_config.as_bytes())?;
            let known_hosts = format!(
                "{} {} {}\n",
                request.manifest.destination.host, ssh.host_key_type, ssh.host_key_base64
            );
            create_private_file(&neutral.join("known-hosts"), known_hosts.as_bytes())?;
            (
                format!(
                    "ssh://git@{}/{}",
                    request.manifest.destination.host, ssh.repository
                ),
                Some(format!("{}:22", request.manifest.destination.host)),
            )
        }
    };
    let remote_config = neutral.join("remote-config");
    let config = format!("[url \"{locator}\"]\n\tinsteadOf = {PLACEHOLDER_URL}\n");
    create_private_file(&remote_config, config.as_bytes())?;
    let repository = run_root.join("repository.git");
    Ok(GitPlan {
        neutral,
        remote_config,
        repository,
        ssh_destination,
    })
}

async fn fetch_inventory(
    manifest: &RemoteGitManifest,
    run_root: &Path,
    plan: &GitPlan,
    deadline: Instant,
) -> Result<(String, Vec<TreeEntry>), RunnerError> {
    let init = git_arguments(plan, ["init", "--quiet", "--bare", "repository.git"])?;
    run_git(init, run_root, plan, 256, deadline, "init").await?;
    check_work_quota(run_root, manifest.max_remote_work_bytes)?;

    let fetch = git_arguments(
        plan,
        [
            "fetch",
            "--depth=1",
            "--no-tags",
            "--no-recurse-submodules",
            "--",
            PLACEHOLDER_URL,
            &manifest.revision,
        ],
    )?;
    run_git(
        fetch,
        &plan.repository,
        plan,
        manifest.max_output_bytes,
        deadline,
        "fetch",
    )
    .await?;
    check_work_quota(run_root, manifest.max_remote_work_bytes)?;

    let rev_parse = git_arguments(plan, ["rev-parse", "--verify", "FETCH_HEAD^{commit}"])?;
    let commit_output = run_git(
        rev_parse,
        &plan.repository,
        plan,
        256,
        deadline,
        "rev_parse",
    )
    .await?;
    let commit = parse_object_id(&commit_output.stdout)?;
    let inventory_args = git_arguments(plan, ["ls-tree", "-rlz", "--full-tree", &commit])?;
    let inventory_output = run_git(
        inventory_args,
        &plan.repository,
        plan,
        manifest.max_output_bytes,
        deadline,
        "inventory",
    )
    .await?;
    let entries = parse_inventory(&inventory_output.stdout, manifest)?;
    if entries.iter().all(|entry| entry.submodule) {
        return Err(RunnerError::EmptySelection);
    }
    Ok((commit, entries))
}

async fn materialize_bundle(
    entries: Vec<TreeEntry>,
    manifest: &RemoteGitManifest,
    plan: &GitPlan,
    output_path: &Path,
    deadline: Instant,
) -> Result<String, RunnerError> {
    let projected_bytes = projected_bundle_bytes(&entries)?;
    if projected_bytes > manifest.max_bundle_bytes {
        return Err(RunnerError::BundleBytesExceeded);
    }
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output_path)
        .map_err(|_| RunnerError::OutputUnavailable)?;
    let mut bundle_digest = Sha256::new();
    bundle_digest.update(b"remote-source-bundle\0");
    write_bundle_piece(&mut output, &mut bundle_digest, BUNDLE_PREFIX)?;
    let batch = git_arguments(plan, ["cat-file", "--batch"])?;
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or(RunnerError::GitTimedOut)?;
    let mut child = spawn_git_batch(batch, &plan.repository, plan)?;
    let mut stdin = child.stdin.take().ok_or(RunnerError::GitUnavailable)?;
    let stdout = child.stdout.take().ok_or(RunnerError::GitUnavailable)?;
    let stderr = child.stderr.take().ok_or(RunnerError::GitUnavailable)?;
    let mut stdout = BufReader::new(stdout);
    let observed = Arc::new(AtomicUsize::new(0));
    let (overflow_tx, mut overflow_rx) = mpsc::channel(1);
    let stderr_reader = tokio::spawn(capture_output(
        stderr,
        manifest.max_output_bytes,
        observed,
        overflow_tx,
        false,
        "blob_batch",
    ));
    let mut wrote_file = false;
    let batch_result = tokio::select! {
        result = tokio::time::timeout(remaining, async {
            for entry in entries {
                if entry.submodule {
                    continue;
                }
                stdin
                    .write_all(entry.object.as_bytes())
                    .await
                    .map_err(|_| RunnerError::GitFailed)?;
                stdin.write_all(b"\n").await.map_err(|_| RunnerError::GitFailed)?;
                stdin.flush().await.map_err(|_| RunnerError::GitFailed)?;
                let content = read_batch_blob(&mut stdout, &entry).await?;
                let file = serde_jcs::to_vec(&BundleFile {
                    path: entry.path,
                    executable: entry.executable,
                    content_hex: encode_hex(&content),
                    digest: digest_string(&content),
                })
                .map_err(|_| RunnerError::OutputUnavailable)?;
                if wrote_file {
                    write_bundle_piece(&mut output, &mut bundle_digest, b",")?;
                }
                write_bundle_piece(&mut output, &mut bundle_digest, &file)?;
                wrote_file = true;
            }
            stdin.shutdown().await.map_err(|_| RunnerError::GitFailed)?;
            drop(stdin);
            child.wait().await.map_err(|_| RunnerError::GitFailed)
        }) => match result {
            Ok(result) => result,
            Err(_) => Err(RunnerError::GitTimedOut),
        },
        Some(()) = overflow_rx.recv() => Err(RunnerError::GitOutputExceeded),
    };
    let status = match batch_result {
        Ok(status) => status,
        Err(error) => {
            let _ = child.kill().await;
            let _ = stderr_reader.await;
            return Err(error);
        }
    };
    stderr_reader.await.map_err(|_| RunnerError::GitFailed)??;
    if !status.success() {
        return Err(RunnerError::GitFailed);
    }
    write_bundle_piece(&mut output, &mut bundle_digest, BUNDLE_SUFFIX)?;
    output
        .sync_all()
        .map_err(|_| RunnerError::OutputUnavailable)?;
    let observed = output
        .metadata()
        .map_err(|_| RunnerError::OutputUnavailable)?
        .len();
    if observed != projected_bytes {
        return Err(RunnerError::BundleBytesExceeded);
    }
    Ok(format!("sha256:{}", encode_hex(&bundle_digest.finalize())))
}

fn spawn_git_batch(
    arguments: Vec<OsString>,
    repository: &Path,
    plan: &GitPlan,
) -> Result<tokio::process::Child, RunnerError> {
    let mut command = Command::new(GIT_PROGRAM);
    command
        .args(arguments)
        .env_clear()
        .envs(git_environment(repository, plan))
        .current_dir(repository)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| RunnerError::GitUnavailable)
}

async fn read_batch_blob<R>(reader: &mut R, entry: &TreeEntry) -> Result<Vec<u8>, RunnerError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut header = Vec::with_capacity(80);
    loop {
        if header.len() >= MAX_BATCH_HEADER_BYTES {
            return Err(RunnerError::InvalidGitOutput);
        }
        let byte = reader
            .read_u8()
            .await
            .map_err(|_| RunnerError::InvalidGitOutput)?;
        if byte == b'\n' {
            break;
        }
        header.push(byte);
    }
    parse_batch_header(&header, entry)?;
    let size = usize::try_from(entry.size).map_err(|_| RunnerError::FileBytesExceeded)?;
    let mut content = vec![0; size];
    reader
        .read_exact(&mut content)
        .await
        .map_err(|_| RunnerError::InvalidGitOutput)?;
    if reader
        .read_u8()
        .await
        .map_err(|_| RunnerError::InvalidGitOutput)?
        != b'\n'
    {
        return Err(RunnerError::InvalidGitOutput);
    }
    Ok(content)
}

fn parse_batch_header(header: &[u8], entry: &TreeEntry) -> Result<(), RunnerError> {
    if !header.is_ascii() {
        return Err(RunnerError::InvalidGitOutput);
    }
    let header = std::str::from_utf8(header).map_err(|_| RunnerError::InvalidGitOutput)?;
    let mut fields = header.split_ascii_whitespace();
    if fields.next() != Some(entry.object.as_str())
        || fields.next() != Some("blob")
        || fields.next().and_then(|size| size.parse::<u64>().ok()) != Some(entry.size)
        || fields.next().is_some()
    {
        return Err(RunnerError::InvalidGitOutput);
    }
    Ok(())
}

fn projected_bundle_bytes(entries: &[TreeEntry]) -> Result<u64, RunnerError> {
    let mut total = u64::try_from(BUNDLE_PREFIX.len() + BUNDLE_SUFFIX.len())
        .map_err(|_| RunnerError::BundleBytesExceeded)?;
    for (file_count, entry) in entries.iter().filter(|entry| !entry.submodule).enumerate() {
        let empty = BundleFile {
            path: entry.path.clone(),
            executable: entry.executable,
            content_hex: String::new(),
            digest: format!("sha256:{}", "0".repeat(64)),
        };
        let metadata_bytes = u64::try_from(
            serde_jcs::to_vec(&empty)
                .map_err(|_| RunnerError::OutputUnavailable)?
                .len(),
        )
        .map_err(|_| RunnerError::BundleBytesExceeded)?;
        total = total
            .checked_add(metadata_bytes)
            .and_then(|value| value.checked_add(entry.size.checked_mul(2)?))
            .and_then(|value| value.checked_add(u64::from(file_count != 0)))
            .ok_or(RunnerError::BundleBytesExceeded)?;
    }
    Ok(total)
}

fn write_bundle_piece(
    output: &mut File,
    digest: &mut Sha256,
    bytes: &[u8],
) -> Result<(), RunnerError> {
    output
        .write_all(bytes)
        .map_err(|_| RunnerError::OutputUnavailable)?;
    digest.update(bytes);
    Ok(())
}

fn git_arguments<const N: usize>(
    plan: &GitPlan,
    command: [&str; N],
) -> Result<Vec<OsString>, RunnerError> {
    let hooks = path_text(&plan.neutral.join("empty-hooks"))?;
    let attributes = path_text(&plan.neutral.join("empty-attributes"))?;
    let excludes = path_text(&plan.neutral.join("empty-excludes"))?;
    let config = path_text(&plan.remote_config)?;
    let mut settings = vec![
        "protocol.allow=never".to_owned(),
        "protocol.file.allow=never".to_owned(),
        "protocol.ext.allow=never".to_owned(),
        "protocol.git.allow=never".to_owned(),
        "protocol.http.allow=never".to_owned(),
        format!("include.path={config}"),
        format!("core.hooksPath={hooks}"),
        format!("core.attributesFile={attributes}"),
        format!("core.excludesFile={excludes}"),
        "core.fsmonitor=false".to_owned(),
        "credential.helper=".to_owned(),
        "credential.useHttpPath=true".to_owned(),
        "submodule.recurse=false".to_owned(),
        "fetch.recurseSubmodules=false".to_owned(),
        "filter.lfs.smudge=".to_owned(),
        "filter.lfs.clean=".to_owned(),
        "filter.lfs.process=".to_owned(),
        "filter.lfs.required=false".to_owned(),
        "http.followRedirects=false".to_owned(),
    ];
    if plan.ssh_destination.is_some() {
        settings.extend([
            "protocol.https.allow=never".to_owned(),
            "protocol.ssh.allow=always".to_owned(),
            format!("core.sshCommand={SSH_COMMAND}"),
        ]);
    } else {
        settings.extend([
            "protocol.https.allow=always".to_owned(),
            "protocol.ssh.allow=never".to_owned(),
            format!("http.proxy={PROXY_URL}"),
        ]);
    }
    let mut arguments = Vec::with_capacity(settings.len() * 2 + N);
    for setting in settings {
        arguments.push(OsString::from("-c"));
        arguments.push(OsString::from(setting));
    }
    arguments.extend(command.into_iter().map(OsString::from));
    Ok(arguments)
}

async fn run_git(
    arguments: Vec<OsString>,
    current_dir: &Path,
    plan: &GitPlan,
    max_output_bytes: usize,
    deadline: Instant,
    stage: &'static str,
) -> Result<GitOutput, RunnerError> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or(RunnerError::GitTimedOut)?;
    let mut command = Command::new(GIT_PROGRAM);
    command
        .args(arguments)
        .env_clear()
        .envs(git_environment(current_dir, plan))
        .current_dir(current_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command.spawn().map_err(|_| RunnerError::GitUnavailable)?;
    let stdout = child.stdout.take().ok_or(RunnerError::GitUnavailable)?;
    let stderr = child.stderr.take().ok_or(RunnerError::GitUnavailable)?;
    let observed = Arc::new(AtomicUsize::new(0));
    let (overflow_tx, mut overflow_rx) = mpsc::channel(1);
    let stdout_reader = tokio::spawn(capture_output(
        stdout,
        max_output_bytes,
        Arc::clone(&observed),
        overflow_tx.clone(),
        true,
        stage,
    ));
    let stderr_reader = tokio::spawn(capture_output(
        stderr,
        max_output_bytes,
        observed,
        overflow_tx,
        false,
        stage,
    ));
    let status = tokio::time::timeout(remaining, async {
        tokio::select! {
            status = child.wait() => status.map_err(|_| RunnerError::GitFailed),
            Some(()) = overflow_rx.recv() => Err(RunnerError::GitOutputExceeded),
        }
    })
    .await;
    let status = match status {
        Ok(Ok(status)) => status,
        Ok(Err(error)) => {
            let _ = child.kill().await;
            return Err(error);
        }
        Err(_) => {
            let _ = child.kill().await;
            return Err(RunnerError::GitTimedOut);
        }
    };
    let stdout = stdout_reader.await.map_err(|_| RunnerError::GitFailed)??;
    stderr_reader.await.map_err(|_| RunnerError::GitFailed)??;
    if !status.success() {
        return Err(RunnerError::GitFailed);
    }
    Ok(GitOutput { stdout })
}

fn git_environment(current_dir: &Path, plan: &GitPlan) -> Vec<(OsString, OsString)> {
    let mut environment = vec![
        (OsString::from("HOME"), current_dir.as_os_str().to_owned()),
        (OsString::from("LC_ALL"), OsString::from("C")),
        (OsString::from("LANG"), OsString::from("C")),
        (OsString::from("GIT_CONFIG_NOSYSTEM"), OsString::from("1")),
        (
            OsString::from("GIT_CONFIG_GLOBAL"),
            OsString::from("/work/run/neutral/empty-config"),
        ),
        (OsString::from("GIT_TERMINAL_PROMPT"), OsString::from("0")),
        (
            OsString::from("GIT_ASKPASS"),
            OsString::from("/usr/bin/false"),
        ),
        (OsString::from("GIT_LFS_SKIP_SMUDGE"), OsString::from("1")),
        (OsString::from("GIT_OPTIONAL_LOCKS"), OsString::from("0")),
    ];
    if let Some(destination) = &plan.ssh_destination {
        environment.extend([
            (
                OsString::from("PROMPTECTOMY_SSH_DESTINATION"),
                OsString::from(destination),
            ),
            (
                OsString::from("SSH_AUTH_SOCK"),
                OsString::from(SSH_AGENT_PATH),
            ),
            (OsString::from("GIT_SSH_VARIANT"), OsString::from("ssh")),
        ]);
    }
    environment
}

async fn capture_output<R>(
    mut reader: R,
    max_output_bytes: usize,
    observed: Arc<AtomicUsize>,
    overflow: mpsc::Sender<()>,
    retain: bool,
    stage: &'static str,
) -> Result<Vec<u8>, RunnerError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut captured = Vec::new();
    let mut chunk = [0_u8; 8192];
    loop {
        let count = reader
            .read(&mut chunk)
            .await
            .map_err(|_| RunnerError::GitFailed)?;
        if count == 0 {
            return Ok(captured);
        }
        let prior = observed.fetch_add(count, Ordering::Relaxed);
        if count > max_output_bytes || prior > max_output_bytes - count {
            eprintln!(
                "git output limit exceeded during {stage}: observed at least {} bytes with a {max_output_bytes} byte limit",
                prior.saturating_add(count)
            );
            let _ = overflow.try_send(());
            return Err(RunnerError::GitOutputExceeded);
        }
        if retain {
            captured.extend_from_slice(&chunk[..count]);
        }
    }
}

fn parse_inventory(
    output: &[u8],
    manifest: &RemoteGitManifest,
) -> Result<Vec<TreeEntry>, RunnerError> {
    let mut entries = Vec::new();
    let mut seen = BTreeSet::new();
    let mut total = 0_u64;
    for record in output
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
    {
        let tab = record
            .iter()
            .position(|byte| *byte == b'\t')
            .ok_or(RunnerError::InvalidGitOutput)?;
        let metadata =
            std::str::from_utf8(&record[..tab]).map_err(|_| RunnerError::InvalidGitOutput)?;
        let fields: Vec<_> = metadata.split_ascii_whitespace().collect();
        if fields.len() != 4 {
            return Err(RunnerError::InvalidGitOutput);
        }
        let path = normalize_path(&record[tab + 1..], manifest.max_path_bytes)?;
        if !seen.insert(path.to_ascii_lowercase()) {
            return Err(RunnerError::PathCollision);
        }
        if !selected(&path, &manifest.selected_roots) {
            continue;
        }
        if entries.len() >= manifest.max_files {
            return Err(RunnerError::FileCountExceeded);
        }
        if !valid_object_id(fields[2]) {
            return Err(RunnerError::InvalidGitOutput);
        }
        let (executable, submodule, size) = match (fields[0], fields[1], fields[3]) {
            ("100644", "blob", value) => (false, false, parse_size(value)?),
            ("100755", "blob", value) => (true, false, parse_size(value)?),
            ("160000", "commit", "-") => (false, true, 0),
            _ => return Err(RunnerError::UnsafePath),
        };
        if size > manifest.max_file_bytes {
            return Err(RunnerError::FileBytesExceeded);
        }
        total = total
            .checked_add(size)
            .ok_or(RunnerError::TotalBytesExceeded)?;
        if total > manifest.max_total_bytes {
            return Err(RunnerError::TotalBytesExceeded);
        }
        entries.push(TreeEntry {
            path,
            object: fields[2].to_owned(),
            size,
            executable,
            submodule,
        });
    }
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(entries)
}

fn normalize_path(raw: &[u8], max_path_bytes: usize) -> Result<String, RunnerError> {
    if raw.is_empty()
        || raw.len() > max_path_bytes
        || raw.first() == Some(&b'/')
        || raw.contains(&b'\\')
        || !raw.is_ascii()
    {
        return Err(RunnerError::UnsafePath);
    }
    let value = std::str::from_utf8(raw).map_err(|_| RunnerError::UnsafePath)?;
    for component in value.split('/') {
        if component.is_empty()
            || component == "."
            || component == ".."
            || component.len() > 255
            || component.bytes().any(|byte| byte.is_ascii_control())
            || component.ends_with(['.', ' '])
            || component.contains(':')
            || component.eq_ignore_ascii_case(".git")
        {
            return Err(RunnerError::UnsafePath);
        }
        let stem = component.split('.').next().ok_or(RunnerError::UnsafePath)?;
        if WINDOWS_DEVICES
            .iter()
            .any(|device| stem.eq_ignore_ascii_case(device))
        {
            return Err(RunnerError::UnsafePath);
        }
    }
    Ok(value.to_owned())
}

fn selected(path: &str, roots: &[String]) -> bool {
    roots.is_empty()
        || roots.iter().any(|root| {
            path == root
                || path
                    .strip_prefix(root)
                    .is_some_and(|rest| rest.starts_with('/'))
        })
}

fn validate_url(url: &str) -> Result<(String, String), RunnerError> {
    if !url.is_ascii()
        || !url.starts_with("https://")
        || url.len() > 2048
        || url.contains(['?', '#', '\\', '%'])
    {
        return Err(RunnerError::LocatorDenied);
    }
    let remainder = &url[8..];
    let (authority, path) = remainder
        .split_once('/')
        .ok_or(RunnerError::LocatorDenied)?;
    let host = authority.strip_suffix(":443").unwrap_or(authority);
    if authority.contains('@')
        || !ALLOWED_HOSTS.contains(&host)
        || path.is_empty()
        || path.starts_with('/')
        || path.split('/').any(|part| {
            part.is_empty()
                || part == "."
                || part == ".."
                || !part.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'~')
                })
        })
    {
        return Err(RunnerError::LocatorDenied);
    }
    let canonical = format!("https://{host}/{path}");
    Ok((host.to_owned(), canonical))
}

fn validate_repository(repository: &str) -> Result<(), RunnerError> {
    if repository.is_empty()
        || repository.len() > 512
        || !repository.is_ascii()
        || repository.starts_with(['/', '-'])
        || repository.contains(['?', '#', '\\', '%'])
        || repository.split('/').any(|component| {
            component.is_empty()
                || component == "."
                || component == ".."
                || !component.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'~')
                })
        })
    {
        return Err(RunnerError::LocatorDenied);
    }
    Ok(())
}

fn validate_host_key(key_type: &str, encoded: &str) -> Result<(), RunnerError> {
    if !matches!(
        key_type,
        "ssh-ed25519"
            | "ssh-rsa"
            | "ecdsa-sha2-nistp256"
            | "ecdsa-sha2-nistp384"
            | "ecdsa-sha2-nistp521"
            | "sk-ssh-ed25519@openssh.com"
            | "sk-ecdsa-sha2-nistp256@openssh.com"
    ) || encoded.is_empty()
        || encoded.len() > 32 * 1024
    {
        return Err(RunnerError::LocatorDenied);
    }
    let decoded = decode_base64(encoded)?;
    if decoded.is_empty() || decoded.len() > 16 * 1024 || decoded.len() < 4 {
        return Err(RunnerError::LocatorDenied);
    }
    let key_type_bytes = usize::try_from(u32::from_be_bytes(
        decoded[..4]
            .try_into()
            .map_err(|_| RunnerError::LocatorDenied)?,
    ))
    .map_err(|_| RunnerError::LocatorDenied)?;
    if key_type_bytes == 0
        || key_type_bytes > 128
        || decoded.get(4..4 + key_type_bytes) != Some(key_type.as_bytes())
    {
        return Err(RunnerError::LocatorDenied);
    }
    Ok(())
}

fn decode_base64(encoded: &str) -> Result<Vec<u8>, RunnerError> {
    if encoded.len() % 4 == 1 {
        return Err(RunnerError::LocatorDenied);
    }
    let mut decoded = Vec::with_capacity(encoded.len().saturating_mul(3) / 4);
    let mut bits = 0_u32;
    let mut bit_count = 0_u8;
    for byte in encoded.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return Err(RunnerError::LocatorDenied),
        };
        bits = (bits << 6) | u32::from(value);
        bit_count += 6;
        if bit_count >= 8 {
            bit_count -= 8;
            decoded.push(u8::try_from(bits >> bit_count).map_err(|_| RunnerError::LocatorDenied)?);
            bits &= (1_u32 << bit_count) - 1;
        }
    }
    if bits != 0 {
        return Err(RunnerError::LocatorDenied);
    }
    Ok(decoded)
}

fn validate_revision(revision: &str) -> Result<(), RunnerError> {
    if revision.is_empty()
        || revision.len() > 200
        || revision.starts_with('-')
        || revision.contains("..")
        || revision.contains("@{")
        || revision.bytes().any(|byte| {
            !(byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'/' | b'-'))
        })
    {
        return Err(RunnerError::InvalidManifest);
    }
    Ok(())
}

fn parse_object_id(output: &[u8]) -> Result<String, RunnerError> {
    let value = std::str::from_utf8(output)
        .map_err(|_| RunnerError::InvalidGitOutput)?
        .trim();
    if !valid_object_id(value) {
        return Err(RunnerError::InvalidGitOutput);
    }
    Ok(value.to_owned())
}

fn valid_object_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn parse_size(value: &str) -> Result<u64, RunnerError> {
    value.parse().map_err(|_| RunnerError::InvalidGitOutput)
}

fn check_work_quota(root: &Path, max_bytes: u64) -> Result<(), RunnerError> {
    let mut stack = vec![root.to_path_buf()];
    let mut count = 0_usize;
    let mut total = 0_u64;
    while let Some(path) = stack.pop() {
        for entry in fs::read_dir(path).map_err(|_| RunnerError::WorkspaceUnavailable)? {
            let entry = entry.map_err(|_| RunnerError::WorkspaceUnavailable)?;
            count += 1;
            if count > MAX_WORK_ENTRIES {
                return Err(RunnerError::WorkBytesExceeded);
            }
            let metadata = entry
                .metadata()
                .map_err(|_| RunnerError::WorkspaceUnavailable)?;
            if metadata.is_dir() {
                stack.push(entry.path());
            } else if metadata.is_file() {
                total = total
                    .checked_add(metadata.len())
                    .ok_or(RunnerError::WorkBytesExceeded)?;
                if total > max_bytes {
                    return Err(RunnerError::WorkBytesExceeded);
                }
            } else {
                return Err(RunnerError::WorkspaceUnavailable);
            }
        }
    }
    Ok(())
}

fn read_bounded(path: &Path, max_bytes: u64) -> Result<Vec<u8>, RunnerError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| RunnerError::RequestUnavailable)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > max_bytes
    {
        return Err(RunnerError::RequestUnavailable);
    }
    let file = File::open(path).map_err(|_| RunnerError::RequestUnavailable)?;
    let mut bytes = Vec::new();
    file.take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| RunnerError::RequestUnavailable)?;
    if u64::try_from(bytes.len()).map_err(|_| RunnerError::RequestUnavailable)? > max_bytes {
        return Err(RunnerError::RequestUnavailable);
    }
    Ok(bytes)
}

#[cfg(unix)]
fn verify_ssh_agent_socket(path: &Path) -> Result<(), RunnerError> {
    use std::os::unix::fs::FileTypeExt as _;

    let metadata = fs::symlink_metadata(path).map_err(|_| RunnerError::SshRelayUnavailable)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_socket() {
        return Err(RunnerError::SshRelayUnavailable);
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_ssh_agent_socket(_: &Path) -> Result<(), RunnerError> {
    Err(RunnerError::SshRelayUnavailable)
}

fn create_private_file(path: &Path, bytes: &[u8]) -> Result<(), RunnerError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|_| RunnerError::WorkspaceUnavailable)?;
    file.write_all(bytes)
        .map_err(|_| RunnerError::WorkspaceUnavailable)?;
    file.sync_all()
        .map_err(|_| RunnerError::WorkspaceUnavailable)
}

pub fn write_success(result: &SuccessResult) -> Result<(), RunnerError> {
    let bytes = serde_jcs::to_vec(result).map_err(|_| RunnerError::OutputUnavailable)?;
    write_new(Path::new(RESULT_PATH), &bytes)
}

pub fn write_failure(error: &RunnerError) -> Result<(), RunnerError> {
    let result = FailureResult {
        schema_version: RESULT_VERSION,
        status: "failed",
        manifest_digest: None,
        error_code: error.to_string(),
    };
    let bytes = serde_jcs::to_vec(&result).map_err(|_| RunnerError::OutputUnavailable)?;
    write_new(Path::new(RESULT_PATH), &bytes)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), RunnerError> {
    let parent = path.parent().ok_or(RunnerError::OutputUnavailable)?;
    fs::create_dir_all(parent).map_err(|_| RunnerError::OutputUnavailable)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| RunnerError::OutputUnavailable)?;
    file.write_all(bytes)
        .map_err(|_| RunnerError::OutputUnavailable)?;
    file.sync_all().map_err(|_| RunnerError::OutputUnavailable)
}

fn digest_file(path: &Path, max_bytes: u64) -> Result<String, RunnerError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| RunnerError::GitUnavailable)?;
    if !metadata.file_type().is_file() || metadata.len() > max_bytes {
        return Err(RunnerError::GitUnavailable);
    }
    let mut file = File::open(path).map_err(|_| RunnerError::GitUnavailable)?;
    let mut digest = Sha256::new();
    let mut chunk = [0_u8; 8192];
    loop {
        let count = file
            .read(&mut chunk)
            .map_err(|_| RunnerError::GitUnavailable)?;
        if count == 0 {
            break;
        }
        digest.update(&chunk[..count]);
    }
    Ok(format!("sha256:{}", encode_hex(&digest.finalize())))
}

fn path_text(path: &Path) -> Result<String, RunnerError> {
    path.to_str()
        .map(ToOwned::to_owned)
        .ok_or(RunnerError::WorkspaceUnavailable)
}

fn is_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn domain_digest(domain: &str, value: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(domain.as_bytes());
    digest.update([0]);
    digest.update(value);
    format!("sha256:{}", encode_hex(&digest.finalize()))
}

fn digest_string(value: &[u8]) -> String {
    format!("sha256:{}", encode_hex(&Sha256::digest(value)))
}

fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    const SSH_HOST_KEY: &str =
        "AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f";

    fn manifest() -> RemoteGitManifest {
        let mut manifest = RemoteGitManifest {
            schema_version: MANIFEST_VERSION.to_owned(),
            source_kind: SourceKind::HttpsRemote,
            manifest_digest: String::new(),
            authority_digest: format!("sha256:{}", "a".repeat(64)),
            locator_digest: domain_digest(
                "remote-locator",
                b"https://github.com/example/project.git",
            ),
            redacted_locator: "https://github.com/<redacted>".to_owned(),
            destination: Destination {
                host: "github.com".to_owned(),
                port: 443,
            },
            revision: "refs/heads/main".to_owned(),
            selected_roots: vec!["src".to_owned()],
            max_files: 10,
            max_total_bytes: 1024,
            max_file_bytes: 512,
            max_path_bytes: 128,
            max_remote_work_bytes: 2048,
            max_bundle_bytes: 2048,
            max_output_bytes: 2048,
            wall_time_seconds: 5,
            checkout_policy: "no_checkout".to_owned(),
            egress_policy: "application_connect_proxy_exact_destination".to_owned(),
            credential_policy: CredentialPolicy::None,
            broker: None,
            backend: BackendPolicy {
                profile: BackendProfile::OrbstackMacosArm64V1,
                image_digest: format!("sha256:{}", "1".repeat(64)),
                runner_digest: format!("sha256:{}", "2".repeat(64)),
                egress_proxy_digest: format!("sha256:{}", "3".repeat(64)),
                ssh_agent_relay_digest: format!("sha256:{}", "4".repeat(64)),
            },
        };
        let encoded = serde_jcs::to_vec(&manifest).expect("manifest");
        manifest.manifest_digest = domain_digest("remote-git-manifest", &encoded);
        manifest
    }

    fn https_request() -> RunnerRequest {
        RunnerRequest {
            schema_version: REQUEST_VERSION.to_owned(),
            manifest: manifest(),
            https_url: Some("https://github.com/example/project.git".to_owned()),
            ssh: None,
        }
    }

    fn ssh_request() -> RunnerRequest {
        let repository = "example/private-project.git";
        let host_key_type = "ssh-ed25519";
        let host_key = format!("{host_key_type} {SSH_HOST_KEY}");
        let mut manifest = manifest();
        manifest.source_kind = SourceKind::SshBrokered;
        manifest.locator_digest = domain_digest("remote-locator", b"request_abc123");
        manifest.redacted_locator = "ssh://github.com/<redacted>".to_owned();
        manifest.destination.port = 22;
        manifest.credential_policy = CredentialPolicy::SshAgentBrokerGrant;
        manifest.broker = Some(BrokerBinding {
            handle_digest: domain_digest("ssh-broker-handle", b"request_abc123"),
            executable_digest: format!("sha256:{}", "4".repeat(64)),
            request_digest: format!("sha256:{}", "5".repeat(64)),
            repository_digest: domain_digest("ssh-repository", repository.as_bytes()),
            host_key_digest: domain_digest("ssh-host-key", host_key.as_bytes()),
            selected_public_key_digest: domain_digest("ssh-selected-public-key", b"selected-key"),
        });
        manifest.manifest_digest.clear();
        manifest.manifest_digest = domain_digest(
            "remote-git-manifest",
            &serde_jcs::to_vec(&manifest).expect("SSH manifest"),
        );
        RunnerRequest {
            schema_version: REQUEST_VERSION.to_owned(),
            manifest,
            https_url: None,
            ssh: Some(SshInput {
                repository: repository.to_owned(),
                host_key_type: host_key_type.to_owned(),
                host_key_base64: SSH_HOST_KEY.to_owned(),
            }),
        }
    }

    fn expected_ssh_config() -> &'static str {
        concat!(
            "Host github.com\n",
            "\tBatchMode yes\n",
            "\tCanonicalizeHostname no\n",
            "\tCheckHostIP no\n",
            "\tClearAllForwardings yes\n",
            "\tCompression no\n",
            "\tConnectionAttempts 1\n",
            "\tConnectTimeout 10\n",
            "\tEnableEscapeCommandline no\n",
            "\tForwardAgent no\n",
            "\tForwardX11 no\n",
            "\tGlobalKnownHostsFile /dev/null\n",
            "\tHostKeyAlgorithms ssh-ed25519\n",
            "\tHostName github.com\n",
            "\tIdentitiesOnly no\n",
            "\tIdentityAgent /work/relay/agent.sock\n",
            "\tIdentityFile none\n",
            "\tKbdInteractiveAuthentication no\n",
            "\tPasswordAuthentication no\n",
            "\tPermitLocalCommand no\n",
            "\tPort 22\n",
            "\tPreferredAuthentications publickey\n",
            "\tProxyCommand /usr/local/bin/promptectomy-ssh-connect %h %p\n",
            "\tPubkeyAuthentication yes\n",
            "\tRequestTTY no\n",
            "\tStrictHostKeyChecking yes\n",
            "\tUpdateHostKeys no\n",
            "\tUser git\n",
            "\tUserKnownHostsFile /work/run/neutral/known-hosts\n",
            "\tVerifyHostKeyDNS no\n",
        )
    }

    #[test]
    fn request_is_strict_and_binds_secret_locator() {
        let request = https_request();
        request.validate().expect("valid request");
        let mut value = serde_json::to_value(&request).expect("request value");
        value["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<RunnerRequest>(value).is_err());

        for denied in [
            "http://github.com/example/project.git",
            "https://token@github.com/example/project.git",
            "https://github.com/example/project.git?token=secret",
            "https://127.0.0.1/example/project.git",
            "https://github.com/example/%2e%2e/project.git",
        ] {
            let mut malicious = request.clone();
            malicious.https_url = Some(denied.to_owned());
            assert!(malicious.validate().is_err(), "{denied}");
        }
    }

    #[test]
    fn ssh_request_binds_only_validated_broker_material() {
        let request = ssh_request();
        request.validate().expect("valid SSH request");

        let mut both_transports = request.clone();
        both_transports.https_url = Some("https://github.com/example/project.git".to_owned());
        assert!(both_transports.validate().is_err());

        let mut changed_repository = request.clone();
        changed_repository
            .ssh
            .as_mut()
            .expect("SSH input")
            .repository = "attacker/repository.git".to_owned();
        assert!(changed_repository.validate().is_err());

        let mut changed_host_key = request.clone();
        changed_host_key
            .ssh
            .as_mut()
            .expect("SSH input")
            .host_key_base64 = "AAAA".to_owned();
        assert!(changed_host_key.validate().is_err());

        let mut unbound_identity = request;
        unbound_identity
            .manifest
            .broker
            .as_mut()
            .expect("broker")
            .selected_public_key_digest = "not-a-digest".to_owned();
        unbound_identity.manifest.manifest_digest.clear();
        unbound_identity.manifest.manifest_digest = domain_digest(
            "remote-git-manifest",
            &serde_jcs::to_vec(&unbound_identity.manifest).expect("mutated manifest"),
        );
        assert!(unbound_identity.validate().is_err());
    }

    #[test]
    fn ssh_request_rejects_hostile_repository_and_host_key_even_if_redigested() {
        for repository in [
            "../secret.git",
            "/absolute.git",
            "owner/repo with space.git",
            "owner/repo%2egit",
            "-oProxyCommand=evil",
        ] {
            let mut request = ssh_request();
            request.ssh.as_mut().expect("SSH input").repository = repository.to_owned();
            request
                .manifest
                .broker
                .as_mut()
                .expect("broker")
                .repository_digest = domain_digest("ssh-repository", repository.as_bytes());
            request.manifest.manifest_digest.clear();
            request.manifest.manifest_digest = domain_digest(
                "remote-git-manifest",
                &serde_jcs::to_vec(&request.manifest).expect("mutated manifest"),
            );
            assert!(request.validate().is_err(), "{repository}");
        }

        for (key_type, key) in [
            ("ssh-ed25519;evil", SSH_HOST_KEY),
            ("ssh-ed25519", "AAAA"),
            ("ssh-ed25519", "not base64"),
            ("ssh-rsa", SSH_HOST_KEY),
        ] {
            let mut request = ssh_request();
            let ssh = request.ssh.as_mut().expect("SSH input");
            ssh.host_key_type = key_type.to_owned();
            ssh.host_key_base64 = key.to_owned();
            let host_key = format!("{key_type} {key}");
            request
                .manifest
                .broker
                .as_mut()
                .expect("broker")
                .host_key_digest = domain_digest("ssh-host-key", host_key.as_bytes());
            request.manifest.manifest_digest.clear();
            request.manifest.manifest_digest = domain_digest(
                "remote-git-manifest",
                &serde_jcs::to_vec(&request.manifest).expect("mutated manifest"),
            );
            assert!(request.validate().is_err(), "{key_type} {key}");
        }
    }

    #[test]
    fn git_plan_keeps_locator_out_of_arguments() {
        let temp = tempfile::tempdir().expect("tempdir");
        let config = temp.path().join("remote-config");
        let url = "https://github.com/private-owner/private-repository.git";
        let plan = GitPlan {
            neutral: temp.path().to_path_buf(),
            remote_config: config,
            repository: temp.path().join("repository.git"),
            ssh_destination: None,
        };
        let arguments = git_arguments(&plan, ["fetch", PLACEHOLDER_URL]).expect("git arguments");
        let rendered = arguments
            .iter()
            .map(|value| value.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ");
        assert!(!rendered.contains(url));
        assert!(rendered.contains(PLACEHOLDER_URL));
    }

    #[test]
    fn ssh_git_plan_is_fixed_and_keeps_broker_material_out_of_arguments() {
        let temp = tempfile::tempdir().expect("tempdir");
        let request = ssh_request();
        request.validate().expect("valid SSH request");
        let plan = prepare_workspace(&request, temp.path()).expect("SSH workspace");
        let arguments = git_arguments(&plan, ["fetch", PLACEHOLDER_URL]).expect("SSH arguments");
        let rendered = arguments
            .iter()
            .map(|value| value.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ");
        assert!(rendered.contains("protocol.ssh.allow=always"));
        assert!(rendered.contains("protocol.https.allow=never"));
        assert!(rendered.contains(&format!("core.sshCommand={SSH_COMMAND}")));
        assert!(rendered.contains(PLACEHOLDER_URL));
        assert!(!rendered.contains("private-project"));
        assert!(!rendered.contains(SSH_HOST_KEY));

        let config = fs::read_to_string(&plan.remote_config).expect("remote config");
        assert_eq!(
            config,
            format!(
                "[url \"ssh://git@github.com/example/private-project.git\"]\n\tinsteadOf = {PLACEHOLDER_URL}\n"
            )
        );
        assert_eq!(
            fs::read_to_string(plan.neutral.join("known-hosts")).expect("known hosts"),
            format!("github.com ssh-ed25519 {SSH_HOST_KEY}\n")
        );
        let ssh_config = fs::read_to_string(plan.neutral.join("ssh-config")).expect("SSH config");
        assert_eq!(ssh_config, expected_ssh_config());

        let environment = git_environment(&plan.repository, &plan);
        assert!(environment.contains(&(
            OsString::from("PROMPTECTOMY_SSH_DESTINATION"),
            OsString::from("github.com:22")
        )));
        assert!(environment.contains(&(
            OsString::from("SSH_AUTH_SOCK"),
            OsString::from(SSH_AGENT_PATH)
        )));
        assert!(environment.contains(&(OsString::from("GIT_SSH_VARIANT"), OsString::from("ssh"))));
    }

    #[cfg(unix)]
    #[test]
    fn ssh_relay_path_must_be_a_real_unix_socket() {
        use std::os::unix::net::UnixListener;

        let temp = tempfile::tempdir().expect("tempdir");
        let socket = temp.path().join("agent.sock");
        let _listener = UnixListener::bind(&socket).expect("relay socket");
        verify_ssh_agent_socket(&socket).expect("real relay socket");

        let file = temp.path().join("not-a-socket");
        fs::write(&file, []).expect("regular file");
        assert!(matches!(
            verify_ssh_agent_socket(&file),
            Err(RunnerError::SshRelayUnavailable)
        ));
        assert!(matches!(
            verify_ssh_agent_socket(&temp.path().join("missing")),
            Err(RunnerError::SshRelayUnavailable)
        ));
    }

    #[test]
    fn inventory_rejects_unsafe_modes_collisions_and_quotas() {
        let manifest = manifest();
        let object = "a".repeat(40);
        let valid = format!("100644 blob {object} 4\tsrc/main.rs\0");
        let parsed = parse_inventory(valid.as_bytes(), &manifest).expect("valid inventory");
        assert_eq!(parsed.len(), 1);
        assert!(!parsed[0].executable);

        let collision =
            format!("100644 blob {object} 1\tsrc/Main.rs\0100644 blob {object} 1\tsrc/main.rs\0");
        assert!(matches!(
            parse_inventory(collision.as_bytes(), &manifest),
            Err(RunnerError::PathCollision)
        ));
        let symlink = format!("120000 blob {object} 4\tsrc/link\0");
        assert!(parse_inventory(symlink.as_bytes(), &manifest).is_err());
        let traversal = format!("100644 blob {object} 4\tsrc/../secret\0");
        assert!(parse_inventory(traversal.as_bytes(), &manifest).is_err());
        let oversized = format!("100644 blob {object} 513\tsrc/large\0");
        assert!(matches!(
            parse_inventory(oversized.as_bytes(), &manifest),
            Err(RunnerError::FileBytesExceeded)
        ));
    }

    #[test]
    fn source_bundle_matches_acquisition_format() {
        let file = BundleFile {
            path: "src/main.rs".to_owned(),
            executable: false,
            content_hex: encode_hex(b"fn main() {}\n"),
            digest: digest_string(b"fn main() {}\n"),
        };
        let bytes = serde_jcs::to_vec(&BundleDocument {
            version: BUNDLE_VERSION,
            files: vec![file.clone()],
        })
        .expect("bundle");
        let mut streamed = BUNDLE_PREFIX.to_vec();
        streamed.extend_from_slice(&serde_jcs::to_vec(&file).expect("bundle file"));
        streamed.extend_from_slice(BUNDLE_SUFFIX);
        assert_eq!(streamed, bytes);
        let value: serde_json::Value = serde_json::from_slice(&bytes).expect("bundle json");
        assert_eq!(value["version"], BUNDLE_VERSION);
        assert_eq!(
            value["files"][0]["content_hex"],
            "666e206d61696e2829207b7d0a"
        );
    }

    #[test]
    fn projected_bundle_bound_covers_near_limit_without_allocating_content() {
        let mut entries = vec![
            TreeEntry {
                path: "first".to_owned(),
                object: "1".repeat(40),
                size: MAX_FILE_BYTES,
                executable: false,
                submodule: false,
            },
            TreeEntry {
                path: "second".to_owned(),
                object: "2".repeat(40),
                size: MAX_FILE_BYTES,
                executable: false,
                submodule: false,
            },
        ];
        let initial = projected_bundle_bytes(&entries).expect("initial projection");
        let excess = initial
            .checked_sub(MAX_BUNDLE_BYTES)
            .expect("two maximum files exceed the bundle bound");
        entries[1].size -= excess.div_ceil(2);
        let accepted = projected_bundle_bytes(&entries).expect("accepted projection");
        assert!(accepted <= MAX_BUNDLE_BYTES);
        assert!(MAX_BUNDLE_BYTES - accepted < 2);
        assert!(entries.iter().map(|entry| entry.size).sum::<u64>() <= MAX_TOTAL_BYTES);
        entries[1].size += 1;
        assert!(projected_bundle_bytes(&entries).expect("rejected projection") > MAX_BUNDLE_BYTES);
    }

    #[tokio::test]
    async fn batch_blob_reader_accepts_binary_content_with_exact_framing() {
        let entry = TreeEntry {
            path: "src/blob".to_owned(),
            object: "a".repeat(40),
            size: 4,
            executable: false,
            submodule: false,
        };
        let frame = format!("{} blob 4\n", entry.object).into_bytes();
        let (mut writer, mut reader) = tokio::io::duplex(512);
        let write = tokio::spawn(async move {
            writer.write_all(&frame).await.expect("header");
            writer.write_all(b"\0\nxy\n").await.expect("content frame");
        });
        let content = read_batch_blob(&mut reader, &entry)
            .await
            .expect("exact batch frame");
        write.await.expect("writer");
        assert_eq!(content, b"\0\nxy");
    }

    #[tokio::test]
    async fn batch_blob_reader_rejects_substitution_size_and_unbounded_headers() {
        let entry = TreeEntry {
            path: "src/blob".to_owned(),
            object: "a".repeat(40),
            size: 4,
            executable: false,
            submodule: false,
        };
        for frame in [
            format!("{} blob 5\nhello\n", entry.object).into_bytes(),
            format!("{} tree 4\ndata\n", entry.object).into_bytes(),
            format!("{} blob 4 extra\ndata\n", entry.object).into_bytes(),
            format!("{} blob 4\ndata!", "b".repeat(40)).into_bytes(),
            vec![b'x'; MAX_BATCH_HEADER_BYTES + 1],
        ] {
            let (mut writer, mut reader) = tokio::io::duplex(1024);
            let write = tokio::spawn(async move {
                writer.write_all(&frame).await.expect("hostile frame");
            });
            assert!(matches!(
                read_batch_blob(&mut reader, &entry).await,
                Err(RunnerError::InvalidGitOutput)
            ));
            write.await.expect("writer");
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn materialization_reads_multiple_objects_through_one_batch_session() {
        let temp = tempfile::tempdir().expect("tempdir");
        let repository = temp.path().join("repository.git");
        let status = std::process::Command::new(GIT_PROGRAM)
            .args(["init", "--quiet", "--bare"])
            .arg(&repository)
            .status()
            .expect("git init");
        assert!(status.success());
        let object = |content: &[u8]| {
            let mut child = std::process::Command::new(GIT_PROGRAM)
                .args(["--git-dir"])
                .arg(&repository)
                .args(["hash-object", "-w", "--stdin"])
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("hash object");
            child
                .stdin
                .take()
                .expect("hash stdin")
                .write_all(content)
                .expect("write object");
            let output = child.wait_with_output().expect("hash output");
            assert!(output.status.success());
            String::from_utf8(output.stdout)
                .expect("object ID")
                .trim()
                .to_owned()
        };
        let first = b"first\0blob";
        let second = b"second\nblob";
        let entries = vec![
            TreeEntry {
                path: "src/first".to_owned(),
                object: object(first),
                size: u64::try_from(first.len()).expect("size"),
                executable: false,
                submodule: false,
            },
            TreeEntry {
                path: "src/second".to_owned(),
                object: object(second),
                size: u64::try_from(second.len()).expect("size"),
                executable: true,
                submodule: false,
            },
        ];
        let neutral = temp.path().join("neutral");
        fs::create_dir(&neutral).expect("neutral");
        fs::create_dir(neutral.join("empty-hooks")).expect("hooks");
        for name in ["empty-config", "empty-attributes", "empty-excludes"] {
            fs::write(neutral.join(name), []).expect("neutral file");
        }
        let remote_config = neutral.join("remote-config");
        fs::write(&remote_config, []).expect("remote config");
        let plan = GitPlan {
            neutral,
            remote_config,
            repository: repository.clone(),
            ssh_destination: None,
        };
        let output = temp.path().join("bundle.json");
        let mut manifest = manifest();
        manifest.max_bundle_bytes = 4096;
        materialize_bundle(
            entries,
            &manifest,
            &plan,
            &output,
            Instant::now() + Duration::from_secs(5),
        )
        .await
        .expect("batch materialization");
        let bundle: serde_json::Value =
            serde_json::from_slice(&fs::read(output).expect("bundle")).expect("bundle JSON");
        assert_eq!(bundle["files"].as_array().expect("files").len(), 2);
        assert_eq!(bundle["files"][0]["content_hex"], encode_hex(first));
        assert_eq!(bundle["files"][1]["content_hex"], encode_hex(second));
    }

    #[test]
    fn success_result_has_only_host_verified_wire_fields() {
        let result = SuccessResult {
            schema_version: RESULT_VERSION,
            manifest_digest: format!("sha256:{}", "a".repeat(64)),
            resolved_commit: "1".repeat(40),
            source_bundle_digest: format!("sha256:{}", "b".repeat(64)),
            git_binary_digest: format!("sha256:{}", "c".repeat(64)),
            git_execution_neutralized: true,
            credentials_isolated: true,
        };
        let value = serde_json::to_value(result).expect("result");
        assert_eq!(value.as_object().expect("object").len(), 7);
        assert_eq!(value["schema_version"], "promptectomy.remote-worker.v1");
    }

    #[tokio::test]
    async fn combined_git_output_limit_fails_closed() {
        let (mut writer, reader) = tokio::io::duplex(16);
        writer.write_all(b"12345").await.expect("write");
        drop(writer);
        let observed = Arc::new(AtomicUsize::new(0));
        let (overflow_tx, mut overflow_rx) = mpsc::channel(1);
        let result = capture_output(reader, 4, observed, overflow_tx, false, "test").await;
        assert!(matches!(result, Err(RunnerError::GitOutputExceeded)));
        assert_eq!(overflow_rx.recv().await, Some(()));
    }

    #[test]
    fn workspace_accepts_an_empty_mountpoint_once() {
        let temp = tempfile::tempdir().expect("tempdir");
        let run_root = temp.path().join("run");
        fs::create_dir(&run_root).expect("pre-created mountpoint");
        let request = https_request();

        prepare_workspace(&request, &run_root).expect("empty mountpoint");
        assert!(matches!(
            prepare_workspace(&request, &run_root),
            Err(RunnerError::WorkspaceUnavailable)
        ));
    }
}
