mod archive;
mod digest;
mod git;
mod oci_remote;
mod path_policy;
mod remote;
mod snapshot;

use std::fmt;
use std::fs::{File, Metadata};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[cfg(all(test, unix))]
use git::{GitCommandPlan, GitOutput, GitRunner, SystemGitRunner, plan_git_clone};
pub use remote::{
    BrokerBinding, ControlAttestation, EgressDestination, ORBSTACK_PUBLIC_GIT_IMAGE_DIGEST,
    ORBSTACK_PUBLIC_GIT_IMAGE_REFERENCE, ORBSTACK_PUBLIC_GIT_PROXY_DIGEST,
    ORBSTACK_PUBLIC_GIT_RELAY_DIGEST, ORBSTACK_PUBLIC_GIT_RUNNER_DIGEST,
    REMOTE_GIT_ATTESTATION_VERSION, REMOTE_GIT_MANIFEST_VERSION, RemoteBackendPolicy,
    RemoteBackendProfile, RemoteCleanupAttestation, RemoteCredentialPolicy,
    RemoteDestinationEnforcement, RemoteGitAttestation, RemoteGitManifest,
    SSH_BROKER_REQUEST_VERSION, SSH_BROKER_RESPONSE_VERSION, SshBrokerGrantRequest,
    build_remote_git_manifest,
};
use remote::{RemoteGitResult, remote_source_bundle_digest, ssh_broker_executable_digest};
use remote::{SshBrokerDecision, load_ssh_broker_request, parse_ssh_broker_response};
pub use snapshot::{AcquiredSnapshot, SnapshotReceipt};

pub const ACQUISITION_PROTOCOL_VERSION: &str = "phase4-acquisition-1";
const MAX_SSH_BROKER_RESPONSE_BYTES: usize = 16 * 1024;
const MAX_SSH_BROKER_SECONDS: u64 = 10;
const ORBSTACK_HOST_AGENT_SOCKET: &str = "/run/host-services/ssh-auth.sock";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    LocalPath,
    HttpsRemote,
    SshBrokered,
    Archive,
    Bundle,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalDirtyPolicy {
    IncludeTrackedAndUntracked,
    TrackedOnly,
    RequireClean,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveFormat {
    Tar,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AcquisitionSource {
    Local {
        path: PathBuf,
        dirty_policy: LocalDirtyPolicy,
    },
    Https {
        url: String,
        revision: String,
    },
    SshBrokered {
        display_host: String,
        opaque_handle: String,
        revision: String,
        broker_executable: PathBuf,
        broker_request: PathBuf,
    },
    Archive {
        path: PathBuf,
        format: ArchiveFormat,
    },
    Bundle {
        path: PathBuf,
    },
}

impl AcquisitionSource {
    #[must_use]
    pub const fn kind(&self) -> SourceKind {
        match self {
            Self::Local { .. } => SourceKind::LocalPath,
            Self::Https { .. } => SourceKind::HttpsRemote,
            Self::SshBrokered { .. } => SourceKind::SshBrokered,
            Self::Archive { .. } => SourceKind::Archive,
            Self::Bundle { .. } => SourceKind::Bundle,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AcquisitionLimits {
    pub max_files: usize,
    pub max_total_bytes: u64,
    pub max_file_bytes: u64,
    pub max_path_bytes: usize,
    pub max_archive_bytes: u64,
    pub max_remote_work_bytes: u64,
    pub max_git_output_bytes: usize,
    pub max_git_seconds: u64,
}

impl Default for AcquisitionLimits {
    fn default() -> Self {
        Self {
            max_files: 100_000,
            max_total_bytes: 64 * 1024 * 1024,
            max_file_bytes: 16 * 1024 * 1024,
            max_path_bytes: 1024,
            max_archive_bytes: 64 * 1024 * 1024,
            max_remote_work_bytes: 256 * 1024 * 1024,
            max_git_output_bytes: 4 * 1024 * 1024,
            max_git_seconds: 300,
        }
    }
}

impl AcquisitionLimits {
    fn validate(&self) -> Result<(), AcquisitionError> {
        if self.max_files == 0
            || self.max_total_bytes == 0
            || self.max_file_bytes == 0
            || self.max_path_bytes == 0
            || self.max_archive_bytes == 0
            || self.max_remote_work_bytes < self.max_total_bytes
            || self.max_git_output_bytes == 0
            || self.max_git_seconds == 0
            || self.max_file_bytes > self.max_total_bytes
        {
            return Err(AcquisitionError::InvalidLimits);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcquisitionRequest {
    pub source: AcquisitionSource,
    pub authority_id: String,
    pub authority_digest: String,
    pub selected_roots: Vec<String>,
    pub limits: AcquisitionLimits,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SnapshotReference {
    pub snapshot_id: String,
    pub repository_id: String,
    pub redacted_locator: String,
    pub revision: String,
    pub manifest_artifact_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrbstackPublicGitBackend {
    docker_program: PathBuf,
    image_reference: String,
    policy: RemoteBackendPolicy,
}

impl OrbstackPublicGitBackend {
    pub fn reviewed(docker_program: impl Into<PathBuf>) -> Result<Self, AcquisitionError> {
        Self::new(
            docker_program,
            ORBSTACK_PUBLIC_GIT_IMAGE_REFERENCE,
            RemoteBackendPolicy::reviewed_orbstack_macos_arm64_v1(),
        )
    }

    fn new(
        docker_program: impl Into<PathBuf>,
        image_reference: impl Into<String>,
        policy: RemoteBackendPolicy,
    ) -> Result<Self, AcquisitionError> {
        let docker_program = docker_program.into();
        let image_reference = image_reference.into();
        policy.validate()?;
        let Some((image_name, image_digest)) = image_reference.rsplit_once('@') else {
            return Err(AcquisitionError::InvalidRemoteBackend);
        };
        if policy != RemoteBackendPolicy::reviewed_orbstack_macos_arm64_v1()
            || !docker_program.is_absolute()
            || image_name != "promptectomy-remote-git"
            || image_digest != policy.image_digest
            || image_reference != ORBSTACK_PUBLIC_GIT_IMAGE_REFERENCE
        {
            return Err(AcquisitionError::InvalidRemoteBackend);
        }
        Ok(Self {
            docker_program,
            image_reference,
            policy,
        })
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ReviewedSshBroker {
    executable: PathBuf,
    executable_digest: String,
    backend: RemoteBackendPolicy,
    orbstack_host_agent: bool,
}

impl ReviewedSshBroker {
    pub fn new(
        executable: impl Into<PathBuf>,
        executable_digest: impl Into<String>,
        backend: RemoteBackendPolicy,
    ) -> Result<Self, AcquisitionError> {
        let executable = executable.into();
        let executable_digest = executable_digest.into();
        backend.validate()?;
        if !executable.is_absolute()
            || !is_digest(&executable_digest)
            || ssh_broker_executable_digest(&executable)? != executable_digest
        {
            return Err(AcquisitionError::InvalidSshBroker);
        }
        Ok(Self {
            executable,
            executable_digest,
            backend,
            orbstack_host_agent: false,
        })
    }

    pub fn with_agent_socket(
        mut self,
        upstream_agent_socket: impl Into<PathBuf>,
    ) -> Result<Self, AcquisitionError> {
        let upstream_agent_socket = upstream_agent_socket.into();
        if upstream_agent_socket != Path::new(ORBSTACK_HOST_AGENT_SOCKET) {
            return Err(AcquisitionError::InvalidSshBroker);
        }
        self.orbstack_host_agent = true;
        Ok(self)
    }
}

impl fmt::Debug for ReviewedSshBroker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReviewedSshBroker")
            .field("executable_digest", &self.executable_digest)
            .field("backend", &self.backend)
            .field("orbstack_host_agent_configured", &self.orbstack_host_agent)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug)]
pub struct Acquirer {
    storage_root: PathBuf,
    public_git_backend: Option<OrbstackPublicGitBackend>,
    ssh_broker: Option<ReviewedSshBroker>,
}

impl Acquirer {
    pub fn new(storage_root: impl Into<PathBuf>) -> Result<Self, AcquisitionError> {
        let storage_root = storage_root.into();
        snapshot::prepare_storage_root(&storage_root)?;
        Ok(Self {
            storage_root,
            public_git_backend: None,
            ssh_broker: None,
        })
    }

    #[must_use]
    pub fn with_public_git_backend(mut self, backend: OrbstackPublicGitBackend) -> Self {
        self.public_git_backend = Some(backend);
        self
    }

    #[must_use]
    pub fn with_reviewed_ssh_broker(mut self, broker: ReviewedSshBroker) -> Self {
        self.ssh_broker = Some(broker);
        self
    }

    pub fn acquire(
        &self,
        request: &AcquisitionRequest,
    ) -> Result<AcquiredSnapshot, AcquisitionError> {
        self.acquire_cancelable(request, &AtomicBool::new(false))
    }

    pub fn acquire_cancelable(
        &self,
        request: &AcquisitionRequest,
        cancelled: &AtomicBool,
    ) -> Result<AcquiredSnapshot, AcquisitionError> {
        if cancelled.load(Ordering::Acquire) {
            return Err(AcquisitionError::Cancelled);
        }
        request.limits.validate()?;
        validate_authority(request)?;
        let selected_roots = path_policy::normalize_selected_roots(
            &request.selected_roots,
            request.limits.max_path_bytes,
        )?;
        let material = match &request.source {
            AcquisitionSource::Local { path, dirty_policy } => {
                if *dirty_policy != LocalDirtyPolicy::IncludeTrackedAndUntracked {
                    return Err(AcquisitionError::LocalGitPolicyUnavailable);
                }
                snapshot::collect_local(&self.storage_root, path, &selected_roots, &request.limits)?
            }
            AcquisitionSource::Https { url, .. } => {
                git::validate_remote_source(&request.source)?;
                let backend = self
                    .public_git_backend
                    .as_ref()
                    .ok_or(AcquisitionError::RemoteGitUnavailable)?;
                Self::acquire_public_https(request, &selected_roots, url, backend, cancelled)?
            }
            AcquisitionSource::SshBrokered { .. } => {
                git::validate_remote_source(&request.source)?;
                let broker = self
                    .ssh_broker
                    .as_ref()
                    .ok_or(AcquisitionError::SshBrokerUnavailable)?;
                let backend = self
                    .public_git_backend
                    .as_ref()
                    .ok_or(AcquisitionError::RemoteGitUnavailable)?;
                Self::acquire_brokered_ssh(request, &selected_roots, broker, backend, cancelled)?
            }
            AcquisitionSource::Archive { path, format } => {
                archive::collect_archive(path, *format, &selected_roots, &request.limits)?
            }
            AcquisitionSource::Bundle { path } => {
                archive::collect_bundle(path, &selected_roots, &request.limits)?
            }
        };
        if cancelled.load(Ordering::Acquire) {
            return Err(AcquisitionError::Cancelled);
        }
        snapshot::publish(&self.storage_root, request, selected_roots, material)
    }

    fn acquire_public_https(
        request: &AcquisitionRequest,
        selected_roots: &[String],
        locator: &str,
        backend: &OrbstackPublicGitBackend,
        cancelled: &AtomicBool,
    ) -> Result<snapshot::CollectedMaterial, AcquisitionError> {
        let manifest = build_remote_git_manifest(request, backend.policy.clone())?;
        let output_tmpfs_bytes = manifest
            .max_bundle_bytes
            .checked_add(
                u64::try_from(manifest.max_output_bytes)
                    .map_err(|_| AcquisitionError::InvalidRemoteBackend)?,
            )
            .ok_or(AcquisitionError::InvalidRemoteBackend)?;
        let config = oci_remote::OciRemoteConfig {
            docker_program: backend.docker_program.clone(),
            image_reference: backend.image_reference.clone(),
            user: "65532:65532".to_owned(),
            pids_limit: 64,
            memory_bytes: 512 * 1024 * 1024,
            nano_cpus: 1_000_000_000,
            output_tmpfs_bytes,
            temp_tmpfs_bytes: 16 * 1024 * 1024,
            relay_upstream: None,
        };
        let result = oci_remote::acquire_public_https(
            &oci_remote::SystemCommandRunner,
            &config,
            &manifest,
            locator,
            cancelled,
        )
        .map_err(map_oci_error)?;
        Self::remote_material(request, selected_roots, manifest, result, None)
    }

    #[cfg(unix)]
    fn acquire_brokered_ssh(
        request: &AcquisitionRequest,
        selected_roots: &[String],
        broker: &ReviewedSshBroker,
        backend: &OrbstackPublicGitBackend,
        cancelled: &AtomicBool,
    ) -> Result<snapshot::CollectedMaterial, AcquisitionError> {
        if broker.backend != backend.policy {
            return Err(AcquisitionError::InvalidRemoteBackend);
        }
        if !broker.orbstack_host_agent {
            return Err(AcquisitionError::SshBrokerUnavailable);
        }
        let grant = Self::preflight_ssh_broker(request, broker, &SystemSshBrokerRunner, cancelled)?;
        let grant_bytes = grant
            .canonical_bytes()
            .map_err(|_| AcquisitionError::InvalidSshBroker)?;
        let manifest = build_remote_git_manifest(request, backend.policy.clone())?;
        let output_tmpfs_bytes = manifest
            .max_bundle_bytes
            .checked_add(
                u64::try_from(manifest.max_output_bytes)
                    .map_err(|_| AcquisitionError::InvalidRemoteBackend)?,
            )
            .ok_or(AcquisitionError::InvalidRemoteBackend)?;
        let config = oci_remote::OciRemoteConfig {
            docker_program: backend.docker_program.clone(),
            image_reference: backend.image_reference.clone(),
            user: "65532:65532".to_owned(),
            pids_limit: 64,
            memory_bytes: 512 * 1024 * 1024,
            nano_cpus: 1_000_000_000,
            output_tmpfs_bytes,
            temp_tmpfs_bytes: 16 * 1024 * 1024,
            relay_upstream: Some(oci_remote::RelayUpstream::OrbstackHost),
        };
        let result = oci_remote::acquire_brokered_ssh(
            &oci_remote::SystemCommandRunner,
            &config,
            &manifest,
            grant.repository(),
            grant.host_key_type(),
            grant.host_key_base64(),
            &grant_bytes,
            cancelled,
        )
        .map_err(map_oci_error)?;
        Self::remote_material(request, selected_roots, manifest, result, Some(()))
    }

    #[cfg(not(unix))]
    fn acquire_brokered_ssh(
        _: &AcquisitionRequest,
        _: &[String],
        _: &ReviewedSshBroker,
        _: &OrbstackPublicGitBackend,
        _: &AtomicBool,
    ) -> Result<snapshot::CollectedMaterial, AcquisitionError> {
        Err(AcquisitionError::GitPlatformUnsupported)
    }

    fn remote_material(
        request: &AcquisitionRequest,
        selected_roots: &[String],
        manifest: RemoteGitManifest,
        result: oci_remote::OciRemoteResult,
        broker_relay_removed: Option<()>,
    ) -> Result<snapshot::CollectedMaterial, AcquisitionError> {
        let attestation = RemoteGitAttestation {
            schema_version: REMOTE_GIT_ATTESTATION_VERSION.to_owned(),
            manifest_digest: manifest.manifest_digest.clone(),
            backend_profile: result.controls.backend_profile,
            image_digest: result.controls.image_digest.clone(),
            runner_digest: result.controls.runner_digest.clone(),
            egress_proxy_digest: result.controls.proxy_digest.clone(),
            git_binary_digest: result.git_binary_digest,
            broker: manifest.broker.clone(),
            observed_destinations: vec![EgressDestination {
                host: result.observed_destination_host,
                port: result.observed_destination_port,
            }],
            remote_work_tmpfs_bytes: result.controls.remote_work_tmpfs_bytes,
            input_tmpfs_bytes: result.controls.input_tmpfs_bytes,
            output_tmpfs_bytes: result.controls.output_tmpfs_bytes,
            temporary_tmpfs_bytes: result.controls.temporary_tmpfs_bytes,
            unaccounted_writable_data_mounts: 0,
            kernel_writable_storage_limit: result.controls.resource_limits,
            root_read_only: result.controls.root_read_only,
            no_new_privileges: result.controls.no_new_privileges,
            capabilities_dropped: result.controls.capabilities_dropped,
            worker_internal_network_only: result.controls.worker_internal_network_only,
            proxy_dual_homed: result.controls.proxy_dual_homed,
            destination_enforcement: result.controls.destination_enforcement,
            kernel_exact_destination_enforced: result.controls.kernel_exact_destination_enforced,
            worker_default_route_absent: result.controls.worker_default_route_absent,
            proxy_gateway_and_host_reachability_kernel_blocked: result
                .controls
                .proxy_gateway_and_host_reachability_kernel_blocked,
            git_execution_neutralized: ControlAttestation::Passed,
            credentials_isolated: result.controls.credentials_isolated,
            resolved_commit: result.resolved_commit,
            source_bundle_digest: remote_source_bundle_digest(&result.source_bundle),
            cleanup: RemoteCleanupAttestation {
                worker_removed: result.controls.cleanup_complete,
                proxy_removed: result.controls.cleanup_complete,
                network_removed: result.controls.cleanup_complete,
                broker_relay_removed: if manifest.broker.is_none() || broker_relay_removed.is_some()
                {
                    ControlAttestation::Passed
                } else {
                    ControlAttestation::Failed
                },
                orphan_check: result.controls.cleanup_complete,
            },
        };
        let remote = RemoteGitResult {
            source_bundle: result.source_bundle,
            attestation: attestation.clone(),
        };
        remote.validate_structure_for(&manifest)?;
        let mut material =
            archive::collect_bundle_bytes(&remote.source_bundle, selected_roots, &request.limits)?;
        material
            .redacted_locator
            .clone_from(&manifest.redacted_locator);
        material
            .source_digest
            .clone_from(&attestation.source_bundle_digest);
        material.revision.clone_from(&attestation.resolved_commit);
        material
            .path_exclusions
            .push("git_metadata_and_unselected_history".to_owned());
        material.remote_manifest = Some(manifest);
        material.remote_attestation = Some(attestation);
        Ok(material)
    }

    fn preflight_ssh_broker(
        acquisition: &AcquisitionRequest,
        broker: &ReviewedSshBroker,
        runner: &dyn SshBrokerRunner,
        cancelled: &AtomicBool,
    ) -> Result<promptectomy_ssh_agent_relay::ValidatedGrant, AcquisitionError> {
        let AcquisitionSource::SshBrokered {
            display_host,
            opaque_handle,
            broker_request,
            ..
        } = &acquisition.source
        else {
            return Err(AcquisitionError::InvalidSshBroker);
        };
        let manifest = build_remote_git_manifest(acquisition, broker.backend.clone())?;
        let binding = manifest
            .broker
            .as_ref()
            .ok_or(AcquisitionError::InvalidRemoteManifest)?;
        if binding.executable_digest != broker.executable_digest {
            return Err(AcquisitionError::SshBrokerDenied);
        }
        let (request_bytes, request) =
            load_ssh_broker_request(broker_request, display_host, opaque_handle)?;
        let relay_grant = request.relay_grant(&manifest)?;
        if crate::digest::digest_string(
            &[b"ssh-broker-request\0".as_slice(), request_bytes.as_slice()].concat(),
        ) != binding.request_digest
        {
            return Err(AcquisitionError::InvalidSshBroker);
        }
        let output = runner.run(
            &SshBrokerCommandPlan {
                program: broker.executable.clone(),
                stdin: request_bytes,
                timeout: Duration::from_secs(
                    acquisition
                        .limits
                        .max_git_seconds
                        .min(MAX_SSH_BROKER_SECONDS),
                ),
                max_output_bytes: MAX_SSH_BROKER_RESPONSE_BYTES,
            },
            cancelled,
        )?;
        if !output.success {
            return Err(AcquisitionError::SshBrokerUnavailable);
        }
        match parse_ssh_broker_response(&output.stdout, binding, &request)? {
            SshBrokerDecision::Granted => Ok(relay_grant),
            SshBrokerDecision::Denied => Err(AcquisitionError::SshBrokerDenied),
            SshBrokerDecision::Unavailable => Err(AcquisitionError::SshBrokerUnavailable),
        }
    }

    #[cfg(all(test, unix))]
    pub(crate) fn acquire_with_runner(
        &self,
        request: &AcquisitionRequest,
        runner: &dyn GitRunner,
    ) -> Result<AcquiredSnapshot, AcquisitionError> {
        request.limits.validate()?;
        validate_authority(request)?;
        let selected_roots = path_policy::normalize_selected_roots(
            &request.selected_roots,
            request.limits.max_path_bytes,
        )?;

        let material = match &request.source {
            AcquisitionSource::Local { path, dirty_policy } => {
                if *dirty_policy != LocalDirtyPolicy::IncludeTrackedAndUntracked {
                    return Err(AcquisitionError::LocalGitPolicyUnavailable);
                }
                snapshot::collect_local(&self.storage_root, path, &selected_roots, &request.limits)?
            }
            AcquisitionSource::Https { .. } | AcquisitionSource::SshBrokered { .. } => {
                git::collect_remote(
                    &self.storage_root,
                    &request.source,
                    &selected_roots,
                    &request.limits,
                    runner,
                )?
            }
            AcquisitionSource::Archive { path, format } => {
                archive::collect_archive(path, *format, &selected_roots, &request.limits)?
            }
            AcquisitionSource::Bundle { path } => {
                archive::collect_bundle(path, &selected_roots, &request.limits)?
            }
        };

        snapshot::publish(&self.storage_root, request, selected_roots, material)
    }
}

#[derive(Clone, Eq, PartialEq)]
struct SshBrokerCommandPlan {
    program: PathBuf,
    stdin: Vec<u8>,
    timeout: Duration,
    max_output_bytes: usize,
}

impl fmt::Debug for SshBrokerCommandPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SshBrokerCommandPlan")
            .field("stdin_bytes", &self.stdin.len())
            .field("timeout", &self.timeout)
            .field("max_output_bytes", &self.max_output_bytes)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SshBrokerCommandOutput {
    success: bool,
    stdout: Vec<u8>,
}

trait SshBrokerRunner: Send + Sync {
    fn run(
        &self,
        plan: &SshBrokerCommandPlan,
        cancelled: &AtomicBool,
    ) -> Result<SshBrokerCommandOutput, AcquisitionError>;
}

struct SystemSshBrokerRunner;

impl SshBrokerRunner for SystemSshBrokerRunner {
    fn run(
        &self,
        plan: &SshBrokerCommandPlan,
        cancelled: &AtomicBool,
    ) -> Result<SshBrokerCommandOutput, AcquisitionError> {
        use crate::oci_remote::CommandRunner as _;

        let output = crate::oci_remote::SystemCommandRunner
            .run(
                &crate::oci_remote::CommandPlan {
                    program: plan.program.clone(),
                    arguments: Vec::new(),
                    environment: Vec::new(),
                    stdin: plan.stdin.clone(),
                    max_output_bytes: plan.max_output_bytes,
                    timeout: plan.timeout,
                },
                cancelled,
            )
            .map_err(|error| match error {
                crate::oci_remote::OciRemoteError::CommandOutputExceeded => {
                    AcquisitionError::SshBrokerOutputExceeded
                }
                crate::oci_remote::OciRemoteError::CommandTimedOut => {
                    AcquisitionError::SshBrokerTimedOut
                }
                crate::oci_remote::OciRemoteError::Cancelled => AcquisitionError::Cancelled,
                _ => AcquisitionError::SshBrokerUnavailable,
            })?;
        Ok(SshBrokerCommandOutput {
            success: output.success,
            stdout: output.stdout,
        })
    }
}

fn map_oci_error(error: oci_remote::OciRemoteError) -> AcquisitionError {
    match error {
        oci_remote::OciRemoteError::InvalidConfiguration => AcquisitionError::InvalidRemoteBackend,
        oci_remote::OciRemoteError::InvalidRequest => AcquisitionError::InvalidRemoteManifest,
        oci_remote::OciRemoteError::CommandStart | oci_remote::OciRemoteError::CommandFailed => {
            AcquisitionError::RemoteRuntimeUnavailable
        }
        oci_remote::OciRemoteError::CommandOutputExceeded => AcquisitionError::GitOutputExceeded,
        oci_remote::OciRemoteError::CommandTimedOut => AcquisitionError::GitTimedOut,
        oci_remote::OciRemoteError::Cancelled => AcquisitionError::Cancelled,
        oci_remote::OciRemoteError::ImageDigestMismatch
        | oci_remote::OciRemoteError::BinaryDigestMismatch
        | oci_remote::OciRemoteError::ControlMismatch
        | oci_remote::OciRemoteError::InvalidOutput
        | oci_remote::OciRemoteError::CleanupFailed => AcquisitionError::InvalidRemoteAttestation,
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum AcquisitionError {
    #[error("the acquisition authority is invalid")]
    InvalidAuthority,
    #[error("the acquisition quotas are invalid")]
    InvalidLimits,
    #[error("the acquisition storage root is not a private directory")]
    UnsafeStorageRoot,
    #[error("private acquisition storage is unsupported on this platform")]
    StoragePermissionUnsupported,
    #[error("the source locator is not allowed by acquisition policy")]
    LocatorDenied,
    #[error("the requested source revision is invalid")]
    InvalidRevision,
    #[error("the selected source root is invalid")]
    InvalidSelectedRoot,
    #[error("the source path is not a supported regular path")]
    InvalidSourcePath,
    #[error("the source contains a path that is unsafe or unsupported")]
    UnsafePath,
    #[error("the source contains duplicate or colliding paths")]
    PathCollision,
    #[error("the source contains a symlink, hardlink, device, or unsupported file type")]
    UnsupportedFileType,
    #[error("the source changed while the immutable snapshot was being created")]
    SourceChanged,
    #[error("the source exceeds the declared file count quota")]
    FileCountExceeded,
    #[error("the selected source roots contain no supported files")]
    EmptySelection,
    #[error("the source exceeds the declared byte quota")]
    TotalBytesExceeded,
    #[error("a source file exceeds the declared per-file quota")]
    FileBytesExceeded,
    #[error("the archive exceeds the declared input quota")]
    ArchiveBytesExceeded,
    #[error("the archive format or header is unsupported")]
    UnsupportedArchive,
    #[error("the archive checksum is invalid")]
    ArchiveChecksumMismatch,
    #[error("the source bundle is malformed or has an invalid digest")]
    InvalidBundle,
    #[error("the requested local Git dirty-state policy is not implemented")]
    LocalGitPolicyUnavailable,
    #[error("the approved SSH broker request is invalid")]
    InvalidSshBroker,
    #[error("the reviewed SSH broker is unavailable")]
    SshBrokerUnavailable,
    #[error("the reviewed SSH broker denied the scoped request")]
    SshBrokerDenied,
    #[error("the reviewed SSH broker response is invalid")]
    InvalidSshBrokerResponse,
    #[error("the reviewed SSH broker exceeded its output bound")]
    SshBrokerOutputExceeded,
    #[error("the reviewed SSH broker exceeded its time bound")]
    SshBrokerTimedOut,
    #[error("the approved SSH broker relay has not been accepted for this backend")]
    SshBrokerRelayUnavailable,
    #[error("Git could not be started inside the acquisition boundary")]
    GitStartFailed,
    #[error("Git exceeded the declared runtime quota")]
    GitTimedOut,
    #[error("Git exceeded the declared output quota")]
    GitOutputExceeded,
    #[error("Git failed without exposing protected process output")]
    GitFailed,
    #[error("Git returned an invalid immutable revision or inventory")]
    InvalidGitOutput,
    #[error("remote Git acquisition is unsupported on this platform")]
    GitPlatformUnsupported,
    #[error("remote Git acquisition requires the bounded broker integration")]
    RemoteGitUnavailable,
    #[error("the remote Git backend configuration is invalid")]
    InvalidRemoteBackend,
    #[error("the accepted remote OCI runtime is unavailable")]
    RemoteRuntimeUnavailable,
    #[error("the acquisition was cancelled")]
    Cancelled,
    #[error("the remote Git acquisition manifest is invalid")]
    InvalidRemoteManifest,
    #[error("the remote Git acquisition attestation is invalid")]
    InvalidRemoteAttestation,
    #[error("the remote Git source bundle exceeds its declared bound or digest")]
    RemoteBundleExceeded,
    #[error("the snapshot could not be published safely")]
    SnapshotPublishFailed,
    #[error("the snapshot bytes failed integrity verification")]
    SnapshotIntegrityFailed,
}

pub(crate) fn validate_authority(request: &AcquisitionRequest) -> Result<(), AcquisitionError> {
    if !request.authority_id.starts_with("auth_")
        || request.authority_id.len() > 128
        || !is_digest(&request.authority_digest)
    {
        return Err(AcquisitionError::InvalidAuthority);
    }
    Ok(())
}

pub(crate) fn is_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn read_bounded(
    path: &Path,
    limit: u64,
    error: AcquisitionError,
) -> Result<Vec<u8>, AcquisitionError> {
    let (first, _) = read_regular_once(path, limit, error)?;
    let (second, _) = read_regular_once(path, limit, error)?;
    if first != second {
        return Err(AcquisitionError::SourceChanged);
    }
    Ok(first)
}

fn read_regular_once(
    path: &Path,
    limit: u64,
    quota_error: AcquisitionError,
) -> Result<(Vec<u8>, Metadata), AcquisitionError> {
    let before = std::fs::symlink_metadata(path).map_err(|_| AcquisitionError::SourceChanged)?;
    if !before.file_type().is_file() || before.file_type().is_symlink() {
        return Err(AcquisitionError::InvalidSourcePath);
    }
    if has_unsupported_hardlink(&before) {
        return Err(AcquisitionError::UnsupportedFileType);
    }
    if before.len() > limit {
        return Err(quota_error);
    }
    let mut file = File::open(path).map_err(|_| AcquisitionError::SourceChanged)?;
    let opened = file
        .metadata()
        .map_err(|_| AcquisitionError::SourceChanged)?;
    if !same_file(&before, &opened) {
        return Err(AcquisitionError::SourceChanged);
    }
    let mut bytes =
        Vec::with_capacity(usize::try_from(before.len().min(limit)).map_err(|_| quota_error)?);
    file.by_ref()
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| AcquisitionError::SourceChanged)?;
    let Ok(length) = u64::try_from(bytes.len()) else {
        return Err(quota_error);
    };
    if length > limit {
        return Err(quota_error);
    }
    let after_handle = file
        .metadata()
        .map_err(|_| AcquisitionError::SourceChanged)?;
    let after_path =
        std::fs::symlink_metadata(path).map_err(|_| AcquisitionError::SourceChanged)?;
    if !same_file(&opened, &after_handle)
        || !same_file(&opened, &after_path)
        || after_handle.len() != length
    {
        return Err(AcquisitionError::SourceChanged);
    }
    Ok((bytes, opened))
}

#[cfg(unix)]
fn has_unsupported_hardlink(metadata: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    metadata.nlink() > 1
}

#[cfg(not(unix))]
fn has_unsupported_hardlink(_: &Metadata) -> bool {
    false
}

#[cfg(unix)]
fn same_file(left: &Metadata, right: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
}

#[cfg(not(unix))]
fn same_file(left: &Metadata, right: &Metadata) -> bool {
    left.len() == right.len() && left.modified().ok() == right.modified().ok()
}

#[cfg(test)]
mod tests;
