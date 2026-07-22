use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::digest::digest_string;
use crate::git::{
    canonical_https_host, validate_allowed_remote_host, validate_https, validate_revision,
};
use crate::{
    AcquisitionError, AcquisitionRequest, AcquisitionSource, SourceKind, is_digest, read_bounded,
    validate_authority,
};

pub const REMOTE_GIT_MANIFEST_VERSION: &str = "promptectomy.remote-git-manifest.v2";
pub const REMOTE_GIT_ATTESTATION_VERSION: &str = "promptectomy.remote-git-attestation.v2";
pub const SSH_BROKER_REQUEST_VERSION: &str = promptectomy_ssh_agent_relay::GRANT_VERSION;
pub const SSH_BROKER_RESPONSE_VERSION: &str = "promptectomy.ssh-broker-response.v1";
pub const ORBSTACK_PUBLIC_GIT_IMAGE_DIGEST: &str =
    "sha256:826575ce5fd3b427e4522d64fe13204a174836cd7a052361ac7dee51d42b182e";
pub const ORBSTACK_PUBLIC_GIT_RUNNER_DIGEST: &str =
    "sha256:9eebe416b538fc6602313e0a306c8d25b8eac5d990d7b31c109ecc30577dd3fc";
pub const ORBSTACK_PUBLIC_GIT_PROXY_DIGEST: &str =
    "sha256:9291a931763138b51888bb2393fc3e2bdc28c9df0d31e7eb8a7ae55db39f026b";
pub const ORBSTACK_PUBLIC_GIT_RELAY_DIGEST: &str =
    "sha256:399c89fce01f0c87a95b09ca5081ae5399eb2446cd31e6d400521c5ec4b183c7";
pub const ORBSTACK_PUBLIC_GIT_IMAGE_REFERENCE: &str = concat!(
    "promptectomy-remote-git@",
    "sha256:826575ce5fd3b427e4522d64fe13204a174836cd7a052361ac7dee51d42b182e"
);
const MAX_BROKER_EXECUTABLE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_BROKER_REQUEST_BYTES: u64 = 64 * 1024;
const REMOTE_MAX_TOTAL_BYTES: u64 = 32 * 1024 * 1024;
const REMOTE_MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;
const REMOTE_MAX_WORK_BYTES: u64 = 256 * 1024 * 1024;
const REMOTE_MAX_BUNDLE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteBackendProfile {
    OrbstackMacosArm64V1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteBackendPolicy {
    pub profile: RemoteBackendProfile,
    pub image_digest: String,
    pub runner_digest: String,
    pub egress_proxy_digest: String,
    pub ssh_agent_relay_digest: String,
}

impl RemoteBackendPolicy {
    #[must_use]
    pub fn reviewed_orbstack_macos_arm64_v1() -> Self {
        Self {
            profile: RemoteBackendProfile::OrbstackMacosArm64V1,
            image_digest: ORBSTACK_PUBLIC_GIT_IMAGE_DIGEST.to_owned(),
            runner_digest: ORBSTACK_PUBLIC_GIT_RUNNER_DIGEST.to_owned(),
            egress_proxy_digest: ORBSTACK_PUBLIC_GIT_PROXY_DIGEST.to_owned(),
            ssh_agent_relay_digest: ORBSTACK_PUBLIC_GIT_RELAY_DIGEST.to_owned(),
        }
    }

    pub(crate) fn validate(&self) -> Result<(), AcquisitionError> {
        if !is_digest(&self.image_digest)
            || !is_digest(&self.runner_digest)
            || !is_digest(&self.egress_proxy_digest)
            || !is_digest(&self.ssh_agent_relay_digest)
        {
            return Err(AcquisitionError::InvalidRemoteManifest);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EgressDestination {
    pub host: String,
    pub port: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerBinding {
    pub handle_digest: String,
    pub executable_digest: String,
    pub request_digest: String,
    pub repository_digest: String,
    pub host_key_digest: String,
    pub selected_public_key_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SshBrokerGrantRequest {
    pub schema_version: String,
    pub opaque_handle: String,
    pub display_host: String,
    pub port: u16,
    pub username: String,
    pub repository: String,
    pub revision: String,
    pub host_key_type: String,
    pub host_key_base64: String,
    pub host_key_sha256: String,
    pub selected_public_key_base64: String,
    pub credential_source: String,
    pub wall_time_seconds: u64,
    pub max_connections: u8,
    pub max_frame_bytes: usize,
    pub max_signatures: u8,
}

impl SshBrokerGrantRequest {
    fn validate_for(
        &self,
        display_host: &str,
        opaque_handle: &str,
    ) -> Result<(), AcquisitionError> {
        if self.schema_version != SSH_BROKER_REQUEST_VERSION
            || self.opaque_handle != opaque_handle
            || self.display_host != display_host
            || self.port != 22
            || self.username != "git"
            || self.credential_source != "selected_ssh_agent"
            || !valid_repository_path(&self.repository)
        {
            return Err(AcquisitionError::InvalidSshBroker);
        }
        promptectomy_ssh_agent_relay::RelayGrant {
            schema_version: self.schema_version.clone(),
            opaque_handle: self.opaque_handle.clone(),
            display_host: self.display_host.clone(),
            port: self.port,
            username: self.username.clone(),
            repository: self.repository.clone(),
            revision: self.revision.clone(),
            host_key_type: self.host_key_type.clone(),
            host_key_base64: self.host_key_base64.clone(),
            host_key_sha256: self.host_key_sha256.clone(),
            selected_public_key_base64: self.selected_public_key_base64.clone(),
            manifest_digest:
                "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                    .to_owned(),
            credential_source: self.credential_source.clone(),
            wall_time_seconds: self.wall_time_seconds,
            max_connections: self.max_connections,
            max_frame_bytes: self.max_frame_bytes,
            max_signatures: self.max_signatures,
        }
        .validate()
        .map_err(|_| AcquisitionError::InvalidSshBroker)?;
        Ok(())
    }

    #[cfg(unix)]
    pub(crate) fn relay_grant(
        &self,
        manifest: &RemoteGitManifest,
    ) -> Result<promptectomy_ssh_agent_relay::ValidatedGrant, AcquisitionError> {
        if self.revision != manifest.revision
            || self.wall_time_seconds != manifest.wall_time_seconds.min(300)
            || self.max_connections != 1
            || self.max_frame_bytes != 256 * 1024
            || self.max_signatures != 4
        {
            return Err(AcquisitionError::InvalidSshBroker);
        }
        promptectomy_ssh_agent_relay::RelayGrant {
            schema_version: self.schema_version.clone(),
            opaque_handle: self.opaque_handle.clone(),
            display_host: self.display_host.clone(),
            port: self.port,
            username: self.username.clone(),
            repository: self.repository.clone(),
            revision: self.revision.clone(),
            host_key_type: self.host_key_type.clone(),
            host_key_base64: self.host_key_base64.clone(),
            host_key_sha256: self.host_key_sha256.clone(),
            selected_public_key_base64: self.selected_public_key_base64.clone(),
            manifest_digest: manifest.manifest_digest.clone(),
            credential_source: self.credential_source.clone(),
            wall_time_seconds: self.wall_time_seconds,
            max_connections: self.max_connections,
            max_frame_bytes: self.max_frame_bytes,
            max_signatures: self.max_signatures,
        }
        .validate()
        .map_err(|_| AcquisitionError::InvalidSshBroker)
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SshBrokerDecision {
    Granted,
    Denied,
    Unavailable,
}

#[cfg(unix)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SshBrokerGrantResponse {
    pub schema_version: String,
    pub request_digest: String,
    pub executable_digest: String,
    pub handle_digest: String,
    pub decision: SshBrokerDecision,
    pub confirmed_host_key_sha256: Option<String>,
}

#[cfg(unix)]
impl SshBrokerGrantResponse {
    pub(crate) fn validate_for(
        &self,
        binding: &BrokerBinding,
        request: &SshBrokerGrantRequest,
    ) -> Result<(), AcquisitionError> {
        if self.schema_version != SSH_BROKER_RESPONSE_VERSION
            || self.request_digest != binding.request_digest
            || self.executable_digest != binding.executable_digest
            || self.handle_digest != binding.handle_digest
            || match self.decision {
                SshBrokerDecision::Granted => {
                    self.confirmed_host_key_sha256.as_deref()
                        != Some(request.host_key_sha256.as_str())
                }
                SshBrokerDecision::Denied | SshBrokerDecision::Unavailable => {
                    self.confirmed_host_key_sha256.is_some()
                }
            }
        {
            return Err(AcquisitionError::InvalidSshBrokerResponse);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteCredentialPolicy {
    None,
    SshAgentBrokerGrant,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlAttestation {
    Passed,
    Failed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteDestinationEnforcement {
    ApplicationConnectProxy,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteGitManifest {
    pub schema_version: String,
    pub source_kind: SourceKind,
    pub manifest_digest: String,
    pub authority_digest: String,
    pub locator_digest: String,
    pub redacted_locator: String,
    pub destination: EgressDestination,
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
    pub credential_policy: RemoteCredentialPolicy,
    pub broker: Option<BrokerBinding>,
    pub backend: RemoteBackendPolicy,
}

impl RemoteGitManifest {
    #[must_use]
    pub fn computed_digest(&self) -> String {
        let mut unsigned = self.clone();
        unsigned.manifest_digest.clear();
        let encoded = serde_jcs::to_vec(&unsigned).expect("remote manifest serializes");
        domain_digest("remote-git-manifest", &encoded)
    }

    pub fn validate(&self) -> Result<(), AcquisitionError> {
        if self.schema_version != REMOTE_GIT_MANIFEST_VERSION
            || self.manifest_digest != self.computed_digest()
            || !is_digest(&self.authority_digest)
            || !is_digest(&self.locator_digest)
            || self.checkout_policy != "no_checkout"
            || self.egress_policy != "application_connect_proxy_exact_destination"
            || self.max_files == 0
            || self.max_total_bytes == 0
            || self.max_file_bytes == 0
            || self.max_file_bytes > self.max_total_bytes
            || self.max_path_bytes == 0
            || self.max_remote_work_bytes < self.max_total_bytes
            || self.max_bundle_bytes == 0
            || self.max_bundle_bytes > self.max_remote_work_bytes
            || self.max_output_bytes == 0
            || self.wall_time_seconds == 0
        {
            return Err(AcquisitionError::InvalidRemoteManifest);
        }
        self.backend.validate()?;
        validate_revision(&self.revision)?;
        let normalized_roots = crate::path_policy::normalize_selected_roots(
            &self.selected_roots,
            self.max_path_bytes,
        )?;
        if normalized_roots != self.selected_roots {
            return Err(AcquisitionError::InvalidRemoteManifest);
        }
        let host = validate_allowed_remote_host(&self.destination.host)
            .map_err(|_| AcquisitionError::InvalidRemoteManifest)?;
        if host != self.destination.host {
            return Err(AcquisitionError::InvalidRemoteManifest);
        }
        match (self.source_kind, self.credential_policy, &self.broker) {
            (SourceKind::HttpsRemote, RemoteCredentialPolicy::None, None)
                if self.destination.port == 443
                    && self.redacted_locator
                        == format!("https://{}/<redacted>", self.destination.host) => {}
            (
                SourceKind::SshBrokered,
                RemoteCredentialPolicy::SshAgentBrokerGrant,
                Some(binding),
            ) if self.destination.port == 22
                && self.redacted_locator
                    == format!("ssh://{}/<redacted>", self.destination.host)
                && is_digest(&binding.handle_digest)
                && is_digest(&binding.executable_digest)
                && is_digest(&binding.request_digest)
                && is_digest(&binding.repository_digest)
                && is_digest(&binding.host_key_digest)
                && is_digest(&binding.selected_public_key_digest) => {}
            _ => return Err(AcquisitionError::InvalidRemoteManifest),
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteCleanupAttestation {
    pub worker_removed: ControlAttestation,
    pub proxy_removed: ControlAttestation,
    pub network_removed: ControlAttestation,
    pub broker_relay_removed: ControlAttestation,
    pub orphan_check: ControlAttestation,
}

impl RemoteCleanupAttestation {
    fn accepted(&self) -> bool {
        [
            self.worker_removed,
            self.proxy_removed,
            self.network_removed,
            self.broker_relay_removed,
            self.orphan_check,
        ]
        .into_iter()
        .all(|value| value == ControlAttestation::Passed)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteGitAttestation {
    pub schema_version: String,
    pub manifest_digest: String,
    pub backend_profile: RemoteBackendProfile,
    pub image_digest: String,
    pub runner_digest: String,
    pub egress_proxy_digest: String,
    pub git_binary_digest: String,
    pub broker: Option<BrokerBinding>,
    pub observed_destinations: Vec<EgressDestination>,
    pub remote_work_tmpfs_bytes: u64,
    pub input_tmpfs_bytes: u64,
    pub output_tmpfs_bytes: u64,
    pub temporary_tmpfs_bytes: u64,
    pub unaccounted_writable_data_mounts: usize,
    pub kernel_writable_storage_limit: ControlAttestation,
    pub root_read_only: ControlAttestation,
    pub no_new_privileges: ControlAttestation,
    pub capabilities_dropped: ControlAttestation,
    pub worker_internal_network_only: ControlAttestation,
    pub proxy_dual_homed: ControlAttestation,
    pub destination_enforcement: RemoteDestinationEnforcement,
    pub kernel_exact_destination_enforced: bool,
    pub worker_default_route_absent: ControlAttestation,
    pub proxy_gateway_and_host_reachability_kernel_blocked: bool,
    pub git_execution_neutralized: ControlAttestation,
    pub credentials_isolated: ControlAttestation,
    pub resolved_commit: String,
    pub source_bundle_digest: String,
    pub cleanup: RemoteCleanupAttestation,
}

impl RemoteGitAttestation {
    pub(crate) fn validate_structure_for(
        &self,
        manifest: &RemoteGitManifest,
    ) -> Result<(), AcquisitionError> {
        manifest.validate()?;
        if self.schema_version != REMOTE_GIT_ATTESTATION_VERSION
            || self.manifest_digest != manifest.manifest_digest
            || self.backend_profile != manifest.backend.profile
            || self.image_digest != manifest.backend.image_digest
            || self.runner_digest != manifest.backend.runner_digest
            || self.egress_proxy_digest != manifest.backend.egress_proxy_digest
            || !is_digest(&self.git_binary_digest)
            || self.broker != manifest.broker
            || self.observed_destinations != [manifest.destination.clone()]
            || self.remote_work_tmpfs_bytes != manifest.max_remote_work_bytes
            || !(128 * 1024..=1024 * 1024).contains(&self.input_tmpfs_bytes)
            || self.output_tmpfs_bytes
                < manifest
                    .max_bundle_bytes
                    .saturating_add(u64::try_from(manifest.max_output_bytes).unwrap_or(u64::MAX))
            || self.output_tmpfs_bytes > 1024 * 1024 * 1024
            || !(4 * 1024 * 1024..=64 * 1024 * 1024).contains(&self.temporary_tmpfs_bytes)
            || self.unaccounted_writable_data_mounts != 0
            || self.kernel_writable_storage_limit != ControlAttestation::Passed
            || self.root_read_only != ControlAttestation::Passed
            || self.no_new_privileges != ControlAttestation::Passed
            || self.capabilities_dropped != ControlAttestation::Passed
            || self.worker_internal_network_only != ControlAttestation::Passed
            || self.proxy_dual_homed != ControlAttestation::Passed
            || self.destination_enforcement != RemoteDestinationEnforcement::ApplicationConnectProxy
            || self.kernel_exact_destination_enforced
            || self.worker_default_route_absent != ControlAttestation::Passed
            || self.proxy_gateway_and_host_reachability_kernel_blocked
            || self.git_execution_neutralized != ControlAttestation::Passed
            || self.credentials_isolated != ControlAttestation::Passed
            || !valid_object_id(&self.resolved_commit)
            || !is_digest(&self.source_bundle_digest)
            || !self.cleanup.accepted()
        {
            return Err(AcquisitionError::InvalidRemoteAttestation);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RemoteGitResult {
    pub source_bundle: Vec<u8>,
    pub attestation: RemoteGitAttestation,
}

impl RemoteGitResult {
    pub(crate) fn validate_structure_for(
        &self,
        manifest: &RemoteGitManifest,
    ) -> Result<(), AcquisitionError> {
        manifest.validate()?;
        let size = u64::try_from(self.source_bundle.len())
            .map_err(|_| AcquisitionError::RemoteBundleExceeded)?;
        if size > manifest.max_bundle_bytes
            || domain_digest("remote-source-bundle", &self.source_bundle)
                != self.attestation.source_bundle_digest
        {
            return Err(AcquisitionError::RemoteBundleExceeded);
        }
        self.attestation.validate_structure_for(manifest)
    }
}

pub fn build_remote_git_manifest(
    request: &AcquisitionRequest,
    backend: RemoteBackendPolicy,
) -> Result<RemoteGitManifest, AcquisitionError> {
    request.limits.validate()?;
    validate_authority(request)?;
    crate::git::validate_remote_source(&request.source)?;
    backend.validate()?;
    let selected_roots = crate::path_policy::normalize_selected_roots(
        &request.selected_roots,
        request.limits.max_path_bytes,
    )?;
    let (source_kind, locator_digest, redacted_locator, destination, revision, credential, broker) =
        match &request.source {
            AcquisitionSource::Https { url, revision } => {
                validate_revision(revision)?;
                let (_, redacted_locator) = validate_https(url)?;
                let host = canonical_https_host(url)?;
                (
                    SourceKind::HttpsRemote,
                    domain_digest("remote-locator", url.as_bytes()),
                    redacted_locator,
                    EgressDestination { host, port: 443 },
                    revision.clone(),
                    RemoteCredentialPolicy::None,
                    None,
                )
            }
            AcquisitionSource::SshBrokered {
                display_host,
                opaque_handle,
                revision,
                broker_executable,
                broker_request,
            } => {
                validate_revision(revision)?;
                let host = validate_allowed_remote_host(display_host)
                    .map_err(|_| AcquisitionError::InvalidSshBroker)?;
                let binding = broker_binding(
                    display_host,
                    opaque_handle,
                    broker_executable,
                    broker_request,
                )?;
                (
                    SourceKind::SshBrokered,
                    domain_digest("remote-locator", opaque_handle.as_bytes()),
                    format!("ssh://{host}/<redacted>"),
                    EgressDestination { host, port: 22 },
                    revision.clone(),
                    RemoteCredentialPolicy::SshAgentBrokerGrant,
                    Some(binding),
                )
            }
            _ => return Err(AcquisitionError::LocatorDenied),
        };
    let mut manifest = RemoteGitManifest {
        schema_version: REMOTE_GIT_MANIFEST_VERSION.to_owned(),
        source_kind,
        manifest_digest: String::new(),
        authority_digest: request.authority_digest.clone(),
        locator_digest,
        redacted_locator,
        destination,
        revision,
        selected_roots,
        max_files: request.limits.max_files,
        max_total_bytes: request.limits.max_total_bytes.min(REMOTE_MAX_TOTAL_BYTES),
        max_file_bytes: request
            .limits
            .max_file_bytes
            .min(request.limits.max_total_bytes)
            .min(REMOTE_MAX_FILE_BYTES),
        max_path_bytes: request.limits.max_path_bytes,
        max_remote_work_bytes: request
            .limits
            .max_remote_work_bytes
            .min(REMOTE_MAX_WORK_BYTES),
        max_bundle_bytes: request
            .limits
            .max_archive_bytes
            .min(REMOTE_MAX_BUNDLE_BYTES),
        max_output_bytes: request.limits.max_git_output_bytes,
        wall_time_seconds: request.limits.max_git_seconds,
        checkout_policy: "no_checkout".to_owned(),
        egress_policy: "application_connect_proxy_exact_destination".to_owned(),
        credential_policy: credential,
        broker,
        backend,
    };
    manifest.manifest_digest = manifest.computed_digest();
    manifest.validate()?;
    Ok(manifest)
}

fn broker_binding(
    display_host: &str,
    opaque_handle: &str,
    executable: &Path,
    request: &Path,
) -> Result<BrokerBinding, AcquisitionError> {
    if opaque_handle.is_empty()
        || opaque_handle.len() > 128
        || !opaque_handle
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(AcquisitionError::InvalidSshBroker);
    }
    let executable_digest = ssh_broker_executable_digest(executable)?;
    let (request_bytes, request) = load_ssh_broker_request(request, display_host, opaque_handle)?;
    Ok(BrokerBinding {
        handle_digest: domain_digest("ssh-broker-handle", opaque_handle.as_bytes()),
        executable_digest,
        request_digest: domain_digest("ssh-broker-request", &request_bytes),
        repository_digest: domain_digest("ssh-repository", request.repository.as_bytes()),
        host_key_digest: domain_digest(
            "ssh-host-key",
            format!("{} {}", request.host_key_type, request.host_key_base64).as_bytes(),
        ),
        selected_public_key_digest: domain_digest(
            "ssh-selected-public-key",
            request.selected_public_key_base64.as_bytes(),
        ),
    })
}

pub(crate) fn ssh_broker_executable_digest(path: &Path) -> Result<String, AcquisitionError> {
    let bytes = read_bounded(
        path,
        MAX_BROKER_EXECUTABLE_BYTES,
        AcquisitionError::InvalidSshBroker,
    )?;
    Ok(domain_digest("ssh-broker-executable", &bytes))
}

pub(crate) fn load_ssh_broker_request(
    path: &Path,
    display_host: &str,
    opaque_handle: &str,
) -> Result<(Vec<u8>, SshBrokerGrantRequest), AcquisitionError> {
    let bytes = read_bounded(
        path,
        MAX_BROKER_REQUEST_BYTES,
        AcquisitionError::InvalidSshBroker,
    )?;
    let request: SshBrokerGrantRequest =
        serde_json::from_slice(&bytes).map_err(|_| AcquisitionError::InvalidSshBroker)?;
    request.validate_for(display_host, opaque_handle)?;
    if serde_jcs::to_vec(&request).map_err(|_| AcquisitionError::InvalidSshBroker)? != bytes {
        return Err(AcquisitionError::InvalidSshBroker);
    }
    Ok((bytes, request))
}

#[cfg(unix)]
pub(crate) fn parse_ssh_broker_response(
    bytes: &[u8],
    binding: &BrokerBinding,
    request: &SshBrokerGrantRequest,
) -> Result<SshBrokerDecision, AcquisitionError> {
    let response: SshBrokerGrantResponse =
        serde_json::from_slice(bytes).map_err(|_| AcquisitionError::InvalidSshBrokerResponse)?;
    response.validate_for(binding, request)?;
    if serde_jcs::to_vec(&response).map_err(|_| AcquisitionError::InvalidSshBrokerResponse)?
        != bytes
    {
        return Err(AcquisitionError::InvalidSshBrokerResponse);
    }
    Ok(response.decision)
}

fn valid_repository_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value.is_ascii()
        && !value.starts_with(['/', '-'])
        && !value.contains(['?', '#', '\\', '%'])
        && value.split('/').all(|component| {
            !component.is_empty()
                && component != "."
                && component != ".."
                && component.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'~')
                })
        })
}

fn domain_digest(domain: &str, value: &[u8]) -> String {
    let mut payload = Vec::with_capacity(domain.len() + value.len() + 1);
    payload.extend_from_slice(domain.as_bytes());
    payload.push(0);
    payload.extend_from_slice(value);
    digest_string(&payload)
}

pub(crate) fn remote_source_bundle_digest(value: &[u8]) -> String {
    domain_digest("remote-source-bundle", value)
}

fn valid_object_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}
