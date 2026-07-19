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

pub const REMOTE_GIT_MANIFEST_VERSION: &str = "promptectomy.remote-git-manifest.v1";
pub const REMOTE_GIT_ATTESTATION_VERSION: &str = "promptectomy.remote-git-attestation.v1";
const MAX_BROKER_EXECUTABLE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_BROKER_REQUEST_BYTES: u64 = 64 * 1024;

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
}

impl RemoteBackendPolicy {
    fn validate(&self) -> Result<(), AcquisitionError> {
        if !is_digest(&self.image_digest)
            || !is_digest(&self.runner_digest)
            || !is_digest(&self.egress_proxy_digest)
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
            || self.egress_policy != "exact_destination_only"
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
                && is_digest(&binding.request_digest) => {}
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
    #[cfg(test)]
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
    pub writable_mount_limit_bytes: u64,
    pub unaccounted_writable_mounts: usize,
    pub kernel_disk_limit: ControlAttestation,
    pub root_read_only: ControlAttestation,
    pub exact_egress_only: ControlAttestation,
    pub git_execution_neutralized: ControlAttestation,
    pub credentials_isolated: ControlAttestation,
    pub resolved_commit: String,
    pub source_bundle_digest: String,
    pub cleanup: RemoteCleanupAttestation,
}

impl RemoteGitAttestation {
    #[cfg(test)]
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
            || self.writable_mount_limit_bytes != manifest.max_remote_work_bytes
            || self.unaccounted_writable_mounts != 0
            || self.kernel_disk_limit != ControlAttestation::Passed
            || self.root_read_only != ControlAttestation::Passed
            || self.exact_egress_only != ControlAttestation::Passed
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

#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RemoteGitResult {
    pub source_bundle: Vec<u8>,
    pub attestation: RemoteGitAttestation,
}

#[cfg(test)]
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
                let binding = broker_binding(opaque_handle, broker_executable, broker_request)?;
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
        max_total_bytes: request.limits.max_total_bytes,
        max_file_bytes: request.limits.max_file_bytes,
        max_path_bytes: request.limits.max_path_bytes,
        max_remote_work_bytes: request.limits.max_remote_work_bytes,
        max_bundle_bytes: request.limits.max_archive_bytes,
        max_output_bytes: request.limits.max_git_output_bytes,
        wall_time_seconds: request.limits.max_git_seconds,
        checkout_policy: "no_checkout".to_owned(),
        egress_policy: "exact_destination_only".to_owned(),
        credential_policy: credential,
        broker,
        backend,
    };
    manifest.manifest_digest = manifest.computed_digest();
    manifest.validate()?;
    Ok(manifest)
}

fn broker_binding(
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
    let executable_bytes = read_bounded(
        executable,
        MAX_BROKER_EXECUTABLE_BYTES,
        AcquisitionError::InvalidSshBroker,
    )?;
    let request_bytes = read_bounded(
        request,
        MAX_BROKER_REQUEST_BYTES,
        AcquisitionError::InvalidSshBroker,
    )?;
    Ok(BrokerBinding {
        handle_digest: domain_digest("ssh-broker-handle", opaque_handle.as_bytes()),
        executable_digest: domain_digest("ssh-broker-executable", &executable_bytes),
        request_digest: domain_digest("ssh-broker-request", &request_bytes),
    })
}

fn domain_digest(domain: &str, value: &[u8]) -> String {
    let mut payload = Vec::with_capacity(domain.len() + value.len() + 1);
    payload.extend_from_slice(domain.as_bytes());
    payload.push(0);
    payload.extend_from_slice(value);
    digest_string(&payload)
}

#[cfg(test)]
fn valid_object_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}
