mod archive;
mod digest;
mod git;
mod path_policy;
mod snapshot;

use std::fs::{File, Metadata};
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use git::{GitCommandPlan, GitOutput, GitRunner, SystemGitRunner, plan_git_clone};
pub use snapshot::{AcquiredSnapshot, SnapshotReceipt};

pub const ACQUISITION_PROTOCOL_VERSION: &str = "phase4-acquisition-1";

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
    pub max_git_output_bytes: usize,
    pub max_git_seconds: u64,
}

impl Default for AcquisitionLimits {
    fn default() -> Self {
        Self {
            max_files: 100_000,
            max_total_bytes: 512 * 1024 * 1024,
            max_file_bytes: 64 * 1024 * 1024,
            max_path_bytes: 1024,
            max_archive_bytes: 512 * 1024 * 1024,
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

#[derive(Clone, Debug)]
pub struct Acquirer {
    storage_root: PathBuf,
}

impl Acquirer {
    pub fn new(storage_root: impl Into<PathBuf>) -> Result<Self, AcquisitionError> {
        let storage_root = storage_root.into();
        snapshot::prepare_storage_root(&storage_root)?;
        Ok(Self { storage_root })
    }

    pub fn acquire(
        &self,
        request: &AcquisitionRequest,
    ) -> Result<AcquiredSnapshot, AcquisitionError> {
        if matches!(
            request.source,
            AcquisitionSource::Https { .. } | AcquisitionSource::SshBrokered { .. }
        ) {
            return Err(AcquisitionError::RemoteGitUnavailable);
        }
        self.acquire_with_runner(request, &SystemGitRunner)
    }

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
    #[error("the snapshot could not be published safely")]
    SnapshotPublishFailed,
    #[error("the snapshot bytes failed integrity verification")]
    SnapshotIntegrityFailed,
}

fn validate_authority(request: &AcquisitionRequest) -> Result<(), AcquisitionError> {
    if !request.authority_id.starts_with("auth_")
        || request.authority_id.len() > 128
        || !is_digest(&request.authority_digest)
    {
        return Err(AcquisitionError::InvalidAuthority);
    }
    Ok(())
}

fn is_digest(value: &str) -> bool {
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
