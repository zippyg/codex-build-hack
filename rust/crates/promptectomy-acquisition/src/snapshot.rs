use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::digest::{digest_string, hex, sha256};
use crate::path_policy::{
    insert_collision_key, may_contain_selected, normalize_filesystem_relative, selected,
};
use crate::{
    ACQUISITION_PROTOCOL_VERSION, AcquisitionError, AcquisitionLimits, AcquisitionRequest,
    AcquisitionSource, LocalDirtyPolicy, SnapshotReference, SourceKind, read_regular_once,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MaterializedFile {
    pub(crate) path: String,
    pub(crate) bytes: Vec<u8>,
    pub(crate) executable: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CollectedMaterial {
    pub(crate) files: Vec<MaterializedFile>,
    pub(crate) redacted_locator: String,
    pub(crate) source_digest: String,
    pub(crate) revision: String,
    pub(crate) git_version: Option<String>,
    pub(crate) submodule_count: usize,
    pub(crate) lfs_pointer_count: usize,
    pub(crate) path_exclusions: Vec<String>,
}

impl CollectedMaterial {
    pub(crate) fn new(
        mut files: Vec<MaterializedFile>,
        redacted_locator: String,
        source_digest: String,
        revision: String,
    ) -> Self {
        files.sort_by(|left, right| left.path.cmp(&right.path));
        Self {
            files,
            redacted_locator,
            source_digest,
            revision,
            git_version: None,
            submodule_count: 0,
            lfs_pointer_count: 0,
            path_exclusions: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SnapshotReceipt {
    pub policy_version: String,
    pub source_kind: SourceKind,
    pub redacted_locator: String,
    pub source_digest: String,
    pub immutable_revision: String,
    pub authority_digest: String,
    pub selected_roots: Vec<String>,
    pub local_dirty_policy: Option<LocalDirtyPolicy>,
    pub submodule_state: String,
    pub lfs_state: String,
    pub path_exclusions: Vec<String>,
    pub file_count: usize,
    pub total_bytes: u64,
    pub tree_digest: String,
    pub tool_version: String,
    pub git_version: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcquiredSnapshot {
    pub reference: SnapshotReference,
    pub receipt: SnapshotReceipt,
    pub snapshot_root: PathBuf,
}

pub(crate) fn prepare_storage_root(root: &Path) -> Result<(), AcquisitionError> {
    if !root.is_absolute() {
        return Err(AcquisitionError::UnsafeStorageRoot);
    }
    if !root.exists() {
        fs::create_dir_all(root).map_err(|_| AcquisitionError::UnsafeStorageRoot)?;
    }
    let metadata = fs::symlink_metadata(root).map_err(|_| AcquisitionError::UnsafeStorageRoot)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(AcquisitionError::UnsafeStorageRoot);
    }
    set_private_directory(root)?;
    for name in ["snapshots", "work"] {
        let child = root.join(name);
        if !child.exists() {
            fs::create_dir(&child).map_err(|_| AcquisitionError::UnsafeStorageRoot)?;
        }
        let metadata =
            fs::symlink_metadata(&child).map_err(|_| AcquisitionError::UnsafeStorageRoot)?;
        if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
            return Err(AcquisitionError::UnsafeStorageRoot);
        }
        set_private_directory(&child)?;
    }
    Ok(())
}

pub(crate) fn collect_local(
    storage_root: &Path,
    source: &Path,
    selected_roots: &[String],
    limits: &AcquisitionLimits,
) -> Result<CollectedMaterial, AcquisitionError> {
    let source_metadata =
        fs::symlink_metadata(source).map_err(|_| AcquisitionError::InvalidSourcePath)?;
    if !source_metadata.file_type().is_dir() || source_metadata.file_type().is_symlink() {
        return Err(AcquisitionError::InvalidSourcePath);
    }
    let source_canonical =
        fs::canonicalize(source).map_err(|_| AcquisitionError::InvalidSourcePath)?;
    let storage_canonical =
        fs::canonicalize(storage_root).map_err(|_| AcquisitionError::UnsafeStorageRoot)?;
    if source_canonical.starts_with(&storage_canonical)
        || storage_canonical.starts_with(&source_canonical)
    {
        return Err(AcquisitionError::InvalidSourcePath);
    }

    let first = scan_local(source, selected_roots, limits)?;
    let second = scan_local(source, selected_roots, limits)?;
    if first != second {
        return Err(AcquisitionError::SourceChanged);
    }
    if first.is_empty() {
        return Err(AcquisitionError::EmptySelection);
    }
    let tree_digest = tree_digest(&first);
    let mut material = CollectedMaterial::new(
        first,
        "local://<redacted>".to_owned(),
        tree_digest.clone(),
        tree_digest,
    );
    material
        .path_exclusions
        .push("root_git_metadata".to_owned());
    Ok(material)
}

fn scan_local(
    source: &Path,
    selected_roots: &[String],
    limits: &AcquisitionLimits,
) -> Result<Vec<MaterializedFile>, AcquisitionError> {
    let mut pending = vec![PathBuf::new()];
    let mut files = Vec::new();
    let mut seen = BTreeSet::new();
    let mut total = 0_u64;
    while let Some(relative) = pending.pop() {
        let directory = source.join(&relative);
        let mut entries = fs::read_dir(directory)
            .map_err(|_| AcquisitionError::InvalidSourcePath)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| AcquisitionError::InvalidSourcePath)?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries.into_iter().rev() {
            let next_relative = relative.join(entry.file_name());
            let relative_name = next_relative.to_str().ok_or(AcquisitionError::UnsafePath)?;
            if relative.as_os_str().is_empty() && relative_name.eq_ignore_ascii_case(".git") {
                continue;
            }
            let metadata =
                fs::symlink_metadata(entry.path()).map_err(|_| AcquisitionError::SourceChanged)?;
            if metadata.file_type().is_symlink() {
                return Err(AcquisitionError::UnsupportedFileType);
            }
            if metadata.file_type().is_dir() {
                let path = normalize_filesystem_relative(&next_relative, limits.max_path_bytes)?;
                if may_contain_selected(&path, selected_roots) {
                    pending.push(next_relative);
                }
                continue;
            }
            if !metadata.file_type().is_file() {
                return Err(AcquisitionError::UnsupportedFileType);
            }
            let path = normalize_filesystem_relative(&next_relative, limits.max_path_bytes)?;
            if !selected(&path, selected_roots) {
                continue;
            }
            insert_collision_key(&path, &mut seen)?;
            add_quota(&mut files, &mut total, metadata.len(), limits)?;
            let (bytes, opened_metadata) = read_regular_once(
                &entry.path(),
                limits.max_file_bytes,
                AcquisitionError::FileBytesExceeded,
            )?;
            files.push(MaterializedFile {
                path,
                bytes,
                executable: executable(&opened_metadata),
            });
        }
    }
    files.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(files)
}

pub(crate) fn add_quota(
    files: &mut [MaterializedFile],
    total: &mut u64,
    size: u64,
    limits: &AcquisitionLimits,
) -> Result<(), AcquisitionError> {
    if files.len() >= limits.max_files {
        return Err(AcquisitionError::FileCountExceeded);
    }
    if size > limits.max_file_bytes {
        return Err(AcquisitionError::FileBytesExceeded);
    }
    *total = total
        .checked_add(size)
        .ok_or(AcquisitionError::TotalBytesExceeded)?;
    if *total > limits.max_total_bytes {
        return Err(AcquisitionError::TotalBytesExceeded);
    }
    Ok(())
}

pub(crate) fn tree_digest(files: &[MaterializedFile]) -> String {
    let mut bytes = Vec::new();
    for file in files {
        bytes.extend_from_slice(
            &u64::try_from(file.path.len())
                .expect("path limit fits u64")
                .to_be_bytes(),
        );
        bytes.extend_from_slice(file.path.as_bytes());
        bytes.push(u8::from(file.executable));
        bytes.extend_from_slice(
            &u64::try_from(file.bytes.len())
                .expect("byte quota fits u64")
                .to_be_bytes(),
        );
        bytes.extend_from_slice(&sha256(&file.bytes));
    }
    digest_string(&bytes)
}

pub(crate) fn publish(
    storage_root: &Path,
    request: &AcquisitionRequest,
    selected_roots: Vec<String>,
    mut material: CollectedMaterial,
) -> Result<AcquiredSnapshot, AcquisitionError> {
    material
        .files
        .sort_by(|left, right| left.path.cmp(&right.path));
    if material.files.is_empty() {
        return Err(AcquisitionError::EmptySelection);
    }
    let tree_digest = tree_digest(&material.files);
    let (receipt, reference, receipt_bytes, receipt_hex) =
        snapshot_identity(request, selected_roots, &material, &tree_digest)?;

    let snapshots_root = storage_root.join("snapshots");
    let final_root = snapshots_root.join(&receipt_hex);
    if final_root.exists() {
        verify_existing(&final_root, &receipt_bytes, &tree_digest)?;
        return Ok(AcquiredSnapshot {
            reference,
            receipt,
            snapshot_root: final_root,
        });
    }

    let staging = unique_work_directory(&storage_root.join("work"), "publish")?;
    let staging_tree = staging.path.join("tree");
    fs::create_dir(&staging_tree).map_err(|_| AcquisitionError::SnapshotPublishFailed)?;
    set_private_directory(&staging_tree)?;
    write_snapshot_files(&staging_tree, &material.files)?;
    let receipt_path = staging.path.join("receipt.json");
    let mut receipt_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&receipt_path)
        .map_err(|_| AcquisitionError::SnapshotPublishFailed)?;
    receipt_file
        .write_all(&receipt_bytes)
        .and_then(|()| receipt_file.sync_all())
        .map_err(|_| AcquisitionError::SnapshotPublishFailed)?;
    set_snapshot_file(&receipt_path, false)?;
    make_tree_read_only(&staging_tree)?;

    match fs::rename(&staging.path, &final_root) {
        Ok(()) => {
            staging.disarm();
            set_read_only_directory(&final_root)?;
        }
        Err(_) if final_root.exists() => {
            verify_existing(&final_root, &receipt_bytes, &tree_digest)?;
        }
        Err(_) => return Err(AcquisitionError::SnapshotPublishFailed),
    }
    Ok(AcquiredSnapshot {
        reference,
        receipt,
        snapshot_root: final_root,
    })
}

fn snapshot_identity(
    request: &AcquisitionRequest,
    selected_roots: Vec<String>,
    material: &CollectedMaterial,
    tree_digest: &str,
) -> Result<(SnapshotReceipt, SnapshotReference, Vec<u8>, String), AcquisitionError> {
    let total_bytes = material
        .files
        .iter()
        .try_fold(0_u64, |total, file| {
            total.checked_add(u64::try_from(file.bytes.len()).ok()?)
        })
        .ok_or(AcquisitionError::TotalBytesExceeded)?;
    let receipt = SnapshotReceipt {
        policy_version: ACQUISITION_PROTOCOL_VERSION.to_owned(),
        source_kind: request.source.kind(),
        redacted_locator: material.redacted_locator.clone(),
        source_digest: material.source_digest.clone(),
        immutable_revision: material.revision.clone(),
        authority_digest: request.authority_digest.clone(),
        selected_roots,
        local_dirty_policy: match &request.source {
            AcquisitionSource::Local { dirty_policy, .. } => Some(*dirty_policy),
            _ => None,
        },
        submodule_state: format!("present_not_initialized:{}", material.submodule_count),
        lfs_state: format!("pointers_not_fetched:{}", material.lfs_pointer_count),
        path_exclusions: material.path_exclusions.clone(),
        file_count: material.files.len(),
        total_bytes,
        tree_digest: tree_digest.to_owned(),
        tool_version: env!("CARGO_PKG_VERSION").to_owned(),
        git_version: material.git_version.clone(),
    };
    let receipt_bytes =
        serde_json::to_vec(&receipt).map_err(|_| AcquisitionError::SnapshotPublishFailed)?;
    let receipt_digest = digest_string(&receipt_bytes);
    let receipt_hex = receipt_digest[7..].to_owned();
    let repository_seed = format!("{}\0{}", receipt.redacted_locator, receipt.source_digest);
    let repository_id = format!("repo_{}", hex(&sha256(repository_seed.as_bytes())));
    let reference = SnapshotReference {
        snapshot_id: format!("snapshot_{receipt_hex}"),
        repository_id,
        redacted_locator: receipt.redacted_locator.clone(),
        revision: material.revision.clone(),
        manifest_artifact_id: receipt_digest,
    };
    Ok((receipt, reference, receipt_bytes, receipt_hex))
}

fn write_snapshot_files(
    staging_tree: &Path,
    files: &[MaterializedFile],
) -> Result<(), AcquisitionError> {
    for file in files {
        let target = staging_tree.join(&file.path);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|_| AcquisitionError::SnapshotPublishFailed)?;
        }
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&target)
            .map_err(|_| AcquisitionError::SnapshotPublishFailed)?;
        output
            .write_all(&file.bytes)
            .and_then(|()| output.sync_all())
            .map_err(|_| AcquisitionError::SnapshotPublishFailed)?;
        set_snapshot_file(&target, file.executable)?;
    }
    Ok(())
}

fn verify_existing(
    root: &Path,
    expected_receipt: &[u8],
    expected_tree_digest: &str,
) -> Result<(), AcquisitionError> {
    let metadata =
        fs::symlink_metadata(root).map_err(|_| AcquisitionError::SnapshotIntegrityFailed)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(AcquisitionError::SnapshotIntegrityFailed);
    }
    let receipt = fs::read(root.join("receipt.json"))
        .map_err(|_| AcquisitionError::SnapshotIntegrityFailed)?;
    if receipt != expected_receipt {
        return Err(AcquisitionError::SnapshotIntegrityFailed);
    }
    let limits = AcquisitionLimits {
        max_files: 1_000_000,
        max_total_bytes: u64::MAX / 2,
        max_file_bytes: u64::MAX / 2,
        max_path_bytes: 4096,
        max_archive_bytes: u64::MAX / 2,
        max_git_output_bytes: usize::MAX / 2,
        max_git_seconds: u64::MAX / 2,
    };
    let actual = scan_local_tree(&root.join("tree"), &limits)?;
    if tree_digest(&actual) != expected_tree_digest {
        return Err(AcquisitionError::SnapshotIntegrityFailed);
    }
    Ok(())
}

fn scan_local_tree(
    root: &Path,
    limits: &AcquisitionLimits,
) -> Result<Vec<MaterializedFile>, AcquisitionError> {
    scan_local(root, &[], limits).map_err(|_| AcquisitionError::SnapshotIntegrityFailed)
}

pub(crate) struct WorkDirectory {
    pub(crate) path: PathBuf,
    armed: bool,
}

impl WorkDirectory {
    pub(crate) fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for WorkDirectory {
    fn drop(&mut self) {
        if self.armed {
            let _ = make_tree_writable(&self.path);
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

pub(crate) fn unique_work_directory(
    parent: &Path,
    prefix: &str,
) -> Result<WorkDirectory, AcquisitionError> {
    let directory = tempfile::Builder::new()
        .prefix(&format!("{prefix}-"))
        .tempdir_in(parent)
        .map_err(|_| AcquisitionError::SnapshotPublishFailed)?;
    let path = directory.keep();
    set_private_directory(&path)?;
    Ok(WorkDirectory { path, armed: true })
}

#[cfg(unix)]
fn executable(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn executable(_: &fs::Metadata) -> bool {
    false
}

#[cfg(unix)]
fn set_private_directory(path: &Path) -> Result<(), AcquisitionError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|_| AcquisitionError::UnsafeStorageRoot)?;
    let mode = fs::symlink_metadata(path)
        .map_err(|_| AcquisitionError::UnsafeStorageRoot)?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        return Err(AcquisitionError::UnsafeStorageRoot);
    }
    Ok(())
}

#[cfg(not(unix))]
fn set_private_directory(_: &Path) -> Result<(), AcquisitionError> {
    Err(AcquisitionError::StoragePermissionUnsupported)
}

#[cfg(unix)]
fn set_snapshot_file(path: &Path, executable: bool) -> Result<(), AcquisitionError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = if executable { 0o500 } else { 0o400 };
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|_| AcquisitionError::SnapshotPublishFailed)
}

#[cfg(not(unix))]
fn set_snapshot_file(_: &Path, _: bool) -> Result<(), AcquisitionError> {
    Err(AcquisitionError::StoragePermissionUnsupported)
}

#[cfg(unix)]
fn set_read_only_directory(path: &Path) -> Result<(), AcquisitionError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o500))
        .map_err(|_| AcquisitionError::SnapshotPublishFailed)
}

#[cfg(not(unix))]
fn set_read_only_directory(_: &Path) -> Result<(), AcquisitionError> {
    Err(AcquisitionError::StoragePermissionUnsupported)
}

fn make_tree_read_only(root: &Path) -> Result<(), AcquisitionError> {
    let mut directories = vec![root.to_path_buf()];
    let mut visited = Vec::new();
    while let Some(directory) = directories.pop() {
        visited.push(directory.clone());
        for entry in
            fs::read_dir(&directory).map_err(|_| AcquisitionError::SnapshotPublishFailed)?
        {
            let entry = entry.map_err(|_| AcquisitionError::SnapshotPublishFailed)?;
            if entry
                .file_type()
                .map_err(|_| AcquisitionError::SnapshotPublishFailed)?
                .is_dir()
            {
                directories.push(entry.path());
            }
        }
    }
    for directory in visited.into_iter().rev() {
        set_read_only_directory(&directory)?;
    }
    Ok(())
}

fn make_tree_writable(root: &Path) -> Result<(), std::io::Error> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if root.exists() {
            fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
            for entry in fs::read_dir(root)? {
                let entry = entry?;
                if entry.file_type()?.is_dir() {
                    make_tree_writable(&entry.path())?;
                } else {
                    fs::set_permissions(entry.path(), fs::Permissions::from_mode(0o600))?;
                }
            }
        }
    }
    #[cfg(not(unix))]
    fs::metadata(root)?;
    Ok(())
}
