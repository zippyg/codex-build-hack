use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
#[cfg(unix)]
use std::path::Component;
use std::path::{Path, PathBuf};

use sha2::{Digest as _, Sha256};

use crate::{ProtectedEnvelopeV2, ProtectedStoreError};

const MAX_ENVELOPE_BYTES: u64 = 96 * 1024 * 1024;

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredEnvelope {
    pub envelope_digest: String,
    pub path: PathBuf,
}

#[derive(Clone, Debug)]
pub struct ProtectedBlobStore {
    root: PathBuf,
}

impl ProtectedBlobStore {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, ProtectedStoreError> {
        let root = root.into();
        if !root.is_absolute() {
            return Err(ProtectedStoreError::UnsafeStorageRoot);
        }
        prepare_private_directory(&root)?;
        Ok(Self { root })
    }

    pub fn put(
        &self,
        envelope: &ProtectedEnvelopeV2,
    ) -> Result<StoredEnvelope, ProtectedStoreError> {
        let encoded = envelope.encode()?;
        let digest = digest(&encoded);
        let hex_digest = digest
            .strip_prefix("sha256:")
            .ok_or(ProtectedStoreError::InvalidEnvelope)?;
        let digest_root = self.root.join("sha256");
        prepare_private_directory(&digest_root)?;
        let directory = digest_root.join(&hex_digest[..2]);
        prepare_private_directory(&directory)?;
        let destination = directory.join(format!("{hex_digest}.json"));
        if destination.exists() {
            read_verified(&destination, &digest)?;
            return Ok(StoredEnvelope {
                envelope_digest: digest,
                path: destination,
            });
        }
        let temporary = directory.join(format!(".pending-{}", envelope.protected_id));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options
            .open(&temporary)
            .map_err(|_| ProtectedStoreError::StorageIo)?;
        let result = (|| {
            file.write_all(&encoded)
                .map_err(|_| ProtectedStoreError::StorageIo)?;
            file.sync_all()
                .map_err(|_| ProtectedStoreError::StorageIo)?;
            drop(file);
            read_verified(&temporary, &digest)?;
            match fs::hard_link(&temporary, &destination) {
                Ok(()) => {}
                Err(_) if destination.exists() => {
                    read_verified(&destination, &digest)?;
                }
                Err(_) => return Err(ProtectedStoreError::StorageIo),
            }
            fs::remove_file(&temporary).map_err(|_| ProtectedStoreError::StorageIo)?;
            sync_directory(&directory)?;
            Ok(StoredEnvelope {
                envelope_digest: digest,
                path: destination,
            })
        })();
        if result.is_err() && temporary.exists() {
            let quarantine = self
                .root
                .join(format!("quarantine-{}", envelope.protected_id));
            let _ = fs::rename(&temporary, quarantine);
        }
        result
    }

    pub fn read(&self, envelope_digest: &str) -> Result<ProtectedEnvelopeV2, ProtectedStoreError> {
        let hex_digest = validate_digest(envelope_digest)?;
        let path = self
            .root
            .join("sha256")
            .join(&hex_digest[..2])
            .join(format!("{hex_digest}.json"));
        let encoded = read_verified(&path, envelope_digest)?;
        ProtectedEnvelopeV2::decode(&encoded)
    }
}

#[cfg(unix)]
fn prepare_private_directory(path: &Path) -> Result<(), ProtectedStoreError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(ProtectedStoreError::UnsafeStorageRoot);
    }
    let mut missing = Vec::new();
    let mut cursor = path;
    loop {
        match cursor.symlink_metadata() {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(ProtectedStoreError::UnsafeStorageRoot);
                }
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                missing.push(cursor);
                cursor = cursor
                    .parent()
                    .ok_or(ProtectedStoreError::UnsafeStorageRoot)?;
            }
            Err(_) => return Err(ProtectedStoreError::StorageIo),
        }
    }
    for directory in missing.into_iter().rev() {
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(directory) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let metadata = directory
                    .symlink_metadata()
                    .map_err(|_| ProtectedStoreError::StorageIo)?;
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(ProtectedStoreError::UnsafeStorageRoot);
                }
            }
            Err(_) => return Err(ProtectedStoreError::StorageIo),
        }
    }
    for ancestor in path.ancestors() {
        let metadata = ancestor
            .symlink_metadata()
            .map_err(|_| ProtectedStoreError::StorageIo)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(ProtectedStoreError::UnsafeStorageRoot);
        }
    }
    let mode = path
        .metadata()
        .map_err(|_| ProtectedStoreError::StorageIo)?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        return Err(ProtectedStoreError::UnsafeStorageRoot);
    }
    Ok(())
}

#[cfg(not(unix))]
fn prepare_private_directory(_path: &Path) -> Result<(), ProtectedStoreError> {
    Err(ProtectedStoreError::StoragePermissionsUnsupported)
}

fn read_verified(path: &Path, expected_digest: &str) -> Result<Vec<u8>, ProtectedStoreError> {
    let metadata = path
        .symlink_metadata()
        .map_err(|_| ProtectedStoreError::BlobMissing)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ProtectedStoreError::BlobTampered);
    }
    if metadata.len() > MAX_ENVELOPE_BYTES {
        return Err(ProtectedStoreError::ContentTooLarge);
    }
    let file = open_read_only(path)?;
    let mut content = Vec::new();
    file.take(MAX_ENVELOPE_BYTES + 1)
        .read_to_end(&mut content)
        .map_err(|_| ProtectedStoreError::StorageIo)?;
    if u64::try_from(content.len()).map_or(true, |size| size > MAX_ENVELOPE_BYTES) {
        return Err(ProtectedStoreError::ContentTooLarge);
    }
    if digest(&content) != expected_digest {
        return Err(ProtectedStoreError::BlobTampered);
    }
    Ok(content)
}

fn sync_directory(directory: &Path) -> Result<(), ProtectedStoreError> {
    #[cfg(unix)]
    {
        open_read_only(directory)?
            .sync_all()
            .map_err(|_| ProtectedStoreError::StorageIo)
    }
    #[cfg(not(unix))]
    {
        let _ = directory;
        Err(ProtectedStoreError::StoragePermissionsUnsupported)
    }
}

fn open_read_only(path: &Path) -> Result<File, ProtectedStoreError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    options
        .open(path)
        .map_err(|_| ProtectedStoreError::StorageIo)
}

fn validate_digest(value: &str) -> Result<&str, ProtectedStoreError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(ProtectedStoreError::InvalidIdentifier);
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(ProtectedStoreError::InvalidIdentifier);
    }
    Ok(hex)
}

fn digest(content: &[u8]) -> String {
    let value = Sha256::digest(content);
    let mut output = String::with_capacity(71);
    output.push_str("sha256:");
    for byte in value {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}
