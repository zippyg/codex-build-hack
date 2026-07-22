use std::collections::BTreeSet;
use std::path::Path;

use serde::Deserialize;

use crate::digest::digest_string;
use crate::path_policy::{insert_collision_key, normalize_path, selected};
use crate::snapshot::{CollectedMaterial, MaterializedFile, add_quota};
use crate::{AcquisitionError, AcquisitionLimits, ArchiveFormat, read_bounded};

const TAR_BLOCK: usize = 512;
const BUNDLE_VERSION: &str = "promptectomy-source-bundle-1";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleDocument {
    version: String,
    files: Vec<BundleFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleFile {
    path: String,
    executable: bool,
    content_hex: String,
    digest: String,
}

pub(crate) fn collect_archive(
    path: &Path,
    format: ArchiveFormat,
    selected_roots: &[String],
    limits: &AcquisitionLimits,
) -> Result<CollectedMaterial, AcquisitionError> {
    let bytes = read_bounded(
        path,
        limits.max_archive_bytes,
        AcquisitionError::ArchiveBytesExceeded,
    )?;
    let source_digest = digest_string(&bytes);
    let files = match format {
        ArchiveFormat::Tar => parse_tar(&bytes, selected_roots, limits)?,
    };
    if files.is_empty() {
        return Err(AcquisitionError::EmptySelection);
    }
    let mut material = CollectedMaterial::new(
        files,
        "archive://<redacted>".to_owned(),
        source_digest.clone(),
        source_digest,
    );
    material.lfs_pointer_count = count_lfs_pointers(&material.files);
    Ok(material)
}

pub(crate) fn collect_bundle(
    path: &Path,
    selected_roots: &[String],
    limits: &AcquisitionLimits,
) -> Result<CollectedMaterial, AcquisitionError> {
    let bytes = read_bounded(
        path,
        limits.max_archive_bytes,
        AcquisitionError::ArchiveBytesExceeded,
    )?;
    collect_bundle_bytes(&bytes, selected_roots, limits)
}

pub(crate) fn collect_bundle_bytes(
    bytes: &[u8],
    selected_roots: &[String],
    limits: &AcquisitionLimits,
) -> Result<CollectedMaterial, AcquisitionError> {
    let document: BundleDocument =
        serde_json::from_slice(bytes).map_err(|_| AcquisitionError::InvalidBundle)?;
    if document.version != BUNDLE_VERSION || document.files.len() > limits.max_files {
        return Err(AcquisitionError::InvalidBundle);
    }
    let mut files = Vec::new();
    let mut seen = BTreeSet::new();
    let mut total = 0_u64;
    for file in document.files {
        let normalized = normalize_path(file.path.as_bytes(), limits.max_path_bytes)?;
        insert_collision_key(&normalized, &mut seen)?;
        let content = decode_hex(&file.content_hex)?;
        if digest_string(&content) != file.digest {
            return Err(AcquisitionError::InvalidBundle);
        }
        if !selected(&normalized, selected_roots) {
            continue;
        }
        add_quota(
            &mut files,
            &mut total,
            u64::try_from(content.len()).map_err(|_| AcquisitionError::FileBytesExceeded)?,
            limits,
        )?;
        files.push(MaterializedFile {
            path: normalized,
            bytes: content,
            executable: file.executable,
        });
    }
    if files.is_empty() {
        return Err(AcquisitionError::EmptySelection);
    }
    let source_digest = digest_string(bytes);
    let mut material = CollectedMaterial::new(
        files,
        "bundle://<redacted>".to_owned(),
        source_digest.clone(),
        source_digest,
    );
    material.lfs_pointer_count = count_lfs_pointers(&material.files);
    Ok(material)
}

pub(crate) fn parse_tar(
    bytes: &[u8],
    selected_roots: &[String],
    limits: &AcquisitionLimits,
) -> Result<Vec<MaterializedFile>, AcquisitionError> {
    if bytes.len() < TAR_BLOCK || !bytes.len().is_multiple_of(TAR_BLOCK) {
        return Err(AcquisitionError::UnsupportedArchive);
    }
    let mut offset = 0_usize;
    let mut zero_blocks = 0_u8;
    let mut files = Vec::new();
    let mut seen = BTreeSet::new();
    let mut total = 0_u64;
    while offset < bytes.len() {
        let header = &bytes[offset..offset + TAR_BLOCK];
        offset += TAR_BLOCK;
        if header.iter().all(|byte| *byte == 0) {
            zero_blocks += 1;
            if zero_blocks == 2 {
                if bytes[offset..].iter().any(|byte| *byte != 0) {
                    return Err(AcquisitionError::UnsupportedArchive);
                }
                break;
            }
            continue;
        }
        if zero_blocks != 0 {
            return Err(AcquisitionError::UnsupportedArchive);
        }
        verify_tar_checksum(header)?;
        if &header[257..263] != b"ustar\0" && &header[257..263] != b"ustar " {
            return Err(AcquisitionError::UnsupportedArchive);
        }
        let name = tar_text(&header[..100])?;
        if name.is_empty() {
            return Err(AcquisitionError::UnsafePath);
        }
        let prefix = tar_text(&header[345..500])?;
        let raw_path = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        let raw_path = raw_path.strip_suffix('/').unwrap_or(&raw_path);
        let path = normalize_path(raw_path.as_bytes(), limits.max_path_bytes)?;
        insert_collision_key(&path, &mut seen)?;
        let size = parse_tar_octal(&header[124..136])?;
        let size_usize =
            usize::try_from(size).map_err(|_| AcquisitionError::ArchiveBytesExceeded)?;
        let padded = size_usize
            .checked_add(TAR_BLOCK - 1)
            .ok_or(AcquisitionError::ArchiveBytesExceeded)?
            / TAR_BLOCK
            * TAR_BLOCK;
        let end = offset
            .checked_add(padded)
            .ok_or(AcquisitionError::ArchiveBytesExceeded)?;
        let content_end = offset
            .checked_add(size_usize)
            .ok_or(AcquisitionError::ArchiveBytesExceeded)?;
        if end > bytes.len() || content_end > bytes.len() {
            return Err(AcquisitionError::UnsupportedArchive);
        }
        match header[156] {
            b'5' => {
                if size != 0 {
                    return Err(AcquisitionError::UnsupportedArchive);
                }
            }
            0 | b'0' => {
                if selected(&path, selected_roots) {
                    add_quota(&mut files, &mut total, size, limits)?;
                    let mode = parse_tar_octal(&header[100..108])?;
                    files.push(MaterializedFile {
                        path,
                        bytes: bytes[offset..content_end].to_vec(),
                        executable: mode & 0o111 != 0,
                    });
                }
            }
            _ => return Err(AcquisitionError::UnsupportedFileType),
        }
        offset = end;
    }
    if zero_blocks < 2 {
        return Err(AcquisitionError::UnsupportedArchive);
    }
    files.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(files)
}

fn verify_tar_checksum(header: &[u8]) -> Result<(), AcquisitionError> {
    let expected = parse_tar_octal(&header[148..156])?;
    let actual = header.iter().enumerate().fold(0_u64, |sum, (index, byte)| {
        sum + if (148..156).contains(&index) {
            u64::from(b' ')
        } else {
            u64::from(*byte)
        }
    });
    if expected != actual {
        return Err(AcquisitionError::ArchiveChecksumMismatch);
    }
    Ok(())
}

fn parse_tar_octal(field: &[u8]) -> Result<u64, AcquisitionError> {
    if field.first().is_some_and(|byte| byte & 0x80 != 0) {
        return Err(AcquisitionError::UnsupportedArchive);
    }
    let value = field
        .iter()
        .copied()
        .skip_while(|byte| *byte == b' ' || *byte == 0)
        .take_while(|byte| *byte != b' ' && *byte != 0)
        .try_fold(0_u64, |value, byte| {
            if !(b'0'..=b'7').contains(&byte) {
                return Err(AcquisitionError::UnsupportedArchive);
            }
            value
                .checked_mul(8)
                .and_then(|value| value.checked_add(u64::from(byte - b'0')))
                .ok_or(AcquisitionError::UnsupportedArchive)
        })?;
    Ok(value)
}

fn tar_text(field: &[u8]) -> Result<String, AcquisitionError> {
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    let value = &field[..end];
    if value.iter().any(u8::is_ascii_control) {
        return Err(AcquisitionError::UnsafePath);
    }
    String::from_utf8(value.to_vec()).map_err(|_| AcquisitionError::UnsafePath)
}

fn decode_hex(value: &str) -> Result<Vec<u8>, AcquisitionError> {
    if !value.len().is_multiple_of(2) || !value.is_ascii() {
        return Err(AcquisitionError::InvalidBundle);
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_digit(pair[0])?;
            let low = hex_digit(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_digit(byte: u8) -> Result<u8, AcquisitionError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(AcquisitionError::InvalidBundle),
    }
}

fn count_lfs_pointers(files: &[MaterializedFile]) -> usize {
    files
        .iter()
        .filter(|file| {
            file.bytes
                .starts_with(b"version https://git-lfs.github.com/spec/v1\n")
        })
        .count()
}
