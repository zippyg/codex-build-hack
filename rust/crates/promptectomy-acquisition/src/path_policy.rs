use std::collections::BTreeSet;
use std::path::{Component, Path};

use crate::AcquisitionError;

const WINDOWS_DEVICES: [&str; 22] = [
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

pub(crate) fn normalize_selected_roots(
    roots: &[String],
    max_path_bytes: usize,
) -> Result<Vec<String>, AcquisitionError> {
    let mut normalized = Vec::with_capacity(roots.len());
    let mut seen = BTreeSet::new();
    for root in roots {
        let root = normalize_path(root.as_bytes(), max_path_bytes)
            .map_err(|_| AcquisitionError::InvalidSelectedRoot)?;
        if !seen.insert(root.to_ascii_lowercase()) {
            return Err(AcquisitionError::InvalidSelectedRoot);
        }
        normalized.push(root);
    }
    normalized.sort();
    Ok(normalized)
}

pub(crate) fn normalize_filesystem_relative(
    path: &Path,
    max_path_bytes: usize,
) -> Result<String, AcquisitionError> {
    let mut value = String::new();
    for component in path.components() {
        match component {
            Component::Normal(component) => {
                let component = component.to_str().ok_or(AcquisitionError::UnsafePath)?;
                if !value.is_empty() {
                    value.push('/');
                }
                value.push_str(component);
            }
            _ => return Err(AcquisitionError::UnsafePath),
        }
    }
    normalize_path(value.as_bytes(), max_path_bytes)
}

pub(crate) fn normalize_path(
    raw: &[u8],
    max_path_bytes: usize,
) -> Result<String, AcquisitionError> {
    if raw.is_empty()
        || raw.len() > max_path_bytes
        || raw.first() == Some(&b'/')
        || raw.contains(&b'\\')
        || !raw.is_ascii()
    {
        return Err(AcquisitionError::UnsafePath);
    }
    let value = std::str::from_utf8(raw).map_err(|_| AcquisitionError::UnsafePath)?;
    let mut components = Vec::new();
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
            return Err(AcquisitionError::UnsafePath);
        }
        let stem = component.split('.').next().expect("split yields one item");
        if WINDOWS_DEVICES
            .iter()
            .any(|device| stem.eq_ignore_ascii_case(device))
        {
            return Err(AcquisitionError::UnsafePath);
        }
        components.push(component);
    }
    Ok(components.join("/"))
}

pub(crate) fn selected(path: &str, roots: &[String]) -> bool {
    roots.is_empty()
        || roots.iter().any(|root| {
            path == root
                || path
                    .strip_prefix(root)
                    .is_some_and(|rest| rest.starts_with('/'))
        })
}

pub(crate) fn may_contain_selected(path: &str, roots: &[String]) -> bool {
    roots.is_empty()
        || roots.iter().any(|root| {
            path == root
                || root
                    .strip_prefix(path)
                    .is_some_and(|rest| rest.starts_with('/'))
                || path
                    .strip_prefix(root)
                    .is_some_and(|rest| rest.starts_with('/'))
        })
}

pub(crate) fn insert_collision_key(
    path: &str,
    seen: &mut BTreeSet<String>,
) -> Result<(), AcquisitionError> {
    if !seen.insert(path.to_ascii_lowercase()) {
        return Err(AcquisitionError::PathCollision);
    }
    Ok(())
}
