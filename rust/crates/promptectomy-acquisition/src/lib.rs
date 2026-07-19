use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const ACQUISITION_PROTOCOL_VERSION: &str = "phase3-acquisition-1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    LocalPath,
    GitRemote,
    Archive,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcquisitionRequest {
    pub source_kind: SourceKind,
    pub protected_locator: PathBuf,
    pub authority_id: String,
    pub authority_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SnapshotReference {
    pub snapshot_id: String,
    pub repository_id: String,
    pub redacted_locator: String,
    pub revision: String,
    pub manifest_artifact_id: String,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum AcquisitionError {
    #[error("repository acquisition is unavailable before the Phase 4 trust boundary")]
    Phase4Required,
}

pub fn acquire(_: &AcquisitionRequest) -> Result<SnapshotReference, AcquisitionError> {
    Err(AcquisitionError::Phase4Required)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase3_boundary_never_opens_or_mutates_a_source() {
        let request = AcquisitionRequest {
            source_kind: SourceKind::LocalPath,
            protected_locator: PathBuf::from("/path/that/must/not/be/opened"),
            authority_id: "auth_019f0000-0000-7000-8000-000000000001".to_owned(),
            authority_digest:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        };
        assert_eq!(acquire(&request), Err(AcquisitionError::Phase4Required));
    }
}
