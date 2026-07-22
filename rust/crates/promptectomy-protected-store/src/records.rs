use serde::{Deserialize, Serialize};

use crate::ProtectedStoreError;

pub const BACKUP_MANIFEST_VERSION: &str = "phase4-protected-backup-manifest-1";
pub const DELETION_PLAN_VERSION: &str = "phase4-protected-deletion-plan-1";
pub const DELETION_RECEIPT_VERSION: &str = "phase4-protected-deletion-receipt-1";
#[cfg(unix)]
pub(crate) const PUT_JOURNAL_VERSION: &str = "phase4-protected-put-journal-1";
#[cfg(unix)]
pub(crate) const KEY_REFERENCE_VERSION: &str = "phase4-protected-key-reference-1";
#[cfg(unix)]
pub(crate) const KEY_REFERENCE_INDEX_VERSION: &str = "phase4-protected-key-reference-index-1";
#[cfg(unix)]
pub(crate) const DELETION_JOURNAL_VERSION: &str = "phase4-protected-deletion-journal-1";
#[cfg(unix)]
pub(crate) const BACKUP_REFERENCE_INDEX_VERSION: &str = "phase4-protected-backup-reference-index-1";
#[cfg(unix)]
pub(crate) const BACKUP_ACKNOWLEDGMENT_VERSION: &str = "phase4-protected-backup-acknowledgment-1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedBackupEntry {
    pub envelope_digest: String,
    pub envelope_bytes: u64,
    pub protected_id: String,
    pub wrapping_key_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedBackupManifestV1 {
    pub version: String,
    pub installation_id: String,
    pub entries: Vec<ProtectedBackupEntry>,
}

impl ProtectedBackupManifestV1 {
    pub fn encode(&self) -> Result<Vec<u8>, ProtectedStoreError> {
        self.validate()?;
        canonical(self, ProtectedStoreError::InvalidBackupManifest)
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, ProtectedStoreError> {
        let manifest: Self = serde_json::from_slice(encoded)
            .map_err(|_| ProtectedStoreError::InvalidBackupManifest)?;
        manifest.validate()?;
        if manifest.encode()? != encoded {
            return Err(ProtectedStoreError::NonCanonicalMetadata);
        }
        Ok(manifest)
    }

    pub(crate) fn validate(&self) -> Result<(), ProtectedStoreError> {
        if self.version != BACKUP_MANIFEST_VERSION
            || !valid_prefixed_id(&self.installation_id, "installation")
            || self.entries.is_empty()
        {
            return Err(ProtectedStoreError::InvalidBackupManifest);
        }
        let mut previous = None;
        for entry in &self.entries {
            if !valid_digest(&entry.envelope_digest)
                || entry.envelope_bytes == 0
                || !valid_prefixed_id(&entry.protected_id, "protected")
                || !valid_prefixed_id(&entry.wrapping_key_id, "key")
                || previous.is_some_and(|value| value >= entry.envelope_digest.as_str())
            {
                return Err(ProtectedStoreError::InvalidBackupManifest);
            }
            previous = Some(entry.envelope_digest.as_str());
        }
        Ok(())
    }
}

#[cfg(unix)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BackupReferenceIndexV1 {
    pub version: String,
    pub envelope_digest: String,
    pub manifest_digests: Vec<String>,
}

#[cfg(unix)]
impl BackupReferenceIndexV1 {
    pub(crate) fn encode(&self) -> Result<Vec<u8>, ProtectedStoreError> {
        self.validate()?;
        canonical(self, ProtectedStoreError::InvalidBackupManifest)
    }

    pub(crate) fn decode(encoded: &[u8]) -> Result<Self, ProtectedStoreError> {
        let index: Self = serde_json::from_slice(encoded)
            .map_err(|_| ProtectedStoreError::InvalidBackupManifest)?;
        index.validate()?;
        if index.encode()? != encoded {
            return Err(ProtectedStoreError::NonCanonicalMetadata);
        }
        Ok(index)
    }

    fn validate(&self) -> Result<(), ProtectedStoreError> {
        if self.version != BACKUP_REFERENCE_INDEX_VERSION
            || !valid_digest(&self.envelope_digest)
            || self.manifest_digests.is_empty()
        {
            return Err(ProtectedStoreError::InvalidBackupManifest);
        }
        let mut previous = None;
        for manifest_digest in &self.manifest_digests {
            if !valid_digest(manifest_digest)
                || previous.is_some_and(|value| value >= manifest_digest.as_str())
            {
                return Err(ProtectedStoreError::InvalidBackupManifest);
            }
            previous = Some(manifest_digest.as_str());
        }
        Ok(())
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BackupAcknowledgmentState {
    Prepared,
    Committed,
}

#[cfg(unix)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BackupAcknowledgmentV1 {
    pub version: String,
    pub state: BackupAcknowledgmentState,
    pub manifest: ProtectedBackupManifestV1,
}

#[cfg(unix)]
impl BackupAcknowledgmentV1 {
    pub(crate) fn encode(&self) -> Result<Vec<u8>, ProtectedStoreError> {
        self.validate()?;
        canonical(self, ProtectedStoreError::InvalidBackupManifest)
    }

    pub(crate) fn decode(encoded: &[u8]) -> Result<Self, ProtectedStoreError> {
        let acknowledgment: Self = serde_json::from_slice(encoded)
            .map_err(|_| ProtectedStoreError::InvalidBackupManifest)?;
        acknowledgment.validate()?;
        if acknowledgment.encode()? != encoded {
            return Err(ProtectedStoreError::NonCanonicalMetadata);
        }
        Ok(acknowledgment)
    }

    fn validate(&self) -> Result<(), ProtectedStoreError> {
        if self.version != BACKUP_ACKNOWLEDGMENT_VERSION {
            return Err(ProtectedStoreError::InvalidBackupManifest);
        }
        self.manifest.validate()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupVerificationReceipt {
    pub manifest_digest: String,
    pub envelope_count: u64,
    pub total_envelope_bytes: u64,
    pub every_envelope_decryptable: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeletionReferenceKind {
    Artifact,
    Backup,
    SharedWrappingKey,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeletionReference {
    pub kind: DeletionReferenceKind,
    pub reference_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedDeletionPlanV1 {
    pub version: String,
    pub envelope_digest: String,
    pub installation_id: String,
    pub protected_id: String,
    pub wrapping_key_id: String,
    pub references: Vec<DeletionReference>,
}

impl ProtectedDeletionPlanV1 {
    pub fn encode(&self) -> Result<Vec<u8>, ProtectedStoreError> {
        self.validate()?;
        canonical(self, ProtectedStoreError::InvalidDeletionPlan)
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, ProtectedStoreError> {
        let plan: Self = serde_json::from_slice(encoded)
            .map_err(|_| ProtectedStoreError::InvalidDeletionPlan)?;
        plan.validate()?;
        if plan.encode()? != encoded {
            return Err(ProtectedStoreError::NonCanonicalMetadata);
        }
        Ok(plan)
    }

    pub(crate) fn validate(&self) -> Result<(), ProtectedStoreError> {
        if self.version != DELETION_PLAN_VERSION
            || !valid_digest(&self.envelope_digest)
            || !valid_prefixed_id(&self.installation_id, "installation")
            || !valid_prefixed_id(&self.protected_id, "protected")
            || !valid_prefixed_id(&self.wrapping_key_id, "key")
        {
            return Err(ProtectedStoreError::InvalidDeletionPlan);
        }
        let mut previous = None;
        for reference in &self.references {
            if !valid_reference_id(&reference.reference_id)
                || previous.is_some_and(|value| value >= reference)
            {
                return Err(ProtectedStoreError::InvalidDeletionPlan);
            }
            previous = Some(reference);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedDeletionReceiptV1 {
    pub version: String,
    pub plan_digest: String,
    pub envelope_digest: String,
    pub protected_id: String,
    pub wrapping_key: WrappingKeyDeletionStatus,
    pub blob: BlobDeletionStatus,
    pub erasure_scope: DeletionErasureScope,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WrappingKeyDeletionStatus {
    DeletedAndAbsenceVerified,
    AlreadyAbsentAndVerified,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlobDeletionStatus {
    Unlinked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeletionErasureScope {
    LogicalStoreAndWrappingKeyOnlyUncontrolledCopiesMayRemain,
}

impl ProtectedDeletionReceiptV1 {
    pub fn encode(&self) -> Result<Vec<u8>, ProtectedStoreError> {
        self.validate()?;
        canonical(self, ProtectedStoreError::InvalidDeletionReceipt)
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, ProtectedStoreError> {
        let receipt: Self = serde_json::from_slice(encoded)
            .map_err(|_| ProtectedStoreError::InvalidDeletionReceipt)?;
        receipt.validate()?;
        if receipt.encode()? != encoded {
            return Err(ProtectedStoreError::NonCanonicalMetadata);
        }
        Ok(receipt)
    }

    pub(crate) fn validate(&self) -> Result<(), ProtectedStoreError> {
        if self.version != DELETION_RECEIPT_VERSION
            || !valid_digest(&self.plan_digest)
            || !valid_digest(&self.envelope_digest)
            || !valid_prefixed_id(&self.protected_id, "protected")
        {
            return Err(ProtectedStoreError::InvalidDeletionReceipt);
        }
        Ok(())
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DeletionState {
    Prepared,
    BlobUnlinked,
    TransactionUnlinked,
    ReferenceRemoved,
    KeyDeleted,
}

#[cfg(unix)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeletionJournalV1 {
    pub version: String,
    pub state: DeletionState,
    pub plan_digest: String,
    pub plan: ProtectedDeletionPlanV1,
    pub wrapping_key: Option<WrappingKeyDeletionStatus>,
}

#[cfg(unix)]
impl DeletionJournalV1 {
    pub(crate) fn encode(&self) -> Result<Vec<u8>, ProtectedStoreError> {
        self.validate()?;
        canonical(self, ProtectedStoreError::InvalidDeletionPlan)
    }

    pub(crate) fn decode(encoded: &[u8]) -> Result<Self, ProtectedStoreError> {
        let journal: Self = serde_json::from_slice(encoded)
            .map_err(|_| ProtectedStoreError::InvalidDeletionPlan)?;
        journal.validate()?;
        if journal.encode()? != encoded {
            return Err(ProtectedStoreError::NonCanonicalMetadata);
        }
        Ok(journal)
    }

    fn validate(&self) -> Result<(), ProtectedStoreError> {
        self.plan.validate()?;
        let key_state_matches = match self.state {
            DeletionState::KeyDeleted => self.wrapping_key.is_some(),
            _ => self.wrapping_key.is_none(),
        };
        if self.version != DELETION_JOURNAL_VERSION
            || !valid_digest(&self.plan_digest)
            || !self.plan.references.is_empty()
            || !key_state_matches
        {
            return Err(ProtectedStoreError::InvalidDeletionPlan);
        }
        Ok(())
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PutState {
    Pending,
    Committed,
}

#[cfg(unix)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PutJournalV1 {
    pub version: String,
    pub state: PutState,
    pub envelope_digest: String,
    pub envelope_bytes: u64,
    pub installation_id: String,
    pub protected_id: String,
    pub wrapping_key_id: String,
}

#[cfg(unix)]
impl PutJournalV1 {
    pub(crate) fn encode(&self) -> Result<Vec<u8>, ProtectedStoreError> {
        self.validate()?;
        canonical(self, ProtectedStoreError::InvalidTransaction)
    }

    pub(crate) fn decode(encoded: &[u8]) -> Result<Self, ProtectedStoreError> {
        let journal: Self =
            serde_json::from_slice(encoded).map_err(|_| ProtectedStoreError::InvalidTransaction)?;
        journal.validate()?;
        if journal.encode()? != encoded {
            return Err(ProtectedStoreError::NonCanonicalMetadata);
        }
        Ok(journal)
    }

    fn validate(&self) -> Result<(), ProtectedStoreError> {
        if self.version != PUT_JOURNAL_VERSION
            || !valid_digest(&self.envelope_digest)
            || self.envelope_bytes == 0
            || !valid_prefixed_id(&self.installation_id, "installation")
            || !valid_prefixed_id(&self.protected_id, "protected")
            || !valid_prefixed_id(&self.wrapping_key_id, "key")
        {
            return Err(ProtectedStoreError::InvalidTransaction);
        }
        Ok(())
    }
}

#[cfg(unix)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct KeyReferenceV1 {
    pub version: String,
    pub envelope_digest: String,
    pub installation_id: String,
    pub protected_id: String,
    pub wrapping_key_id: String,
}

#[cfg(unix)]
impl KeyReferenceV1 {
    fn validate(&self) -> Result<(), ProtectedStoreError> {
        if self.version != KEY_REFERENCE_VERSION
            || !valid_digest(&self.envelope_digest)
            || !valid_prefixed_id(&self.installation_id, "installation")
            || !valid_prefixed_id(&self.protected_id, "protected")
            || !valid_prefixed_id(&self.wrapping_key_id, "key")
        {
            return Err(ProtectedStoreError::InvalidTransaction);
        }
        Ok(())
    }
}

#[cfg(unix)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct KeyReferenceIndexV1 {
    pub version: String,
    pub installation_id: String,
    pub wrapping_key_id: String,
    pub entries: Vec<KeyReferenceV1>,
}

#[cfg(unix)]
impl KeyReferenceIndexV1 {
    pub(crate) fn encode(&self) -> Result<Vec<u8>, ProtectedStoreError> {
        self.validate()?;
        canonical(self, ProtectedStoreError::InvalidTransaction)
    }

    pub(crate) fn decode(encoded: &[u8]) -> Result<Self, ProtectedStoreError> {
        let index: Self =
            serde_json::from_slice(encoded).map_err(|_| ProtectedStoreError::InvalidTransaction)?;
        index.validate()?;
        if index.encode()? != encoded {
            return Err(ProtectedStoreError::NonCanonicalMetadata);
        }
        Ok(index)
    }

    fn validate(&self) -> Result<(), ProtectedStoreError> {
        if self.version != KEY_REFERENCE_INDEX_VERSION
            || !valid_prefixed_id(&self.installation_id, "installation")
            || !valid_prefixed_id(&self.wrapping_key_id, "key")
            || self.entries.is_empty()
        {
            return Err(ProtectedStoreError::InvalidTransaction);
        }
        let mut previous = None;
        for entry in &self.entries {
            entry.validate()?;
            if entry.installation_id != self.installation_id
                || entry.wrapping_key_id != self.wrapping_key_id
                || previous.is_some_and(|digest| digest >= entry.envelope_digest.as_str())
            {
                return Err(ProtectedStoreError::InvalidTransaction);
            }
            previous = Some(entry.envelope_digest.as_str());
        }
        Ok(())
    }
}

pub(crate) fn valid_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    })
}

pub(crate) fn valid_prefixed_id(value: &str, prefix: &str) -> bool {
    let Some(hex) = value
        .strip_prefix(prefix)
        .and_then(|rest| rest.strip_prefix('_'))
    else {
        return false;
    };
    hex.len() == 64
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_reference_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
}

fn canonical<T: Serialize>(
    value: &T,
    error: ProtectedStoreError,
) -> Result<Vec<u8>, ProtectedStoreError> {
    serde_jcs::to_vec(value).map_err(|_| error)
}
