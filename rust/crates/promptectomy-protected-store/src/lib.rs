mod backend;
mod envelope;
mod records;
mod storage;

pub use backend::{BackendKind, BackendReadiness, KeyLocator, SystemKeyStore, WrappingKeyStore};
pub use envelope::{
    ALGORITHM, DATA_CLASS, ENVELOPE_VERSION, ProtectedEnvelopeV2, new_installation_id, new_key_id,
    open, rewrap, seal,
};
pub use records::{
    BACKUP_MANIFEST_VERSION, BackupVerificationReceipt, BlobDeletionStatus, DELETION_PLAN_VERSION,
    DELETION_RECEIPT_VERSION, DeletionErasureScope, DeletionReference, DeletionReferenceKind,
    ProtectedBackupEntry, ProtectedBackupManifestV1, ProtectedDeletionPlanV1,
    ProtectedDeletionReceiptV1, WrappingKeyDeletionStatus,
};
pub use storage::{ProtectedBlobStore, StoredEnvelope};

use thiserror::Error;

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ProtectedStoreError {
    #[error("the protected-store identifier is invalid")]
    InvalidIdentifier,
    #[error("the protected envelope is invalid")]
    InvalidEnvelope,
    #[error("the protected envelope is not canonical JSON")]
    NonCanonicalEnvelope,
    #[error("the protected metadata is not canonical JSON")]
    NonCanonicalMetadata,
    #[error("the protected content exceeds the accepted byte limit")]
    ContentTooLarge,
    #[error("the platform has no accepted protected key store")]
    UnsupportedPlatform,
    #[error("the protected key store is unavailable")]
    BackendUnavailable,
    #[error("the protected key store denied access")]
    AccessDenied,
    #[error("the protected wrapping key does not exist")]
    KeyMissing,
    #[error("the protected wrapping key has an invalid value")]
    InvalidKeyValue,
    #[error("the protected wrapping key conflicts with an existing key")]
    KeyConflict,
    #[error("the protected key-store lookup was ambiguous")]
    AmbiguousKey,
    #[error("the protected envelope failed authentication")]
    AuthenticationFailed,
    #[error("the protected storage root is unsafe")]
    UnsafeStorageRoot,
    #[error("private protected storage is unsupported on this platform")]
    StoragePermissionsUnsupported,
    #[error("the protected blob conflicts with existing storage")]
    StorageConflict,
    #[error("the protected blob is missing")]
    BlobMissing,
    #[error("the protected blob failed its storage digest check")]
    BlobTampered,
    #[error("the protected put transaction is invalid")]
    InvalidTransaction,
    #[error("the protected backup manifest is invalid")]
    InvalidBackupManifest,
    #[error("the protected backup failed verification")]
    BackupVerificationFailed,
    #[error("the protected deletion plan is invalid")]
    InvalidDeletionPlan,
    #[error("the protected deletion receipt is invalid")]
    InvalidDeletionReceipt,
    #[error("the protected blob still has references")]
    BlobReferenced,
    #[error("the protected wrapping key is still present")]
    KeyDeletionUnverified,
    #[error("the protected deletion tombstone no longer matches storage state")]
    DeletionStateChanged,
    #[error("the protected store could not complete a local storage operation")]
    StorageIo,
}

#[cfg(test)]
mod tests;
