mod backend;
mod envelope;
mod storage;

pub use backend::{BackendKind, BackendReadiness, KeyLocator, SystemKeyStore, WrappingKeyStore};
pub use envelope::{
    ALGORITHM, DATA_CLASS, ENVELOPE_VERSION, ProtectedEnvelopeV2, new_installation_id, new_key_id,
    open, rewrap, seal,
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
    #[error("the protected store could not complete a local storage operation")]
    StorageIo,
}

#[cfg(test)]
mod tests;
