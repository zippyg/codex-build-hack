use std::path::PathBuf;

#[cfg(unix)]
use std::fs::File;
#[cfg(unix)]
use std::io::{Read as _, Write as _};
#[cfg(unix)]
use std::os::fd::OwnedFd;
#[cfg(unix)]
use std::path::Component;
#[cfg(unix)]
use std::path::Path;
#[cfg(unix)]
use std::sync::{Arc, Mutex, MutexGuard};

#[cfg(unix)]
use rustix::fs::{
    AtFlags, FileType, Mode, OFlags, fstat, fsync, linkat, mkdirat, openat, renameat, unlinkat,
};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use rustix::fs::{FlockOperation, flock};
#[cfg(unix)]
use sha2::{Digest as _, Sha256};

#[cfg(unix)]
use crate::records::{
    BACKUP_ACKNOWLEDGMENT_VERSION, BACKUP_REFERENCE_INDEX_VERSION, BackupAcknowledgmentState,
    BackupAcknowledgmentV1, BackupReferenceIndexV1, DELETION_JOURNAL_VERSION, DeletionJournalV1,
    DeletionState, KEY_REFERENCE_INDEX_VERSION, KEY_REFERENCE_VERSION, KeyReferenceIndexV1,
    KeyReferenceV1, PUT_JOURNAL_VERSION, PutJournalV1, PutState, valid_digest,
};
#[cfg(unix)]
use crate::{
    BACKUP_MANIFEST_VERSION, BackendReadiness, BlobDeletionStatus, DELETION_PLAN_VERSION,
    DELETION_RECEIPT_VERSION, DeletionErasureScope, KeyLocator, ProtectedBackupEntry,
    WrappingKeyDeletionStatus, open,
};
use crate::{
    BackupVerificationReceipt, DeletionReference, ProtectedBackupManifestV1,
    ProtectedDeletionPlanV1, ProtectedDeletionReceiptV1, ProtectedEnvelopeV2, ProtectedStoreError,
    WrappingKeyStore,
};

#[cfg(unix)]
const MAX_ENVELOPE_BYTES: u64 = 96 * 1024 * 1024;
#[cfg(unix)]
const MAX_METADATA_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Eq, PartialEq)]
pub struct StoredEnvelope {
    pub envelope_digest: String,
    pub(crate) path: PathBuf,
}

impl std::fmt::Debug for StoredEnvelope {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StoredEnvelope")
            .field("envelope_digest", &self.envelope_digest)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub struct ProtectedBlobStore {
    #[cfg(unix)]
    root: PathBuf,
    #[cfg(unix)]
    root_fd: Arc<OwnedFd>,
    #[cfg(unix)]
    lock_fd: Arc<OwnedFd>,
    #[cfg(unix)]
    local_lock: Arc<Mutex<()>>,
}

impl std::fmt::Debug for ProtectedBlobStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProtectedBlobStore")
            .finish_non_exhaustive()
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DeletionCrashPoint {
    BlobUnlinked,
    TransactionUnlinked,
    ReferenceRemoved,
    KeyDeleted,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PutCrashPoint {
    JournalWritten,
    BlobWritten,
    ReferenceWritten,
    BlobPublished,
    JournalCommitted,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BackupAcknowledgmentCrashPoint {
    EntryValidated(usize),
    CommitRenamed,
    CommitDurabilityRollbackAndReadFailed,
}

#[cfg(unix)]
struct PreparedBackupManifest {
    manifest: ProtectedBackupManifestV1,
    manifest_digest: String,
    pin_records: Vec<(String, Vec<u8>)>,
    maximum_metadata_bytes: u64,
}

#[cfg(unix)]
struct OperationGuard<'a> {
    _local: MutexGuard<'a, ()>,
    lock_fd: &'a OwnedFd,
}

#[cfg(unix)]
impl Drop for OperationGuard<'_> {
    fn drop(&mut self) {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let _ = flock(self.lock_fd, FlockOperation::Unlock);
    }
}

impl ProtectedBlobStore {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, ProtectedStoreError> {
        let root = root.into();
        #[cfg(unix)]
        {
            let root_fd = open_private_root(&root)?;
            let lock_fd = open_operation_lock(&root_fd)?;
            Ok(Self {
                root,
                root_fd: Arc::new(root_fd),
                lock_fd: Arc::new(lock_fd),
                local_lock: Arc::new(Mutex::new(())),
            })
        }
        #[cfg(not(unix))]
        {
            let _ = root;
            Err(ProtectedStoreError::StoragePermissionsUnsupported)
        }
    }

    pub fn put(
        &self,
        envelope: &ProtectedEnvelopeV2,
    ) -> Result<StoredEnvelope, ProtectedStoreError> {
        #[cfg(unix)]
        {
            let _operation = self.acquire_operation()?;
            self.put_unix(envelope, None)
        }
        #[cfg(not(unix))]
        {
            let _ = envelope;
            Err(ProtectedStoreError::StoragePermissionsUnsupported)
        }
    }

    #[cfg(all(test, unix))]
    pub(crate) fn put_with_crash(
        &self,
        envelope: &ProtectedEnvelopeV2,
        crash: PutCrashPoint,
    ) -> Result<StoredEnvelope, ProtectedStoreError> {
        let _operation = self.acquire_operation()?;
        self.put_unix(envelope, Some(crash))
    }

    pub fn read(&self, envelope_digest: &str) -> Result<ProtectedEnvelopeV2, ProtectedStoreError> {
        #[cfg(unix)]
        {
            let _operation = self.acquire_operation()?;
            self.read_encoded_unix(envelope_digest)
                .map(|(_, envelope)| envelope)
        }
        #[cfg(not(unix))]
        {
            let _ = envelope_digest;
            Err(ProtectedStoreError::StoragePermissionsUnsupported)
        }
    }

    pub fn create_backup_manifest(
        &self,
        envelope_digests: &[String],
    ) -> Result<ProtectedBackupManifestV1, ProtectedStoreError> {
        #[cfg(unix)]
        {
            let _operation = self.acquire_operation()?;
            self.create_backup_manifest_unix(envelope_digests, MAX_METADATA_BYTES)
        }
        #[cfg(not(unix))]
        {
            let _ = envelope_digests;
            Err(ProtectedStoreError::StoragePermissionsUnsupported)
        }
    }

    #[cfg(all(test, unix))]
    pub(crate) fn create_backup_manifest_with_metadata_limit(
        &self,
        envelope_digests: &[String],
        metadata_limit: u64,
    ) -> Result<ProtectedBackupManifestV1, ProtectedStoreError> {
        let _operation = self.acquire_operation()?;
        self.create_backup_manifest_unix(envelope_digests, metadata_limit)
    }

    #[cfg(all(test, unix))]
    pub(crate) fn backup_manifest_metadata_requirement(
        &self,
        envelope_digests: &[String],
    ) -> Result<u64, ProtectedStoreError> {
        let _operation = self.acquire_operation()?;
        Ok(self
            .prepare_backup_manifest(envelope_digests)?
            .maximum_metadata_bytes)
    }

    pub fn acknowledge_backup_removal(
        &self,
        manifest: &ProtectedBackupManifestV1,
    ) -> Result<bool, ProtectedStoreError> {
        #[cfg(unix)]
        {
            let _operation = self.acquire_operation()?;
            self.acknowledge_backup_removal_unix(manifest, None)
        }
        #[cfg(not(unix))]
        {
            let _ = manifest;
            Err(ProtectedStoreError::StoragePermissionsUnsupported)
        }
    }

    #[cfg(all(test, unix))]
    pub(crate) fn acknowledge_backup_removal_with_crash(
        &self,
        manifest: &ProtectedBackupManifestV1,
        crash: BackupAcknowledgmentCrashPoint,
    ) -> Result<bool, ProtectedStoreError> {
        let _operation = self.acquire_operation()?;
        self.acknowledge_backup_removal_unix(manifest, Some(crash))
    }

    pub fn verify_backup(
        &self,
        manifest: &ProtectedBackupManifestV1,
        key_store: &impl WrappingKeyStore,
    ) -> Result<BackupVerificationReceipt, ProtectedStoreError> {
        #[cfg(unix)]
        {
            let _operation = self.acquire_operation()?;
            manifest.validate()?;
            let mut total_envelope_bytes = 0_u64;
            for entry in &manifest.entries {
                let (encoded, envelope) = self.read_encoded_unix(&entry.envelope_digest)?;
                if envelope.installation_id != manifest.installation_id
                    || envelope.protected_id != entry.protected_id
                    || envelope.wrapping_key_id != entry.wrapping_key_id
                    || u64::try_from(encoded.len()).ok() != Some(entry.envelope_bytes)
                {
                    return Err(ProtectedStoreError::BackupVerificationFailed);
                }
                let plaintext = open(&envelope, key_store)?;
                drop(plaintext);
                total_envelope_bytes = total_envelope_bytes
                    .checked_add(entry.envelope_bytes)
                    .ok_or(ProtectedStoreError::ContentTooLarge)?;
            }
            let encoded = manifest.encode()?;
            Ok(BackupVerificationReceipt {
                manifest_digest: digest(&encoded),
                envelope_count: u64::try_from(manifest.entries.len())
                    .map_err(|_| ProtectedStoreError::ContentTooLarge)?,
                total_envelope_bytes,
                every_envelope_decryptable: true,
            })
        }
        #[cfg(not(unix))]
        {
            let _ = (manifest, key_store);
            Err(ProtectedStoreError::StoragePermissionsUnsupported)
        }
    }

    pub fn plan_deletion(
        &self,
        envelope_digest: &str,
        references: Vec<DeletionReference>,
    ) -> Result<ProtectedDeletionPlanV1, ProtectedStoreError> {
        #[cfg(unix)]
        {
            let _operation = self.acquire_operation()?;
            self.plan_deletion_unix(envelope_digest, references)
        }
        #[cfg(not(unix))]
        {
            let _ = (envelope_digest, references);
            Err(ProtectedStoreError::StoragePermissionsUnsupported)
        }
    }

    pub fn execute_deletion(
        &self,
        plan: &ProtectedDeletionPlanV1,
        key_store: &impl WrappingKeyStore,
    ) -> Result<ProtectedDeletionReceiptV1, ProtectedStoreError> {
        #[cfg(unix)]
        {
            let _operation = self.acquire_operation()?;
            self.execute_deletion_unix(plan, key_store, None)
        }
        #[cfg(not(unix))]
        {
            let _ = (plan, key_store);
            Err(ProtectedStoreError::StoragePermissionsUnsupported)
        }
    }

    #[cfg(all(test, unix))]
    pub(crate) fn execute_deletion_with_crash(
        &self,
        plan: &ProtectedDeletionPlanV1,
        key_store: &impl WrappingKeyStore,
        crash: DeletionCrashPoint,
    ) -> Result<ProtectedDeletionReceiptV1, ProtectedStoreError> {
        let _operation = self.acquire_operation()?;
        self.execute_deletion_unix(plan, key_store, Some(crash))
    }

    #[cfg(unix)]
    fn acquire_operation(&self) -> Result<OperationGuard<'_>, ProtectedStoreError> {
        let local = self
            .local_lock
            .lock()
            .map_err(|_| ProtectedStoreError::StorageIo)?;
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        flock(&self.lock_fd, FlockOperation::LockExclusive)
            .map_err(|_| ProtectedStoreError::StorageIo)?;
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        return Err(ProtectedStoreError::StoragePermissionsUnsupported);
        Ok(OperationGuard {
            _local: local,
            lock_fd: &self.lock_fd,
        })
    }

    #[cfg(unix)]
    fn create_backup_manifest_unix(
        &self,
        envelope_digests: &[String],
        metadata_limit: u64,
    ) -> Result<ProtectedBackupManifestV1, ProtectedStoreError> {
        let prepared = self.prepare_backup_manifest(envelope_digests)?;
        if prepared.maximum_metadata_bytes > metadata_limit
            || prepared.maximum_metadata_bytes > MAX_METADATA_BYTES
        {
            return Err(ProtectedStoreError::ContentTooLarge);
        }
        self.reset_backup_acknowledgment(&prepared.manifest_digest)?;
        for (envelope_digest, encoded) in &prepared.pin_records {
            let hex_digest = digest_hex(envelope_digest)?;
            let directory = self.open_digest_directory("backup-references", hex_digest, true)?;
            write_record_at(&directory, &metadata_name(hex_digest), encoded)?;
        }
        Ok(prepared.manifest)
    }

    #[cfg(unix)]
    fn prepare_backup_manifest(
        &self,
        envelope_digests: &[String],
    ) -> Result<PreparedBackupManifest, ProtectedStoreError> {
        let mut entries = Vec::with_capacity(envelope_digests.len());
        let mut installation_id = None;
        for envelope_digest in envelope_digests {
            let (encoded, envelope) = self.read_encoded_unix(envelope_digest)?;
            match &installation_id {
                Some(expected) if expected != &envelope.installation_id => {
                    return Err(ProtectedStoreError::InvalidBackupManifest);
                }
                None => installation_id = Some(envelope.installation_id.clone()),
                _ => {}
            }
            entries.push(ProtectedBackupEntry {
                envelope_digest: envelope_digest.clone(),
                envelope_bytes: u64::try_from(encoded.len())
                    .map_err(|_| ProtectedStoreError::ContentTooLarge)?,
                protected_id: envelope.protected_id,
                wrapping_key_id: envelope.wrapping_key_id,
            });
        }
        entries.sort_by(|left, right| left.envelope_digest.cmp(&right.envelope_digest));
        let manifest = ProtectedBackupManifestV1 {
            version: BACKUP_MANIFEST_VERSION.to_owned(),
            installation_id: installation_id.ok_or(ProtectedStoreError::InvalidBackupManifest)?,
            entries,
        };
        manifest.validate()?;
        let manifest_digest = digest(&manifest.encode()?);
        let mut acknowledgment = BackupAcknowledgmentV1 {
            version: BACKUP_ACKNOWLEDGMENT_VERSION.to_owned(),
            state: BackupAcknowledgmentState::Prepared,
            manifest: manifest.clone(),
        };
        let mut maximum_metadata_bytes = u64::try_from(acknowledgment.encode()?.len())
            .map_err(|_| ProtectedStoreError::ContentTooLarge)?;
        acknowledgment.state = BackupAcknowledgmentState::Committed;
        maximum_metadata_bytes = maximum_metadata_bytes.max(
            u64::try_from(acknowledgment.encode()?.len())
                .map_err(|_| ProtectedStoreError::ContentTooLarge)?,
        );

        let mut pin_records = Vec::with_capacity(manifest.entries.len());
        for entry in &manifest.entries {
            let mut index = self
                .backup_reference_index_if_present(&entry.envelope_digest)?
                .unwrap_or_else(|| BackupReferenceIndexV1 {
                    version: BACKUP_REFERENCE_INDEX_VERSION.to_owned(),
                    envelope_digest: entry.envelope_digest.clone(),
                    manifest_digests: Vec::new(),
                });
            match index
                .manifest_digests
                .binary_search_by(|value| value.as_str().cmp(manifest_digest.as_str()))
            {
                Ok(_) => {}
                Err(position) => index
                    .manifest_digests
                    .insert(position, manifest_digest.clone()),
            }
            let encoded = index.encode()?;
            maximum_metadata_bytes = maximum_metadata_bytes.max(
                u64::try_from(encoded.len()).map_err(|_| ProtectedStoreError::ContentTooLarge)?,
            );
            pin_records.push((entry.envelope_digest.clone(), encoded));
        }
        Ok(PreparedBackupManifest {
            manifest,
            manifest_digest,
            pin_records,
            maximum_metadata_bytes,
        })
    }

    #[cfg(unix)]
    fn plan_deletion_unix(
        &self,
        envelope_digest: &str,
        mut references: Vec<DeletionReference>,
    ) -> Result<ProtectedDeletionPlanV1, ProtectedStoreError> {
        let (_, envelope) = self.read_encoded_unix(envelope_digest)?;
        references.extend(self.same_key_peer_references(
            &envelope.installation_id,
            &envelope.wrapping_key_id,
            envelope_digest,
        )?);
        references.extend(self.backup_references(envelope_digest)?);
        references.sort();
        references.dedup();
        let plan = ProtectedDeletionPlanV1 {
            version: DELETION_PLAN_VERSION.to_owned(),
            envelope_digest: envelope_digest.to_owned(),
            installation_id: envelope.installation_id,
            protected_id: envelope.protected_id,
            wrapping_key_id: envelope.wrapping_key_id,
            references,
        };
        plan.validate()?;
        Ok(plan)
    }

    #[cfg(unix)]
    fn put_unix(
        &self,
        envelope: &ProtectedEnvelopeV2,
        crash: Option<PutCrashPoint>,
    ) -> Result<StoredEnvelope, ProtectedStoreError> {
        let encoded = envelope.encode()?;
        let envelope_bytes =
            u64::try_from(encoded.len()).map_err(|_| ProtectedStoreError::ContentTooLarge)?;
        let envelope_digest = digest(&encoded);
        let hex_digest = digest_hex(&envelope_digest)?.to_owned();
        let blob_directory = self.open_digest_directory("sha256", &hex_digest, true)?;
        let journal_directory = self.open_digest_directory("transactions", &hex_digest, true)?;
        let destination = blob_name(&hex_digest);
        let pending = pending_blob_name(&hex_digest);
        let journal_name = metadata_name(&hex_digest);
        let journal = PutJournalV1 {
            version: PUT_JOURNAL_VERSION.to_owned(),
            state: PutState::Pending,
            envelope_digest: envelope_digest.clone(),
            envelope_bytes,
            installation_id: envelope.installation_id.clone(),
            protected_id: envelope.protected_id.clone(),
            wrapping_key_id: envelope.wrapping_key_id.clone(),
        };

        if let Some(encoded) = read_optional_at(
            &journal_directory,
            &journal_name,
            MAX_METADATA_BYTES,
            ProtectedStoreError::InvalidTransaction,
        )? {
            let existing = PutJournalV1::decode(&encoded)?;
            verify_put_journal(&existing, &journal)?;
        } else {
            write_record_at(&journal_directory, &journal_name, &journal.encode()?)?;
        }
        interrupt_put(crash, PutCrashPoint::JournalWritten)?;

        if let Some(existing) = read_optional_at(
            &blob_directory,
            &destination,
            MAX_ENVELOPE_BYTES,
            ProtectedStoreError::BlobTampered,
        )? {
            verify_blob(&existing, &envelope_digest)?;
            if let Some(pending_bytes) = read_optional_at(
                &blob_directory,
                &pending,
                MAX_ENVELOPE_BYTES,
                ProtectedStoreError::BlobTampered,
            )? {
                verify_blob(&pending_bytes, &envelope_digest)?;
                unlink_file_at(&blob_directory, &pending)?;
                fsync(&blob_directory).map_err(|_| ProtectedStoreError::StorageIo)?;
            }
        } else if !create_file_at(&blob_directory, &pending, &encoded)? {
            let existing = read_required_at(
                &blob_directory,
                &pending,
                MAX_ENVELOPE_BYTES,
                ProtectedStoreError::BlobTampered,
            )?;
            verify_blob(&existing, &envelope_digest)?;
        } else {
            fsync(&blob_directory).map_err(|_| ProtectedStoreError::StorageIo)?;
        }
        interrupt_put(crash, PutCrashPoint::BlobWritten)?;

        self.write_key_reference(envelope, &envelope_digest)?;
        interrupt_put(crash, PutCrashPoint::ReferenceWritten)?;

        if read_optional_at(
            &blob_directory,
            &destination,
            MAX_ENVELOPE_BYTES,
            ProtectedStoreError::BlobTampered,
        )?
        .is_none()
        {
            publish_pending(&blob_directory, &pending, &destination, &envelope_digest)?;
        }
        interrupt_put(crash, PutCrashPoint::BlobPublished)?;

        Self::commit_journal(&journal_directory, &journal_name, journal)?;
        interrupt_put(crash, PutCrashPoint::JournalCommitted)?;
        Ok(self.stored_envelope(envelope_digest, &hex_digest))
    }

    #[cfg(unix)]
    fn read_encoded_unix(
        &self,
        envelope_digest: &str,
    ) -> Result<(Vec<u8>, ProtectedEnvelopeV2), ProtectedStoreError> {
        let hex_digest = digest_hex(envelope_digest)?;
        let blob_directory = self.open_digest_directory("sha256", hex_digest, false)?;
        let destination = blob_name(hex_digest);
        let pending = pending_blob_name(hex_digest);
        let final_bytes = read_optional_at(
            &blob_directory,
            &destination,
            MAX_ENVELOPE_BYTES,
            ProtectedStoreError::BlobTampered,
        )?;
        let final_present = final_bytes.is_some();
        let journal_directory = match self.open_digest_directory("transactions", hex_digest, false)
        {
            Ok(directory) => directory,
            Err(ProtectedStoreError::BlobMissing) if final_bytes.is_none() => {
                return Err(ProtectedStoreError::BlobMissing);
            }
            Err(ProtectedStoreError::BlobMissing) => {
                return Err(ProtectedStoreError::InvalidTransaction);
            }
            Err(error) => return Err(error),
        };
        let journal_name = metadata_name(hex_digest);
        let journal_bytes = read_optional_at(
            &journal_directory,
            &journal_name,
            MAX_METADATA_BYTES,
            ProtectedStoreError::InvalidTransaction,
        )?;
        let mut journal = if let Some(journal_bytes) = journal_bytes {
            PutJournalV1::decode(&journal_bytes)?
        } else if final_bytes.is_none()
            && read_optional_at(
                &blob_directory,
                &pending,
                MAX_ENVELOPE_BYTES,
                ProtectedStoreError::BlobTampered,
            )?
            .is_none()
        {
            return Err(ProtectedStoreError::BlobMissing);
        } else {
            return Err(ProtectedStoreError::InvalidTransaction);
        };
        if journal.envelope_digest != envelope_digest {
            return Err(ProtectedStoreError::InvalidTransaction);
        }
        if journal.state == PutState::Committed && !final_present {
            return Err(ProtectedStoreError::InvalidTransaction);
        }

        let encoded = if let Some(encoded) = final_bytes {
            encoded
        } else {
            read_required_at(
                &blob_directory,
                &pending,
                MAX_ENVELOPE_BYTES,
                ProtectedStoreError::BlobMissing,
            )?
        };
        verify_blob(&encoded, envelope_digest)?;
        let envelope = ProtectedEnvelopeV2::decode(&encoded)?;
        if journal.protected_id != envelope.protected_id
            || journal.installation_id != envelope.installation_id
            || journal.wrapping_key_id != envelope.wrapping_key_id
            || journal.envelope_bytes != u64::try_from(encoded.len()).unwrap_or(u64::MAX)
        {
            return Err(ProtectedStoreError::InvalidTransaction);
        }
        if journal.state == PutState::Committed {
            self.verify_key_reference(&envelope, envelope_digest)?;
        } else {
            self.write_key_reference(&envelope, envelope_digest)?;
        }
        if !final_present {
            publish_pending(&blob_directory, &pending, &destination, envelope_digest)?;
        }
        if journal.state == PutState::Pending {
            journal.state = PutState::Committed;
            write_record_at(&journal_directory, &journal_name, &journal.encode()?)?;
        }
        if read_optional_at(
            &blob_directory,
            &pending,
            MAX_ENVELOPE_BYTES,
            ProtectedStoreError::BlobTampered,
        )?
        .is_some()
        {
            publish_pending(&blob_directory, &pending, &destination, envelope_digest)?;
        }
        Ok((encoded, envelope))
    }

    #[cfg(unix)]
    #[allow(
        clippy::too_many_lines,
        reason = "the deletion transaction stays linear so its durable ordering is auditable"
    )]
    fn execute_deletion_unix(
        &self,
        plan: &ProtectedDeletionPlanV1,
        key_store: &impl WrappingKeyStore,
        crash: Option<DeletionCrashPoint>,
    ) -> Result<ProtectedDeletionReceiptV1, ProtectedStoreError> {
        plan.validate()?;
        self.ensure_no_backup_references(&plan.envelope_digest)?;
        if !plan.references.is_empty() {
            return Err(ProtectedStoreError::BlobReferenced);
        }
        let plan_encoded = plan.encode()?;
        let plan_digest = digest(&plan_encoded);
        let hex_digest = digest_hex(&plan.envelope_digest)?;
        let deletion_directory = self.open_digest_directory("deletions", hex_digest, true)?;
        let receipt_name = metadata_name(hex_digest);
        let pending_name = format!("{hex_digest}.pending.json");
        if let Some(encoded) = read_optional_at(
            &deletion_directory,
            &receipt_name,
            MAX_METADATA_BYTES,
            ProtectedStoreError::InvalidDeletionReceipt,
        )? {
            let receipt = ProtectedDeletionReceiptV1::decode(&encoded)?;
            verify_receipt(&receipt, plan, &plan_digest)?;
            self.verify_deleted_state(plan, key_store)?;
            Self::remove_matching_deletion_journal(
                &deletion_directory,
                &pending_name,
                plan,
                &plan_digest,
            )?;
            return Ok(receipt);
        }
        let mut journal = if let Some(encoded) = read_optional_at(
            &deletion_directory,
            &pending_name,
            MAX_METADATA_BYTES,
            ProtectedStoreError::InvalidDeletionPlan,
        )? {
            let journal = DeletionJournalV1::decode(&encoded)?;
            if journal.plan != *plan || journal.plan_digest != plan_digest {
                return Err(ProtectedStoreError::InvalidDeletionPlan);
            }
            journal
        } else {
            self.ensure_deletion_reference_safety(plan, false)?;
            let (_, envelope) = self.read_encoded_unix(&plan.envelope_digest)?;
            if envelope.installation_id != plan.installation_id
                || envelope.protected_id != plan.protected_id
                || envelope.wrapping_key_id != plan.wrapping_key_id
            {
                return Err(ProtectedStoreError::InvalidDeletionPlan);
            }
            let journal = DeletionJournalV1 {
                version: DELETION_JOURNAL_VERSION.to_owned(),
                state: DeletionState::Prepared,
                plan_digest: plan_digest.clone(),
                plan: plan.clone(),
                wrapping_key: None,
            };
            write_record_at(&deletion_directory, &pending_name, &journal.encode()?)?;
            journal
        };
        let allow_missing_reference = journal.state >= DeletionState::TransactionUnlinked;
        self.ensure_no_backup_references(&plan.envelope_digest)?;
        self.ensure_deletion_reference_safety(plan, allow_missing_reference)?;

        if journal.state < DeletionState::BlobUnlinked {
            self.unlink_deletion_blobs(hex_digest, &plan.envelope_digest)?;
            interrupt_deletion(crash, DeletionCrashPoint::BlobUnlinked)?;
            Self::checkpoint_deletion(
                &deletion_directory,
                &pending_name,
                &mut journal,
                DeletionState::BlobUnlinked,
                None,
            )?;
        } else {
            self.verify_blobs_absent(hex_digest)?;
        }

        if journal.state < DeletionState::TransactionUnlinked {
            self.unlink_put_transaction(hex_digest)?;
            interrupt_deletion(crash, DeletionCrashPoint::TransactionUnlinked)?;
            Self::checkpoint_deletion(
                &deletion_directory,
                &pending_name,
                &mut journal,
                DeletionState::TransactionUnlinked,
                None,
            )?;
        } else {
            self.verify_put_transaction_absent(hex_digest)?;
        }

        if journal.state < DeletionState::ReferenceRemoved {
            self.remove_key_reference_idempotent(plan)?;
            interrupt_deletion(crash, DeletionCrashPoint::ReferenceRemoved)?;
            Self::checkpoint_deletion(
                &deletion_directory,
                &pending_name,
                &mut journal,
                DeletionState::ReferenceRemoved,
                None,
            )?;
        } else {
            self.verify_key_reference_absent(plan)?;
        }

        let locator = KeyLocator::new(&plan.installation_id, &plan.wrapping_key_id)?;
        let wrapping_key = if journal.state < DeletionState::KeyDeleted {
            let status = delete_wrapping_key(key_store, &locator)?;
            interrupt_deletion(crash, DeletionCrashPoint::KeyDeleted)?;
            Self::checkpoint_deletion(
                &deletion_directory,
                &pending_name,
                &mut journal,
                DeletionState::KeyDeleted,
                Some(status),
            )?;
            status
        } else {
            if key_store.readiness(&locator)? != BackendReadiness::KeyMissing {
                return Err(ProtectedStoreError::DeletionStateChanged);
            }
            journal
                .wrapping_key
                .ok_or(ProtectedStoreError::InvalidDeletionPlan)?
        };

        self.verify_deleted_state(plan, key_store)?;

        let receipt = ProtectedDeletionReceiptV1 {
            version: DELETION_RECEIPT_VERSION.to_owned(),
            plan_digest,
            envelope_digest: plan.envelope_digest.clone(),
            protected_id: plan.protected_id.clone(),
            wrapping_key,
            blob: BlobDeletionStatus::Unlinked,
            erasure_scope:
                DeletionErasureScope::LogicalStoreAndWrappingKeyOnlyUncontrolledCopiesMayRemain,
        };
        write_record_at(&deletion_directory, &receipt_name, &receipt.encode()?)?;
        unlink_file_if_present(&deletion_directory, &pending_name)?;
        fsync(&deletion_directory).map_err(|_| ProtectedStoreError::StorageIo)?;
        Ok(receipt)
    }

    #[cfg(unix)]
    fn checkpoint_deletion(
        directory: &OwnedFd,
        name: &str,
        journal: &mut DeletionJournalV1,
        state: DeletionState,
        wrapping_key: Option<WrappingKeyDeletionStatus>,
    ) -> Result<(), ProtectedStoreError> {
        journal.state = state;
        journal.wrapping_key = wrapping_key;
        write_record_at(directory, name, &journal.encode()?)
    }

    #[cfg(unix)]
    fn remove_matching_deletion_journal(
        directory: &OwnedFd,
        name: &str,
        plan: &ProtectedDeletionPlanV1,
        plan_digest: &str,
    ) -> Result<(), ProtectedStoreError> {
        let Some(encoded) = read_optional_at(
            directory,
            name,
            MAX_METADATA_BYTES,
            ProtectedStoreError::InvalidDeletionPlan,
        )?
        else {
            return Ok(());
        };
        let journal = DeletionJournalV1::decode(&encoded)?;
        if journal.plan != *plan || journal.plan_digest != plan_digest {
            return Err(ProtectedStoreError::InvalidDeletionPlan);
        }
        unlink_file_at(directory, name)?;
        fsync(directory).map_err(|_| ProtectedStoreError::StorageIo)
    }

    #[cfg(unix)]
    fn ensure_deletion_reference_safety(
        &self,
        plan: &ProtectedDeletionPlanV1,
        allow_missing_target: bool,
    ) -> Result<(), ProtectedStoreError> {
        let Some(index) = self.key_reference_index_if_present(&plan.wrapping_key_id)? else {
            return if allow_missing_target {
                Ok(())
            } else {
                Err(ProtectedStoreError::InvalidTransaction)
            };
        };
        if index.installation_id != plan.installation_id
            || index.wrapping_key_id != plan.wrapping_key_id
        {
            return Err(ProtectedStoreError::InvalidTransaction);
        }
        let mut target_present = false;
        for reference in index.entries {
            if reference.envelope_digest == plan.envelope_digest {
                if reference.protected_id != plan.protected_id {
                    return Err(ProtectedStoreError::InvalidTransaction);
                }
                target_present = true;
            } else {
                return Err(ProtectedStoreError::BlobReferenced);
            }
        }
        if target_present || allow_missing_target {
            Ok(())
        } else {
            Err(ProtectedStoreError::InvalidTransaction)
        }
    }

    #[cfg(unix)]
    fn unlink_deletion_blobs(
        &self,
        hex_digest: &str,
        envelope_digest: &str,
    ) -> Result<(), ProtectedStoreError> {
        let directory = match self.open_digest_directory("sha256", hex_digest, false) {
            Ok(directory) => directory,
            Err(ProtectedStoreError::BlobMissing) => return Ok(()),
            Err(error) => return Err(error),
        };
        for name in [blob_name(hex_digest), pending_blob_name(hex_digest)] {
            if let Some(encoded) = read_optional_at(
                &directory,
                &name,
                MAX_ENVELOPE_BYTES,
                ProtectedStoreError::BlobTampered,
            )? {
                verify_blob(&encoded, envelope_digest)?;
                unlink_file_at(&directory, &name)?;
            }
        }
        fsync(&directory).map_err(|_| ProtectedStoreError::StorageIo)
    }

    #[cfg(unix)]
    fn verify_blobs_absent(&self, hex_digest: &str) -> Result<(), ProtectedStoreError> {
        let directory = match self.open_digest_directory("sha256", hex_digest, false) {
            Ok(directory) => directory,
            Err(ProtectedStoreError::BlobMissing) => return Ok(()),
            Err(error) => return Err(error),
        };
        for name in [blob_name(hex_digest), pending_blob_name(hex_digest)] {
            if read_optional_at(
                &directory,
                &name,
                MAX_ENVELOPE_BYTES,
                ProtectedStoreError::BlobTampered,
            )?
            .is_some()
            {
                return Err(ProtectedStoreError::DeletionStateChanged);
            }
        }
        Ok(())
    }

    #[cfg(unix)]
    fn unlink_put_transaction(&self, hex_digest: &str) -> Result<(), ProtectedStoreError> {
        let directory = match self.open_digest_directory("transactions", hex_digest, false) {
            Ok(directory) => directory,
            Err(ProtectedStoreError::BlobMissing) => return Ok(()),
            Err(error) => return Err(error),
        };
        unlink_file_if_present(&directory, &metadata_name(hex_digest))?;
        fsync(&directory).map_err(|_| ProtectedStoreError::StorageIo)
    }

    #[cfg(unix)]
    fn verify_put_transaction_absent(&self, hex_digest: &str) -> Result<(), ProtectedStoreError> {
        let directory = match self.open_digest_directory("transactions", hex_digest, false) {
            Ok(directory) => directory,
            Err(ProtectedStoreError::BlobMissing) => return Ok(()),
            Err(error) => return Err(error),
        };
        if read_optional_at(
            &directory,
            &metadata_name(hex_digest),
            MAX_METADATA_BYTES,
            ProtectedStoreError::InvalidTransaction,
        )?
        .is_some()
        {
            return Err(ProtectedStoreError::DeletionStateChanged);
        }
        Ok(())
    }

    #[cfg(unix)]
    fn remove_key_reference_idempotent(
        &self,
        plan: &ProtectedDeletionPlanV1,
    ) -> Result<(), ProtectedStoreError> {
        let Some(mut index) = self.key_reference_index_if_present(&plan.wrapping_key_id)? else {
            return Ok(());
        };
        if index.installation_id != plan.installation_id
            || index.wrapping_key_id != plan.wrapping_key_id
        {
            return Err(ProtectedStoreError::InvalidTransaction);
        }
        let Ok(position) = index
            .entries
            .binary_search_by(|entry| entry.envelope_digest.as_str().cmp(&plan.envelope_digest))
        else {
            return Err(ProtectedStoreError::BlobReferenced);
        };
        if index.entries[position].protected_id != plan.protected_id {
            return Err(ProtectedStoreError::InvalidTransaction);
        }
        if index.entries.len() != 1 {
            return Err(ProtectedStoreError::BlobReferenced);
        }
        index.entries.remove(position);
        let directory = self.open_key_reference_directory(&plan.wrapping_key_id, false)?;
        unlink_file_at(&directory, &key_index_name(&plan.wrapping_key_id)?)?;
        fsync(&directory).map_err(|_| ProtectedStoreError::StorageIo)
    }

    #[cfg(unix)]
    fn verify_key_reference_absent(
        &self,
        plan: &ProtectedDeletionPlanV1,
    ) -> Result<(), ProtectedStoreError> {
        let Some(index) = self.key_reference_index_if_present(&plan.wrapping_key_id)? else {
            return Ok(());
        };
        if index.installation_id != plan.installation_id
            || index.wrapping_key_id != plan.wrapping_key_id
        {
            return Err(ProtectedStoreError::InvalidTransaction);
        }
        Err(ProtectedStoreError::DeletionStateChanged)
    }

    #[cfg(unix)]
    fn acknowledge_backup_removal_unix(
        &self,
        manifest: &ProtectedBackupManifestV1,
        crash: Option<BackupAcknowledgmentCrashPoint>,
    ) -> Result<bool, ProtectedStoreError> {
        manifest.validate()?;
        let manifest_digest = digest(&manifest.encode()?);
        if self
            .backup_acknowledgment_if_present(&manifest_digest)?
            .is_some_and(|acknowledgment| {
                acknowledgment.state == BackupAcknowledgmentState::Committed
                    && acknowledgment.manifest == *manifest
            })
        {
            return Ok(false);
        }
        for (position, entry) in manifest.entries.iter().enumerate() {
            let Some(index) = self.backup_reference_index_if_present(&entry.envelope_digest)?
            else {
                return Ok(false);
            };
            if index
                .manifest_digests
                .binary_search_by(|digest| digest.as_str().cmp(manifest_digest.as_str()))
                .is_err()
            {
                return Ok(false);
            }
            interrupt_backup_acknowledgment(
                crash,
                BackupAcknowledgmentCrashPoint::EntryValidated(position),
            )?;
        }

        let directory = self.open_digest_directory(
            "backup-acknowledgments",
            digest_hex(&manifest_digest)?,
            true,
        )?;
        let name = metadata_name(digest_hex(&manifest_digest)?);
        let mut acknowledgment = BackupAcknowledgmentV1 {
            version: BACKUP_ACKNOWLEDGMENT_VERSION.to_owned(),
            state: BackupAcknowledgmentState::Prepared,
            manifest: manifest.clone(),
        };
        if let Some(existing) = read_optional_at(
            &directory,
            &name,
            MAX_METADATA_BYTES,
            ProtectedStoreError::InvalidBackupManifest,
        )? {
            let existing = BackupAcknowledgmentV1::decode(&existing)?;
            if existing.manifest != acknowledgment.manifest {
                return Err(ProtectedStoreError::InvalidBackupManifest);
            }
            acknowledgment = existing;
        } else {
            write_record_at(&directory, &name, &acknowledgment.encode()?)?;
        }
        if acknowledgment.state == BackupAcknowledgmentState::Committed {
            return Ok(false);
        }
        let prepared = acknowledgment.encode()?;
        acknowledgment.state = BackupAcknowledgmentState::Committed;
        commit_backup_acknowledgment(
            &directory,
            &name,
            &prepared,
            &acknowledgment.encode()?,
            crash,
        )?;
        Ok(true)
    }

    #[cfg(unix)]
    fn reset_backup_acknowledgment(
        &self,
        manifest_digest: &str,
    ) -> Result<(), ProtectedStoreError> {
        let hex_digest = digest_hex(manifest_digest)?;
        let directory =
            match self.open_digest_directory("backup-acknowledgments", hex_digest, false) {
                Ok(directory) => directory,
                Err(ProtectedStoreError::BlobMissing) => return Ok(()),
                Err(error) => return Err(error),
            };
        let name = metadata_name(hex_digest);
        let Some(encoded) = read_optional_at(
            &directory,
            &name,
            MAX_METADATA_BYTES,
            ProtectedStoreError::InvalidBackupManifest,
        )?
        else {
            return Ok(());
        };
        let acknowledgment = BackupAcknowledgmentV1::decode(&encoded)?;
        if digest(&acknowledgment.manifest.encode()?) != manifest_digest {
            return Err(ProtectedStoreError::InvalidBackupManifest);
        }
        unlink_file_if_present(&directory, &backup_commit_name(&name))?;
        unlink_file_at(&directory, &name)?;
        fsync(&directory).map_err(|_| ProtectedStoreError::StorageIo)
    }

    #[cfg(unix)]
    fn backup_acknowledgment_if_present(
        &self,
        manifest_digest: &str,
    ) -> Result<Option<BackupAcknowledgmentV1>, ProtectedStoreError> {
        let hex_digest = digest_hex(manifest_digest)?;
        let directory =
            match self.open_digest_directory("backup-acknowledgments", hex_digest, false) {
                Ok(directory) => directory,
                Err(ProtectedStoreError::BlobMissing) => return Ok(None),
                Err(error) => return Err(error),
            };
        let Some(encoded) = read_optional_at(
            &directory,
            &metadata_name(hex_digest),
            MAX_METADATA_BYTES,
            ProtectedStoreError::InvalidBackupManifest,
        )?
        else {
            return Ok(None);
        };
        let acknowledgment = BackupAcknowledgmentV1::decode(&encoded)?;
        if digest(&acknowledgment.manifest.encode()?) != manifest_digest {
            return Err(ProtectedStoreError::InvalidBackupManifest);
        }
        Ok(Some(acknowledgment))
    }

    #[cfg(unix)]
    fn backup_reference_is_active(
        &self,
        envelope_digest: &str,
        manifest_digest: &str,
    ) -> Result<bool, ProtectedStoreError> {
        let Some(acknowledgment) = self.backup_acknowledgment_if_present(manifest_digest)? else {
            return Ok(true);
        };
        if acknowledgment.state == BackupAcknowledgmentState::Prepared {
            return Ok(true);
        }
        if acknowledgment
            .manifest
            .entries
            .binary_search_by(|entry| entry.envelope_digest.as_str().cmp(envelope_digest))
            .is_err()
        {
            return Err(ProtectedStoreError::InvalidBackupManifest);
        }
        Ok(false)
    }

    #[cfg(unix)]
    fn backup_references(
        &self,
        envelope_digest: &str,
    ) -> Result<Vec<DeletionReference>, ProtectedStoreError> {
        let Some(index) = self.backup_reference_index_if_present(envelope_digest)? else {
            return Ok(Vec::new());
        };
        let mut references = Vec::new();
        for reference_id in index.manifest_digests {
            if self.backup_reference_is_active(envelope_digest, &reference_id)? {
                references.push(DeletionReference {
                    kind: crate::DeletionReferenceKind::Backup,
                    reference_id,
                });
            }
        }
        Ok(references)
    }

    #[cfg(unix)]
    fn ensure_no_backup_references(
        &self,
        envelope_digest: &str,
    ) -> Result<(), ProtectedStoreError> {
        if self.backup_references(envelope_digest)?.is_empty() {
            Ok(())
        } else {
            Err(ProtectedStoreError::BlobReferenced)
        }
    }

    #[cfg(unix)]
    fn backup_reference_index_if_present(
        &self,
        envelope_digest: &str,
    ) -> Result<Option<BackupReferenceIndexV1>, ProtectedStoreError> {
        let hex_digest = digest_hex(envelope_digest)?;
        let directory = match self.open_digest_directory("backup-references", hex_digest, false) {
            Ok(directory) => directory,
            Err(ProtectedStoreError::BlobMissing) => return Ok(None),
            Err(error) => return Err(error),
        };
        let Some(encoded) = read_optional_at(
            &directory,
            &metadata_name(hex_digest),
            MAX_METADATA_BYTES,
            ProtectedStoreError::InvalidBackupManifest,
        )?
        else {
            return Ok(None);
        };
        let index = BackupReferenceIndexV1::decode(&encoded)?;
        if index.envelope_digest != envelope_digest {
            return Err(ProtectedStoreError::InvalidBackupManifest);
        }
        Ok(Some(index))
    }

    #[cfg(unix)]
    fn write_key_reference(
        &self,
        envelope: &ProtectedEnvelopeV2,
        envelope_digest: &str,
    ) -> Result<(), ProtectedStoreError> {
        let directory = self.open_key_reference_directory(&envelope.wrapping_key_id, true)?;
        let reference = KeyReferenceV1 {
            version: KEY_REFERENCE_VERSION.to_owned(),
            envelope_digest: envelope_digest.to_owned(),
            installation_id: envelope.installation_id.clone(),
            protected_id: envelope.protected_id.clone(),
            wrapping_key_id: envelope.wrapping_key_id.clone(),
        };
        let name = key_index_name(&envelope.wrapping_key_id)?;
        let existing = read_optional_at(
            &directory,
            &name,
            MAX_METADATA_BYTES,
            ProtectedStoreError::InvalidTransaction,
        )?;
        let mut index = match existing {
            Some(encoded) => KeyReferenceIndexV1::decode(&encoded)?,
            None => KeyReferenceIndexV1 {
                version: KEY_REFERENCE_INDEX_VERSION.to_owned(),
                installation_id: envelope.installation_id.clone(),
                wrapping_key_id: envelope.wrapping_key_id.clone(),
                entries: Vec::new(),
            },
        };
        if index.installation_id != envelope.installation_id
            || index.wrapping_key_id != envelope.wrapping_key_id
        {
            return Err(ProtectedStoreError::StorageConflict);
        }
        match index
            .entries
            .binary_search_by(|entry| entry.envelope_digest.as_str().cmp(envelope_digest))
        {
            Ok(position) if index.entries[position] == reference => return Ok(()),
            Ok(_) => return Err(ProtectedStoreError::StorageConflict),
            Err(position) => index.entries.insert(position, reference),
        }
        write_record_at(&directory, &name, &index.encode()?)
    }

    #[cfg(unix)]
    fn load_key_reference_index(
        &self,
        installation_id: &str,
        wrapping_key_id: &str,
    ) -> Result<KeyReferenceIndexV1, ProtectedStoreError> {
        let directory = self.open_key_reference_directory(wrapping_key_id, false)?;
        let encoded = read_required_at(
            &directory,
            &key_index_name(wrapping_key_id)?,
            MAX_METADATA_BYTES,
            ProtectedStoreError::InvalidTransaction,
        )?;
        let index = KeyReferenceIndexV1::decode(&encoded)?;
        if index.installation_id != installation_id || index.wrapping_key_id != wrapping_key_id {
            return Err(ProtectedStoreError::InvalidTransaction);
        }
        Ok(index)
    }

    #[cfg(unix)]
    fn key_reference_index_if_present(
        &self,
        wrapping_key_id: &str,
    ) -> Result<Option<KeyReferenceIndexV1>, ProtectedStoreError> {
        let directory = match self.open_key_reference_directory(wrapping_key_id, false) {
            Ok(directory) => directory,
            Err(ProtectedStoreError::BlobMissing) => return Ok(None),
            Err(error) => return Err(error),
        };
        read_optional_at(
            &directory,
            &key_index_name(wrapping_key_id)?,
            MAX_METADATA_BYTES,
            ProtectedStoreError::InvalidTransaction,
        )?
        .map(|encoded| KeyReferenceIndexV1::decode(&encoded))
        .transpose()
    }

    #[cfg(unix)]
    fn find_key_reference<'a>(
        index: &'a KeyReferenceIndexV1,
        envelope_digest: &str,
    ) -> Result<(usize, &'a KeyReferenceV1), ProtectedStoreError> {
        let position = index
            .entries
            .binary_search_by(|entry| entry.envelope_digest.as_str().cmp(envelope_digest))
            .map_err(|_| ProtectedStoreError::InvalidTransaction)?;
        Ok((position, &index.entries[position]))
    }

    #[cfg(unix)]
    fn verify_key_reference(
        &self,
        envelope: &ProtectedEnvelopeV2,
        envelope_digest: &str,
    ) -> Result<(), ProtectedStoreError> {
        let index =
            self.load_key_reference_index(&envelope.installation_id, &envelope.wrapping_key_id)?;
        let (_, reference) = Self::find_key_reference(&index, envelope_digest)?;
        if reference.installation_id != envelope.installation_id
            || reference.protected_id != envelope.protected_id
            || reference.wrapping_key_id != envelope.wrapping_key_id
        {
            return Err(ProtectedStoreError::InvalidTransaction);
        }
        Ok(())
    }

    #[cfg(unix)]
    fn same_key_peer_references(
        &self,
        installation_id: &str,
        wrapping_key_id: &str,
        envelope_digest: &str,
    ) -> Result<Vec<DeletionReference>, ProtectedStoreError> {
        let index = self.load_key_reference_index(installation_id, wrapping_key_id)?;
        Self::find_key_reference(&index, envelope_digest)?;
        Ok(index
            .entries
            .into_iter()
            .filter(|reference| reference.envelope_digest != envelope_digest)
            .map(|reference| DeletionReference {
                kind: crate::DeletionReferenceKind::SharedWrappingKey,
                reference_id: reference.envelope_digest,
            })
            .collect())
    }

    #[cfg(unix)]
    fn verify_deleted_state(
        &self,
        plan: &ProtectedDeletionPlanV1,
        key_store: &impl WrappingKeyStore,
    ) -> Result<(), ProtectedStoreError> {
        let locator = KeyLocator::new(&plan.installation_id, &plan.wrapping_key_id)?;
        if key_store.readiness(&locator)? != BackendReadiness::KeyMissing {
            return Err(ProtectedStoreError::KeyDeletionUnverified);
        }
        let hex_digest = digest_hex(&plan.envelope_digest)?;
        match self.open_digest_directory("sha256", hex_digest, false) {
            Ok(directory) => {
                if read_optional_at(
                    &directory,
                    &blob_name(hex_digest),
                    MAX_ENVELOPE_BYTES,
                    ProtectedStoreError::BlobTampered,
                )?
                .is_some()
                    || read_optional_at(
                        &directory,
                        &pending_blob_name(hex_digest),
                        MAX_ENVELOPE_BYTES,
                        ProtectedStoreError::BlobTampered,
                    )?
                    .is_some()
                {
                    return Err(ProtectedStoreError::DeletionStateChanged);
                }
            }
            Err(ProtectedStoreError::BlobMissing) => {}
            Err(error) => return Err(error),
        }
        self.verify_put_transaction_absent(hex_digest)?;
        if !self.backup_references(&plan.envelope_digest)?.is_empty() {
            return Err(ProtectedStoreError::DeletionStateChanged);
        }
        if let Some(index) = self.key_reference_index_if_present(&plan.wrapping_key_id)? {
            if index.installation_id != plan.installation_id
                || index.wrapping_key_id != plan.wrapping_key_id
            {
                return Err(ProtectedStoreError::InvalidTransaction);
            }
            if !index.entries.is_empty() {
                return Err(ProtectedStoreError::DeletionStateChanged);
            }
        }
        Ok(())
    }

    #[cfg(unix)]
    fn open_digest_directory(
        &self,
        namespace: &str,
        hex_digest: &str,
        create: bool,
    ) -> Result<OwnedFd, ProtectedStoreError> {
        let namespace = open_private_dir_at(&self.root_fd, namespace, create)?;
        open_private_dir_at(&namespace, &hex_digest[..2], create)
    }

    #[cfg(unix)]
    fn open_key_reference_directory(
        &self,
        wrapping_key_id: &str,
        create: bool,
    ) -> Result<OwnedFd, ProtectedStoreError> {
        let key_hex = wrapping_key_id
            .strip_prefix("key_")
            .filter(|value| {
                value.len() == 64
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            })
            .ok_or(ProtectedStoreError::InvalidIdentifier)?;
        let namespace = open_private_dir_at(&self.root_fd, "key-references", create)?;
        open_private_dir_at(&namespace, &key_hex[..2], create)
    }

    #[cfg(unix)]
    fn commit_journal(
        directory: &OwnedFd,
        name: &str,
        mut journal: PutJournalV1,
    ) -> Result<(), ProtectedStoreError> {
        journal.state = PutState::Committed;
        write_record_at(directory, name, &journal.encode()?)
    }

    #[cfg(unix)]
    fn stored_envelope(&self, envelope_digest: String, hex_digest: &str) -> StoredEnvelope {
        StoredEnvelope {
            envelope_digest,
            path: self
                .root
                .join("sha256")
                .join(&hex_digest[..2])
                .join(blob_name(hex_digest)),
        }
    }
}

#[cfg(unix)]
fn interrupt_deletion(
    configured: Option<DeletionCrashPoint>,
    current: DeletionCrashPoint,
) -> Result<(), ProtectedStoreError> {
    if configured == Some(current) {
        Err(ProtectedStoreError::StorageIo)
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn interrupt_put(
    configured: Option<PutCrashPoint>,
    current: PutCrashPoint,
) -> Result<(), ProtectedStoreError> {
    if configured == Some(current) {
        Err(ProtectedStoreError::StorageIo)
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn interrupt_backup_acknowledgment(
    configured: Option<BackupAcknowledgmentCrashPoint>,
    current: BackupAcknowledgmentCrashPoint,
) -> Result<(), ProtectedStoreError> {
    if configured == Some(current) {
        Err(ProtectedStoreError::StorageIo)
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn open_operation_lock(root: &OwnedFd) -> Result<OwnedFd, ProtectedStoreError> {
    let name = ".operation.lock";
    if create_file_at(root, name, &[])? {
        fsync(root).map_err(|_| ProtectedStoreError::StorageIo)?;
    }
    let fd = openat(
        root,
        name,
        OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ProtectedStoreError::UnsafeStorageRoot)?;
    validate_private_file(&fd, ProtectedStoreError::UnsafeStorageRoot)?;
    Ok(fd)
}

#[cfg(unix)]
fn open_private_root(path: &Path) -> Result<OwnedFd, ProtectedStoreError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(ProtectedStoreError::UnsafeStorageRoot);
    }
    let mut directory = openat(rustix::fs::CWD, "/", directory_flags(), Mode::empty())
        .map_err(|_| ProtectedStoreError::StorageIo)?;
    for component in path.components() {
        let Component::Normal(name) = component else {
            continue;
        };
        match mkdirat(&directory, name, Mode::from_raw_mode(0o700)) {
            Ok(()) | Err(rustix::io::Errno::EXIST) => {}
            Err(_) => return Err(ProtectedStoreError::StorageIo),
        }
        directory = openat(&directory, name, directory_flags(), Mode::empty())
            .map_err(|_| ProtectedStoreError::UnsafeStorageRoot)?;
    }
    validate_private_directory(&directory)?;
    Ok(directory)
}

#[cfg(unix)]
fn open_private_dir_at(
    parent: &impl std::os::fd::AsFd,
    name: &str,
    create: bool,
) -> Result<OwnedFd, ProtectedStoreError> {
    if create {
        match mkdirat(parent, name, Mode::from_raw_mode(0o700)) {
            Ok(()) => fsync(parent).map_err(|_| ProtectedStoreError::StorageIo)?,
            Err(rustix::io::Errno::EXIST) => {}
            Err(_) => return Err(ProtectedStoreError::StorageIo),
        }
    }
    let directory = openat(parent, name, directory_flags(), Mode::empty()).map_err(|error| {
        if error == rustix::io::Errno::NOENT {
            ProtectedStoreError::BlobMissing
        } else {
            ProtectedStoreError::UnsafeStorageRoot
        }
    })?;
    validate_private_directory(&directory)?;
    Ok(directory)
}

#[cfg(unix)]
fn validate_private_directory(
    directory: &impl std::os::fd::AsFd,
) -> Result<(), ProtectedStoreError> {
    let stat = fstat(directory).map_err(|_| ProtectedStoreError::StorageIo)?;
    let permissions = Mode::from_raw_mode(stat.st_mode);
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || !(permissions & (Mode::RWXG | Mode::RWXO)).is_empty()
    {
        return Err(ProtectedStoreError::UnsafeStorageRoot);
    }
    Ok(())
}

#[cfg(unix)]
fn directory_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

#[cfg(unix)]
fn create_file_at(
    directory: &impl std::os::fd::AsFd,
    name: &str,
    content: &[u8],
) -> Result<bool, ProtectedStoreError> {
    let fd = match openat(
        directory,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::EXIST) => return Ok(false),
        Err(_) => return Err(ProtectedStoreError::StorageIo),
    };
    validate_private_file(&fd, ProtectedStoreError::BlobTampered)?;
    let mut file = File::from(fd);
    file.write_all(content)
        .map_err(|_| ProtectedStoreError::StorageIo)?;
    file.sync_all()
        .map_err(|_| ProtectedStoreError::StorageIo)?;
    Ok(true)
}

#[cfg(unix)]
fn write_record_at(
    directory: &impl std::os::fd::AsFd,
    name: &str,
    encoded: &[u8],
) -> Result<(), ProtectedStoreError> {
    if u64::try_from(encoded.len()).map_or(true, |length| length > MAX_METADATA_BYTES) {
        return Err(ProtectedStoreError::ContentTooLarge);
    }
    let temporary = format!(".{name}.next");
    unlink_file_if_present(directory, &temporary)?;
    if !create_file_at(directory, &temporary, encoded)? {
        return Err(ProtectedStoreError::StorageConflict);
    }
    renameat(directory, &temporary, directory, name).map_err(|_| ProtectedStoreError::StorageIo)?;
    fsync(directory).map_err(|_| ProtectedStoreError::StorageIo)
}

#[cfg(unix)]
fn commit_backup_acknowledgment(
    directory: &impl std::os::fd::AsFd,
    name: &str,
    prepared: &[u8],
    committed: &[u8],
    crash: Option<BackupAcknowledgmentCrashPoint>,
) -> Result<(), ProtectedStoreError> {
    if u64::try_from(committed.len()).map_or(true, |length| length > MAX_METADATA_BYTES) {
        return Err(ProtectedStoreError::ContentTooLarge);
    }
    let staged = backup_commit_name(name);
    unlink_file_if_present(directory, &staged)?;
    if !create_file_at(directory, &staged, committed)? {
        return Err(ProtectedStoreError::StorageConflict);
    }
    fsync(directory).map_err(|_| ProtectedStoreError::StorageIo)?;
    renameat(directory, &staged, directory, name).map_err(|_| ProtectedStoreError::StorageIo)?;
    let triple_failure =
        crash == Some(BackupAcknowledgmentCrashPoint::CommitDurabilityRollbackAndReadFailed);
    let durability = if triple_failure {
        Err(ProtectedStoreError::StorageIo)
    } else {
        interrupt_backup_acknowledgment(crash, BackupAcknowledgmentCrashPoint::CommitRenamed)
            .and_then(|()| fsync(directory).map_err(|_| ProtectedStoreError::StorageIo))
    };
    if durability.is_ok() {
        return Ok(());
    }
    if !triple_failure && write_record_at(directory, name, prepared).is_ok() {
        return Err(ProtectedStoreError::StorageIo);
    }
    Ok(())
}

#[cfg(unix)]
fn read_optional_at(
    directory: &impl std::os::fd::AsFd,
    name: &str,
    maximum: u64,
    tampered: ProtectedStoreError,
) -> Result<Option<Vec<u8>>, ProtectedStoreError> {
    let fd = match openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) if error == rustix::io::Errno::LOOP || error == rustix::io::Errno::NOTDIR => {
            return Err(tampered);
        }
        Err(_) => return Err(ProtectedStoreError::StorageIo),
    };
    validate_private_file(&fd, tampered)?;
    let stat = fstat(&fd).map_err(|_| ProtectedStoreError::StorageIo)?;
    if stat.st_size < 0 || u64::try_from(stat.st_size).map_or(true, |length| length > maximum) {
        return Err(ProtectedStoreError::ContentTooLarge);
    }
    let file = File::from(fd);
    let mut content = Vec::new();
    file.take(maximum + 1)
        .read_to_end(&mut content)
        .map_err(|_| ProtectedStoreError::StorageIo)?;
    if u64::try_from(content.len()).map_or(true, |length| length > maximum) {
        return Err(ProtectedStoreError::ContentTooLarge);
    }
    Ok(Some(content))
}

#[cfg(unix)]
fn read_required_at(
    directory: &impl std::os::fd::AsFd,
    name: &str,
    maximum: u64,
    missing: ProtectedStoreError,
) -> Result<Vec<u8>, ProtectedStoreError> {
    read_optional_at(directory, name, maximum, missing)?.ok_or(missing)
}

#[cfg(unix)]
fn validate_private_file(
    file: &impl std::os::fd::AsFd,
    tampered: ProtectedStoreError,
) -> Result<(), ProtectedStoreError> {
    let stat = fstat(file).map_err(|_| ProtectedStoreError::StorageIo)?;
    let permissions = Mode::from_raw_mode(stat.st_mode);
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || !(permissions & (Mode::RWXG | Mode::RWXO)).is_empty()
    {
        return Err(tampered);
    }
    Ok(())
}

#[cfg(unix)]
fn publish_pending(
    directory: &impl std::os::fd::AsFd,
    pending: &str,
    destination: &str,
    expected_digest: &str,
) -> Result<(), ProtectedStoreError> {
    match linkat(directory, pending, directory, destination, AtFlags::empty()) {
        Ok(()) => {}
        Err(rustix::io::Errno::EXIST) => {
            let existing = read_required_at(
                directory,
                destination,
                MAX_ENVELOPE_BYTES,
                ProtectedStoreError::BlobTampered,
            )?;
            verify_blob(&existing, expected_digest)?;
        }
        Err(_) => return Err(ProtectedStoreError::StorageIo),
    }
    fsync(directory).map_err(|_| ProtectedStoreError::StorageIo)?;
    unlink_file_if_present(directory, pending)?;
    fsync(directory).map_err(|_| ProtectedStoreError::StorageIo)
}

#[cfg(unix)]
fn unlink_file_at(
    directory: &impl std::os::fd::AsFd,
    name: &str,
) -> Result<(), ProtectedStoreError> {
    unlinkat(directory, name, AtFlags::empty()).map_err(|_| ProtectedStoreError::StorageIo)
}

#[cfg(unix)]
fn unlink_file_if_present(
    directory: &impl std::os::fd::AsFd,
    name: &str,
) -> Result<(), ProtectedStoreError> {
    match unlinkat(directory, name, AtFlags::empty()) {
        Ok(()) | Err(rustix::io::Errno::NOENT) => Ok(()),
        Err(_) => Err(ProtectedStoreError::StorageIo),
    }
}

#[cfg(unix)]
fn verify_blob(content: &[u8], expected_digest: &str) -> Result<(), ProtectedStoreError> {
    if digest(content) != expected_digest {
        return Err(ProtectedStoreError::BlobTampered);
    }
    Ok(())
}

#[cfg(unix)]
fn verify_put_journal(
    existing: &PutJournalV1,
    expected: &PutJournalV1,
) -> Result<(), ProtectedStoreError> {
    if existing.envelope_digest != expected.envelope_digest
        || existing.envelope_bytes != expected.envelope_bytes
        || existing.installation_id != expected.installation_id
        || existing.protected_id != expected.protected_id
        || existing.wrapping_key_id != expected.wrapping_key_id
    {
        return Err(ProtectedStoreError::InvalidTransaction);
    }
    Ok(())
}

#[cfg(unix)]
fn delete_wrapping_key(
    key_store: &impl WrappingKeyStore,
    locator: &KeyLocator,
) -> Result<WrappingKeyDeletionStatus, ProtectedStoreError> {
    let status = key_store.readiness(locator)?;
    match key_store.delete(locator) {
        Ok(()) | Err(ProtectedStoreError::KeyMissing) => {}
        Err(error) => return Err(error),
    }
    if key_store.readiness(locator)? != BackendReadiness::KeyMissing {
        return Err(ProtectedStoreError::KeyDeletionUnverified);
    }
    Ok(match status {
        BackendReadiness::Ready => WrappingKeyDeletionStatus::DeletedAndAbsenceVerified,
        BackendReadiness::KeyMissing => WrappingKeyDeletionStatus::AlreadyAbsentAndVerified,
    })
}

#[cfg(unix)]
fn verify_receipt(
    receipt: &ProtectedDeletionReceiptV1,
    plan: &ProtectedDeletionPlanV1,
    plan_digest: &str,
) -> Result<(), ProtectedStoreError> {
    if receipt.plan_digest != plan_digest
        || receipt.envelope_digest != plan.envelope_digest
        || receipt.protected_id != plan.protected_id
    {
        return Err(ProtectedStoreError::InvalidDeletionReceipt);
    }
    Ok(())
}

#[cfg(unix)]
fn digest_hex(value: &str) -> Result<&str, ProtectedStoreError> {
    if !valid_digest(value) {
        return Err(ProtectedStoreError::InvalidIdentifier);
    }
    value
        .strip_prefix("sha256:")
        .ok_or(ProtectedStoreError::InvalidIdentifier)
}

#[cfg(unix)]
fn blob_name(hex_digest: &str) -> String {
    format!("{hex_digest}.json")
}

#[cfg(unix)]
fn pending_blob_name(hex_digest: &str) -> String {
    format!(".{hex_digest}.pending")
}

#[cfg(unix)]
fn metadata_name(hex_digest: &str) -> String {
    format!("{hex_digest}.json")
}

#[cfg(unix)]
fn backup_commit_name(name: &str) -> String {
    format!(".{name}.commit")
}

#[cfg(unix)]
fn key_index_name(wrapping_key_id: &str) -> Result<String, ProtectedStoreError> {
    let key_hex = wrapping_key_id
        .strip_prefix("key_")
        .filter(|value| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        })
        .ok_or(ProtectedStoreError::InvalidIdentifier)?;
    Ok(format!("{key_hex}.json"))
}

#[cfg(unix)]
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
