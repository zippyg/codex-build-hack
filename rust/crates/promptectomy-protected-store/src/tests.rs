use std::collections::BTreeMap;
#[cfg(unix)]
use std::path::Path;
use std::sync::Mutex;

use base64::Engine as _;
use zeroize::Zeroizing;

use super::*;

#[derive(Default)]
struct MemoryKeyStore {
    keys: Mutex<BTreeMap<String, [u8; 32]>>,
    delete_failures: Mutex<usize>,
}

impl MemoryKeyStore {
    fn insert(&self, locator: &KeyLocator, key: [u8; 32]) {
        self.keys
            .lock()
            .expect("memory key store lock")
            .insert(locator.to_string(), key);
    }

    #[cfg(unix)]
    fn contains(&self, locator: &KeyLocator) -> bool {
        self.keys
            .lock()
            .expect("memory key store lock")
            .contains_key(&locator.to_string())
    }

    #[cfg(unix)]
    fn fail_next_delete(&self) {
        *self.delete_failures.lock().expect("delete failure lock") = 1;
    }
}

impl WrappingKeyStore for MemoryKeyStore {
    fn backend(&self) -> Result<BackendKind, ProtectedStoreError> {
        Ok(BackendKind::MacOsKeychain)
    }

    fn readiness(&self, locator: &KeyLocator) -> Result<BackendReadiness, ProtectedStoreError> {
        if self
            .keys
            .lock()
            .expect("memory key store lock")
            .contains_key(&locator.to_string())
        {
            Ok(BackendReadiness::Ready)
        } else {
            Ok(BackendReadiness::KeyMissing)
        }
    }

    fn load(&self, locator: &KeyLocator) -> Result<Zeroizing<[u8; 32]>, ProtectedStoreError> {
        self.keys
            .lock()
            .expect("memory key store lock")
            .get(&locator.to_string())
            .copied()
            .map(Zeroizing::new)
            .ok_or(ProtectedStoreError::KeyMissing)
    }

    fn store(&self, locator: &KeyLocator, key: &[u8; 32]) -> Result<(), ProtectedStoreError> {
        let mut keys = self.keys.lock().expect("memory key store lock");
        match keys.get(&locator.to_string()) {
            Some(existing) if existing == key => Ok(()),
            Some(_) => Err(ProtectedStoreError::KeyConflict),
            None => {
                keys.insert(locator.to_string(), *key);
                Ok(())
            }
        }
    }

    fn delete(&self, locator: &KeyLocator) -> Result<(), ProtectedStoreError> {
        let mut failures = self.delete_failures.lock().expect("delete failure lock");
        if *failures > 0 {
            *failures -= 1;
            return Err(ProtectedStoreError::BackendUnavailable);
        }
        drop(failures);
        self.keys
            .lock()
            .expect("memory key store lock")
            .remove(&locator.to_string())
            .map(|_| ())
            .ok_or(ProtectedStoreError::KeyMissing)
    }
}

fn fixture() -> (MemoryKeyStore, String, String, KeyLocator) {
    let store = MemoryKeyStore::default();
    let installation_id = new_installation_id().expect("installation ID");
    let key_id = new_key_id().expect("key ID");
    let locator = KeyLocator::new(&installation_id, &key_id).expect("locator");
    store.insert(&locator, [7_u8; 32]);
    (store, installation_id, key_id, locator)
}

#[test]
fn opaque_identifiers_and_locators_are_strict() {
    let first = new_installation_id().expect("first ID");
    let second = new_installation_id().expect("second ID");
    let key_id = new_key_id().expect("key ID");
    assert_ne!(first, second);
    assert!(KeyLocator::new(&first, &key_id).is_ok());
    assert_eq!(
        KeyLocator::new("installation_../escape", &key_id),
        Err(ProtectedStoreError::InvalidIdentifier)
    );
}

#[test]
fn key_creation_is_idempotent_but_never_overwrites() {
    let (store, _, _, locator) = fixture();
    assert_eq!(store.store(&locator, &[7_u8; 32]), Ok(()));
    assert_eq!(
        store.store(&locator, &[8_u8; 32]),
        Err(ProtectedStoreError::KeyConflict)
    );
}

#[test]
fn envelope_round_trip_is_canonical_and_contains_no_plaintext() {
    let (store, installation_id, key_id, _) = fixture();
    let plaintext = b"synthetic protected evidence";
    let envelope = seal(plaintext, &installation_id, &key_id, &store).expect("seal");
    let encoded = envelope.encode().expect("encode");
    assert!(
        !encoded
            .windows(plaintext.len())
            .any(|window| window == plaintext)
    );
    assert_eq!(
        ProtectedEnvelopeV2::decode(&encoded).expect("decode"),
        envelope
    );
    assert_eq!(open(&envelope, &store).expect("open").as_slice(), plaintext);

    let mut noncanonical = b" ".to_vec();
    noncanonical.extend_from_slice(&encoded);
    assert_eq!(
        ProtectedEnvelopeV2::decode(&noncanonical),
        Err(ProtectedStoreError::NonCanonicalEnvelope)
    );
}

#[test]
fn tamper_and_missing_key_fail_typed() {
    let (store, installation_id, key_id, locator) = fixture();
    let mut envelope = seal(b"evidence", &installation_id, &key_id, &store).expect("seal");
    let mut ciphertext = base64::engine::general_purpose::STANDARD
        .decode(&envelope.ciphertext)
        .expect("ciphertext");
    ciphertext[0] ^= 1;
    envelope.ciphertext = base64::engine::general_purpose::STANDARD.encode(ciphertext);
    assert_eq!(
        open(&envelope, &store),
        Err(ProtectedStoreError::AuthenticationFailed)
    );
    store.delete(&locator).expect("delete test key");
    assert_eq!(
        open(&envelope, &store),
        Err(ProtectedStoreError::KeyMissing)
    );
}

#[test]
fn rewrap_changes_only_wrapping_fields() {
    let (store, installation_id, old_key_id, _) = fixture();
    let new_key_id = new_key_id().expect("new key ID");
    let new_locator = KeyLocator::new(&installation_id, &new_key_id).expect("new locator");
    store.insert(&new_locator, [11_u8; 32]);
    let envelope = seal(b"rotation fixture", &installation_id, &old_key_id, &store).expect("seal");
    let rotated = rewrap(&envelope, &new_key_id, &store).expect("rewrap");
    assert_eq!(rotated.protected_id, envelope.protected_id);
    assert_eq!(rotated.content_nonce, envelope.content_nonce);
    assert_eq!(rotated.ciphertext, envelope.ciphertext);
    assert_ne!(rotated.wrapping_nonce, envelope.wrapping_nonce);
    assert_ne!(rotated.wrapped_data_key, envelope.wrapped_data_key);
    assert_eq!(
        open(&rotated, &store).expect("open rotated").as_slice(),
        b"rotation fixture"
    );
}

#[cfg(unix)]
#[test]
fn blob_store_publishes_only_authenticated_envelopes_and_detects_tamper() {
    let (store, installation_id, key_id, _) = fixture();
    let envelope = seal(b"file fixture", &installation_id, &key_id, &store).expect("seal");
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary
        .path()
        .canonicalize()
        .expect("canonical temporary directory")
        .join("protected");
    let blobs = ProtectedBlobStore::new(&root).expect("blob store");
    let stored = blobs.put(&envelope).expect("put");
    let root_text = root.to_string_lossy();
    assert!(!format!("{blobs:?}").contains(root_text.as_ref()));
    assert!(!format!("{stored:?}").contains(root_text.as_ref()));
    assert_eq!(blobs.read(&stored.envelope_digest).expect("read"), envelope);
    assert!(
        !std::fs::read(&stored.path)
            .expect("stored envelope")
            .windows(b"file fixture".len())
            .any(|window| window == b"file fixture")
    );
    std::fs::write(&stored.path, b"tampered").expect("tamper fixture");
    assert_eq!(
        blobs.read(&stored.envelope_digest),
        Err(ProtectedStoreError::BlobTampered)
    );
}

#[cfg(unix)]
#[test]
fn blob_store_remains_anchored_when_the_root_path_is_swapped() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    let (keys, installation_id, key_id, _) = fixture();
    let envelope = seal(b"ancestor swap canary", &installation_id, &key_id, &keys).expect("seal");
    let temporary = tempfile::tempdir().expect("temporary directory");
    let parent = temporary.path().canonicalize().expect("canonical parent");
    let root = parent.join("protected");
    let store = ProtectedBlobStore::new(&root).expect("blob store");
    let anchored = parent.join("anchored");
    std::fs::rename(&root, &anchored).expect("rename opened root");
    let redirect = parent.join("redirect");
    std::fs::create_dir(&redirect).expect("redirect directory");
    std::fs::set_permissions(&redirect, std::fs::Permissions::from_mode(0o700))
        .expect("redirect permissions");
    symlink(&redirect, &root).expect("replacement symlink");

    let stored = store.put(&envelope).expect("descriptor-anchored put");
    assert_eq!(
        store.read(&stored.envelope_digest).expect("anchored read"),
        envelope
    );
    assert!(anchored.join("sha256").is_dir());
    assert!(
        std::fs::read_dir(&redirect)
            .expect("redirect contents")
            .next()
            .is_none()
    );
}

#[cfg(unix)]
#[test]
fn blob_store_rejects_a_swapped_final_symlink() {
    use std::os::unix::fs::symlink;

    let (keys, installation_id, key_id, _) = fixture();
    let envelope = seal(b"final swap canary", &installation_id, &key_id, &keys).expect("seal");
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary
        .path()
        .canonicalize()
        .expect("canonical parent")
        .join("protected");
    let store = ProtectedBlobStore::new(&root).expect("blob store");
    let stored = store.put(&envelope).expect("put");
    let decoy = temporary.path().join("decoy");
    std::fs::write(&decoy, b"decoy").expect("decoy");
    std::fs::remove_file(&stored.path).expect("remove final blob");
    symlink(&decoy, &stored.path).expect("swap final symlink");

    assert_eq!(
        store.read(&stored.envelope_digest),
        Err(ProtectedStoreError::BlobTampered)
    );
}

#[cfg(unix)]
#[test]
fn put_resumes_after_every_durable_stage() {
    use crate::records::{PutJournalV1, PutState};
    use crate::storage::PutCrashPoint;
    use sha2::Digest as _;
    use std::fmt::Write as _;

    for crash in [
        PutCrashPoint::JournalWritten,
        PutCrashPoint::BlobWritten,
        PutCrashPoint::ReferenceWritten,
        PutCrashPoint::BlobPublished,
        PutCrashPoint::JournalCommitted,
    ] {
        let (keys, installation_id, key_id, _) = fixture();
        let envelope =
            seal(b"interrupted put canary", &installation_id, &key_id, &keys).expect("seal");
        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = temporary
            .path()
            .canonicalize()
            .expect("canonical parent")
            .join("protected");
        let store = ProtectedBlobStore::new(&root).expect("blob store");
        assert_eq!(
            store.put_with_crash(&envelope, crash),
            Err(ProtectedStoreError::StorageIo),
            "{crash:?}"
        );
        let mut envelope_digest = "sha256:".to_owned();
        for byte in sha2::Sha256::digest(envelope.encode().expect("encode")) {
            write!(&mut envelope_digest, "{byte:02x}").expect("digest string");
        }
        let hex = envelope_digest
            .strip_prefix("sha256:")
            .expect("digest prefix");
        let journal_path = root
            .join("transactions")
            .join(&hex[..2])
            .join(format!("{hex}.json"));
        let interrupted =
            PutJournalV1::decode(&std::fs::read(&journal_path).expect("durable put journal"))
                .expect("canonical put journal");
        assert_eq!(interrupted.envelope_digest, envelope_digest, "{crash:?}");
        if matches!(
            crash,
            PutCrashPoint::JournalWritten | PutCrashPoint::BlobWritten
        ) {
            assert!(!root.join("key-references").exists(), "{crash:?}");
        }
        assert_eq!(
            interrupted.state,
            if crash == PutCrashPoint::JournalCommitted {
                PutState::Committed
            } else {
                PutState::Pending
            },
            "{crash:?}"
        );
        drop(store);

        let resumed = ProtectedBlobStore::new(&root).expect("reopened blob store");
        let stored = resumed.put(&envelope).expect("resume put");
        assert_eq!(stored.envelope_digest, envelope_digest, "{crash:?}");
        assert_eq!(
            resumed
                .read(&stored.envelope_digest)
                .expect("read resumed put"),
            envelope,
            "{crash:?}"
        );
        let committed =
            PutJournalV1::decode(&std::fs::read(&journal_path).expect("committed put journal"))
                .expect("canonical committed journal");
        assert_eq!(committed.state, PutState::Committed, "{crash:?}");
        assert_tree_has_no_transaction_temporaries(&root);
    }
}

#[cfg(unix)]
#[test]
fn put_recovery_remains_resumable_when_recovery_crashes() {
    use crate::storage::PutCrashPoint;

    let stages = [
        PutCrashPoint::JournalWritten,
        PutCrashPoint::BlobWritten,
        PutCrashPoint::ReferenceWritten,
        PutCrashPoint::BlobPublished,
        PutCrashPoint::JournalCommitted,
    ];
    for pair in stages.windows(2) {
        let (keys, installation_id, key_id, _) = fixture();
        let envelope = seal(
            b"repeated interrupted put canary",
            &installation_id,
            &key_id,
            &keys,
        )
        .expect("seal");
        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = temporary
            .path()
            .canonicalize()
            .expect("canonical parent")
            .join("protected");
        let first = ProtectedBlobStore::new(&root).expect("blob store");
        assert_eq!(
            first.put_with_crash(&envelope, pair[0]),
            Err(ProtectedStoreError::StorageIo),
            "{:?}",
            pair[0]
        );
        drop(first);

        let second = ProtectedBlobStore::new(&root).expect("first recovery store");
        assert_eq!(
            second.put_with_crash(&envelope, pair[1]),
            Err(ProtectedStoreError::StorageIo),
            "{:?} then {:?}",
            pair[0],
            pair[1]
        );
        drop(second);

        let final_attempt = ProtectedBlobStore::new(&root).expect("second recovery store");
        let stored = final_attempt
            .put(&envelope)
            .expect("complete recovered put");
        assert_eq!(
            final_attempt
                .read(&stored.envelope_digest)
                .expect("read recovered put"),
            envelope,
            "{:?} then {:?}",
            pair[0],
            pair[1]
        );
        assert_tree_has_no_transaction_temporaries(&root);
    }
}

#[cfg(unix)]
#[test]
fn read_completes_every_recoverable_put_stage() {
    use crate::storage::PutCrashPoint;
    use sha2::Digest as _;
    use std::fmt::Write as _;

    for crash in [
        PutCrashPoint::BlobWritten,
        PutCrashPoint::ReferenceWritten,
        PutCrashPoint::BlobPublished,
        PutCrashPoint::JournalCommitted,
    ] {
        let (keys, installation_id, key_id, _) = fixture();
        let envelope =
            seal(b"read recovery canary", &installation_id, &key_id, &keys).expect("seal");
        let mut envelope_digest = "sha256:".to_owned();
        for byte in sha2::Sha256::digest(envelope.encode().expect("encode")) {
            write!(&mut envelope_digest, "{byte:02x}").expect("digest string");
        }
        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = temporary
            .path()
            .canonicalize()
            .expect("canonical parent")
            .join("protected");
        let store = ProtectedBlobStore::new(&root).expect("blob store");
        assert_eq!(
            store.put_with_crash(&envelope, crash),
            Err(ProtectedStoreError::StorageIo),
            "{crash:?}"
        );
        drop(store);

        let resumed = ProtectedBlobStore::new(&root).expect("reopened blob store");
        assert_eq!(
            resumed.read(&envelope_digest).expect("read recovery"),
            envelope,
            "{crash:?}"
        );
        assert_tree_has_no_transaction_temporaries(&root);
    }
}

#[cfg(unix)]
#[test]
fn pending_blob_without_its_durable_journal_fails_closed() {
    let (keys, installation_id, key_id, _) = fixture();
    let envelope = seal(b"missing journal canary", &installation_id, &key_id, &keys).expect("seal");
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary
        .path()
        .canonicalize()
        .expect("canonical parent")
        .join("protected");
    let store = ProtectedBlobStore::new(&root).expect("blob store");
    let stored = store.put(&envelope).expect("put");
    let hex = stored.envelope_digest.trim_start_matches("sha256:");
    let pending = stored
        .path
        .parent()
        .expect("blob directory")
        .join(format!(".{hex}.pending"));
    std::fs::rename(&stored.path, &pending).expect("restore pending state");
    let journal = root
        .join("transactions")
        .join(&hex[..2])
        .join(format!("{hex}.json"));
    std::fs::remove_file(journal).expect("remove journal");

    assert_eq!(
        store.read(&stored.envelope_digest),
        Err(ProtectedStoreError::InvalidTransaction)
    );
}

#[cfg(unix)]
#[test]
fn canonical_put_metadata_tamper_fails_closed() {
    let (keys, installation_id, key_id, _) = fixture();
    let envelope = seal(b"journal canary", &installation_id, &key_id, &keys).expect("seal");
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary
        .path()
        .canonicalize()
        .expect("canonical parent")
        .join("protected");
    let store = ProtectedBlobStore::new(&root).expect("blob store");
    let stored = store.put(&envelope).expect("put");
    let hex = stored.envelope_digest.trim_start_matches("sha256:");
    let journal = root
        .join("transactions")
        .join(&hex[..2])
        .join(format!("{hex}.json"));
    std::fs::write(journal, b"{}").expect("tamper journal");

    assert_eq!(
        store.read(&stored.envelope_digest),
        Err(ProtectedStoreError::InvalidTransaction)
    );
}

#[cfg(unix)]
#[test]
fn backup_manifest_verifies_inventory_and_decryptability() {
    let (keys, installation_id, key_id, locator) = fixture();
    let first = seal(b"first backup canary", &installation_id, &key_id, &keys).expect("first seal");
    let second =
        seal(b"second backup canary", &installation_id, &key_id, &keys).expect("second seal");
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary
        .path()
        .canonicalize()
        .expect("canonical parent")
        .join("protected");
    let store = ProtectedBlobStore::new(&root).expect("blob store");
    let first = store.put(&first).expect("first put");
    let second = store.put(&second).expect("second put");
    let manifest = store
        .create_backup_manifest(&[
            second.envelope_digest.clone(),
            first.envelope_digest.clone(),
        ])
        .expect("backup manifest");
    let encoded = manifest.encode().expect("encode manifest");
    assert_eq!(
        ProtectedBackupManifestV1::decode(&encoded).expect("decode manifest"),
        manifest
    );
    let receipt = store
        .verify_backup(&manifest, &keys)
        .expect("verify backup");
    assert_eq!(receipt.envelope_count, 2);
    assert!(receipt.every_envelope_decryptable);

    let wrong_keys = MemoryKeyStore::default();
    wrong_keys.insert(&locator, [31_u8; 32]);
    assert_eq!(
        store.verify_backup(&manifest, &wrong_keys),
        Err(ProtectedStoreError::AuthenticationFailed)
    );
    assert_eq!(
        store.verify_backup(&manifest, &MemoryKeyStore::default()),
        Err(ProtectedStoreError::KeyMissing)
    );

    let mut altered = manifest.clone();
    altered.entries[0].envelope_bytes += 1;
    assert_eq!(
        store.verify_backup(&altered, &keys),
        Err(ProtectedStoreError::BackupVerificationFailed)
    );
}

#[cfg(unix)]
#[test]
fn store_owned_backup_pin_blocks_forged_deletion_until_acknowledged() {
    let (keys, installation_id, key_id, locator) = fixture();
    let envelope = seal(b"retained backup canary", &installation_id, &key_id, &keys).expect("seal");
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary
        .path()
        .canonicalize()
        .expect("canonical parent")
        .join("protected");
    let store = ProtectedBlobStore::new(&root).expect("blob store");
    let stored = store.put(&envelope).expect("put");
    let manifest = store
        .create_backup_manifest(std::slice::from_ref(&stored.envelope_digest))
        .expect("backup manifest");
    let receipt = store
        .verify_backup(&manifest, &keys)
        .expect("verify backup");
    let mut forged = store
        .plan_deletion(&stored.envelope_digest, Vec::new())
        .expect("store-derived plan");
    assert_eq!(
        forged.references,
        vec![DeletionReference {
            kind: DeletionReferenceKind::Backup,
            reference_id: receipt.manifest_digest,
        }]
    );
    forged.references.clear();

    assert_eq!(
        store.execute_deletion(&forged, &keys),
        Err(ProtectedStoreError::BlobReferenced)
    );
    assert!(keys.contains(&locator));
    assert_eq!(
        store.read(&stored.envelope_digest).expect("retained blob"),
        envelope
    );

    let mut wrong_manifest = manifest.clone();
    wrong_manifest.entries[0].envelope_bytes += 1;
    assert_eq!(store.acknowledge_backup_removal(&wrong_manifest), Ok(false));
    assert_eq!(
        store.execute_deletion(&forged, &keys),
        Err(ProtectedStoreError::BlobReferenced)
    );
    assert_eq!(store.acknowledge_backup_removal(&manifest), Ok(true));
    assert_eq!(store.acknowledge_backup_removal(&manifest), Ok(false));
    let recreated = store
        .create_backup_manifest(std::slice::from_ref(&stored.envelope_digest))
        .expect("recreate identical manifest");
    assert_eq!(recreated, manifest);
    assert!(
        store
            .plan_deletion(&stored.envelope_digest, Vec::new())
            .expect("recreated pinned plan")
            .references
            .iter()
            .any(|reference| reference.kind == DeletionReferenceKind::Backup)
    );
    assert_eq!(store.acknowledge_backup_removal(&recreated), Ok(true));
    let plan = store
        .plan_deletion(&stored.envelope_digest, Vec::new())
        .expect("released plan");
    assert!(plan.references.is_empty());
    store.execute_deletion(&plan, &keys).expect("delete");
    assert!(!keys.contains(&locator));
}

#[cfg(unix)]
#[test]
fn backup_acknowledgment_failures_before_atomic_commit_keep_every_pin() {
    use crate::storage::BackupAcknowledgmentCrashPoint;

    let (keys, installation_id, first_key_id, first_locator) = fixture();
    let second_key_id = new_key_id().expect("second key ID");
    let second_locator =
        KeyLocator::new(&installation_id, &second_key_id).expect("second key locator");
    keys.insert(&second_locator, [13_u8; 32]);
    let first = seal(
        b"first atomic backup canary",
        &installation_id,
        &first_key_id,
        &keys,
    )
    .expect("first seal");
    let second = seal(
        b"second atomic backup canary",
        &installation_id,
        &second_key_id,
        &keys,
    )
    .expect("second seal");
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary
        .path()
        .canonicalize()
        .expect("canonical parent")
        .join("protected");
    let mut store = ProtectedBlobStore::new(&root).expect("blob store");
    let first = store.put(&first).expect("put first");
    let second = store.put(&second).expect("put second");
    let manifest = store
        .create_backup_manifest(&[
            first.envelope_digest.clone(),
            second.envelope_digest.clone(),
        ])
        .expect("backup manifest");

    for crash in [
        BackupAcknowledgmentCrashPoint::EntryValidated(1),
        BackupAcknowledgmentCrashPoint::CommitRenamed,
    ] {
        assert_eq!(
            store.acknowledge_backup_removal_with_crash(&manifest, crash),
            Err(ProtectedStoreError::StorageIo),
            "{crash:?}"
        );
        drop(store);
        store = ProtectedBlobStore::new(&root).expect("reopened blob store");
        for stored in [&first, &second] {
            let mut forged = store
                .plan_deletion(&stored.envelope_digest, Vec::new())
                .expect("pinned plan");
            assert!(
                forged
                    .references
                    .iter()
                    .any(|reference| reference.kind == DeletionReferenceKind::Backup),
                "{crash:?}"
            );
            forged.references.clear();
            assert_eq!(
                store.execute_deletion(&forged, &keys),
                Err(ProtectedStoreError::BlobReferenced),
                "{crash:?}"
            );
            assert!(store.read(&stored.envelope_digest).is_ok(), "{crash:?}");
        }
        assert!(keys.contains(&first_locator), "{crash:?}");
        assert!(keys.contains(&second_locator), "{crash:?}");
    }

    assert_eq!(store.acknowledge_backup_removal(&manifest), Ok(true));
    for (stored, locator) in [(&first, &first_locator), (&second, &second_locator)] {
        let plan = store
            .plan_deletion(&stored.envelope_digest, Vec::new())
            .expect("released plan");
        assert!(plan.references.is_empty());
        store.execute_deletion(&plan, &keys).expect("delete");
        assert!(!keys.contains(locator));
    }
}

#[cfg(unix)]
#[test]
fn backup_acknowledgment_triple_failure_after_rename_never_reports_error() {
    use crate::storage::BackupAcknowledgmentCrashPoint;

    let (keys, installation_id, key_id, locator) = fixture();
    let envelope = seal(b"triple failure canary", &installation_id, &key_id, &keys).expect("seal");
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary
        .path()
        .canonicalize()
        .expect("canonical parent")
        .join("protected");
    let store = ProtectedBlobStore::new(&root).expect("blob store");
    let stored = store.put(&envelope).expect("put");
    let manifest = store
        .create_backup_manifest(std::slice::from_ref(&stored.envelope_digest))
        .expect("backup manifest");
    assert_eq!(
        store.acknowledge_backup_removal_with_crash(
            &manifest,
            BackupAcknowledgmentCrashPoint::CommitDurabilityRollbackAndReadFailed,
        ),
        Ok(true)
    );
    drop(store);

    let reopened = ProtectedBlobStore::new(&root).expect("reopened blob store");
    let plan = reopened
        .plan_deletion(&stored.envelope_digest, Vec::new())
        .expect("committed plan");
    assert!(plan.references.is_empty());
    reopened.execute_deletion(&plan, &keys).expect("delete");
    assert!(!keys.contains(&locator));
}

#[cfg(unix)]
#[test]
fn backup_manifest_preflight_accepts_exact_bound_and_rejects_one_byte_over_without_pin() {
    let (keys, installation_id, first_key_id, _) = fixture();
    let second_key_id = new_key_id().expect("second key ID");
    let second_locator =
        KeyLocator::new(&installation_id, &second_key_id).expect("second key locator");
    keys.insert(&second_locator, [17_u8; 32]);
    let first = seal(
        b"exact metadata bound",
        &installation_id,
        &first_key_id,
        &keys,
    )
    .expect("first seal");
    let second = seal(
        b"one byte over bound",
        &installation_id,
        &second_key_id,
        &keys,
    )
    .expect("second seal");
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary
        .path()
        .canonicalize()
        .expect("canonical parent")
        .join("protected");
    let store = ProtectedBlobStore::new(&root).expect("blob store");
    let first = store.put(&first).expect("put first");
    let second = store.put(&second).expect("put second");

    let first_input = [first.envelope_digest.clone()];
    let exact = store
        .backup_manifest_metadata_requirement(&first_input)
        .expect("exact requirement");
    store
        .create_backup_manifest_with_metadata_limit(&first_input, exact)
        .expect("exact bound accepted");
    assert!(
        store
            .plan_deletion(&first.envelope_digest, Vec::new())
            .expect("first plan")
            .references
            .iter()
            .any(|reference| reference.kind == DeletionReferenceKind::Backup)
    );

    let second_input = [second.envelope_digest.clone()];
    let required = store
        .backup_manifest_metadata_requirement(&second_input)
        .expect("second requirement");
    assert_eq!(
        store.create_backup_manifest_with_metadata_limit(&second_input, required - 1),
        Err(ProtectedStoreError::ContentTooLarge)
    );
    assert!(
        store
            .plan_deletion(&second.envelope_digest, Vec::new())
            .expect("unpinned second plan")
            .references
            .iter()
            .all(|reference| reference.kind != DeletionReferenceKind::Backup)
    );
}

#[cfg(unix)]
#[test]
fn tampered_backup_acknowledgment_fails_closed() {
    let (keys, installation_id, key_id, _) = fixture();
    let envelope = seal(
        b"acknowledgment tamper canary",
        &installation_id,
        &key_id,
        &keys,
    )
    .expect("seal");
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary
        .path()
        .canonicalize()
        .expect("canonical parent")
        .join("protected");
    let store = ProtectedBlobStore::new(&root).expect("blob store");
    let stored = store.put(&envelope).expect("put");
    let manifest = store
        .create_backup_manifest(std::slice::from_ref(&stored.envelope_digest))
        .expect("backup manifest");
    let manifest_digest = store
        .verify_backup(&manifest, &keys)
        .expect("verify backup")
        .manifest_digest;
    let mut forged = store
        .plan_deletion(&stored.envelope_digest, Vec::new())
        .expect("pinned plan");
    forged.references.clear();
    assert_eq!(store.acknowledge_backup_removal(&manifest), Ok(true));
    let hex = manifest_digest.trim_start_matches("sha256:");
    let acknowledgment = root
        .join("backup-acknowledgments")
        .join(&hex[..2])
        .join(format!("{hex}.json"));
    std::fs::write(acknowledgment, b"{}").expect("tamper acknowledgment");

    assert_eq!(
        store.plan_deletion(&stored.envelope_digest, Vec::new()),
        Err(ProtectedStoreError::InvalidBackupManifest)
    );
    assert_eq!(
        store.execute_deletion(&forged, &keys),
        Err(ProtectedStoreError::InvalidBackupManifest)
    );
}

#[cfg(unix)]
#[test]
fn referenced_deletion_is_refused_and_retry_is_idempotent() {
    let (keys, installation_id, key_id, locator) = fixture();
    let envelope = seal(b"deletion canary", &installation_id, &key_id, &keys).expect("seal");
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary
        .path()
        .canonicalize()
        .expect("canonical parent")
        .join("protected");
    let store = ProtectedBlobStore::new(&root).expect("blob store");
    let stored = store.put(&envelope).expect("put");
    let blocked = store
        .plan_deletion(
            &stored.envelope_digest,
            vec![DeletionReference {
                kind: DeletionReferenceKind::Backup,
                reference_id: "backup:synthetic".to_owned(),
            }],
        )
        .expect("referenced plan");
    assert_eq!(
        store.execute_deletion(&blocked, &keys),
        Err(ProtectedStoreError::BlobReferenced)
    );
    assert!(keys.contains(&locator));
    assert_eq!(
        store.read(&stored.envelope_digest).expect("still readable"),
        envelope
    );

    let plan = store
        .plan_deletion(&stored.envelope_digest, Vec::new())
        .expect("unreferenced plan");
    let receipt = store.execute_deletion(&plan, &keys).expect("delete");
    assert_eq!(
        receipt.wrapping_key,
        WrappingKeyDeletionStatus::DeletedAndAbsenceVerified
    );
    assert_eq!(receipt.blob, BlobDeletionStatus::Unlinked);
    assert_eq!(
        receipt.erasure_scope,
        DeletionErasureScope::LogicalStoreAndWrappingKeyOnlyUncontrolledCopiesMayRemain
    );
    assert!(!keys.contains(&locator));
    assert_eq!(
        store.read(&stored.envelope_digest),
        Err(ProtectedStoreError::BlobMissing)
    );
    assert_eq!(
        store
            .execute_deletion(&plan, &keys)
            .expect("idempotent retry"),
        receipt
    );
}

#[cfg(unix)]
#[test]
fn store_derived_key_inventory_blocks_a_forged_unreferenced_plan() {
    let (keys, installation_id, key_id, locator) = fixture();
    let first = seal(b"first shared-key blob", &installation_id, &key_id, &keys).expect("seal");
    let second = seal(b"second shared-key blob", &installation_id, &key_id, &keys).expect("seal");
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary
        .path()
        .canonicalize()
        .expect("canonical parent")
        .join("protected");
    let store = ProtectedBlobStore::new(&root).expect("blob store");
    let first = store.put(&first).expect("first put");
    let second = store.put(&second).expect("second put");
    let mut plan = store
        .plan_deletion(&first.envelope_digest, Vec::new())
        .expect("derived plan");
    assert_eq!(
        plan.references,
        vec![DeletionReference {
            kind: DeletionReferenceKind::SharedWrappingKey,
            reference_id: second.envelope_digest.clone(),
        }]
    );
    plan.references.clear();

    assert_eq!(
        store.execute_deletion(&plan, &keys),
        Err(ProtectedStoreError::BlobReferenced)
    );
    assert!(keys.contains(&locator));
    assert!(store.read(&first.envelope_digest).is_ok());
    assert!(store.read(&second.envelope_digest).is_ok());
}

#[cfg(unix)]
#[test]
fn recovered_put_preserves_shared_key_deletion_safety() {
    use crate::storage::PutCrashPoint;

    let (keys, installation_id, key_id, locator) = fixture();
    let first = seal(b"stable shared-key blob", &installation_id, &key_id, &keys).expect("seal");
    let second = seal(
        b"interrupted shared-key blob",
        &installation_id,
        &key_id,
        &keys,
    )
    .expect("seal");
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary
        .path()
        .canonicalize()
        .expect("canonical parent")
        .join("protected");
    let store = ProtectedBlobStore::new(&root).expect("blob store");
    let first = store.put(&first).expect("put first");
    assert_eq!(
        store.put_with_crash(&second, PutCrashPoint::ReferenceWritten),
        Err(ProtectedStoreError::StorageIo)
    );
    drop(store);

    let resumed = ProtectedBlobStore::new(&root).expect("reopened blob store");
    let second = resumed.put(&second).expect("resume second put");
    let mut forged = resumed
        .plan_deletion(&first.envelope_digest, Vec::new())
        .expect("derived plan");
    assert_eq!(
        forged.references,
        vec![DeletionReference {
            kind: DeletionReferenceKind::SharedWrappingKey,
            reference_id: second.envelope_digest,
        }]
    );
    forged.references.clear();
    assert_eq!(
        resumed.execute_deletion(&forged, &keys),
        Err(ProtectedStoreError::BlobReferenced)
    );
    assert!(keys.contains(&locator));
}

#[cfg(unix)]
#[test]
fn deletion_receipt_retry_rejects_recreated_key_or_blob() {
    let (keys, installation_id, key_id, locator) = fixture();
    let envelope = seal(b"stale receipt canary", &installation_id, &key_id, &keys).expect("seal");
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary
        .path()
        .canonicalize()
        .expect("canonical parent")
        .join("protected");
    let store = ProtectedBlobStore::new(&root).expect("blob store");
    let stored = store.put(&envelope).expect("put");
    let plan = store
        .plan_deletion(&stored.envelope_digest, Vec::new())
        .expect("plan");
    store.execute_deletion(&plan, &keys).expect("delete");

    keys.insert(&locator, [7_u8; 32]);
    assert_eq!(
        store.execute_deletion(&plan, &keys),
        Err(ProtectedStoreError::KeyDeletionUnverified)
    );
    keys.delete(&locator).expect("remove recreated key");
    store.put(&envelope).expect("recreate blob");
    assert_eq!(
        store.execute_deletion(&plan, &keys),
        Err(ProtectedStoreError::DeletionStateChanged)
    );
}

#[cfg(unix)]
#[test]
fn concurrent_store_instances_leave_one_canonical_transaction() {
    use std::sync::{Arc, Barrier};

    let (keys, installation_id, key_id, _) = fixture();
    let envelope =
        Arc::new(seal(b"concurrent put canary", &installation_id, &key_id, &keys).expect("seal"));
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary
        .path()
        .canonicalize()
        .expect("canonical parent")
        .join("protected");
    let instances = (0..8)
        .map(|_| ProtectedBlobStore::new(&root).expect("blob store"))
        .collect::<Vec<_>>();
    let barrier = Arc::new(Barrier::new(instances.len()));
    let handles = instances
        .into_iter()
        .map(|store| {
            let barrier = Arc::clone(&barrier);
            let envelope = Arc::clone(&envelope);
            std::thread::spawn(move || {
                barrier.wait();
                let stored = store.put(&envelope).expect("concurrent put");
                assert_eq!(
                    store.read(&stored.envelope_digest).expect("read"),
                    *envelope
                );
                stored.envelope_digest
            })
        })
        .collect::<Vec<_>>();
    let digests = handles
        .into_iter()
        .map(|handle| handle.join().expect("join concurrent put"))
        .collect::<Vec<_>>();
    assert!(digests.windows(2).all(|pair| pair[0] == pair[1]));
    assert_tree_has_no_transaction_temporaries(&root);
}

#[cfg(unix)]
#[test]
fn deletion_resumes_after_every_destructive_step() {
    use crate::records::DeletionJournalV1;
    use crate::storage::DeletionCrashPoint;

    for crash in [
        DeletionCrashPoint::BlobUnlinked,
        DeletionCrashPoint::TransactionUnlinked,
        DeletionCrashPoint::ReferenceRemoved,
        DeletionCrashPoint::KeyDeleted,
    ] {
        let (keys, installation_id, key_id, locator) = fixture();
        let envelope = seal(
            b"interrupted deletion canary",
            &installation_id,
            &key_id,
            &keys,
        )
        .expect("seal");
        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = temporary
            .path()
            .canonicalize()
            .expect("canonical parent")
            .join("protected");
        let store = ProtectedBlobStore::new(&root).expect("blob store");
        let stored = store.put(&envelope).expect("put");
        let plan = store
            .plan_deletion(&stored.envelope_digest, Vec::new())
            .expect("plan");
        assert_eq!(
            store.execute_deletion_with_crash(&plan, &keys, crash),
            Err(ProtectedStoreError::StorageIo),
            "{crash:?}"
        );
        let hex = stored
            .envelope_digest
            .strip_prefix("sha256:")
            .expect("digest prefix");
        let pending = root
            .join("deletions")
            .join(&hex[..2])
            .join(format!("{hex}.pending.json"));
        let journal =
            DeletionJournalV1::decode(&std::fs::read(pending).expect("durable deletion journal"))
                .expect("canonical deletion journal");
        assert_eq!(journal.plan, plan, "{crash:?}");
        drop(store);

        let resumed = ProtectedBlobStore::new(&root).expect("reopened blob store");
        let receipt = resumed
            .execute_deletion(&plan, &keys)
            .expect("resume deletion");
        assert_eq!(receipt.blob, BlobDeletionStatus::Unlinked, "{crash:?}");
        assert!(!keys.contains(&locator), "{crash:?}");
        assert_eq!(
            resumed.read(&stored.envelope_digest),
            Err(ProtectedStoreError::BlobMissing),
            "{crash:?}"
        );
    }
}

#[cfg(unix)]
#[test]
fn key_store_delete_failure_is_retryable() {
    let (keys, installation_id, key_id, locator) = fixture();
    let envelope = seal(b"key retry canary", &installation_id, &key_id, &keys).expect("seal");
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary
        .path()
        .canonicalize()
        .expect("canonical parent")
        .join("protected");
    let store = ProtectedBlobStore::new(&root).expect("blob store");
    let stored = store.put(&envelope).expect("put");
    let plan = store
        .plan_deletion(&stored.envelope_digest, Vec::new())
        .expect("plan");
    keys.fail_next_delete();

    assert_eq!(
        store.execute_deletion(&plan, &keys),
        Err(ProtectedStoreError::BackendUnavailable)
    );
    assert!(keys.contains(&locator));
    drop(store);

    let resumed = ProtectedBlobStore::new(&root).expect("reopened blob store");
    let receipt = resumed
        .execute_deletion(&plan, &keys)
        .expect("retry deletion");
    assert_eq!(
        receipt.wrapping_key,
        WrappingKeyDeletionStatus::DeletedAndAbsenceVerified
    );
    assert!(!keys.contains(&locator));
}

#[cfg(unix)]
#[test]
fn deletion_retry_rejects_a_new_shared_key_peer() {
    let (keys, installation_id, key_id, locator) = fixture();
    let first = seal(b"first deletion peer", &installation_id, &key_id, &keys).expect("seal");
    let second = seal(b"new deletion peer", &installation_id, &key_id, &keys).expect("seal");
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary
        .path()
        .canonicalize()
        .expect("canonical parent")
        .join("protected");
    let store = ProtectedBlobStore::new(&root).expect("blob store");
    let first = store.put(&first).expect("put first");
    let plan = store
        .plan_deletion(&first.envelope_digest, Vec::new())
        .expect("plan");
    keys.fail_next_delete();
    assert_eq!(
        store.execute_deletion(&plan, &keys),
        Err(ProtectedStoreError::BackendUnavailable)
    );

    store.put(&second).expect("put new peer");
    assert_eq!(
        store.execute_deletion(&plan, &keys),
        Err(ProtectedStoreError::BlobReferenced)
    );
    assert!(keys.contains(&locator));
}

#[cfg(unix)]
#[test]
fn protected_store_files_never_contain_plaintext() {
    let (keys, installation_id, key_id, _) = fixture();
    let plaintext = b"plaintext persistence canary 44731";
    let envelope = seal(plaintext, &installation_id, &key_id, &keys).expect("seal");
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary
        .path()
        .canonicalize()
        .expect("canonical parent")
        .join("protected");
    let store = ProtectedBlobStore::new(&root).expect("blob store");
    let stored = store.put(&envelope).expect("put");
    let manifest = store
        .create_backup_manifest(&[stored.envelope_digest])
        .expect("backup manifest");
    assert!(
        !manifest
            .encode()
            .expect("manifest bytes")
            .windows(plaintext.len())
            .any(|window| window == plaintext)
    );
    assert_tree_excludes(&root, plaintext);
}

#[cfg(unix)]
fn assert_tree_excludes(path: &Path, needle: &[u8]) {
    for entry in std::fs::read_dir(path).expect("read protected tree") {
        let entry = entry.expect("protected tree entry");
        let file_type = entry.file_type().expect("entry type");
        if file_type.is_dir() {
            assert_tree_excludes(&entry.path(), needle);
        } else if file_type.is_file() {
            let content = std::fs::read(entry.path()).expect("protected file");
            assert!(!content.windows(needle.len()).any(|window| window == needle));
        }
    }
}

#[cfg(unix)]
fn assert_tree_has_no_transaction_temporaries(path: &Path) {
    for entry in std::fs::read_dir(path).expect("read protected tree") {
        let entry = entry.expect("protected tree entry");
        if entry.file_type().expect("entry type").is_dir() {
            assert_tree_has_no_transaction_temporaries(&entry.path());
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        assert!(!name.ends_with(".next"));
        assert!(!name.ends_with(".pending"));
        assert!(!name.ends_with(".pending.json"));
    }
}

#[cfg(unix)]
#[test]
fn blob_store_rejects_symlinked_ancestors_and_public_roots() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    let temporary = tempfile::tempdir().expect("temporary directory");
    let canonical = temporary
        .path()
        .canonicalize()
        .expect("canonical temporary directory");
    let private = canonical.join("private");
    std::fs::create_dir(&private).expect("private fixture");
    std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700))
        .expect("private permissions");
    let redirect = canonical.join("redirect");
    symlink(&private, &redirect).expect("symlink fixture");
    assert!(matches!(
        ProtectedBlobStore::new(redirect.join("blobs")),
        Err(ProtectedStoreError::UnsafeStorageRoot)
    ));

    let public = canonical.join("public");
    std::fs::create_dir(&public).expect("public fixture");
    std::fs::set_permissions(&public, std::fs::Permissions::from_mode(0o755))
        .expect("public permissions");
    assert!(matches!(
        ProtectedBlobStore::new(&public),
        Err(ProtectedStoreError::UnsafeStorageRoot)
    ));
    assert_eq!(
        std::fs::metadata(&public)
            .expect("public metadata")
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
}
