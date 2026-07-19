use std::collections::BTreeMap;
use std::sync::Mutex;

use base64::Engine as _;
use zeroize::Zeroizing;

use super::*;

#[derive(Default)]
struct MemoryKeyStore {
    keys: Mutex<BTreeMap<String, [u8; 32]>>,
}

impl MemoryKeyStore {
    fn insert(&self, locator: &KeyLocator, key: [u8; 32]) {
        self.keys
            .lock()
            .expect("memory key store lock")
            .insert(locator.to_string(), key);
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

#[test]
fn system_store_selects_only_an_accepted_native_backend() {
    let backend = SystemKeyStore.backend();
    #[cfg(target_os = "macos")]
    assert_eq!(backend, Ok(BackendKind::MacOsKeychain));
    #[cfg(target_os = "windows")]
    assert_eq!(backend, Ok(BackendKind::WindowsCredentialManager));
    #[cfg(target_os = "linux")]
    assert_eq!(backend, Ok(BackendKind::LinuxSecretService));
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    assert_eq!(backend, Err(ProtectedStoreError::UnsupportedPlatform));
}
