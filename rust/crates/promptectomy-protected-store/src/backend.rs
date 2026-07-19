use std::fmt;

use subtle::ConstantTimeEq as _;
use zeroize::{Zeroize, Zeroizing};

use crate::ProtectedStoreError;

const SERVICE: &str = "dev.promptectomy.protected-evidence.v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendKind {
    MacOsKeychain,
    WindowsCredentialManager,
    LinuxSecretService,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendReadiness {
    Ready,
    KeyMissing,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyLocator {
    installation_id: String,
    key_id: String,
}

impl KeyLocator {
    pub fn new(installation_id: &str, key_id: &str) -> Result<Self, ProtectedStoreError> {
        if !valid_id(installation_id, "installation") || !valid_id(key_id, "key") {
            return Err(ProtectedStoreError::InvalidIdentifier);
        }
        Ok(Self {
            installation_id: installation_id.to_owned(),
            key_id: key_id.to_owned(),
        })
    }

    fn account(&self) -> String {
        format!("{}/{}", self.installation_id, self.key_id)
    }
}

impl fmt::Display for KeyLocator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.account())
    }
}

pub trait WrappingKeyStore {
    fn backend(&self) -> Result<BackendKind, ProtectedStoreError>;
    fn readiness(&self, locator: &KeyLocator) -> Result<BackendReadiness, ProtectedStoreError>;
    fn load(&self, locator: &KeyLocator) -> Result<Zeroizing<[u8; 32]>, ProtectedStoreError>;
    fn store(&self, locator: &KeyLocator, key: &[u8; 32]) -> Result<(), ProtectedStoreError>;
    fn delete(&self, locator: &KeyLocator) -> Result<(), ProtectedStoreError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemKeyStore;

impl WrappingKeyStore for SystemKeyStore {
    fn backend(&self) -> Result<BackendKind, ProtectedStoreError> {
        #[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
        return Ok(platform_backend());
        #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
        return Err(ProtectedStoreError::UnsupportedPlatform);
    }

    fn readiness(&self, locator: &KeyLocator) -> Result<BackendReadiness, ProtectedStoreError> {
        match native_entry(locator)?.get_secret() {
            Ok(mut secret) => {
                let valid = secret.len() == 32;
                secret.zeroize();
                if valid {
                    Ok(BackendReadiness::Ready)
                } else {
                    Err(ProtectedStoreError::InvalidKeyValue)
                }
            }
            Err(keyring::Error::NoEntry) => Ok(BackendReadiness::KeyMissing),
            Err(error) => Err(map_keyring_error(&error)),
        }
    }

    fn load(&self, locator: &KeyLocator) -> Result<Zeroizing<[u8; 32]>, ProtectedStoreError> {
        let mut secret = Zeroizing::new(
            native_entry(locator)?
                .get_secret()
                .map_err(|error| map_keyring_error(&error))?,
        );
        if secret.len() != 32 {
            return Err(ProtectedStoreError::InvalidKeyValue);
        }
        let mut key = Zeroizing::new([0_u8; 32]);
        key.copy_from_slice(secret.as_slice());
        secret.zeroize();
        Ok(key)
    }

    fn store(&self, locator: &KeyLocator, key: &[u8; 32]) -> Result<(), ProtectedStoreError> {
        let entry = native_entry(locator)?;
        match entry.get_secret() {
            Ok(mut existing) => {
                let matches = existing.len() == key.len()
                    && bool::from(existing.as_slice().ct_eq(key.as_slice()));
                existing.zeroize();
                return if matches {
                    Ok(())
                } else {
                    Err(ProtectedStoreError::KeyConflict)
                };
            }
            Err(keyring::Error::NoEntry) => {}
            Err(error) => return Err(map_keyring_error(&error)),
        }
        entry
            .set_secret(key)
            .map_err(|error| map_keyring_error(&error))?;
        let mut stored = Zeroizing::new(
            entry
                .get_secret()
                .map_err(|error| map_keyring_error(&error))?,
        );
        let verified =
            stored.len() == key.len() && bool::from(stored.as_slice().ct_eq(key.as_slice()));
        stored.zeroize();
        if !verified {
            return Err(ProtectedStoreError::InvalidKeyValue);
        }
        Ok(())
    }

    fn delete(&self, locator: &KeyLocator) -> Result<(), ProtectedStoreError> {
        let entry = native_entry(locator)?;
        entry
            .delete_credential()
            .map_err(|error| map_keyring_error(&error))?;
        match entry.get_secret() {
            Err(keyring::Error::NoEntry) => Ok(()),
            Ok(mut residual) => {
                residual.zeroize();
                Err(ProtectedStoreError::AccessDenied)
            }
            Err(error) => Err(map_keyring_error(&error)),
        }
    }
}

fn valid_id(value: &str, prefix: &str) -> bool {
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

#[cfg(target_os = "macos")]
fn platform_backend() -> BackendKind {
    BackendKind::MacOsKeychain
}

#[cfg(target_os = "windows")]
fn platform_backend() -> BackendKind {
    BackendKind::WindowsCredentialManager
}

#[cfg(target_os = "linux")]
fn platform_backend() -> BackendKind {
    BackendKind::LinuxSecretService
}

#[cfg(target_os = "macos")]
fn native_entry(locator: &KeyLocator) -> Result<keyring::Entry, ProtectedStoreError> {
    let credential =
        keyring::macos::MacCredential::new_with_target(None, SERVICE, &locator.account())
            .map_err(|error| map_keyring_error(&error))?;
    Ok(keyring::Entry::new_with_credential(Box::new(credential)))
}

#[cfg(target_os = "windows")]
fn native_entry(locator: &KeyLocator) -> Result<keyring::Entry, ProtectedStoreError> {
    let credential = keyring::windows::WinCredential::new_with_target(
        Some(&format!("{SERVICE}/{}", locator.account())),
        SERVICE,
        &locator.account(),
    )
    .map_err(|error| map_keyring_error(&error))?;
    Ok(keyring::Entry::new_with_credential(Box::new(credential)))
}

#[cfg(target_os = "linux")]
fn native_entry(locator: &KeyLocator) -> Result<keyring::Entry, ProtectedStoreError> {
    let credential = keyring::secret_service::SsCredential::new_with_target(
        Some("default"),
        SERVICE,
        &locator.account(),
    )
    .map_err(|error| map_keyring_error(&error))?;
    Ok(keyring::Entry::new_with_credential(Box::new(credential)))
}

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
fn native_entry(_locator: &KeyLocator) -> Result<(), ProtectedStoreError> {
    Err(ProtectedStoreError::UnsupportedPlatform)
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
fn map_keyring_error(error: &keyring::Error) -> ProtectedStoreError {
    match error {
        keyring::Error::NoEntry => ProtectedStoreError::KeyMissing,
        keyring::Error::NoStorageAccess(_) => ProtectedStoreError::AccessDenied,
        keyring::Error::Ambiguous(_) => ProtectedStoreError::AmbiguousKey,
        keyring::Error::BadEncoding(_) => ProtectedStoreError::InvalidKeyValue,
        keyring::Error::TooLong(_, _) | keyring::Error::Invalid(_, _) => {
            ProtectedStoreError::InvalidIdentifier
        }
        _ => ProtectedStoreError::BackendUnavailable,
    }
}
