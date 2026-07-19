use aes_gcm::aead::{Aead, Nonce, Payload};
use aes_gcm::{Aes256Gcm, Key, KeyInit as _};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::{KeyLocator, ProtectedStoreError, WrappingKeyStore};

pub const ENVELOPE_VERSION: &str = "phase4-protected-envelope-2";
pub const ALGORITHM: &str = "AES-256-GCM";
pub const DATA_CLASS: &str = "D2_protected_evidence";
const MAX_PLAINTEXT_BYTES: usize = 64 * 1024 * 1024;
const MAX_ENCODED_BYTES: usize = 96 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedEnvelopeV2 {
    pub version: String,
    pub algorithm: String,
    pub protected_id: String,
    pub data_class: String,
    pub installation_id: String,
    pub wrapping_key_id: String,
    pub content_nonce: String,
    pub wrapping_nonce: String,
    pub wrapped_data_key: String,
    pub ciphertext: String,
}

impl ProtectedEnvelopeV2 {
    pub fn encode(&self) -> Result<Vec<u8>, ProtectedStoreError> {
        self.validate()?;
        serde_jcs::to_vec(self).map_err(|_| ProtectedStoreError::InvalidEnvelope)
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, ProtectedStoreError> {
        if encoded.len() > MAX_ENCODED_BYTES {
            return Err(ProtectedStoreError::ContentTooLarge);
        }
        let envelope: Self =
            serde_json::from_slice(encoded).map_err(|_| ProtectedStoreError::InvalidEnvelope)?;
        envelope.validate()?;
        let canonical = envelope.encode()?;
        if canonical != encoded {
            return Err(ProtectedStoreError::NonCanonicalEnvelope);
        }
        Ok(envelope)
    }

    fn validate(&self) -> Result<(), ProtectedStoreError> {
        if self.version != ENVELOPE_VERSION
            || self.algorithm != ALGORITHM
            || self.data_class != DATA_CLASS
            || !valid_id(&self.protected_id, "protected")
            || !valid_id(&self.installation_id, "installation")
            || !valid_id(&self.wrapping_key_id, "key")
        {
            return Err(ProtectedStoreError::InvalidEnvelope);
        }
        let content_nonce = decode_exact::<12>(&self.content_nonce)?;
        let wrapping_nonce = decode_exact::<12>(&self.wrapping_nonce)?;
        let wrapped_data_key = decode_exact::<48>(&self.wrapped_data_key)?;
        let ciphertext = BASE64
            .decode(&self.ciphertext)
            .map_err(|_| ProtectedStoreError::InvalidEnvelope)?;
        if ciphertext.len() < 16 || ciphertext.len() > MAX_PLAINTEXT_BYTES + 16 {
            return Err(ProtectedStoreError::InvalidEnvelope);
        }
        let _ = (content_nonce, wrapping_nonce, wrapped_data_key);
        Ok(())
    }
}

pub fn new_installation_id() -> Result<String, ProtectedStoreError> {
    new_id("installation")
}

pub fn new_key_id() -> Result<String, ProtectedStoreError> {
    new_id("key")
}

pub fn seal(
    plaintext: &[u8],
    installation_id: &str,
    wrapping_key_id: &str,
    key_store: &impl WrappingKeyStore,
) -> Result<ProtectedEnvelopeV2, ProtectedStoreError> {
    if plaintext.len() > MAX_PLAINTEXT_BYTES {
        return Err(ProtectedStoreError::ContentTooLarge);
    }
    let locator = KeyLocator::new(installation_id, wrapping_key_id)?;
    let wrapping_key = key_store.load(&locator)?;
    let protected_id = new_id("protected")?;
    let content_aad = content_aad(&protected_id, installation_id)?;
    let wrapping_aad = wrapping_aad(&protected_id, installation_id, wrapping_key_id)?;
    let mut data_key = Zeroizing::new([0_u8; 32]);
    getrandom::fill(data_key.as_mut()).map_err(|_| ProtectedStoreError::BackendUnavailable)?;
    let content_nonce = random_nonce()?;
    let wrapping_nonce = random_nonce()?;
    let ciphertext = encrypt(&data_key, &content_nonce, plaintext, &content_aad)?;
    let wrapped_data_key = encrypt(
        &wrapping_key,
        &wrapping_nonce,
        data_key.as_ref(),
        &wrapping_aad,
    )?;
    Ok(ProtectedEnvelopeV2 {
        version: ENVELOPE_VERSION.to_owned(),
        algorithm: ALGORITHM.to_owned(),
        protected_id,
        data_class: DATA_CLASS.to_owned(),
        installation_id: installation_id.to_owned(),
        wrapping_key_id: wrapping_key_id.to_owned(),
        content_nonce: BASE64.encode(content_nonce),
        wrapping_nonce: BASE64.encode(wrapping_nonce),
        wrapped_data_key: BASE64.encode(wrapped_data_key),
        ciphertext: BASE64.encode(ciphertext),
    })
}

pub fn open(
    envelope: &ProtectedEnvelopeV2,
    key_store: &impl WrappingKeyStore,
) -> Result<Zeroizing<Vec<u8>>, ProtectedStoreError> {
    envelope.validate()?;
    let locator = KeyLocator::new(&envelope.installation_id, &envelope.wrapping_key_id)?;
    let wrapping_key = key_store.load(&locator)?;
    let content_nonce = decode_exact::<12>(&envelope.content_nonce)?;
    let wrapping_nonce = decode_exact::<12>(&envelope.wrapping_nonce)?;
    let mut wrapped_data_key = Zeroizing::new(decode_exact::<48>(&envelope.wrapped_data_key)?);
    let wrapping_aad = wrapping_aad(
        &envelope.protected_id,
        &envelope.installation_id,
        &envelope.wrapping_key_id,
    )?;
    let unwrapped = decrypt(
        &wrapping_key,
        &wrapping_nonce,
        wrapped_data_key.as_ref(),
        &wrapping_aad,
    )?;
    wrapped_data_key.zeroize();
    let mut data_key = key_array(unwrapped)?;
    let content_aad = content_aad(&envelope.protected_id, &envelope.installation_id)?;
    let ciphertext = Zeroizing::new(
        BASE64
            .decode(&envelope.ciphertext)
            .map_err(|_| ProtectedStoreError::InvalidEnvelope)?,
    );
    let plaintext = decrypt(
        &data_key,
        &content_nonce,
        ciphertext.as_slice(),
        &content_aad,
    )?;
    data_key.zeroize();
    Ok(Zeroizing::new(plaintext))
}

pub fn rewrap(
    envelope: &ProtectedEnvelopeV2,
    new_wrapping_key_id: &str,
    key_store: &impl WrappingKeyStore,
) -> Result<ProtectedEnvelopeV2, ProtectedStoreError> {
    envelope.validate()?;
    let old_locator = KeyLocator::new(&envelope.installation_id, &envelope.wrapping_key_id)?;
    let new_locator = KeyLocator::new(&envelope.installation_id, new_wrapping_key_id)?;
    let old_wrapping_key = key_store.load(&old_locator)?;
    let new_wrapping_key = key_store.load(&new_locator)?;
    let wrapping_nonce = decode_exact::<12>(&envelope.wrapping_nonce)?;
    let old_aad = wrapping_aad(
        &envelope.protected_id,
        &envelope.installation_id,
        &envelope.wrapping_key_id,
    )?;
    let wrapped = Zeroizing::new(decode_exact::<48>(&envelope.wrapped_data_key)?);
    let unwrapped = decrypt(
        &old_wrapping_key,
        &wrapping_nonce,
        wrapped.as_ref(),
        &old_aad,
    )?;
    let mut data_key = key_array(unwrapped)?;
    let new_nonce = random_nonce()?;
    let new_aad = wrapping_aad(
        &envelope.protected_id,
        &envelope.installation_id,
        new_wrapping_key_id,
    )?;
    let new_wrapped = encrypt(&new_wrapping_key, &new_nonce, data_key.as_ref(), &new_aad)?;
    data_key.zeroize();
    Ok(ProtectedEnvelopeV2 {
        wrapping_key_id: new_wrapping_key_id.to_owned(),
        wrapping_nonce: BASE64.encode(new_nonce),
        wrapped_data_key: BASE64.encode(new_wrapped),
        ..envelope.clone()
    })
}

fn content_aad(protected_id: &str, installation_id: &str) -> Result<Vec<u8>, ProtectedStoreError> {
    serde_jcs::to_vec(&serde_json::json!({
        "version": ENVELOPE_VERSION,
        "algorithm": ALGORITHM,
        "protected_id": protected_id,
        "data_class": DATA_CLASS,
        "installation_id": installation_id,
    }))
    .map_err(|_| ProtectedStoreError::InvalidEnvelope)
}

fn wrapping_aad(
    protected_id: &str,
    installation_id: &str,
    wrapping_key_id: &str,
) -> Result<Vec<u8>, ProtectedStoreError> {
    serde_jcs::to_vec(&serde_json::json!({
        "version": ENVELOPE_VERSION,
        "algorithm": ALGORITHM,
        "protected_id": protected_id,
        "data_class": DATA_CLASS,
        "installation_id": installation_id,
        "wrapping_key_id": wrapping_key_id,
        "purpose": "wrapped_data_key",
    }))
    .map_err(|_| ProtectedStoreError::InvalidEnvelope)
}

fn encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, ProtectedStoreError> {
    let key: &Key<Aes256Gcm> = key.into();
    let nonce: &Nonce<Aes256Gcm> = nonce.into();
    Aes256Gcm::new(key)
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| ProtectedStoreError::AuthenticationFailed)
}

fn decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, ProtectedStoreError> {
    let key: &Key<Aes256Gcm> = key.into();
    let nonce: &Nonce<Aes256Gcm> = nonce.into();
    Aes256Gcm::new(key)
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| ProtectedStoreError::AuthenticationFailed)
}

fn key_array(mut value: Vec<u8>) -> Result<Zeroizing<[u8; 32]>, ProtectedStoreError> {
    if value.len() != 32 {
        value.zeroize();
        return Err(ProtectedStoreError::AuthenticationFailed);
    }
    let mut key = Zeroizing::new([0_u8; 32]);
    key.copy_from_slice(&value);
    value.zeroize();
    Ok(key)
}

fn random_nonce() -> Result<[u8; 12], ProtectedStoreError> {
    let mut nonce = [0_u8; 12];
    getrandom::fill(&mut nonce).map_err(|_| ProtectedStoreError::BackendUnavailable)?;
    Ok(nonce)
}

fn new_id(prefix: &str) -> Result<String, ProtectedStoreError> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| ProtectedStoreError::BackendUnavailable)?;
    let encoded = hex(&bytes);
    bytes.zeroize();
    Ok(format!("{prefix}_{encoded}"))
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

fn decode_exact<const N: usize>(value: &str) -> Result<[u8; N], ProtectedStoreError> {
    let decoded = BASE64
        .decode(value)
        .map_err(|_| ProtectedStoreError::InvalidEnvelope)?;
    decoded
        .try_into()
        .map_err(|_| ProtectedStoreError::InvalidEnvelope)
}

fn hex(value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}
