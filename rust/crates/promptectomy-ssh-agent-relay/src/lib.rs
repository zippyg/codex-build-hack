#![forbid(unsafe_code)]

use std::fmt;
#[cfg(unix)]
use std::io::{Read as _, Write as _};
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
#[cfg(unix)]
use std::path::Path;
#[cfg(unix)]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(unix)]
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

pub const GRANT_VERSION: &str = "promptectomy.ssh-broker-request.v2";
pub const RECEIPT_VERSION: &str = "promptectomy.ssh-agent-relay-receipt.v1";
#[cfg(unix)]
const IDENTITIES_REQUEST: u8 = 11;
#[cfg(unix)]
const IDENTITIES_ANSWER: u8 = 12;
#[cfg(unix)]
const SIGN_REQUEST: u8 = 13;
#[cfg(unix)]
const SIGN_RESPONSE: u8 = 14;
#[cfg(unix)]
const SUCCESS: u8 = 6;
#[cfg(unix)]
const FAILURE: u8 = 5;
#[cfg(unix)]
const EXTENSION: u8 = 27;
#[cfg(unix)]
const SESSION_BIND: &[u8] = b"session-bind@openssh.com";
#[cfg(unix)]
const QUERY: &[u8] = b"query";
#[cfg(unix)]
const MAX_IDENTITY_COMMENT: usize = 256;
#[cfg(unix)]
const MAX_IDENTITIES: u32 = 256;
#[cfg(unix)]
const MAX_SESSION_ID_BYTES: usize = 64 * 1024;
#[cfg(unix)]
const MAX_SIGNATURE_BYTES: usize = 64 * 1024;
#[cfg(unix)]
const CANCEL_POLL: Duration = Duration::from_millis(50);

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RelayGrant {
    pub schema_version: String,
    pub opaque_handle: String,
    pub display_host: String,
    pub port: u16,
    pub username: String,
    pub repository: String,
    pub revision: String,
    pub host_key_type: String,
    pub host_key_base64: String,
    pub host_key_sha256: String,
    pub selected_public_key_base64: String,
    pub manifest_digest: String,
    pub credential_source: String,
    pub wall_time_seconds: u64,
    pub max_connections: u8,
    pub max_frame_bytes: usize,
    pub max_signatures: u8,
}

impl fmt::Debug for RelayGrant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayGrant")
            .field("schema_version", &self.schema_version)
            .field("display_host", &self.display_host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("revision", &self.revision)
            .field("host_key_type", &self.host_key_type)
            .field("host_key_sha256", &self.host_key_sha256)
            .field("manifest_digest", &self.manifest_digest)
            .field("wall_time_seconds", &self.wall_time_seconds)
            .field("max_connections", &self.max_connections)
            .field("max_frame_bytes", &self.max_frame_bytes)
            .field("max_signatures", &self.max_signatures)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedGrant {
    grant: RelayGrant,
    host_key: Vec<u8>,
    selected_public_key: Vec<u8>,
}

impl RelayGrant {
    pub fn validate(self) -> Result<ValidatedGrant, RelayError> {
        if self.schema_version != GRANT_VERSION
            || self.port != 22
            || self.username != "git"
            || self.credential_source != "selected_ssh_agent"
            || !valid_handle(&self.opaque_handle)
            || !valid_host(&self.display_host)
            || !valid_repository(&self.repository)
            || !valid_revision(&self.revision)
            || !valid_key_type(&self.host_key_type)
            || !valid_digest(&self.manifest_digest)
            || !(1..=300).contains(&self.wall_time_seconds)
            || self.max_connections != 1
            || !(1024..=256 * 1024).contains(&self.max_frame_bytes)
            || !(1..=4).contains(&self.max_signatures)
        {
            return Err(RelayError::InvalidGrant);
        }
        let host_key = decode_blob(&self.host_key_base64, 16 * 1024)?;
        let selected_public_key = decode_blob(&self.selected_public_key_base64, 16 * 1024)?;
        if ssh_string_prefix(&host_key)? != self.host_key_type.as_bytes()
            || !valid_fingerprint(&self.host_key_sha256, &host_key)
            || ssh_string_prefix(&selected_public_key)?.is_empty()
        {
            return Err(RelayError::InvalidGrant);
        }
        Ok(ValidatedGrant {
            grant: self,
            host_key,
            selected_public_key,
        })
    }
}

impl ValidatedGrant {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, RelayError> {
        serde_jcs::to_vec(&self.grant).map_err(|_| RelayError::InvalidGrant)
    }

    #[must_use]
    pub fn manifest_digest(&self) -> &str {
        &self.grant.manifest_digest
    }

    #[must_use]
    pub fn repository(&self) -> &str {
        &self.grant.repository
    }

    #[must_use]
    pub fn host_key_type(&self) -> &str {
        &self.grant.host_key_type
    }

    #[must_use]
    pub fn host_key_base64(&self) -> &str {
        &self.grant.host_key_base64
    }

    #[must_use]
    pub const fn wall_time_seconds(&self) -> u64 {
        self.grant.wall_time_seconds
    }

    #[cfg(unix)]
    pub fn serve(
        &self,
        listener: &UnixListener,
        upstream_path: &Path,
    ) -> Result<RelayReceipt, RelayError> {
        self.serve_cancelable(listener, upstream_path, &AtomicBool::new(false))
    }

    #[cfg(unix)]
    pub fn serve_cancelable(
        &self,
        listener: &UnixListener,
        upstream_path: &Path,
        cancelled: &AtomicBool,
    ) -> Result<RelayReceipt, RelayError> {
        self.serve_with_receipts(listener, upstream_path, cancelled, |_| Ok(()))
    }

    #[cfg(unix)]
    pub fn serve_with_receipts(
        &self,
        listener: &UnixListener,
        upstream_path: &Path,
        cancelled: &AtomicBool,
        mut publish: impl FnMut(RelayReceipt) -> Result<(), RelayError>,
    ) -> Result<RelayReceipt, RelayError> {
        listener
            .set_nonblocking(true)
            .map_err(|_| RelayError::RelayUnavailable)?;
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(self.grant.wall_time_seconds))
            .ok_or(RelayError::InvalidGrant)?;
        let mut client = loop {
            if cancelled.load(Ordering::Acquire) {
                return Err(RelayError::Cancelled);
            }
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err(RelayError::TimedOut);
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => return Err(RelayError::RelayUnavailable),
            }
        };
        let mut upstream =
            UnixStream::connect(upstream_path).map_err(|_| RelayError::UpstreamUnavailable)?;
        client
            .set_nonblocking(false)
            .map_err(|_| RelayError::RelayUnavailable)?;
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(RelayError::TimedOut)?;
        client
            .set_read_timeout(Some(remaining))
            .map_err(|_| RelayError::RelayUnavailable)?;
        client
            .set_write_timeout(Some(remaining))
            .map_err(|_| RelayError::RelayUnavailable)?;
        upstream
            .set_read_timeout(Some(remaining))
            .map_err(|_| RelayError::UpstreamUnavailable)?;
        upstream
            .set_write_timeout(Some(remaining))
            .map_err(|_| RelayError::UpstreamUnavailable)?;
        self.relay(
            &mut client,
            &mut upstream,
            deadline,
            cancelled,
            &mut publish,
        )
    }

    #[cfg(unix)]
    fn relay(
        &self,
        client: &mut UnixStream,
        upstream: &mut UnixStream,
        deadline: Instant,
        cancelled: &AtomicBool,
        publish: &mut impl FnMut(RelayReceipt) -> Result<(), RelayError>,
    ) -> Result<RelayReceipt, RelayError> {
        let mut bound = false;
        let mut signatures = 0_u8;
        loop {
            set_deadline(client, deadline, RelayError::RelayUnavailable)?;
            if cancelled.load(Ordering::Acquire) {
                return Err(RelayError::Cancelled);
            }
            let frame = match read_frame(client, self.grant.max_frame_bytes, deadline, cancelled) {
                Ok(frame) => frame,
                Err(RelayError::ConnectionClosed) if bound && signatures > 0 => {
                    return Ok(RelayReceipt {
                        session_bound: true,
                        signatures,
                    });
                }
                Err(error) => return Err(error),
            };
            let Some(kind) = frame.first().copied() else {
                write_frame(client, &[FAILURE], self.grant.max_frame_bytes)?;
                continue;
            };
            match kind {
                IDENTITIES_REQUEST if frame.len() == 1 => {
                    let response = forward(
                        upstream,
                        &frame,
                        self.grant.max_frame_bytes,
                        deadline,
                        cancelled,
                    )?;
                    let filtered = filter_identities(&response, &self.selected_public_key)?;
                    write_frame(client, &filtered, self.grant.max_frame_bytes)?;
                }
                EXTENSION => {
                    let Ok(extension) = extension_name(&frame) else {
                        write_frame(client, &[FAILURE], self.grant.max_frame_bytes)?;
                        continue;
                    };
                    let valid = if extension == QUERY {
                        validate_query(&frame)
                    } else if extension == SESSION_BIND {
                        validate_session_bind(&frame, &self.host_key)
                    } else {
                        Err(RelayError::InvalidMessage)
                    };
                    if valid.is_err() {
                        write_frame(client, &[FAILURE], self.grant.max_frame_bytes)?;
                        continue;
                    }
                    let response = forward(
                        upstream,
                        &frame,
                        self.grant.max_frame_bytes,
                        deadline,
                        cancelled,
                    )?;
                    if extension == SESSION_BIND {
                        if response != [SUCCESS] {
                            return Err(RelayError::SessionBindDenied);
                        }
                        bound = true;
                    }
                    write_frame(client, &response, self.grant.max_frame_bytes)?;
                }
                SIGN_REQUEST if bound && signatures < self.grant.max_signatures => {
                    if validate_sign_request(&frame, &self.selected_public_key).is_err() {
                        write_frame(client, &[FAILURE], self.grant.max_frame_bytes)?;
                        continue;
                    }
                    let response = forward(
                        upstream,
                        &frame,
                        self.grant.max_frame_bytes,
                        deadline,
                        cancelled,
                    )?;
                    if response.first().copied() != Some(SIGN_RESPONSE) {
                        return Err(RelayError::SignatureDenied);
                    }
                    signatures = signatures.saturating_add(1);
                    write_frame(client, &response, self.grant.max_frame_bytes)?;
                    publish(RelayReceipt {
                        session_bound: true,
                        signatures,
                    })?;
                }
                _ => write_frame(client, &[FAILURE], self.grant.max_frame_bytes)?,
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RelayReceiptDocument {
    pub schema_version: String,
    pub manifest_digest: String,
    pub session_bound: bool,
    pub signatures: u8,
}

impl RelayReceiptDocument {
    #[must_use]
    pub fn from_receipt(manifest_digest: &str, receipt: RelayReceipt) -> Self {
        Self {
            schema_version: RECEIPT_VERSION.to_owned(),
            manifest_digest: manifest_digest.to_owned(),
            session_bound: receipt.session_bound,
            signatures: receipt.signatures,
        }
    }
}

#[cfg(unix)]
fn set_deadline(
    stream: &UnixStream,
    deadline: Instant,
    error: RelayError,
) -> Result<(), RelayError> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or(RelayError::TimedOut)?;
    stream
        .set_read_timeout(Some(remaining.min(CANCEL_POLL)))
        .map_err(|_| error)?;
    stream.set_write_timeout(Some(remaining)).map_err(|_| error)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayReceipt {
    pub session_bound: bool,
    pub signatures: u8,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum RelayError {
    #[error("invalid_grant")]
    InvalidGrant,
    #[error("relay_unavailable")]
    RelayUnavailable,
    #[error("upstream_unavailable")]
    UpstreamUnavailable,
    #[error("frame_exceeded")]
    FrameExceeded,
    #[error("invalid_agent_message")]
    InvalidMessage,
    #[error("session_bind_denied")]
    SessionBindDenied,
    #[error("signature_denied")]
    SignatureDenied,
    #[error("timed_out")]
    TimedOut,
    #[error("cancelled")]
    Cancelled,
    #[error("connection_closed")]
    ConnectionClosed,
    #[error("receipt_unavailable")]
    ReceiptUnavailable,
}

#[cfg(unix)]
fn read_frame(
    stream: &mut UnixStream,
    max: usize,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Result<Vec<u8>, RelayError> {
    let mut header = [0_u8; 4];
    read_exact_until(stream, &mut header, deadline, cancelled)?;
    let size =
        usize::try_from(u32::from_be_bytes(header)).map_err(|_| RelayError::FrameExceeded)?;
    if size == 0 || size > max {
        return Err(RelayError::FrameExceeded);
    }
    let mut payload = vec![0_u8; size];
    read_exact_until(stream, &mut payload, deadline, cancelled)?;
    Ok(payload)
}

#[cfg(unix)]
fn read_exact_until(
    stream: &mut UnixStream,
    mut bytes: &mut [u8],
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Result<(), RelayError> {
    while !bytes.is_empty() {
        if cancelled.load(Ordering::Acquire) {
            return Err(RelayError::Cancelled);
        }
        if Instant::now() >= deadline {
            return Err(RelayError::TimedOut);
        }
        match stream.read(bytes) {
            Ok(0) => return Err(RelayError::ConnectionClosed),
            Ok(read) => bytes = &mut bytes[read..],
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
                ) =>
            {
                return Err(RelayError::ConnectionClosed);
            }
            Err(_) => return Err(RelayError::RelayUnavailable),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn write_frame(stream: &mut UnixStream, payload: &[u8], max: usize) -> Result<(), RelayError> {
    if payload.is_empty() || payload.len() > max {
        return Err(RelayError::FrameExceeded);
    }
    let size = u32::try_from(payload.len()).map_err(|_| RelayError::FrameExceeded)?;
    stream
        .write_all(&size.to_be_bytes())
        .and_then(|()| stream.write_all(payload))
        .map_err(|_| RelayError::RelayUnavailable)
}

#[cfg(unix)]
fn forward(
    upstream: &mut UnixStream,
    payload: &[u8],
    max: usize,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Result<Vec<u8>, RelayError> {
    set_deadline(upstream, deadline, RelayError::UpstreamUnavailable)?;
    write_frame(upstream, payload, max).map_err(|_| RelayError::UpstreamUnavailable)?;
    read_frame(upstream, max, deadline, cancelled).map_err(|error| match error {
        RelayError::Cancelled | RelayError::TimedOut => error,
        _ => RelayError::UpstreamUnavailable,
    })
}

#[cfg(unix)]
fn filter_identities(response: &[u8], selected: &[u8]) -> Result<Vec<u8>, RelayError> {
    if response.first().copied() != Some(IDENTITIES_ANSWER) {
        return Err(RelayError::InvalidMessage);
    }
    let mut cursor = Cursor::new(&response[1..]);
    let count = cursor.u32()?;
    if count > MAX_IDENTITIES {
        return Err(RelayError::InvalidMessage);
    }
    let mut found = false;
    for _ in 0..count {
        let key = cursor.string(16 * 1024)?;
        let _comment = cursor.string(MAX_IDENTITY_COMMENT)?;
        found |= key == selected;
    }
    cursor.finish()?;
    if !found {
        return Ok(vec![IDENTITIES_ANSWER, 0, 0, 0, 0]);
    }
    let mut filtered = vec![IDENTITIES_ANSWER];
    filtered.extend_from_slice(&1_u32.to_be_bytes());
    push_string(&mut filtered, selected)?;
    push_string(&mut filtered, b"promptectomy-selected-key")?;
    Ok(filtered)
}

#[cfg(unix)]
fn extension_name(frame: &[u8]) -> Result<&[u8], RelayError> {
    let mut cursor = Cursor::new(frame.get(1..).ok_or(RelayError::InvalidMessage)?);
    cursor.string(128)
}

#[cfg(unix)]
fn validate_query(frame: &[u8]) -> Result<(), RelayError> {
    let mut cursor = Cursor::new(frame.get(1..).ok_or(RelayError::InvalidMessage)?);
    if cursor.string(128)? != QUERY {
        return Err(RelayError::InvalidMessage);
    }
    while !cursor.remaining().is_empty() {
        if cursor.string(128)? != SESSION_BIND {
            return Err(RelayError::InvalidMessage);
        }
    }
    Ok(())
}

#[cfg(unix)]
fn validate_session_bind(frame: &[u8], expected_host_key: &[u8]) -> Result<(), RelayError> {
    let mut cursor = Cursor::new(frame.get(1..).ok_or(RelayError::InvalidMessage)?);
    if cursor.string(128)? != SESSION_BIND
        || cursor.string(16 * 1024)? != expected_host_key
        || cursor.string(MAX_SESSION_ID_BYTES)?.is_empty()
        || cursor.string(MAX_SIGNATURE_BYTES)?.is_empty()
        || cursor.byte()? != 0
    {
        return Err(RelayError::InvalidMessage);
    }
    cursor.finish()
}

#[cfg(unix)]
fn validate_sign_request(frame: &[u8], selected: &[u8]) -> Result<(), RelayError> {
    let mut cursor = Cursor::new(frame.get(1..).ok_or(RelayError::InvalidMessage)?);
    if cursor.string(16 * 1024)? != selected || cursor.string(64 * 1024)?.is_empty() {
        return Err(RelayError::InvalidMessage);
    }
    let flags = cursor.u32()?;
    if !matches!(flags, 0 | 2 | 4) {
        return Err(RelayError::InvalidMessage);
    }
    cursor.finish()
}

struct Cursor<'a> {
    remaining: &'a [u8],
}

impl<'a> Cursor<'a> {
    const fn new(remaining: &'a [u8]) -> Self {
        Self { remaining }
    }

    #[cfg(unix)]
    fn byte(&mut self) -> Result<u8, RelayError> {
        let (&value, rest) = self
            .remaining
            .split_first()
            .ok_or(RelayError::InvalidMessage)?;
        self.remaining = rest;
        Ok(value)
    }

    fn u32(&mut self) -> Result<u32, RelayError> {
        let bytes = self.remaining.get(..4).ok_or(RelayError::InvalidMessage)?;
        self.remaining = &self.remaining[4..];
        Ok(u32::from_be_bytes(
            bytes.try_into().map_err(|_| RelayError::InvalidMessage)?,
        ))
    }

    fn string(&mut self, max: usize) -> Result<&'a [u8], RelayError> {
        let size = usize::try_from(self.u32()?).map_err(|_| RelayError::InvalidMessage)?;
        if size > max {
            return Err(RelayError::InvalidMessage);
        }
        let value = self
            .remaining
            .get(..size)
            .ok_or(RelayError::InvalidMessage)?;
        self.remaining = &self.remaining[size..];
        Ok(value)
    }

    #[cfg(unix)]
    fn finish(self) -> Result<(), RelayError> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(RelayError::InvalidMessage)
        }
    }

    #[cfg(unix)]
    const fn remaining(&self) -> &[u8] {
        self.remaining
    }
}

#[cfg(unix)]
fn push_string(output: &mut Vec<u8>, value: &[u8]) -> Result<(), RelayError> {
    output.extend_from_slice(
        &u32::try_from(value.len())
            .map_err(|_| RelayError::InvalidMessage)?
            .to_be_bytes(),
    );
    output.extend_from_slice(value);
    Ok(())
}

fn decode_blob(value: &str, max: usize) -> Result<Vec<u8>, RelayError> {
    if value.is_empty() || value.len() > max.saturating_mul(2) {
        return Err(RelayError::InvalidGrant);
    }
    let decoded = STANDARD_NO_PAD
        .decode(value)
        .map_err(|_| RelayError::InvalidGrant)?;
    if decoded.is_empty() || decoded.len() > max {
        return Err(RelayError::InvalidGrant);
    }
    Ok(decoded)
}

fn ssh_string_prefix(blob: &[u8]) -> Result<&[u8], RelayError> {
    let mut cursor = Cursor::new(blob);
    cursor.string(128)
}

fn valid_fingerprint(value: &str, blob: &[u8]) -> bool {
    let Some(encoded) = value.strip_prefix("SHA256:") else {
        return false;
    };
    encoded == STANDARD_NO_PAD.encode(Sha256::digest(blob))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_handle(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn valid_host(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn valid_repository(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && !value.starts_with(['/', '-'])
        && value.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && part.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'~')
                })
        })
}

fn valid_revision(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 200
        && !value.starts_with('-')
        && !value.contains("..")
        && !value.contains("@{")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'/' | b'-'))
}

fn valid_key_type(value: &str) -> bool {
    matches!(
        value,
        "ssh-ed25519"
            | "ssh-rsa"
            | "ecdsa-sha2-nistp256"
            | "ecdsa-sha2-nistp384"
            | "ecdsa-sha2-nistp521"
            | "sk-ssh-ed25519@openssh.com"
            | "sk-ecdsa-sha2-nistp256@openssh.com"
    )
}

#[cfg(all(test, unix))]
mod tests;
