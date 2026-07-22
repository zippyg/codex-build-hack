use std::io::{Read as _, Write as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::thread;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;

use super::*;

fn string(value: &[u8]) -> Vec<u8> {
    let mut encoded = u32::try_from(value.len())
        .expect("bounded")
        .to_be_bytes()
        .to_vec();
    encoded.extend_from_slice(value);
    encoded
}

fn key_blob(key_type: &[u8], marker: &[u8]) -> Vec<u8> {
    [string(key_type), string(marker)].concat()
}

fn grant(host_key: &[u8], selected: &[u8]) -> RelayGrant {
    RelayGrant {
        schema_version: GRANT_VERSION.to_owned(),
        opaque_handle: "grant_abc123".to_owned(),
        display_host: "github.com".to_owned(),
        port: 22,
        username: "git".to_owned(),
        repository: "owner/private.git".to_owned(),
        revision: "main".to_owned(),
        host_key_type: "ssh-ed25519".to_owned(),
        host_key_base64: STANDARD_NO_PAD.encode(host_key),
        host_key_sha256: format!(
            "SHA256:{}",
            STANDARD_NO_PAD.encode(Sha256::digest(host_key))
        ),
        selected_public_key_base64: STANDARD_NO_PAD.encode(selected),
        manifest_digest: format!("sha256:{}", "a".repeat(64)),
        credential_source: "selected_ssh_agent".to_owned(),
        wall_time_seconds: 2,
        max_connections: 1,
        max_frame_bytes: 256 * 1024,
        max_signatures: 2,
    }
}

fn send(stream: &mut UnixStream, payload: &[u8]) -> Vec<u8> {
    stream
        .write_all(&u32::try_from(payload.len()).expect("bounded").to_be_bytes())
        .expect("header");
    stream.write_all(payload).expect("payload");
    let mut header = [0_u8; 4];
    stream.read_exact(&mut header).expect("response header");
    let mut response = vec![0_u8; u32::from_be_bytes(header) as usize];
    stream.read_exact(&mut response).expect("response");
    response
}

#[test]
fn grant_binds_host_key_identity_destination_revision_manifest_and_quotas() {
    let host = key_blob(b"ssh-ed25519", b"host");
    let selected = key_blob(b"ssh-ed25519", b"selected");
    grant(&host, &selected).validate().expect("valid grant");

    let mut cases = Vec::new();
    let mut changed = grant(&host, &selected);
    changed.repository = "../escape.git".to_owned();
    cases.push(changed);
    let mut changed = grant(&host, &selected);
    changed.host_key_sha256 = format!("SHA256:{}", "A".repeat(43));
    cases.push(changed);
    let mut changed = grant(&host, &selected);
    changed.max_connections = 2;
    cases.push(changed);
    let mut changed = grant(&host, &selected);
    changed.max_frame_bytes = 256 * 1024 + 1;
    cases.push(changed);
    for invalid in cases {
        assert_eq!(invalid.validate(), Err(RelayError::InvalidGrant));
    }
}

#[test]
fn relay_filters_identity_requires_valid_bind_and_allows_only_selected_signatures() {
    let temp = TempDir::new().expect("temp");
    let upstream_path = temp.path().join("upstream.sock");
    let relay_path = temp.path().join("relay.sock");
    let upstream_listener = UnixListener::bind(&upstream_path).expect("upstream listener");
    let relay_listener = UnixListener::bind(&relay_path).expect("relay listener");
    let host = key_blob(b"ssh-ed25519", b"host");
    let selected = key_blob(b"ssh-ed25519", b"selected");
    let other = key_blob(b"ssh-ed25519", b"other");
    let validated = grant(&host, &selected).validate().expect("grant");
    let selected_upstream = selected.clone();
    let other_upstream = other.clone();
    let host_client = host.clone();
    let selected_client = selected.clone();

    let upstream = thread::spawn(move || {
        let (mut stream, _) = upstream_listener.accept().expect("accept upstream");
        let identities = read_frame(
            &mut stream,
            256 * 1024,
            Instant::now() + Duration::from_secs(5),
            &AtomicBool::new(false),
        )
        .expect("identities request");
        assert_eq!(identities, [IDENTITIES_REQUEST]);
        let mut response = vec![IDENTITIES_ANSWER];
        response.extend_from_slice(&2_u32.to_be_bytes());
        push_string(&mut response, &other_upstream).expect("other key");
        push_string(&mut response, b"private comment canary").expect("comment");
        push_string(&mut response, &selected_upstream).expect("selected key");
        push_string(&mut response, b"selected private comment").expect("comment");
        write_frame(&mut stream, &response, 256 * 1024).expect("identities response");

        let bind = read_frame(
            &mut stream,
            256 * 1024,
            Instant::now() + Duration::from_secs(5),
            &AtomicBool::new(false),
        )
        .expect("bind");
        assert_eq!(extension_name(&bind).expect("extension"), SESSION_BIND);
        write_frame(&mut stream, &[SUCCESS], 256 * 1024).expect("bind success");

        let sign = read_frame(
            &mut stream,
            256 * 1024,
            Instant::now() + Duration::from_secs(5),
            &AtomicBool::new(false),
        )
        .expect("sign");
        assert_eq!(sign.first(), Some(&SIGN_REQUEST));
        let mut signed = vec![SIGN_RESPONSE];
        signed.extend_from_slice(&string(b"synthetic-signature"));
        write_frame(&mut stream, &signed, 256 * 1024).expect("signature");
    });
    let relay = thread::spawn(move || validated.serve(&relay_listener, &upstream_path));
    let mut client = UnixStream::connect(&relay_path).expect("connect relay");

    let identities = send(&mut client, &[IDENTITIES_REQUEST]);
    assert_eq!(identities.first(), Some(&IDENTITIES_ANSWER));
    assert!(
        identities
            .windows(selected_client.len())
            .any(|part| part == selected_client)
    );
    assert!(!identities.windows(other.len()).any(|part| part == other));
    assert!(!String::from_utf8_lossy(&identities).contains("private comment"));

    let mut premature_sign = vec![SIGN_REQUEST];
    premature_sign.extend_from_slice(&string(&selected_client));
    premature_sign.extend_from_slice(&string(b"userauth"));
    premature_sign.extend_from_slice(&0_u32.to_be_bytes());
    assert_eq!(send(&mut client, &premature_sign), [FAILURE]);

    let mut wrong_bind = vec![EXTENSION];
    wrong_bind.extend_from_slice(&string(SESSION_BIND));
    wrong_bind.extend_from_slice(&string(&key_blob(b"ssh-ed25519", b"wrong")));
    wrong_bind.extend_from_slice(&string(b"session"));
    wrong_bind.extend_from_slice(&string(b"signature"));
    wrong_bind.push(0);
    assert_eq!(send(&mut client, &wrong_bind), [FAILURE]);

    let mut bind = vec![EXTENSION];
    bind.extend_from_slice(&string(SESSION_BIND));
    bind.extend_from_slice(&string(&host_client));
    bind.extend_from_slice(&string(b"session"));
    bind.extend_from_slice(&string(b"signature"));
    bind.push(0);
    assert_eq!(send(&mut client, &bind), [SUCCESS]);

    let mut wrong_sign = vec![SIGN_REQUEST];
    wrong_sign.extend_from_slice(&string(&other));
    wrong_sign.extend_from_slice(&string(b"userauth"));
    wrong_sign.extend_from_slice(&0_u32.to_be_bytes());
    assert_eq!(send(&mut client, &wrong_sign), [FAILURE]);
    assert_eq!(send(&mut client, &[17]), [FAILURE]);

    assert_eq!(
        send(&mut client, &premature_sign).first(),
        Some(&SIGN_RESPONSE)
    );
    drop(client);
    assert_eq!(
        relay.join().expect("relay thread").expect("receipt"),
        RelayReceipt {
            session_bound: true,
            signatures: 1,
        }
    );
    upstream.join().expect("upstream thread");
}

#[test]
fn live_receipts_advance_only_after_valid_signatures_while_the_client_is_open() {
    let temp = TempDir::new().expect("temp");
    let upstream_path = temp.path().join("upstream.sock");
    let relay_path = temp.path().join("relay.sock");
    let upstream_listener = UnixListener::bind(&upstream_path).expect("upstream listener");
    let relay_listener = UnixListener::bind(&relay_path).expect("relay listener");
    let host = key_blob(b"ssh-ed25519", b"host");
    let selected = key_blob(b"ssh-ed25519", b"selected");
    let other = key_blob(b"ssh-ed25519", b"other");
    let validated = grant(&host, &selected).validate().expect("grant");
    let upstream = thread::spawn(move || {
        let (mut stream, _) = upstream_listener.accept().expect("accept upstream");
        let cancelled = AtomicBool::new(false);
        let bind = read_frame(
            &mut stream,
            256 * 1024,
            Instant::now() + Duration::from_secs(5),
            &cancelled,
        )
        .expect("bind");
        assert_eq!(extension_name(&bind).expect("extension"), SESSION_BIND);
        write_frame(&mut stream, &[SUCCESS], 256 * 1024).expect("bind success");
        for _ in 0..2 {
            let sign = read_frame(
                &mut stream,
                256 * 1024,
                Instant::now() + Duration::from_secs(5),
                &cancelled,
            )
            .expect("sign");
            assert_eq!(sign.first(), Some(&SIGN_REQUEST));
            let mut signed = vec![SIGN_RESPONSE];
            signed.extend_from_slice(&string(b"synthetic-signature"));
            write_frame(&mut stream, &signed, 256 * 1024).expect("signature");
        }
    });
    let (receipts, published) = std::sync::mpsc::channel();
    let relay = thread::spawn(move || {
        validated.serve_with_receipts(
            &relay_listener,
            &upstream_path,
            &AtomicBool::new(false),
            |receipt| {
                receipts
                    .send(receipt)
                    .map_err(|_| RelayError::ReceiptUnavailable)
            },
        )
    });
    let mut client = UnixStream::connect(&relay_path).expect("connect relay");
    let mut bind = vec![EXTENSION];
    bind.extend_from_slice(&string(SESSION_BIND));
    bind.extend_from_slice(&string(&host));
    bind.extend_from_slice(&string(b"session"));
    bind.extend_from_slice(&string(b"signature"));
    bind.push(0);
    assert_eq!(send(&mut client, &bind), [SUCCESS]);

    let mut sign = vec![SIGN_REQUEST];
    sign.extend_from_slice(&string(&selected));
    sign.extend_from_slice(&string(b"userauth"));
    sign.extend_from_slice(&0_u32.to_be_bytes());
    assert_eq!(send(&mut client, &sign).first(), Some(&SIGN_RESPONSE));
    assert_eq!(
        published.recv_timeout(Duration::from_secs(1)),
        Ok(RelayReceipt {
            session_bound: true,
            signatures: 1,
        })
    );

    let mut denied = vec![SIGN_REQUEST];
    denied.extend_from_slice(&string(&other));
    denied.extend_from_slice(&string(b"userauth"));
    denied.extend_from_slice(&0_u32.to_be_bytes());
    assert_eq!(send(&mut client, &denied), [FAILURE]);
    assert!(published.try_recv().is_err());

    assert_eq!(send(&mut client, &sign).first(), Some(&SIGN_RESPONSE));
    assert_eq!(
        published.recv_timeout(Duration::from_secs(1)),
        Ok(RelayReceipt {
            session_bound: true,
            signatures: 2,
        })
    );
    drop(client);
    assert_eq!(
        relay.join().expect("relay thread").expect("receipt"),
        RelayReceipt {
            session_bound: true,
            signatures: 2,
        }
    );
    upstream.join().expect("upstream thread");
}

#[test]
fn forwarding_session_bind_is_denied_without_reaching_upstream() {
    let host = key_blob(b"ssh-ed25519", b"host");
    let selected = key_blob(b"ssh-ed25519", b"selected");
    let mut bind = vec![EXTENSION];
    bind.extend_from_slice(&string(SESSION_BIND));
    bind.extend_from_slice(&string(&host));
    bind.extend_from_slice(&string(b"session"));
    bind.extend_from_slice(&string(b"signature"));
    bind.push(1);
    assert_eq!(
        validate_session_bind(&bind, &host),
        Err(RelayError::InvalidMessage)
    );
    grant(&host, &selected).validate().expect("valid grant");
}

#[test]
fn relay_cancellation_stops_an_unused_listener() {
    let temp = TempDir::new().expect("temp");
    let upstream_path = temp.path().join("upstream.sock");
    let relay_path = temp.path().join("relay.sock");
    let relay_listener = UnixListener::bind(&relay_path).expect("relay listener");
    let host = key_blob(b"ssh-ed25519", b"host");
    let selected = key_blob(b"ssh-ed25519", b"selected");
    let validated = grant(&host, &selected).validate().expect("grant");
    let cancelled = AtomicBool::new(true);
    assert_eq!(
        validated.serve_cancelable(&relay_listener, &upstream_path, &cancelled),
        Err(RelayError::Cancelled)
    );
}

#[test]
fn upstream_signature_denial_fails_closed() {
    let temp = TempDir::new().expect("temp");
    let upstream_path = temp.path().join("upstream.sock");
    let relay_path = temp.path().join("relay.sock");
    let upstream_listener = UnixListener::bind(&upstream_path).expect("upstream listener");
    let relay_listener = UnixListener::bind(&relay_path).expect("relay listener");
    let host = key_blob(b"ssh-ed25519", b"host");
    let selected = key_blob(b"ssh-ed25519", b"selected");
    let validated = grant(&host, &selected).validate().expect("grant");
    let upstream = thread::spawn(move || {
        let (mut stream, _) = upstream_listener.accept().expect("accept upstream");
        let cancelled = AtomicBool::new(false);
        read_frame(
            &mut stream,
            256 * 1024,
            Instant::now() + Duration::from_secs(5),
            &cancelled,
        )
        .expect("bind");
        write_frame(&mut stream, &[SUCCESS], 256 * 1024).expect("bind success");
        read_frame(
            &mut stream,
            256 * 1024,
            Instant::now() + Duration::from_secs(5),
            &cancelled,
        )
        .expect("sign");
        write_frame(&mut stream, &[FAILURE], 256 * 1024).expect("sign denied");
    });
    let relay = thread::spawn(move || validated.serve(&relay_listener, &upstream_path));
    let mut client = UnixStream::connect(&relay_path).expect("connect relay");
    let mut bind = vec![EXTENSION];
    bind.extend_from_slice(&string(SESSION_BIND));
    bind.extend_from_slice(&string(&host));
    bind.extend_from_slice(&string(b"session"));
    bind.extend_from_slice(&string(b"signature"));
    bind.push(0);
    assert_eq!(send(&mut client, &bind), [SUCCESS]);
    let mut sign = vec![SIGN_REQUEST];
    sign.extend_from_slice(&string(&selected));
    sign.extend_from_slice(&string(b"userauth"));
    sign.extend_from_slice(&0_u32.to_be_bytes());
    client
        .write_all(&u32::try_from(sign.len()).expect("bounded").to_be_bytes())
        .expect("sign header");
    client.write_all(&sign).expect("sign request");
    assert_eq!(
        relay.join().expect("relay thread"),
        Err(RelayError::SignatureDenied)
    );
    upstream.join().expect("upstream thread");
}

#[test]
fn signature_quota_denies_extra_requests_without_forwarding() {
    let temp = TempDir::new().expect("temp");
    let upstream_path = temp.path().join("upstream.sock");
    let relay_path = temp.path().join("relay.sock");
    let upstream_listener = UnixListener::bind(&upstream_path).expect("upstream listener");
    let relay_listener = UnixListener::bind(&relay_path).expect("relay listener");
    let host = key_blob(b"ssh-ed25519", b"host");
    let selected = key_blob(b"ssh-ed25519", b"selected");
    let mut scoped = grant(&host, &selected);
    scoped.max_signatures = 1;
    let validated = scoped.validate().expect("grant");
    let upstream = thread::spawn(move || {
        let (mut stream, _) = upstream_listener.accept().expect("accept upstream");
        let cancelled = AtomicBool::new(false);
        read_frame(
            &mut stream,
            256 * 1024,
            Instant::now() + Duration::from_secs(5),
            &cancelled,
        )
        .expect("bind");
        write_frame(&mut stream, &[SUCCESS], 256 * 1024).expect("bind success");
        read_frame(
            &mut stream,
            256 * 1024,
            Instant::now() + Duration::from_secs(5),
            &cancelled,
        )
        .expect("sign");
        let mut signed = vec![SIGN_RESPONSE];
        signed.extend_from_slice(&string(b"synthetic-signature"));
        write_frame(&mut stream, &signed, 256 * 1024).expect("signature");
    });
    let relay = thread::spawn(move || validated.serve(&relay_listener, &upstream_path));
    let mut client = UnixStream::connect(&relay_path).expect("connect relay");
    let mut bind = vec![EXTENSION];
    bind.extend_from_slice(&string(SESSION_BIND));
    bind.extend_from_slice(&string(&host));
    bind.extend_from_slice(&string(b"session"));
    bind.extend_from_slice(&string(b"signature"));
    bind.push(0);
    assert_eq!(send(&mut client, &bind), [SUCCESS]);
    let mut sign = vec![SIGN_REQUEST];
    sign.extend_from_slice(&string(&selected));
    sign.extend_from_slice(&string(b"userauth"));
    sign.extend_from_slice(&0_u32.to_be_bytes());
    assert_eq!(send(&mut client, &sign).first(), Some(&SIGN_RESPONSE));
    assert_eq!(send(&mut client, &sign), [FAILURE]);
    drop(client);
    assert_eq!(
        relay.join().expect("relay thread").expect("receipt"),
        RelayReceipt {
            session_bound: true,
            signatures: 1,
        }
    );
    upstream.join().expect("upstream thread");
}
