#![forbid(unsafe_code)]

#[cfg(unix)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::net::UnixListener;
    use std::path::Path;
    use std::time::{Duration, Instant};

    use promptectomy_ssh_agent_relay::{RelayError, RelayGrant, RelayReceiptDocument};

    const GRANT: &str = "/work/input/grant.json";
    const UPSTREAM: &str = "/work/upstream/agent.sock";
    const RELAY: &str = "/work/relay/agent.sock";
    const RECEIPT: &str = "/work/output/receipt.json";
    const RECEIPT_TMP: &str = "/work/output/receipt.tmp";
    const MAX_GRANT_BYTES: u64 = 64 * 1024;
    const TEARDOWN_ALLOWANCE_SECONDS: u64 = 15;

    let deadline = Instant::now() + Duration::from_secs(10);
    let grant = loop {
        match fs::metadata(GRANT) {
            Ok(metadata) if metadata.is_file() && metadata.len() <= MAX_GRANT_BYTES => {
                let bytes = fs::read(GRANT)?;
                break serde_json::from_slice::<RelayGrant>(&bytes)?.validate()?;
            }
            Ok(_) => return Err("invalid relay grant file".into()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if Instant::now() >= deadline {
                    return Err("relay grant timeout".into());
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error.into()),
        }
    };
    if !Path::new(UPSTREAM).exists()
        || Path::new(RELAY).exists()
        || Path::new(RECEIPT).exists()
        || Path::new(RECEIPT_TMP).exists()
    {
        return Err("invalid relay filesystem state".into());
    }
    let listener = UnixListener::bind(RELAY)?;
    fs::set_permissions(RELAY, fs::Permissions::from_mode(0o666))?;
    let manifest_digest = grant.manifest_digest().to_owned();
    let process_deadline = Instant::now()
        + Duration::from_secs(
            grant
                .wall_time_seconds()
                .saturating_add(TEARDOWN_ALLOWANCE_SECONDS),
        );
    grant.serve_with_receipts(
        &listener,
        Path::new(UPSTREAM),
        &std::sync::atomic::AtomicBool::new(false),
        |receipt| {
            publish_receipt(
                Path::new(RECEIPT),
                Path::new(RECEIPT_TMP),
                &RelayReceiptDocument::from_receipt(&manifest_digest, receipt),
            )
            .map_err(|_| RelayError::ReceiptUnavailable)
        },
    )?;
    while Instant::now() < process_deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    Err("relay teardown deadline exceeded".into())
}

#[cfg(unix)]
fn publish_receipt(
    receipt: &std::path::Path,
    temporary: &std::path::Path,
    document: &promptectomy_ssh_agent_relay::RelayReceiptDocument,
) -> Result<(), std::io::Error> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let bytes = serde_jcs::to_vec(document).map_err(std::io::Error::other)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    std::fs::rename(temporary, receipt)?;
    std::fs::File::open(
        receipt
            .parent()
            .ok_or_else(|| std::io::Error::other("receipt has no parent"))?,
    )?
    .sync_all()
}

#[cfg(not(unix))]
fn main() {
    std::process::exit(2);
}

#[cfg(all(test, unix))]
mod tests {
    use promptectomy_ssh_agent_relay::{RECEIPT_VERSION, RelayReceiptDocument};

    use super::publish_receipt;

    #[test]
    fn receipt_publication_atomically_replaces_the_prior_signature_count() {
        let temp = tempfile::tempdir().expect("tempdir");
        let receipt = temp.path().join("receipt.json");
        let temporary = temp.path().join("receipt.tmp");
        for signatures in [1, 2] {
            let expected = RelayReceiptDocument {
                schema_version: RECEIPT_VERSION.to_owned(),
                manifest_digest: format!("sha256:{}", "a".repeat(64)),
                session_bound: true,
                signatures,
            };
            publish_receipt(&receipt, &temporary, &expected).expect("publish receipt");
            let actual = serde_json::from_slice::<RelayReceiptDocument>(
                &std::fs::read(&receipt).expect("read receipt"),
            )
            .expect("parse receipt");
            assert_eq!(actual, expected);
            assert!(!temporary.exists());
        }
    }
}
