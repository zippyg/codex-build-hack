use std::path::PathBuf;

use promptectomy_acquisition::{
    Acquirer, AcquisitionLimits, AcquisitionRequest, AcquisitionSource, OrbstackPublicGitBackend,
    RemoteDestinationEnforcement,
};

#[test]
#[ignore = "requires the accepted local OrbStack backend and pinned image"]
fn public_git_acquisition_is_isolated_content_bound_and_persisted() {
    let backend = OrbstackPublicGitBackend::reviewed(
        std::env::var_os("PROMPTECTOMY_DOCKER_PROGRAM")
            .map_or_else(|| PathBuf::from("/opt/homebrew/bin/docker"), PathBuf::from),
    )
    .expect("accepted backend configuration");
    let state = tempfile::tempdir().expect("private state parent");
    let state_root = state.path().join("acquisition");
    let acquirer = Acquirer::new(&state_root)
        .expect("acquirer")
        .with_public_git_backend(backend);
    let snapshot = acquirer
        .acquire(&AcquisitionRequest {
            source: AcquisitionSource::Https {
                url: "https://github.com/zippyg/codex-build-hack.git".to_owned(),
                revision: "main".to_owned(),
            },
            authority_id: "auth_phase4_live_public_git".to_owned(),
            authority_digest: format!("sha256:{}", "a".repeat(64)),
            selected_roots: vec!["README.md".to_owned()],
            limits: AcquisitionLimits {
                max_files: 16,
                max_total_bytes: 4 * 1024 * 1024,
                max_file_bytes: 4 * 1024 * 1024,
                max_path_bytes: 1024,
                max_archive_bytes: 16 * 1024 * 1024,
                max_remote_work_bytes: 64 * 1024 * 1024,
                max_git_output_bytes: 4 * 1024 * 1024,
                max_git_seconds: 60,
            },
        })
        .expect("isolated public Git acquisition");

    let snapshot_root = state_root.join("snapshots").join(
        snapshot
            .reference
            .snapshot_id
            .strip_prefix("snapshot_")
            .expect("snapshot id"),
    );
    assert!(snapshot_root.join("tree/README.md").is_file());
    assert!(snapshot_root.join("remote-manifest.json").is_file());
    assert!(snapshot_root.join("remote-attestation.json").is_file());
    assert_eq!(snapshot.receipt.file_count, 1);
    assert!(snapshot.receipt.remote_manifest_digest.is_some());
    assert!(snapshot.receipt.remote_attestation_digest.is_some());
    let attestation = snapshot.remote_attestation.expect("remote attestation");
    assert_eq!(
        attestation.destination_enforcement,
        RemoteDestinationEnforcement::ApplicationConnectProxy
    );
    assert!(!attestation.kernel_exact_destination_enforced);
}
