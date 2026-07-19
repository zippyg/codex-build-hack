#[cfg(unix)]
use std::fs;
use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;
#[cfg(unix)]
use std::sync::Mutex;

use tempfile::TempDir;

use super::*;
#[cfg(unix)]
use crate::digest::digest_string;

const AUTHORITY_DIGEST: &str =
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
#[cfg(unix)]
const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

fn request(source: AcquisitionSource) -> AcquisitionRequest {
    AcquisitionRequest {
        source,
        authority_id: "auth_019f0000-0000-7000-8000-000000000001".to_owned(),
        authority_digest: AUTHORITY_DIGEST.to_owned(),
        selected_roots: Vec::new(),
        limits: AcquisitionLimits {
            max_files: 32,
            max_total_bytes: 16 * 1024,
            max_file_bytes: 8 * 1024,
            max_path_bytes: 256,
            max_archive_bytes: 32 * 1024,
            max_remote_work_bytes: 64 * 1024,
            max_git_output_bytes: 16 * 1024,
            max_git_seconds: 5,
        },
    }
}

fn local_source(path: &Path) -> AcquisitionSource {
    AcquisitionSource::Local {
        path: path.to_path_buf(),
        dirty_policy: LocalDirtyPolicy::IncludeTrackedAndUntracked,
    }
}

fn remote_backend_policy() -> RemoteBackendPolicy {
    RemoteBackendPolicy {
        profile: RemoteBackendProfile::OrbstackMacosArm64V1,
        image_digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111"
            .to_owned(),
        runner_digest: "sha256:2222222222222222222222222222222222222222222222222222222222222222"
            .to_owned(),
        egress_proxy_digest:
            "sha256:3333333333333333333333333333333333333333333333333333333333333333".to_owned(),
    }
}

fn test_domain_digest(domain: &str, value: &[u8]) -> String {
    let mut payload = Vec::with_capacity(domain.len() + value.len() + 1);
    payload.extend_from_slice(domain.as_bytes());
    payload.push(0);
    payload.extend_from_slice(value);
    crate::digest::digest_string(&payload)
}

fn accepted_remote_attestation(
    manifest: &RemoteGitManifest,
    source_bundle: &[u8],
) -> RemoteGitAttestation {
    RemoteGitAttestation {
        schema_version: REMOTE_GIT_ATTESTATION_VERSION.to_owned(),
        manifest_digest: manifest.manifest_digest.clone(),
        backend_profile: manifest.backend.profile,
        image_digest: manifest.backend.image_digest.clone(),
        runner_digest: manifest.backend.runner_digest.clone(),
        egress_proxy_digest: manifest.backend.egress_proxy_digest.clone(),
        git_binary_digest:
            "sha256:4444444444444444444444444444444444444444444444444444444444444444".to_owned(),
        broker: manifest.broker.clone(),
        observed_destinations: vec![manifest.destination.clone()],
        writable_mount_limit_bytes: manifest.max_remote_work_bytes,
        unaccounted_writable_mounts: 0,
        kernel_disk_limit: ControlAttestation::Passed,
        root_read_only: ControlAttestation::Passed,
        exact_egress_only: ControlAttestation::Passed,
        git_execution_neutralized: ControlAttestation::Passed,
        credentials_isolated: ControlAttestation::Passed,
        resolved_commit: "0123456789abcdef0123456789abcdef01234567".to_owned(),
        source_bundle_digest: test_domain_digest("remote-source-bundle", source_bundle),
        cleanup: RemoteCleanupAttestation {
            worker_removed: ControlAttestation::Passed,
            proxy_removed: ControlAttestation::Passed,
            network_removed: ControlAttestation::Passed,
            broker_relay_removed: ControlAttestation::Passed,
            orphan_check: ControlAttestation::Passed,
        },
    }
}

trait AttestationTestExt {
    fn model_copy_for_test<F>(self, update: F) -> Self
    where
        F: FnOnce(&mut Self);
}

impl AttestationTestExt for RemoteGitAttestation {
    fn model_copy_for_test<F>(mut self, update: F) -> Self
    where
        F: FnOnce(&mut Self),
    {
        update(&mut self);
        self
    }
}

#[cfg(unix)]
#[test]
fn local_snapshot_is_content_bound_redacted_and_idempotent() {
    let temp = TempDir::new().expect("temp dir");
    let source = temp.path().join("private-project-name");
    fs::create_dir(&source).expect("source");
    fs::write(source.join("main.py"), b"print('safe')\n").expect("file");
    fs::create_dir(source.join("src")).expect("source root");
    fs::write(source.join("src/lib.py"), b"VALUE = 1\n").expect("file");
    fs::create_dir(source.join(".git")).expect("git metadata");
    fs::write(source.join(".git/config"), b"credential = secret\n").expect("git config");

    let acquirer = Acquirer::new(temp.path().join("state")).expect("acquirer");
    let first = acquirer
        .acquire(&request(local_source(&source)))
        .expect("local acquisition");
    let second = acquirer
        .acquire(&request(local_source(&source)))
        .expect("idempotent acquisition");

    assert_eq!(first.reference, second.reference);
    assert_eq!(first.snapshot_root, second.snapshot_root);
    assert_eq!(first.reference.redacted_locator, "local://<redacted>");
    assert!(
        !serde_json::to_string(&first.receipt)
            .expect("receipt")
            .contains("private-project-name")
    );
    assert_eq!(
        fs::read(first.snapshot_root.join("tree/main.py")).expect("snapshot file"),
        b"print('safe')\n"
    );
    assert!(!first.snapshot_root.join("tree/.git").exists());
    assert_eq!(first.receipt.file_count, 2);
}

#[cfg(unix)]
#[test]
fn existing_snapshot_tamper_fails_integrity_reuse() {
    use std::os::unix::fs::PermissionsExt;

    let temp = TempDir::new().expect("temp dir");
    let source = temp.path().join("source");
    fs::create_dir(&source).expect("source");
    fs::write(source.join("main.py"), b"original\n").expect("file");
    let acquirer = Acquirer::new(temp.path().join("state")).expect("acquirer");
    let acquisition = request(local_source(&source));
    let snapshot = acquirer.acquire(&acquisition).expect("snapshot");
    let snapshot_file = snapshot.snapshot_root.join("tree/main.py");
    fs::set_permissions(&snapshot_file, fs::Permissions::from_mode(0o600)).expect("writable");
    fs::write(&snapshot_file, b"tampered\n").expect("tamper fixture");

    assert_eq!(
        acquirer.acquire(&acquisition),
        Err(AcquisitionError::SnapshotIntegrityFailed)
    );
}

#[cfg(unix)]
#[test]
fn selected_roots_exclude_siblings_and_are_bound_into_identity() {
    let temp = TempDir::new().expect("temp dir");
    let source = temp.path().join("source");
    fs::create_dir_all(source.join("src")).expect("src");
    fs::create_dir_all(source.join("private")).expect("private");
    fs::write(source.join("src/lib.rs"), b"pub fn safe() {}\n").expect("source");
    fs::write(source.join("private/key.txt"), b"canary").expect("private");
    let acquirer = Acquirer::new(temp.path().join("state")).expect("acquirer");
    let mut selected = request(local_source(&source));
    selected.selected_roots = vec!["src".to_owned()];
    let snapshot = acquirer.acquire(&selected).expect("selected snapshot");

    assert!(snapshot.snapshot_root.join("tree/src/lib.rs").exists());
    assert!(!snapshot.snapshot_root.join("tree/private/key.txt").exists());
    assert_eq!(snapshot.receipt.selected_roots, ["src"]);
}

#[cfg(unix)]
#[test]
fn selected_roots_do_not_traverse_unrelated_hostile_siblings() {
    use std::os::unix::fs::symlink;

    let temp = TempDir::new().expect("temp dir");
    let source = temp.path().join("source");
    fs::create_dir_all(source.join("src")).expect("src");
    fs::create_dir_all(source.join("unselected")).expect("unselected");
    fs::write(source.join("src/lib.rs"), b"pub fn safe() {}\n").expect("source");
    symlink(
        temp.path().join("outside"),
        source.join("unselected/escape"),
    )
    .expect("hostile sibling");
    let acquirer = Acquirer::new(temp.path().join("state")).expect("acquirer");
    let mut selected = request(local_source(&source));
    selected.selected_roots = vec!["src".to_owned()];

    let snapshot = acquirer.acquire(&selected).expect("selected snapshot");
    assert!(snapshot.snapshot_root.join("tree/src/lib.rs").exists());
    assert!(!snapshot.snapshot_root.join("tree/unselected").exists());
}

#[cfg(unix)]
#[test]
fn storage_and_source_must_be_disjoint() {
    let temp = TempDir::new().expect("temp dir");
    let source = temp.path().join("source");
    fs::create_dir(&source).expect("source");
    fs::write(source.join("file.txt"), b"content").expect("file");
    let acquirer = Acquirer::new(source.join("state")).expect("acquirer");
    assert_eq!(
        acquirer.acquire(&request(local_source(&source))),
        Err(AcquisitionError::InvalidSourcePath)
    );
}

#[cfg(unix)]
#[test]
fn local_symlink_is_rejected_without_following_it() {
    use std::os::unix::fs::symlink;

    let temp = TempDir::new().expect("temp dir");
    let source = temp.path().join("source");
    fs::create_dir(&source).expect("source");
    fs::write(temp.path().join("outside"), b"canary").expect("outside");
    symlink(temp.path().join("outside"), source.join("escape")).expect("symlink");
    let acquirer = Acquirer::new(temp.path().join("state")).expect("acquirer");
    assert_eq!(
        acquirer.acquire(&request(local_source(&source))),
        Err(AcquisitionError::UnsupportedFileType)
    );
}

#[test]
fn portable_path_policy_rejects_traversal_devices_and_case_collisions() {
    assert_eq!(
        path_policy::normalize_path(b"../escape", 100),
        Err(AcquisitionError::UnsafePath)
    );
    assert_eq!(
        path_policy::normalize_path(b"src/NUL.txt", 100),
        Err(AcquisitionError::UnsafePath)
    );
    assert_eq!(
        path_policy::normalize_path("src/\u{00e9}.rs".as_bytes(), 100),
        Err(AcquisitionError::UnsafePath)
    );
    let mut seen = std::collections::BTreeSet::new();
    path_policy::insert_collision_key("Readme.md", &mut seen).expect("first path");
    assert_eq!(
        path_policy::insert_collision_key("README.md", &mut seen),
        Err(AcquisitionError::PathCollision)
    );
}

#[test]
fn archive_rejects_traversal_links_duplicates_and_bad_checksum() {
    let limits = request(local_source(Path::new("/unused"))).limits;
    let traversal = tar(&[("../escape", b"bad", b'0')]);
    assert_eq!(
        archive::parse_tar(&traversal, &[], &limits),
        Err(AcquisitionError::UnsafePath)
    );
    let symlink = tar(&[("link", b"target", b'2')]);
    assert_eq!(
        archive::parse_tar(&symlink, &[], &limits),
        Err(AcquisitionError::UnsupportedFileType)
    );
    let collision = tar(&[("README.md", b"one", b'0'), ("readme.md", b"two", b'0')]);
    assert_eq!(
        archive::parse_tar(&collision, &[], &limits),
        Err(AcquisitionError::PathCollision)
    );
    let mut bad_checksum = tar(&[("safe.txt", b"safe", b'0')]);
    bad_checksum[0] ^= 1;
    assert_eq!(
        archive::parse_tar(&bad_checksum, &[], &limits),
        Err(AcquisitionError::ArchiveChecksumMismatch)
    );
}

#[cfg(unix)]
#[test]
fn tar_archive_and_bundle_publish_identical_content_as_distinct_receipts() {
    let temp = TempDir::new().expect("temp dir");
    let content = b"hello\n";
    let archive_path = temp.path().join("source.tar");
    fs::write(&archive_path, tar(&[("src/main.py", content, b'0')])).expect("tar");
    let bundle_path = temp.path().join("source.bundle.json");
    let bundle = serde_json::json!({
        "version": "promptectomy-source-bundle-1",
        "files": [{
            "path": "src/main.py",
            "executable": false,
            "content_hex": "68656c6c6f0a",
            "digest": digest_string(content),
        }]
    });
    fs::write(&bundle_path, serde_json::to_vec(&bundle).expect("bundle")).expect("bundle file");
    let acquirer = Acquirer::new(temp.path().join("state")).expect("acquirer");
    let archive_snapshot = acquirer
        .acquire(&request(AcquisitionSource::Archive {
            path: archive_path,
            format: ArchiveFormat::Tar,
        }))
        .expect("archive");
    let bundle_snapshot = acquirer
        .acquire(&request(AcquisitionSource::Bundle { path: bundle_path }))
        .expect("bundle");

    assert_eq!(
        archive_snapshot.receipt.tree_digest,
        bundle_snapshot.receipt.tree_digest
    );
    assert_ne!(
        archive_snapshot.reference.snapshot_id,
        bundle_snapshot.reference.snapshot_id
    );
    assert_eq!(
        fs::read(bundle_snapshot.snapshot_root.join("tree/src/main.py")).expect("snapshot file"),
        content
    );
}

#[cfg(unix)]
#[test]
fn bundle_digest_and_quota_fail_closed() {
    let temp = TempDir::new().expect("temp dir");
    let bundle_path = temp.path().join("source.bundle.json");
    fs::write(
        &bundle_path,
        br#"{"version":"promptectomy-source-bundle-1","files":[{"path":"a","executable":false,"content_hex":"00","digest":"sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}]}"#,
    )
    .expect("bundle");
    let acquirer = Acquirer::new(temp.path().join("state")).expect("acquirer");
    assert_eq!(
        acquirer.acquire(&request(AcquisitionSource::Bundle { path: bundle_path })),
        Err(AcquisitionError::InvalidBundle)
    );

    let source = temp.path().join("source");
    fs::create_dir(&source).expect("source");
    fs::write(source.join("large"), [0_u8; 64]).expect("large file");
    let mut limited = request(local_source(&source));
    limited.limits.max_file_bytes = 32;
    assert_eq!(
        acquirer.acquire(&limited),
        Err(AcquisitionError::FileBytesExceeded)
    );
}

#[cfg(unix)]
#[test]
fn https_policy_rejects_credentials_queries_redirect_ambiguity_and_local_hosts() {
    let limits = AcquisitionLimits::default();
    let temp = TempDir::new().expect("temp dir");
    let destination = temp.path().join("repo");
    for denied in [
        "http://github.com/owner/repo",
        "https://token@github.com/owner/repo",
        "https://github.com/owner/repo?token=secret",
        "https://127.0.0.1/repo",
        "https://localhost/repo",
        "https://attacker.example/repo",
        "https://github.com/owner/%2e%2e/repo",
    ] {
        let source = AcquisitionSource::Https {
            url: denied.to_owned(),
            revision: "main".to_owned(),
        };
        assert_eq!(
            plan_git_clone(&source, temp.path(), &destination, &limits),
            Err(AcquisitionError::LocatorDenied),
            "{denied}"
        );
    }
}

#[test]
fn remote_https_manifest_is_content_bound_redacted_and_exact_destination_only() {
    let source = AcquisitionSource::Https {
        url: "https://github.com/private-owner/private-repository.git".to_owned(),
        revision: "refs/heads/main".to_owned(),
    };
    let mut acquisition = request(source);
    acquisition.selected_roots = vec!["src".to_owned()];
    let manifest =
        build_remote_git_manifest(&acquisition, remote_backend_policy()).expect("remote manifest");

    assert_eq!(manifest.source_kind, SourceKind::HttpsRemote);
    assert_eq!(manifest.destination.host, "github.com");
    assert_eq!(manifest.destination.port, 443);
    assert_eq!(manifest.redacted_locator, "https://github.com/<redacted>");
    assert_eq!(manifest.egress_policy, "exact_destination_only");
    assert_eq!(manifest.checkout_policy, "no_checkout");
    assert_eq!(manifest.selected_roots, ["src"]);
    assert_eq!(manifest.manifest_digest, manifest.computed_digest());
    manifest.validate().expect("valid manifest");
    let encoded = serde_json::to_string(&manifest).expect("manifest json");
    assert!(!encoded.contains("private-owner"));
    assert!(!encoded.contains("private-repository"));

    let second = build_remote_git_manifest(&acquisition, remote_backend_policy())
        .expect("deterministic manifest");
    assert_eq!(second, manifest);

    let mut unapproved = manifest;
    unapproved.destination.host = "attacker.example".to_owned();
    unapproved.redacted_locator = "https://attacker.example/<redacted>".to_owned();
    unapproved.manifest_digest = unapproved.computed_digest();
    assert_eq!(
        unapproved.validate(),
        Err(AcquisitionError::InvalidRemoteManifest)
    );
}

#[cfg(unix)]
#[test]
fn remote_ssh_manifest_binds_broker_bytes_without_persisting_paths_or_content() {
    use std::os::unix::fs::PermissionsExt;

    let temp = TempDir::new().expect("temp dir");
    let broker = temp.path().join("broker-private-name");
    let broker_request = temp.path().join("request-private-name");
    let request_canary = b"PRIVATE_REPOSITORY_LOCATOR_CANARY";
    fs::write(&broker, b"#!/bin/sh\nexit 1\n").expect("broker");
    fs::set_permissions(&broker, fs::Permissions::from_mode(0o700)).expect("broker mode");
    fs::write(&broker_request, request_canary).expect("broker request");
    fs::set_permissions(&broker_request, fs::Permissions::from_mode(0o600)).expect("request mode");
    let acquisition = request(AcquisitionSource::SshBrokered {
        display_host: "github.com".to_owned(),
        opaque_handle: "private_handle_canary".to_owned(),
        revision: "main".to_owned(),
        broker_executable: broker.clone(),
        broker_request: broker_request.clone(),
    });
    let manifest =
        build_remote_git_manifest(&acquisition, remote_backend_policy()).expect("broker manifest");

    assert_eq!(manifest.destination.port, 22);
    assert_eq!(
        manifest.credential_policy,
        RemoteCredentialPolicy::SshAgentBrokerGrant
    );
    assert!(manifest.broker.is_some());
    manifest.validate().expect("valid manifest");
    let encoded = serde_json::to_string(&manifest).expect("manifest json");
    for protected in [
        broker.to_string_lossy().as_ref(),
        broker_request.to_string_lossy().as_ref(),
        "private_handle_canary",
        std::str::from_utf8(request_canary).expect("ascii canary"),
    ] {
        assert!(!encoded.contains(protected), "leaked {protected}");
    }

    fs::write(&broker_request, b"changed request").expect("changed request");
    let changed = build_remote_git_manifest(&acquisition, remote_backend_policy())
        .expect("changed broker manifest");
    assert_ne!(changed.manifest_digest, manifest.manifest_digest);
    assert_ne!(changed.broker, manifest.broker);
}

#[cfg(unix)]
#[test]
fn remote_ssh_manifest_rejects_unapproved_hosts_and_unsafe_broker_files() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    let temp = TempDir::new().expect("temp dir");
    let broker = temp.path().join("broker");
    let broker_request = temp.path().join("request");
    fs::write(&broker, b"#!/bin/sh\nexit 1\n").expect("broker");
    fs::set_permissions(&broker, fs::Permissions::from_mode(0o700)).expect("broker mode");
    fs::write(&broker_request, b"opaque request").expect("request");
    fs::set_permissions(&broker_request, fs::Permissions::from_mode(0o600)).expect("request mode");

    let source = |display_host: &str, executable: PathBuf| {
        request(AcquisitionSource::SshBrokered {
            display_host: display_host.to_owned(),
            opaque_handle: "request_abc123".to_owned(),
            revision: "main".to_owned(),
            broker_executable: executable,
            broker_request: broker_request.clone(),
        })
    };
    assert_eq!(
        build_remote_git_manifest(
            &source("attacker.example", broker.clone()),
            remote_backend_policy()
        ),
        Err(AcquisitionError::InvalidSshBroker)
    );

    let symlinked = temp.path().join("broker-link");
    symlink(&broker, &symlinked).expect("broker symlink");
    assert_eq!(
        build_remote_git_manifest(&source("github.com", symlinked), remote_backend_policy()),
        Err(AcquisitionError::InvalidSshBroker)
    );
}

#[test]
fn remote_attestation_structure_requires_every_isolation_egress_and_cleanup_control() {
    let acquisition = request(AcquisitionSource::Https {
        url: "https://github.com/example/project.git".to_owned(),
        revision: "main".to_owned(),
    });
    let manifest =
        build_remote_git_manifest(&acquisition, remote_backend_policy()).expect("remote manifest");
    let bundle = b"synthetic bounded source bundle";
    let accepted = accepted_remote_attestation(&manifest, bundle);
    accepted
        .validate_structure_for(&manifest)
        .expect("structurally valid attestation");
    RemoteGitResult {
        source_bundle: bundle.to_vec(),
        attestation: accepted.clone(),
    }
    .validate_structure_for(&manifest)
    .expect("structurally valid result");

    let rejected = [
        accepted
            .clone()
            .model_copy_for_test(|value| value.kernel_disk_limit = ControlAttestation::Failed),
        accepted
            .clone()
            .model_copy_for_test(|value| value.root_read_only = ControlAttestation::Failed),
        accepted
            .clone()
            .model_copy_for_test(|value| value.exact_egress_only = ControlAttestation::Failed),
        accepted.clone().model_copy_for_test(|value| {
            value.git_execution_neutralized = ControlAttestation::Failed;
        }),
        accepted.clone().model_copy_for_test(|value| {
            value.credentials_isolated = ControlAttestation::Failed;
        }),
        accepted.clone().model_copy_for_test(|value| {
            value.unaccounted_writable_mounts = 1;
        }),
        accepted.clone().model_copy_for_test(|value| {
            value.observed_destinations = vec![EgressDestination {
                host: "gitlab.com".to_owned(),
                port: 443,
            }];
        }),
        accepted.clone().model_copy_for_test(|value| {
            value.cleanup.orphan_check = ControlAttestation::Failed;
        }),
    ];
    for attestation in rejected {
        assert_eq!(
            attestation.validate_structure_for(&manifest),
            Err(AcquisitionError::InvalidRemoteAttestation)
        );
    }
}

#[test]
fn remote_result_rejects_bundle_tamper_and_oversize() {
    let mut acquisition = request(AcquisitionSource::Https {
        url: "https://github.com/example/project.git".to_owned(),
        revision: "main".to_owned(),
    });
    acquisition.limits.max_archive_bytes = 32;
    let manifest =
        build_remote_git_manifest(&acquisition, remote_backend_policy()).expect("remote manifest");
    let bundle = b"safe";
    let attestation = accepted_remote_attestation(&manifest, bundle);

    assert_eq!(
        RemoteGitResult {
            source_bundle: b"tampered".to_vec(),
            attestation: attestation.clone(),
        }
        .validate_structure_for(&manifest),
        Err(AcquisitionError::RemoteBundleExceeded)
    );
    assert_eq!(
        RemoteGitResult {
            source_bundle: vec![0; 33],
            attestation,
        }
        .validate_structure_for(&manifest),
        Err(AcquisitionError::RemoteBundleExceeded)
    );
}

#[cfg(unix)]
#[test]
fn production_remote_path_validates_input_then_fails_before_host_git() {
    let temp = TempDir::new().expect("temp dir");
    let acquirer = Acquirer::new(temp.path().join("state")).expect("acquirer");
    let denied = request(AcquisitionSource::Https {
        url: "https://token@github.com/example/project.git".to_owned(),
        revision: "main".to_owned(),
    });
    assert_eq!(
        acquirer.acquire(&denied),
        Err(AcquisitionError::LocatorDenied)
    );

    let accepted_input = request(AcquisitionSource::Https {
        url: "https://github.com/example/project.git".to_owned(),
        revision: "main".to_owned(),
    });
    assert_eq!(
        acquirer.acquire(&accepted_input),
        Err(AcquisitionError::RemoteGitUnavailable)
    );
}

#[cfg(unix)]
#[test]
fn public_git_plan_clears_inherited_execution_surfaces() {
    let temp = TempDir::new().expect("temp dir");
    fs::create_dir(temp.path().join("empty-hooks")).expect("hooks");
    let source = AcquisitionSource::Https {
        url: "https://github.com/example/project.git".to_owned(),
        revision: "main".to_owned(),
    };
    let plan = plan_git_clone(
        &source,
        temp.path(),
        &temp.path().join("repo"),
        &AcquisitionLimits::default(),
    )
    .expect("plan");
    let arguments = plan
        .arguments
        .iter()
        .map(|value| value.to_string_lossy())
        .collect::<Vec<_>>()
        .join(" ");
    let environment = plan
        .environment
        .iter()
        .map(|(key, value)| format!("{}={}", key.to_string_lossy(), value.to_string_lossy()))
        .collect::<Vec<_>>()
        .join(" ");
    for required in [
        "protocol.allow=never",
        "protocol.file.allow=never",
        "protocol.ext.allow=never",
        "protocol.https.allow=always",
        "credential.helper=",
        "submodule.recurse=false",
        "filter.lfs.smudge=",
        "http.followRedirects=false",
        "--no-checkout",
        "--no-recurse-submodules",
    ] {
        assert!(arguments.contains(required), "missing {required}");
    }
    for required in [
        "GIT_CONFIG_NOSYSTEM=1",
        "GIT_TERMINAL_PROMPT=0",
        "GIT_ASKPASS=/usr/bin/false",
        "GIT_LFS_SKIP_SMUDGE=1",
    ] {
        assert!(environment.contains(required), "missing {required}");
    }
    assert!(!environment.contains("SSH_AUTH_SOCK"));
}

#[cfg(unix)]
#[test]
fn system_git_runner_bounds_output_and_returns_no_stderr() {
    let temp = TempDir::new().expect("temp dir");
    let base = GitCommandPlan {
        program: "/usr/bin/git".into(),
        arguments: vec!["--version".into()],
        environment: vec![("LC_ALL".into(), "C".into())],
        current_directory: temp.path().to_path_buf(),
        max_output_bytes: 128,
        timeout: std::time::Duration::from_secs(5),
    };
    let output = SystemGitRunner.run(&base).expect("bounded Git");
    assert!(output.success);
    assert!(output.stdout.starts_with(b"git version "));

    let limited = GitCommandPlan {
        max_output_bytes: 1,
        ..base
    };
    assert_eq!(
        SystemGitRunner.run(&limited),
        Err(AcquisitionError::GitOutputExceeded)
    );
}

#[cfg(unix)]
#[test]
fn brokered_ssh_uses_only_an_opaque_git_locator() {
    use std::os::unix::fs::PermissionsExt;

    let temp = TempDir::new().expect("temp dir");
    let broker = temp.path().join("broker");
    let broker_request = temp.path().join("request");
    fs::write(&broker, b"#!/bin/sh\nexit 1\n").expect("broker");
    fs::set_permissions(&broker, fs::Permissions::from_mode(0o700)).expect("mode");
    fs::write(&broker_request, b"private/repository/name").expect("request");
    fs::set_permissions(&broker_request, fs::Permissions::from_mode(0o600)).expect("mode");
    let source = AcquisitionSource::SshBrokered {
        display_host: "github.com".to_owned(),
        opaque_handle: "request_abc123".to_owned(),
        revision: "main".to_owned(),
        broker_executable: broker,
        broker_request,
    };
    let plan = plan_git_clone(
        &source,
        temp.path(),
        &temp.path().join("repo"),
        &AcquisitionLimits::default(),
    )
    .expect("plan");
    let arguments = plan
        .arguments
        .iter()
        .map(|value| value.to_string_lossy())
        .collect::<Vec<_>>()
        .join(" ");
    assert!(arguments.contains("ssh://promptectomy-broker.invalid/request_abc123"));
    assert!(!arguments.contains("private/repository/name"));
    assert!(!arguments.contains("github.com"));
}

#[cfg(unix)]
#[test]
fn fake_public_remote_is_inventoried_without_checkout_filters_or_submodules() {
    let temp = TempDir::new().expect("temp dir");
    let runner = ScriptedRunner::new(vec![
        GitOutput {
            success: true,
            stdout: Vec::new(),
        },
        GitOutput {
            success: true,
            stdout: format!("{COMMIT}\n").into_bytes(),
        },
        GitOutput {
            success: true,
            stdout: "100644 blob 1111111111111111111111111111111111111111 6\tsrc/main.py\0\
                     160000 commit 2222222222222222222222222222222222222222 -\tvendor/lib\0"
                .as_bytes()
                .to_vec(),
        },
        GitOutput {
            success: true,
            stdout: b"hello\n".to_vec(),
        },
        GitOutput {
            success: true,
            stdout: b"git version 2.50.1\n".to_vec(),
        },
    ]);
    let acquirer = Acquirer::new(temp.path().join("state")).expect("acquirer");
    let snapshot = acquirer
        .acquire_with_runner(
            &request(AcquisitionSource::Https {
                url: "https://github.com/example/project.git".to_owned(),
                revision: "main".to_owned(),
            }),
            &runner,
        )
        .expect("remote snapshot");
    assert_eq!(snapshot.reference.revision, COMMIT);
    assert_eq!(
        snapshot.receipt.submodule_state,
        "present_not_initialized:1"
    );
    assert_eq!(
        snapshot.receipt.git_version.as_deref(),
        Some("git version 2.50.1")
    );
    assert_eq!(
        fs::read(snapshot.snapshot_root.join("tree/src/main.py")).expect("snapshot file"),
        b"hello\n"
    );
    assert_eq!(runner.remaining(), 0);
}

#[cfg(unix)]
#[test]
fn system_remote_acquisition_is_typed_unavailable_until_bounded_broker_exists() {
    let temp = TempDir::new().expect("temp dir");
    let acquirer = Acquirer::new(temp.path().join("state")).expect("acquirer");
    assert_eq!(
        acquirer.acquire(&request(AcquisitionSource::Https {
            url: "https://github.com/example/project.git".to_owned(),
            revision: "main".to_owned(),
        })),
        Err(AcquisitionError::RemoteGitUnavailable)
    );
}

#[cfg(not(unix))]
#[test]
fn private_snapshot_storage_is_typed_unsupported() {
    let temp = TempDir::new().expect("temp dir");
    assert!(matches!(
        Acquirer::new(temp.path().join("state")),
        Err(AcquisitionError::StoragePermissionUnsupported)
    ));
}

#[cfg(unix)]
#[test]
fn local_hardlink_is_rejected_as_external_content_risk() {
    use std::fs::hard_link;

    let temp = TempDir::new().expect("temp dir");
    let source = temp.path().join("source");
    fs::create_dir(&source).expect("source");
    let outside = temp.path().join("outside-secret");
    fs::write(&outside, b"outside").expect("outside");
    hard_link(&outside, source.join("inside")).expect("hardlink");

    let acquirer = Acquirer::new(temp.path().join("state")).expect("acquirer");
    assert_eq!(
        acquirer.acquire(&request(local_source(&source))),
        Err(AcquisitionError::UnsupportedFileType)
    );
}

#[cfg(unix)]
#[derive(Debug)]
struct ScriptedRunner {
    outputs: Mutex<Vec<GitOutput>>,
}

#[cfg(unix)]
impl ScriptedRunner {
    fn new(mut outputs: Vec<GitOutput>) -> Self {
        outputs.reverse();
        Self {
            outputs: Mutex::new(outputs),
        }
    }

    fn remaining(&self) -> usize {
        self.outputs.lock().expect("runner lock").len()
    }
}

#[cfg(unix)]
impl GitRunner for ScriptedRunner {
    fn run(&self, _: &GitCommandPlan) -> Result<GitOutput, AcquisitionError> {
        self.outputs
            .lock()
            .expect("runner lock")
            .pop()
            .ok_or(AcquisitionError::GitFailed)
    }
}

fn tar(entries: &[(&str, &[u8], u8)]) -> Vec<u8> {
    let mut archive = Vec::new();
    for (path, content, kind) in entries {
        let mut header = [0_u8; 512];
        header[..path.len()].copy_from_slice(path.as_bytes());
        write_octal(&mut header[100..108], 0o644);
        write_octal(&mut header[108..116], 0);
        write_octal(&mut header[116..124], 0);
        write_octal(
            &mut header[124..136],
            u64::try_from(content.len()).expect("test size"),
        );
        write_octal(&mut header[136..148], 0);
        header[148..156].fill(b' ');
        header[156] = *kind;
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let checksum = header.iter().map(|byte| u64::from(*byte)).sum();
        write_checksum(&mut header[148..156], checksum);
        archive.extend_from_slice(&header);
        archive.extend_from_slice(content);
        let padding = (512 - content.len() % 512) % 512;
        archive.resize(archive.len() + padding, 0);
    }
    archive.resize(archive.len() + 1024, 0);
    archive
}

fn write_octal(field: &mut [u8], value: u64) {
    field.fill(b'0');
    let text = format!("{value:o}");
    let start = field.len() - text.len() - 1;
    field[start..start + text.len()].copy_from_slice(text.as_bytes());
    field[field.len() - 1] = 0;
}

fn write_checksum(field: &mut [u8], value: u64) {
    field.fill(b'0');
    let text = format!("{value:06o}");
    field[..6].copy_from_slice(text.as_bytes());
    field[6] = 0;
    field[7] = b' ';
}
