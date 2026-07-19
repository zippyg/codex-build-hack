#![cfg(all(unix, feature = "protocol-test-child"))]

use std::path::{Path, PathBuf};
use std::time::Duration;

use promptectomy_protocol::{
    AdapterCancellation, AdapterSupervisor, BudgetLimits, CancellationPolicy, EndpointKind,
    MESSAGE_SCHEMA_VERSION, MessageBody, OperationKind, ProtocolError, ProtocolMessage,
    RequestBody, SupervisorConfig, SupervisorError,
};
use serde_json::{Value, json};
use tempfile::TempDir;

fn child_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_promptectomy-protocol-test-child"))
}

fn private_directory() -> TempDir {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::Builder::new()
        .prefix("promptectomy-protocol-")
        .tempdir()
        .unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    directory
}

fn config(directory: &Path) -> SupervisorConfig {
    let mut config = SupervisorConfig::new(
        child_path(),
        directory.to_path_buf(),
        EndpointKind::PythonAdapter,
        vec!["synthetic".to_owned()],
    );
    config.max_response_bytes = 1_024;
    config.max_stderr_bytes = 1_024;
    config.max_runtime = Duration::from_secs(3);
    config
}

fn request(mode: &str) -> ProtocolMessage {
    ProtocolMessage {
        schema_version: MESSAGE_SCHEMA_VERSION.to_owned(),
        message_id: format!("request_{mode}"),
        request_id: Some(format!("request_id_{mode}")),
        body: MessageBody::Request(RequestBody {
            endpoint: EndpointKind::PythonAdapter,
            operation: OperationKind::DiscoverPython,
            deadline: None,
            budgets: BudgetLimits {
                wall_time_ms: Some(3_000),
                ..BudgetLimits::default()
            },
            cancellation: CancellationPolicy {
                cancel_token: format!("cancel_{mode}"),
                poll_interval_ms: 10,
            },
            payload: json!({"mode": mode}),
        }),
    }
}

fn response_payload(response: &ProtocolMessage) -> &Value {
    let MessageBody::Result(result) = &response.body else {
        panic!("expected result response");
    };
    &result.payload
}

#[tokio::test]
async fn successful_child_completes_exact_negotiation_and_request() {
    let directory = private_directory();
    let response = AdapterSupervisor::new(config(directory.path()))
        .run(request("success"), &AdapterCancellation::new())
        .await
        .unwrap();

    assert_eq!(response.request_id.as_deref(), Some("request_id_success"));
    assert_eq!(response_payload(&response), &json!({"ok": true}));
}

#[tokio::test]
async fn oversized_and_malformed_responses_are_typed_protocol_failures() {
    let directory = private_directory();
    let oversized = AdapterSupervisor::new(config(directory.path()))
        .run(request("oversize"), &AdapterCancellation::new())
        .await
        .unwrap_err();
    assert_eq!(
        oversized,
        SupervisorError::Protocol(ProtocolError::FrameTooLarge {
            max: 1_024,
            actual: 2_048,
        })
    );

    let malformed = AdapterSupervisor::new(config(directory.path()))
        .run(request("malformed"), &AdapterCancellation::new())
        .await
        .unwrap_err();
    assert_eq!(
        malformed,
        SupervisorError::Protocol(ProtocolError::InvalidJson)
    );
}

#[tokio::test]
async fn nonzero_exit_is_typed_and_stderr_is_discarded() {
    let directory = private_directory();
    for _ in 0..32 {
        let error = AdapterSupervisor::new(config(directory.path()))
            .run(request("nonzero"), &AdapterCancellation::new())
            .await
            .unwrap_err();

        assert!(
            matches!(error, SupervisorError::Exited { code: 23, .. }),
            "unexpected supervisor outcome: {error:?}"
        );
    }
}

#[tokio::test]
async fn signal_exit_is_typed() {
    let directory = private_directory();
    for _ in 0..32 {
        let error = AdapterSupervisor::new(config(directory.path()))
            .run(request("signal"), &AdapterCancellation::new())
            .await
            .unwrap_err();

        assert!(
            matches!(error, SupervisorError::Signaled { signal: 9, .. }),
            "unexpected supervisor outcome: {error:?}"
        );
    }
}

#[tokio::test]
async fn timeout_and_cancellation_terminate_the_child() {
    let directory = private_directory();
    let mut timeout_config = config(directory.path());
    timeout_config.max_runtime = Duration::from_millis(150);
    let timeout_error = AdapterSupervisor::new(timeout_config)
        .run(request("timeout"), &AdapterCancellation::new())
        .await
        .unwrap_err();
    assert!(matches!(timeout_error, SupervisorError::TimedOut { .. }));

    let cancellation = AdapterCancellation::new();
    let trigger = cancellation.clone();
    let cancel_task = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        trigger.cancel();
    });
    let cancel_error = AdapterSupervisor::new(config(directory.path()))
        .run(request("timeout"), &cancellation)
        .await
        .unwrap_err();
    cancel_task.await.unwrap();
    assert!(matches!(cancel_error, SupervisorError::Cancelled { .. }));
}

#[tokio::test]
async fn cwd_is_private_and_the_child_environment_is_empty() {
    let directory = private_directory();
    let response = AdapterSupervisor::new(config(directory.path()))
        .run(request("environment"), &AdapterCancellation::new())
        .await
        .unwrap();
    let payload = response_payload(&response);

    assert_eq!(
        payload["cwd"],
        json!(directory.path().canonicalize().unwrap().to_string_lossy())
    );
    assert_eq!(payload["home_present"], json!(false));
    assert_eq!(payload["path_present"], json!(false));
    assert_eq!(payload["user_present"], json!(false));
    assert_eq!(payload["openai_key_present"], json!(false));
}

#[tokio::test]
async fn relative_executable_is_rejected_before_spawn() {
    let directory = private_directory();
    let mut relative = config(directory.path());
    relative.executable = PathBuf::from("promptectomy-protocol-test-child");
    assert!(matches!(
        AdapterSupervisor::new(relative)
            .run(request("success"), &AdapterCancellation::new())
            .await,
        Err(SupervisorError::ExecutablePathNotAbsolute)
    ));
}

#[tokio::test]
async fn pre_cancelled_request_never_spawns_the_adapter() {
    let directory = private_directory();
    let cancellation = AdapterCancellation::new();
    cancellation.cancel();
    let error = AdapterSupervisor::new(config(directory.path()))
        .run(request("marker"), &cancellation)
        .await
        .unwrap_err();

    assert!(matches!(error, SupervisorError::Cancelled { .. }));
    assert!(!directory.path().join("spawned.marker").exists());
}

#[tokio::test]
async fn absolute_symlinks_are_resolved_before_spawn_and_cwd_validation() {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::fs::symlink;

    let directory = private_directory();
    let executable_link = directory.path().join("adapter-link");
    let cwd_link = directory.path().join("cwd-link");
    let private_cwd = directory.path().join("private-cwd");
    std::fs::create_dir(&private_cwd).unwrap();
    std::fs::set_permissions(&private_cwd, std::fs::Permissions::from_mode(0o700)).unwrap();
    symlink(child_path(), &executable_link).unwrap();
    symlink(&private_cwd, &cwd_link).unwrap();

    let response = AdapterSupervisor::new(config(&cwd_link))
        .run(request("success"), &AdapterCancellation::new())
        .await
        .unwrap();
    assert_eq!(response_payload(&response), &json!({"ok": true}));

    let mut linked_executable = config(&private_cwd);
    linked_executable.executable = executable_link;
    let response = AdapterSupervisor::new(linked_executable)
        .run(request("success"), &AdapterCancellation::new())
        .await
        .unwrap();
    assert_eq!(response_payload(&response), &json!({"ok": true}));
}

#[tokio::test]
async fn stderr_overflow_is_bounded_and_typed() {
    let directory = private_directory();
    let mut child_config = config(directory.path());
    child_config.max_stderr_bytes = 64;
    let error = AdapterSupervisor::new(child_config)
        .run(request("stderr_oversize"), &AdapterCancellation::new())
        .await
        .unwrap_err();

    let SupervisorError::StderrTooLarge {
        max,
        actual,
        stderr,
    } = error
    else {
        panic!("expected stderr bound failure");
    };
    assert_eq!(max, 64);
    assert!(actual > max);
    assert!(stderr.truncated);
    assert!(stderr.discarded_bytes >= actual);
}

#[tokio::test]
async fn timeout_kills_the_full_process_group_without_an_orphan() {
    use rustix::process::{Pid, test_kill_process};

    let directory = private_directory();
    let mut child_config = config(directory.path());
    child_config.max_runtime = Duration::from_millis(1_500);
    let error = AdapterSupervisor::new(child_config)
        .run(request("orphan"), &AdapterCancellation::new())
        .await
        .unwrap_err();
    assert!(matches!(error, SupervisorError::TimedOut { .. }));

    let raw_pid = tokio::fs::read_to_string(directory.path().join("descendant.pid"))
        .await
        .unwrap();
    let pid = Pid::from_raw(raw_pid.parse::<i32>().unwrap()).unwrap();
    for _ in 0..80 {
        if test_kill_process(pid).is_err() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("descendant process {raw_pid} survived process-group termination");
}
