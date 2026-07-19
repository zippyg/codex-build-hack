use std::ffi::OsString;
use std::future::Future;
#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;
#[cfg(unix)]
use std::process::{ExitStatus, Stdio};
use std::time::Duration;
#[cfg(unix)]
use std::time::{SystemTime, UNIX_EPOCH};

use thiserror::Error;
#[cfg(unix)]
use tokio::io::{AsyncRead, AsyncReadExt};
#[cfg(unix)]
use tokio::process::{Child, Command};
#[cfg(unix)]
use tokio::sync::oneshot;
use tokio::sync::watch;
#[cfg(unix)]
use tokio::task::JoinHandle;
#[cfg(unix)]
use tokio::time::{Instant, sleep_until, timeout};

use crate::{EndpointKind, HelloBody, MessageKind, ProtocolError, ProtocolLimits, ProtocolMessage};
#[cfg(unix)]
use crate::{MessageBody, PROTOCOL_MAJOR, PROTOCOL_NAME, negotiate, read_frame, write_frame};

#[cfg(unix)]
const MAX_SUPERVISOR_RUNTIME: Duration = Duration::from_secs(86_400);
#[cfg(unix)]
const MAX_STDERR_BYTES: usize = 1_048_576;
#[cfg(unix)]
const EXIT_RACE_GRACE: Duration = Duration::from_millis(250);

#[cfg(unix)]
enum SupervisorOutcome {
    Response(Box<ProtocolMessage>),
    Protocol(Box<SupervisorError>),
    Exit(std::io::Result<ExitStatus>),
    Timeout,
    Cancel,
    Stderr(usize),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SafeStderr {
    pub discarded_bytes: usize,
    pub truncated: bool,
}

impl SafeStderr {
    #[cfg(unix)]
    fn empty() -> Self {
        Self {
            discarded_bytes: 0,
            truncated: false,
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SupervisorError {
    #[error("adapter executable path must be absolute")]
    ExecutablePathNotAbsolute,
    #[error("adapter executable is not a regular file")]
    InvalidExecutable,
    #[error("adapter private working directory path must be absolute")]
    WorkingDirectoryNotAbsolute,
    #[error("adapter private working directory is invalid")]
    InvalidWorkingDirectory,
    #[error("adapter working directory is accessible to other users")]
    InsecureWorkingDirectory,
    #[error("adapter supervisor configuration exceeds bound: {field}")]
    InvalidBound { field: &'static str },
    #[error("adapter request endpoint does not match the supervised endpoint")]
    EndpointMismatch,
    #[error("adapter request must contain a request message with a request id")]
    InvalidRequest,
    #[error("adapter process could not be spawned")]
    Spawn,
    #[error("adapter process pipe is unavailable: {pipe}")]
    MissingPipe { pipe: &'static str },
    #[error("adapter protocol failed: {0}")]
    Protocol(ProtocolError),
    #[error("adapter sent {actual:?} while {expected:?} was required")]
    UnexpectedMessage {
        expected: MessageKind,
        actual: MessageKind,
    },
    #[error("adapter negotiation identity does not match the configured endpoint")]
    PeerIdentityMismatch,
    #[error("adapter did not acknowledge the exact negotiated protocol")]
    NegotiationMismatch,
    #[error("adapter response does not correlate to the request")]
    ResponseMismatch,
    #[error("adapter exited before producing a response with code {code}")]
    Exited { code: i32, stderr: SafeStderr },
    #[error("adapter was terminated by signal {signal}")]
    Signaled { signal: i32, stderr: SafeStderr },
    #[error("adapter exceeded its deadline")]
    TimedOut { stderr: SafeStderr },
    #[error("adapter was cancelled")]
    Cancelled { stderr: SafeStderr },
    #[error("adapter stderr exceeds {max} bytes: at least {actual}")]
    StderrTooLarge {
        max: usize,
        actual: usize,
        stderr: SafeStderr,
    },
    #[error("adapter stderr could not be drained")]
    StderrRead,
    #[error("adapter process tree could not be terminated")]
    Termination,
    #[error("adapter process-tree containment is not implemented on this platform")]
    ProcessTreeUnsupported,
    #[error("system clock is before the Unix epoch")]
    InvalidClock,
}

impl From<ProtocolError> for SupervisorError {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

#[derive(Clone, Debug)]
pub struct SupervisorConfig {
    pub executable: PathBuf,
    pub arguments: Vec<OsString>,
    pub private_working_directory: PathBuf,
    pub local_hello: HelloBody,
    pub expected_peer_endpoint: EndpointKind,
    pub limits: ProtocolLimits,
    pub max_response_bytes: usize,
    pub max_stderr_bytes: usize,
    pub max_runtime: Duration,
}

impl SupervisorConfig {
    pub fn new(
        executable: PathBuf,
        private_working_directory: PathBuf,
        expected_peer_endpoint: EndpointKind,
        capabilities: Vec<String>,
    ) -> Self {
        let local_hello = HelloBody::new(
            EndpointKind::ControlPlane,
            "promptectomy-rust-control-plane",
            capabilities,
        );
        let limits = local_hello.limits.clone();
        Self {
            executable,
            arguments: Vec::new(),
            private_working_directory,
            local_hello,
            expected_peer_endpoint,
            max_response_bytes: usize::try_from(limits.max_frame_bytes).unwrap_or(usize::MAX),
            max_stderr_bytes: 16_384,
            max_runtime: Duration::from_secs(60),
            limits,
        }
    }
}

#[derive(Clone, Debug)]
pub struct AdapterCancellation {
    sender: watch::Sender<bool>,
}

impl Default for AdapterCancellation {
    fn default() -> Self {
        Self::new()
    }
}

impl AdapterCancellation {
    pub fn new() -> Self {
        let (sender, _) = watch::channel(false);
        Self { sender }
    }

    pub fn cancel(&self) {
        self.sender.send_replace(true);
    }

    #[cfg(unix)]
    fn subscribe(&self) -> watch::Receiver<bool> {
        self.sender.subscribe()
    }
}

#[derive(Clone, Debug)]
pub struct AdapterSupervisor {
    config: SupervisorConfig,
}

impl AdapterSupervisor {
    pub fn new(config: SupervisorConfig) -> Self {
        Self { config }
    }

    pub fn run<'a>(
        &'a self,
        request: ProtocolMessage,
        cancellation: &'a AdapterCancellation,
    ) -> impl Future<Output = Result<ProtocolMessage, SupervisorError>> + 'a {
        #[cfg(not(unix))]
        {
            let _ = &self.config;
            drop(request);
            let _ = cancellation;
            std::future::ready(Err(SupervisorError::ProcessTreeUnsupported))
        }

        #[cfg(unix)]
        self.run_unix(request, cancellation)
    }

    #[cfg(unix)]
    async fn run_unix(
        &self,
        request: ProtocolMessage,
        cancellation: &AdapterCancellation,
    ) -> Result<ProtocolMessage, SupervisorError> {
        let prepared = PreparedConfig::new(&self.config)?;
        let request_id = validate_request(&request, self.config.expected_peer_endpoint)?;
        crate::encode_message(&request, &self.config.limits)?;
        let runtime = effective_runtime(&request, self.config.max_runtime)?;
        if runtime.is_zero() {
            return Err(SupervisorError::TimedOut {
                stderr: SafeStderr::empty(),
            });
        }
        let deadline = Instant::now() + runtime;
        let mut cancellation = cancellation.subscribe();
        if *cancellation.borrow() {
            return Err(SupervisorError::Cancelled {
                stderr: SafeStderr::empty(),
            });
        }

        let mut command = Command::new(&prepared.executable);
        command
            .args(&self.config.arguments)
            .current_dir(&prepared.working_directory)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .process_group(0);

        let mut child = command.spawn().map_err(|_| SupervisorError::Spawn)?;
        let pid = child.id().ok_or(SupervisorError::Spawn)?;
        let stdin = child
            .stdin
            .take()
            .ok_or(SupervisorError::MissingPipe { pipe: "stdin" })?;
        let stdout = child
            .stdout
            .take()
            .ok_or(SupervisorError::MissingPipe { pipe: "stdout" })?;
        let stderr = child
            .stderr
            .take()
            .ok_or(SupervisorError::MissingPipe { pipe: "stderr" })?;
        let (stderr_overflow_tx, mut stderr_overflow_rx) = oneshot::channel();
        let stderr_task = tokio::spawn(capture_stderr(
            stderr,
            self.config.max_stderr_bytes,
            stderr_overflow_tx,
        ));
        let exchange = exchange(stdin, stdout, &self.config, request, &request_id);
        tokio::pin!(exchange);

        let outcome = tokio::select! {
            biased;
            () = cancellation_requested(&mut cancellation) => SupervisorOutcome::Cancel,
            () = sleep_until(deadline) => SupervisorOutcome::Timeout,
            actual = stderr_exceeded(&mut stderr_overflow_rx) => SupervisorOutcome::Stderr(actual),
            result = &mut exchange => match result {
                Ok(response) => SupervisorOutcome::Response(Box::new(response)),
                Err(error) => SupervisorOutcome::Protocol(Box::new(error)),
            },
            status = child.wait() => SupervisorOutcome::Exit(status),
        };

        self.finish_outcome(outcome, &mut child, pid, stderr_task)
            .await
    }

    #[cfg(unix)]
    async fn finish_outcome(
        &self,
        outcome: SupervisorOutcome,
        child: &mut Child,
        pid: u32,
        stderr_task: JoinHandle<std::io::Result<CapturedStderr>>,
    ) -> Result<ProtocolMessage, SupervisorError> {
        match outcome {
            SupervisorOutcome::Response(response) => {
                terminate_process_group(child, pid, true).await?;
                let stderr = finish_stderr(stderr_task).await?;
                if stderr.truncated {
                    return Err(SupervisorError::StderrTooLarge {
                        max: self.config.max_stderr_bytes,
                        actual: self.config.max_stderr_bytes.saturating_add(1),
                        stderr,
                    });
                }
                Ok(*response)
            }
            SupervisorOutcome::Protocol(protocol_error) => {
                if let Ok(status) = timeout(EXIT_RACE_GRACE, child.wait()).await {
                    let status = status.map_err(|_| SupervisorError::Termination)?;
                    terminate_process_group_after_exit(pid)?;
                    let stderr = finish_stderr(stderr_task).await?;
                    return Err(exit_error(status, stderr));
                }
                terminate_process_group(child, pid, true).await?;
                finish_stderr(stderr_task).await?;
                Err(*protocol_error)
            }
            SupervisorOutcome::Exit(status) => {
                let status = status.map_err(|_| SupervisorError::Termination)?;
                terminate_process_group_after_exit(pid)?;
                let stderr = finish_stderr(stderr_task).await?;
                Err(exit_error(status, stderr))
            }
            SupervisorOutcome::Timeout => {
                terminate_process_group(child, pid, true).await?;
                let stderr = finish_stderr(stderr_task).await?;
                Err(SupervisorError::TimedOut { stderr })
            }
            SupervisorOutcome::Cancel => {
                terminate_process_group(child, pid, true).await?;
                let stderr = finish_stderr(stderr_task).await?;
                Err(SupervisorError::Cancelled { stderr })
            }
            SupervisorOutcome::Stderr(actual) => {
                terminate_process_group(child, pid, true).await?;
                let mut stderr = finish_stderr(stderr_task).await?;
                stderr.truncated = true;
                Err(SupervisorError::StderrTooLarge {
                    max: self.config.max_stderr_bytes,
                    actual,
                    stderr,
                })
            }
        }
    }
}

#[cfg(unix)]
struct PreparedConfig {
    executable: PathBuf,
    working_directory: PathBuf,
}

#[cfg(unix)]
impl PreparedConfig {
    fn new(config: &SupervisorConfig) -> Result<Self, SupervisorError> {
        config.limits.validate()?;
        if config.local_hello.protocol != PROTOCOL_NAME
            || config.local_hello.major != PROTOCOL_MAJOR
            || config.local_hello.endpoint != EndpointKind::ControlPlane
            || config.local_hello.limits != config.limits
            || config.expected_peer_endpoint == EndpointKind::ControlPlane
        {
            return Err(SupervisorError::PeerIdentityMismatch);
        }
        let max_frame = usize::try_from(config.limits.max_frame_bytes).unwrap_or(usize::MAX);
        if config.max_response_bytes < 4 || config.max_response_bytes > max_frame {
            return Err(SupervisorError::InvalidBound {
                field: "max_response_bytes",
            });
        }
        if config.max_stderr_bytes == 0 || config.max_stderr_bytes > MAX_STDERR_BYTES {
            return Err(SupervisorError::InvalidBound {
                field: "max_stderr_bytes",
            });
        }
        if config.max_runtime.is_zero() || config.max_runtime > MAX_SUPERVISOR_RUNTIME {
            return Err(SupervisorError::InvalidBound {
                field: "max_runtime",
            });
        }
        if !config.executable.is_absolute() {
            return Err(SupervisorError::ExecutablePathNotAbsolute);
        }
        let executable = config
            .executable
            .canonicalize()
            .map_err(|_| SupervisorError::InvalidExecutable)?;
        if !executable
            .metadata()
            .is_ok_and(|metadata| metadata.is_file())
        {
            return Err(SupervisorError::InvalidExecutable);
        }
        if !config.private_working_directory.is_absolute() {
            return Err(SupervisorError::WorkingDirectoryNotAbsolute);
        }
        let working_directory = config
            .private_working_directory
            .canonicalize()
            .map_err(|_| SupervisorError::InvalidWorkingDirectory)?;
        let metadata = working_directory
            .metadata()
            .map_err(|_| SupervisorError::InvalidWorkingDirectory)?;
        if !metadata.is_dir() {
            return Err(SupervisorError::InvalidWorkingDirectory);
        }
        validate_private_directory(&working_directory, &metadata)?;
        Ok(Self {
            executable,
            working_directory,
        })
    }
}

#[cfg(unix)]
fn validate_private_directory(
    _path: &Path,
    metadata: &std::fs::Metadata,
) -> Result<(), SupervisorError> {
    use std::os::unix::fs::PermissionsExt;

    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(SupervisorError::InsecureWorkingDirectory);
    }
    Ok(())
}

#[cfg(unix)]
fn validate_request(
    request: &ProtocolMessage,
    endpoint: EndpointKind,
) -> Result<String, SupervisorError> {
    let request_id = request
        .request_id
        .as_ref()
        .filter(|value| !value.is_empty())
        .cloned()
        .ok_or(SupervisorError::InvalidRequest)?;
    let MessageBody::Request(body) = &request.body else {
        return Err(SupervisorError::InvalidRequest);
    };
    if body.endpoint != endpoint {
        return Err(SupervisorError::EndpointMismatch);
    }
    Ok(request_id)
}

#[cfg(unix)]
fn effective_runtime(
    request: &ProtocolMessage,
    configured: Duration,
) -> Result<Duration, SupervisorError> {
    let MessageBody::Request(body) = &request.body else {
        return Err(SupervisorError::InvalidRequest);
    };
    let mut runtime = configured;
    if let Some(wall_time_ms) = body.budgets.wall_time_ms {
        runtime = runtime.min(Duration::from_millis(wall_time_ms));
    }
    if let Some(deadline) = &body.deadline {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| SupervisorError::InvalidClock)?
            .as_millis();
        let deadline_ms = u128::from(deadline.unix_epoch_ms);
        if deadline_ms <= now_ms {
            return Ok(Duration::ZERO);
        }
        let remaining_ms = u64::try_from(deadline_ms - now_ms).unwrap_or(u64::MAX);
        runtime = runtime.min(Duration::from_millis(remaining_ms));
    }
    Ok(runtime)
}

#[cfg(unix)]
async fn exchange(
    mut stdin: tokio::process::ChildStdin,
    mut stdout: tokio::process::ChildStdout,
    config: &SupervisorConfig,
    request: ProtocolMessage,
    request_id: &str,
) -> Result<ProtocolMessage, SupervisorError> {
    let local_hello = ProtocolMessage::hello("supervisor_hello", config.local_hello.clone());
    write_frame(&mut stdin, &config.limits, &local_hello).await?;

    let response_limits = response_limits(config)?;
    let peer_hello = read_frame(&mut stdout, &response_limits).await?;
    if peer_hello.request_id.is_some() {
        return Err(SupervisorError::NegotiationMismatch);
    }
    let MessageBody::Hello(peer_hello_body) = &peer_hello.body else {
        return Err(SupervisorError::UnexpectedMessage {
            expected: MessageKind::Hello,
            actual: peer_hello.kind(),
        });
    };
    if peer_hello_body.endpoint != config.expected_peer_endpoint {
        return Err(SupervisorError::PeerIdentityMismatch);
    }
    let negotiated = negotiate(&config.local_hello, peer_hello_body)?;
    let ready = ProtocolMessage {
        schema_version: crate::MESSAGE_SCHEMA_VERSION.to_owned(),
        message_id: "supervisor_ready".to_owned(),
        request_id: None,
        body: MessageBody::Ready(crate::ReadyBody {
            negotiated: negotiated.clone(),
        }),
    };
    write_frame(&mut stdin, &negotiated.limits, &ready).await?;

    let negotiated_response_limits = negotiated_response_limits(config, &negotiated.limits)?;
    let peer_ready = read_frame(&mut stdout, &negotiated_response_limits).await?;
    if peer_ready.request_id.is_some() {
        return Err(SupervisorError::NegotiationMismatch);
    }
    let peer_ready_kind = peer_ready.kind();
    let MessageBody::Ready(peer_ready_body) = peer_ready.body else {
        return Err(SupervisorError::UnexpectedMessage {
            expected: MessageKind::Ready,
            actual: peer_ready_kind,
        });
    };
    if peer_ready_body.negotiated != negotiated {
        return Err(SupervisorError::NegotiationMismatch);
    }

    write_frame(&mut stdin, &negotiated.limits, &request).await?;
    let response = read_frame(&mut stdout, &negotiated_response_limits).await?;
    if response.request_id.as_deref() != Some(request_id)
        || !matches!(
            response.body,
            MessageBody::Result(_) | MessageBody::Failure(_)
        )
    {
        return Err(SupervisorError::ResponseMismatch);
    }
    Ok(response)
}

#[cfg(unix)]
fn negotiated_response_limits(
    config: &SupervisorConfig,
    negotiated: &ProtocolLimits,
) -> Result<ProtocolLimits, SupervisorError> {
    let mut limits = negotiated.clone();
    let configured_max =
        u32::try_from(config.max_response_bytes).map_err(|_| SupervisorError::InvalidBound {
            field: "max_response_bytes",
        })?;
    limits.max_frame_bytes = limits.max_frame_bytes.min(configured_max);
    limits.validate()?;
    Ok(limits)
}

#[cfg(unix)]
fn response_limits(config: &SupervisorConfig) -> Result<ProtocolLimits, SupervisorError> {
    let mut limits = config.limits.clone();
    limits.max_frame_bytes =
        u32::try_from(config.max_response_bytes).map_err(|_| SupervisorError::InvalidBound {
            field: "max_response_bytes",
        })?;
    limits.validate()?;
    Ok(limits)
}

#[cfg(unix)]
async fn cancellation_requested(receiver: &mut watch::Receiver<bool>) {
    while !*receiver.borrow() {
        if receiver.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

#[cfg(unix)]
async fn stderr_exceeded(receiver: &mut oneshot::Receiver<usize>) -> usize {
    match receiver.await {
        Ok(actual) => actual,
        Err(_) => std::future::pending().await,
    }
}

#[cfg(unix)]
struct CapturedStderr {
    total: usize,
    exceeded: bool,
}

#[cfg(unix)]
async fn capture_stderr<R>(
    mut stderr: R,
    max: usize,
    overflow: oneshot::Sender<usize>,
) -> std::io::Result<CapturedStderr>
where
    R: AsyncRead + Unpin,
{
    let mut total = 0_usize;
    let mut overflow = Some(overflow);
    let mut buffer = [0_u8; 4_096];
    loop {
        let amount = stderr.read(&mut buffer).await?;
        if amount == 0 {
            break;
        }
        total = total.saturating_add(amount);
        if total > max
            && let Some(sender) = overflow.take()
        {
            let _ = sender.send(total);
        }
    }
    Ok(CapturedStderr {
        total,
        exceeded: total > max,
    })
}

#[cfg(unix)]
async fn finish_stderr(
    task: JoinHandle<std::io::Result<CapturedStderr>>,
) -> Result<SafeStderr, SupervisorError> {
    let captured = task
        .await
        .map_err(|_| SupervisorError::StderrRead)?
        .map_err(|_| SupervisorError::StderrRead)?;
    Ok(SafeStderr {
        discarded_bytes: captured.total,
        truncated: captured.exceeded,
    })
}

#[cfg(unix)]
async fn terminate_process_group(
    child: &mut Child,
    pid: u32,
    wait_for_child: bool,
) -> Result<(), SupervisorError> {
    use rustix::process::{Pid, Signal, kill_process_group};

    let pid = Pid::from_raw(pid.cast_signed()).ok_or(SupervisorError::Termination)?;
    if let Err(error) = kill_process_group(pid, Signal::KILL)
        && error != rustix::io::Errno::SRCH
    {
        return Err(SupervisorError::Termination);
    }
    if wait_for_child {
        child
            .wait()
            .await
            .map_err(|_| SupervisorError::Termination)?;
    }
    Ok(())
}

#[cfg(unix)]
fn terminate_process_group_after_exit(pid: u32) -> Result<(), SupervisorError> {
    use rustix::process::{Pid, Signal, kill_process_group};

    let pid = Pid::from_raw(pid.cast_signed()).ok_or(SupervisorError::Termination)?;
    if let Err(error) = kill_process_group(pid, Signal::KILL)
        && error != rustix::io::Errno::SRCH
    {
        return Err(SupervisorError::Termination);
    }
    Ok(())
}

#[cfg(unix)]
fn exit_error(status: ExitStatus, stderr: SafeStderr) -> SupervisorError {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;

        if let Some(signal) = status.signal() {
            return SupervisorError::Signaled { signal, stderr };
        }
    }
    SupervisorError::Exited {
        code: status.code().unwrap_or(-1),
        stderr,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn stderr_content_is_discarded() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let (mut writer, reader) = tokio::io::duplex(64);
        let unsafe_stderr = b"path /private/x\x1b[31m\xe2\x80\xaesecret\n";
        let expected_bytes = unsafe_stderr.len();
        let task = runtime.spawn(async move {
            use tokio::io::AsyncWriteExt;
            writer.write_all(unsafe_stderr).await.unwrap();
        });
        let (overflow, _) = oneshot::channel();
        let stderr = runtime.block_on(async {
            task.await.unwrap();
            finish_stderr(tokio::spawn(capture_stderr(reader, 64, overflow)))
                .await
                .unwrap()
        });
        assert_eq!(stderr.discarded_bytes, expected_bytes);
        assert!(!stderr.truncated);
    }

    #[cfg(not(unix))]
    #[tokio::test]
    async fn unsupported_platform_fails_before_process_launch() {
        let config = SupervisorConfig::new(
            PathBuf::from("C:\\absolute\\adapter.exe"),
            PathBuf::from("C:\\private"),
            EndpointKind::PythonAdapter,
            Vec::new(),
        );
        let error = AdapterSupervisor::new(config)
            .run(
                ProtocolMessage::hello(
                    "not-a-request",
                    HelloBody::new(EndpointKind::PythonAdapter, "test", Vec::new()),
                ),
                &AdapterCancellation::new(),
            )
            .await
            .unwrap_err();
        assert_eq!(error, SupervisorError::ProcessTreeUnsupported);
    }
}
