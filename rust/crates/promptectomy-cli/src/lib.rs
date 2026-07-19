use std::ffi::OsString;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum, error::ErrorKind};
use promptectomy_contracts::{SCHEMA_SHA256, SCHEMA_VERSION};
use promptectomy_daemon::{
    ApiEnvelope, ClientResponse, DaemonConfig, DaemonError, EndpointMetadata, PROTOCOL_VERSION,
    SafeError, default_config, open_core_store, read_metadata, request, sanitize_terminal,
    unavailable,
};
use serde::Serialize;
use serde_json::{Value, json};
use thiserror::Error;

pub const CLI_PROTOCOL_VERSION: &str = "phase3-cli-1";
const WATCH_RECONNECT_ATTEMPTS: usize = 6;

#[derive(Debug, Parser)]
#[command(name = "promptectomy")]
#[command(about = "PROMPTECTOMY local control plane")]
pub struct Cli {
    #[arg(long, global = true)]
    pub json: bool,
    #[arg(long, global = true)]
    pub plain: bool,
    #[arg(long = "no-color", global = true)]
    pub no_color: bool,
    #[arg(long, global = true)]
    pub daemon_dir: Option<PathBuf>,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Doctor,
    Status(StatusArgs),
    Watch(WatchArgs),
    Report(ReportArgs),
    Cancel(RunIdArgs),
    Daemon(DaemonArgs),
    Gc(GcArgs),
    MigratePythonV2(MigrationArgs),
    Init(PathArg),
    Inspect(PathArg),
    Audit(PathArg),
    Draft(PathArg),
    Calls(RunIdArgs),
    Finding(IdArg),
    Candidate(IdArg),
    Diff(IdArg),
    Apply(ApplyArgs),
    Resume(RunIdArgs),
    Export(RunIdArgs),
    Delete(IdArg),
    Tui(OptionRunIdArgs),
}

#[derive(Debug, Args)]
pub struct StatusArgs {
    pub run_id: Option<String>,
}

#[derive(Debug, Args)]
pub struct WatchArgs {
    pub run_id: String,
    #[arg(long, default_value_t = 0)]
    pub cursor: u64,
    #[arg(long)]
    pub once: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum ReportFormat {
    Json,
    Md,
    Html,
    Ndjson,
    Sarif,
    Junit,
}

#[derive(Debug, Args)]
pub struct ReportArgs {
    pub run_id: String,
    #[arg(long, value_enum, default_value_t = ReportFormat::Json)]
    pub format: ReportFormat,
}

#[derive(Debug, Args)]
pub struct RunIdArgs {
    pub run_id: String,
}

#[derive(Debug, Args)]
pub struct OptionRunIdArgs {
    pub run_id: Option<String>,
}

#[derive(Debug, Args)]
pub struct IdArg {
    pub id: String,
}

#[derive(Debug, Args)]
pub struct PathArg {
    pub path: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct ApplyArgs {
    pub candidate_id: String,
    #[arg(long)]
    pub branch: String,
}

#[derive(Debug, Args)]
pub struct DaemonArgs {
    #[arg(long)]
    pub endpoint_json: bool,
}

#[derive(Debug, Args)]
pub struct GcArgs {
    #[arg(long, default_value_t = true)]
    pub dry_run: bool,
}

#[derive(Debug, Args)]
pub struct MigrationArgs {
    pub database: PathBuf,
}

#[derive(Debug, Error)]
pub enum CliError {
    #[error("input is invalid")]
    InvalidInput,
    #[error("daemon is unavailable")]
    DaemonUnavailable,
    #[error("request failed")]
    Request,
    #[error("output failed")]
    Output,
    #[error("trusted core rejected the request")]
    Core(SafeError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExitClass {
    Success = 0,
    InputContract = 2,
    UnsupportedEvidence = 3,
    PolicyAuthority = 4,
    AcquisitionAdapterToolchain = 5,
    AgentBudget = 6,
    ExecutorCandidateEvaluator = 7,
    CancelledInterrupted = 8,
    StateStorageIntegrityInternal = 9,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct CliEnvelope<'a> {
    schema_version: &'a str,
    cli_protocol_version: &'a str,
    daemon_protocol_version: &'a str,
    command: &'a str,
    status: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<SafeError>,
}

pub async fn run_from<I, T>(arguments: I) -> i32
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let arguments: Vec<OsString> = arguments.into_iter().map(Into::into).collect();
    match Cli::try_parse_from(&arguments) {
        Ok(cli) => run(cli).await as i32,
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) =>
        {
            let text = sanitize_terminal(&error.to_string());
            if write!(io::stdout().lock(), "{text}").is_ok() {
                ExitClass::Success as i32
            } else {
                ExitClass::StateStorageIntegrityInternal as i32
            }
        }
        Err(_) => emit_parse_error(
            arguments
                .iter()
                .any(|argument| argument.to_string_lossy() == "--json"),
        ) as i32,
    }
}

fn emit_parse_error(json_output: bool) -> ExitClass {
    let envelope = CliEnvelope {
        schema_version: SCHEMA_VERSION,
        cli_protocol_version: CLI_PROTOCOL_VERSION,
        daemon_protocol_version: PROTOCOL_VERSION,
        command: "cli",
        status: "error",
        data: None,
        error: Some(safe_error(
            "invalid_arguments",
            "input",
            false,
            "The command arguments are invalid.",
            "Run `promptectomy --help` and provide all required noninteractive arguments.",
        )),
    };
    let text = if json_output {
        serde_json::to_string(&envelope)
    } else {
        Ok(human(&envelope))
    };
    match text {
        Ok(text) if writeln!(io::stdout().lock(), "{text}").is_ok() => ExitClass::InputContract,
        _ => ExitClass::StateStorageIntegrityInternal,
    }
}

#[allow(clippy::too_many_lines)]
pub async fn run(cli: Cli) -> ExitClass {
    let config = cli
        .daemon_dir
        .clone()
        .map_or_else(default_config, DaemonConfig::new);
    let result = match &cli.command {
        Command::Doctor => doctor(&config).await,
        Command::Status(args) => status(&config, args).await,
        Command::Watch(args) => watch(&config, args).await,
        Command::Report(args) => report(&config, args).await,
        Command::Cancel(args) => {
            let run_id = match validate_typed_id(&args.run_id, "run") {
                Ok(run_id) => run_id,
                Err(error) => return emit_error(&cli, error),
            };
            post_empty(&config, "cancel", &format!("/v2/runs/{run_id}/cancel")).await
        }
        Command::Daemon(args) => daemon(&config, args).await,
        Command::Gc(args) => gc(&config, args).await,
        Command::MigratePythonV2(args) => migrate_python_v2(&config, args),
        Command::Init(_) => Ok(local_unavailable(
            "init",
            "Rust repository initialization is not implemented in Phase 3.",
        )),
        Command::Inspect(_) => Ok(local_unavailable(
            "inspect",
            "Use the accepted Python oracle until Rust inspection lands.",
        )),
        Command::Audit(_) => Ok(local_unavailable(
            "audit",
            "Use the accepted Python oracle until Rust audit lands.",
        )),
        Command::Draft(_) => Ok(local_unavailable(
            "draft",
            "Draft requires later agent/executor integration.",
        )),
        Command::Calls(_) => Ok(local_unavailable(
            "calls",
            "Callsite views require later Rust state projections.",
        )),
        Command::Finding(_) => Ok(local_unavailable(
            "finding",
            "Finding views require later Rust state projections.",
        )),
        Command::Candidate(_) => Ok(local_unavailable(
            "candidate",
            "Candidate views require later Rust state projections.",
        )),
        Command::Diff(_) => Ok(local_unavailable(
            "diff",
            "Candidate diffs require later artifact projection.",
        )),
        Command::Apply(args) => match (
            validate_typed_id(&args.candidate_id, "candidate"),
            validate_branch(&args.branch),
        ) {
            (Ok(_), Ok(())) => Ok(local_unavailable(
                "apply",
                "Apply is a separate later authority flow.",
            )),
            _ => Err(CliError::InvalidInput),
        },
        Command::Resume(_) => Ok(local_unavailable(
            "resume",
            "Resume requires later orchestration leases.",
        )),
        Command::Export(_) => Ok(local_unavailable(
            "export",
            "Export requires later frozen artifact support.",
        )),
        Command::Delete(_) => Ok(local_unavailable(
            "delete",
            "Deletion requires later retention policy support.",
        )),
        Command::Tui(_) => Ok(local_unavailable(
            "tui",
            "The Ratatui interface is Phase 6.",
        )),
    };
    match result {
        Ok(output) => emit(&cli, &output),
        Err(error) => emit_error(&cli, error),
    }
}

async fn doctor(config: &DaemonConfig) -> Result<CliEnvelope<'static>, CliError> {
    let metadata_present = std::fs::symlink_metadata(config.metadata_path()).is_ok();
    let metadata_result = read_metadata(config);
    let metadata_invalid = metadata_present && metadata_result.is_err();
    let metadata = metadata_result.ok();
    let daemon = match metadata.as_ref() {
        Some(metadata) => request(metadata, "GET", "/v2/health", None).await.ok(),
        None => None,
    };
    Ok(CliEnvelope {
        schema_version: SCHEMA_VERSION,
        cli_protocol_version: CLI_PROTOCOL_VERSION,
        daemon_protocol_version: PROTOCOL_VERSION,
        command: "doctor",
        status: "ok",
        data: Some(json!({
            "contracts": {
                "schema_version": SCHEMA_VERSION,
                "schema_sha256": SCHEMA_SHA256
            },
            "local_api": {
                "metadata_present": metadata_present,
                "metadata_valid": metadata.is_some(),
                "metadata_error": metadata_invalid.then_some("endpoint_metadata_invalid"),
                "daemon_reachable": daemon.as_ref().is_some_and(|response| response.status == 200),
                "transport": metadata.as_ref().map_or("unavailable", |value| value.transport.as_str()),
                "private": metadata.as_ref().is_some_and(|value| value.private),
                "loopback_tcp_default": false,
            },
            "unsupported": {
                "windows_named_pipe": cfg!(windows),
                "agent_connector": true,
                "apply": true,
                "tui": true
            }
        })),
        error: None,
    })
}

async fn status(
    config: &DaemonConfig,
    args: &StatusArgs,
) -> Result<CliEnvelope<'static>, CliError> {
    let path = args.run_id.as_ref().map_or_else(
        || Ok("/v2/status".to_owned()),
        |run_id| validate_typed_id(run_id, "run").map(|value| format!("/v2/runs/{value}")),
    )?;
    Ok(wrap_response("status", get(config, &path).await?))
}

async fn watch(config: &DaemonConfig, args: &WatchArgs) -> Result<CliEnvelope<'static>, CliError> {
    let run_id = validate_typed_id(&args.run_id, "run")?;
    let mut cursor = args.cursor;
    loop {
        let path = format!("/v2/runs/{run_id}/events?cursor={cursor}&limit=100");
        let output = wrap_response("watch", get_with_reconnect(config, &path).await?);
        if output.status == "error" || args.once {
            return Ok(output);
        }
        let projection = get_with_reconnect(config, &format!("/v2/runs/{run_id}")).await?;
        if projection
            .envelope
            .data
            .as_ref()
            .and_then(|data| data.get("status"))
            .and_then(Value::as_str)
            .is_some_and(is_terminal_status)
        {
            return Ok(output);
        }
        cursor = output
            .data
            .as_ref()
            .and_then(|data| data.get("next_cursor"))
            .and_then(Value::as_u64)
            .unwrap_or(cursor);
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

async fn report(
    config: &DaemonConfig,
    args: &ReportArgs,
) -> Result<CliEnvelope<'static>, CliError> {
    let format = match args.format {
        ReportFormat::Json => "json",
        ReportFormat::Md => "md",
        ReportFormat::Html | ReportFormat::Ndjson | ReportFormat::Sarif | ReportFormat::Junit => {
            return Ok(local_unavailable(
                "report",
                "Only JSON and Markdown reports are wired in Phase 3.",
            ));
        }
    };
    let run_id = validate_typed_id(&args.run_id, "run")?;
    post_empty(
        config,
        "report",
        &format!("/v2/runs/{run_id}/report?format={format}"),
    )
    .await
}

async fn daemon(
    config: &DaemonConfig,
    args: &DaemonArgs,
) -> Result<CliEnvelope<'static>, CliError> {
    if args.endpoint_json {
        let metadata = read_metadata(config).map_err(|_| CliError::DaemonUnavailable)?;
        return Ok(CliEnvelope {
            schema_version: SCHEMA_VERSION,
            cli_protocol_version: CLI_PROTOCOL_VERSION,
            daemon_protocol_version: PROTOCOL_VERSION,
            command: "daemon",
            status: "ok",
            data: Some(json!(redact_metadata(&metadata))),
            error: None,
        });
    }
    promptectomy_daemon::serve(config.clone())
        .await
        .map_err(|_| CliError::DaemonUnavailable)?;
    Ok(success("daemon", json!({"stopped": true})))
}

async fn gc(config: &DaemonConfig, args: &GcArgs) -> Result<CliEnvelope<'static>, CliError> {
    if !args.dry_run {
        return Ok(local_unavailable(
            "gc",
            "Non-dry-run GC requires later retention policy support.",
        ));
    }
    post_empty(config, "gc", "/v2/gc").await
}

fn migrate_python_v2(
    config: &DaemonConfig,
    args: &MigrationArgs,
) -> Result<CliEnvelope<'static>, CliError> {
    let mut store = open_core_store(config).map_err(map_daemon_state_error)?;
    let imported_runs = store
        .import_python_v2(&args.database)
        .map_err(|error| CliError::Core(core_safe_error(error.safe_error())))?;
    Ok(success(
        "migrate-python-v2",
        json!({"imported_runs": imported_runs}),
    ))
}

fn map_daemon_state_error(error: DaemonError) -> CliError {
    match error {
        DaemonError::Core(error) => CliError::Core(core_safe_error(error.safe_error())),
        _ => CliError::Core(safe_error(
            "state_unavailable",
            "state",
            true,
            "Private state is unavailable.",
            "Stop the active daemon or repair the owner-only state directory before retrying.",
        )),
    }
}

fn core_safe_error(error: promptectomy_core::SafeError) -> SafeError {
    SafeError {
        code: error.code,
        category: error.category,
        retryable: error.retryable,
        safe_message: sanitize_terminal(&error.safe_message),
        next_action: sanitize_terminal(&error.next_action),
    }
}

async fn get(config: &DaemonConfig, path: &str) -> Result<ClientResponse, CliError> {
    let metadata = read_metadata(config).map_err(|_| CliError::DaemonUnavailable)?;
    request(&metadata, "GET", path, None)
        .await
        .map_err(|_| CliError::Request)
}

async fn get_with_reconnect(config: &DaemonConfig, path: &str) -> Result<ClientResponse, CliError> {
    let mut delay = Duration::from_millis(50);
    for attempt in 0..WATCH_RECONNECT_ATTEMPTS {
        match get(config, path).await {
            Ok(response) => return Ok(response),
            Err(CliError::DaemonUnavailable | CliError::Request)
                if attempt + 1 < WATCH_RECONNECT_ATTEMPTS =>
            {
                tokio::time::sleep(delay).await;
                delay = delay.saturating_mul(2).min(Duration::from_millis(800));
            }
            Err(_) => return Err(CliError::DaemonUnavailable),
        }
    }
    Err(CliError::DaemonUnavailable)
}

async fn post_empty(
    config: &DaemonConfig,
    command: &'static str,
    path: &str,
) -> Result<CliEnvelope<'static>, CliError> {
    Ok(wrap_response(command, {
        let metadata = read_metadata(config).map_err(|_| CliError::DaemonUnavailable)?;
        request(&metadata, "POST", path, None)
            .await
            .map_err(|_| CliError::Request)?
    }))
}

fn wrap_response(command: &'static str, response: ClientResponse) -> CliEnvelope<'static> {
    let ApiEnvelope {
        status,
        data,
        error,
        ..
    } = response.envelope;
    CliEnvelope {
        schema_version: SCHEMA_VERSION,
        cli_protocol_version: CLI_PROTOCOL_VERSION,
        daemon_protocol_version: PROTOCOL_VERSION,
        command,
        status: if status == "ok" { "ok" } else { "error" },
        data,
        error,
    }
}

fn success(command: &'static str, data: Value) -> CliEnvelope<'static> {
    CliEnvelope {
        schema_version: SCHEMA_VERSION,
        cli_protocol_version: CLI_PROTOCOL_VERSION,
        daemon_protocol_version: PROTOCOL_VERSION,
        command,
        status: "ok",
        data: Some(data),
        error: None,
    }
}

fn local_unavailable(command: &'static str, next_action: &str) -> CliEnvelope<'static> {
    let envelope = unavailable(&format!("{command}_unavailable"), next_action);
    CliEnvelope {
        schema_version: SCHEMA_VERSION,
        cli_protocol_version: CLI_PROTOCOL_VERSION,
        daemon_protocol_version: PROTOCOL_VERSION,
        command,
        status: "error",
        data: None,
        error: envelope.error,
    }
}

fn emit(cli: &Cli, output: &CliEnvelope<'_>) -> ExitClass {
    let printed = if cli.json {
        serde_json::to_string(output).map_err(|_| CliError::Output)
    } else {
        Ok(human(output))
    };
    match printed {
        Ok(text) => {
            if writeln!(io::stdout().lock(), "{text}").is_ok() {
                exit_for(output.error.as_ref())
            } else {
                ExitClass::StateStorageIntegrityInternal
            }
        }
        Err(_) => ExitClass::StateStorageIntegrityInternal,
    }
}

fn human(output: &CliEnvelope<'_>) -> String {
    if let Some(error) = &output.error {
        return sanitize_terminal(&format!(
            "{}: {}\nnext: {}",
            error.code, error.safe_message, error.next_action
        ));
    }
    if output.command == "report"
        && let Some(content) = output
            .data
            .as_ref()
            .and_then(|data| data.get("content"))
            .and_then(Value::as_str)
    {
        return sanitize_terminal(content);
    }
    let data = output
        .data
        .as_ref()
        .map_or_else(|| "{}".to_owned(), Value::to_string);
    sanitize_terminal(&format!("{}: {}", output.command, data))
}

fn exit_for(error: Option<&SafeError>) -> ExitClass {
    match error.map(|error| error.category.as_str()) {
        None => ExitClass::Success,
        Some("input" | "contract") => ExitClass::InputContract,
        Some("unsupported" | "evidence") => ExitClass::UnsupportedEvidence,
        Some("policy" | "authority") => ExitClass::PolicyAuthority,
        Some("acquisition" | "adapter" | "toolchain") => ExitClass::AcquisitionAdapterToolchain,
        Some("agent" | "budget") => ExitClass::AgentBudget,
        Some("executor" | "candidate" | "evaluator") => ExitClass::ExecutorCandidateEvaluator,
        Some("cancel" | "cancelled" | "interrupted") => ExitClass::CancelledInterrupted,
        Some(_) => ExitClass::StateStorageIntegrityInternal,
    }
}

fn safe_error(
    code: &str,
    category: &str,
    retryable: bool,
    safe_message: &str,
    next_action: &str,
) -> SafeError {
    SafeError {
        code: code.to_owned(),
        category: category.to_owned(),
        retryable,
        safe_message: sanitize_terminal(safe_message),
        next_action: sanitize_terminal(next_action),
    }
}

fn redact_metadata(metadata: &EndpointMetadata) -> Value {
    json!({
        "schema_version": metadata.schema_version,
        "protocol_version": metadata.protocol_version,
        "transport": metadata.transport,
        "private": metadata.private,
        "token_present": !metadata.token.is_empty()
    })
}

fn validate_typed_id<'a>(value: &'a str, prefix: &str) -> Result<&'a str, CliError> {
    let uuid = value
        .strip_prefix(prefix)
        .and_then(|suffix| suffix.strip_prefix('_'))
        .ok_or(CliError::InvalidInput)?;
    let bytes = uuid.as_bytes();
    let valid = bytes.len() == 36
        && [8, 13, 18, 23].iter().all(|index| bytes[*index] == b'-')
        && bytes.iter().enumerate().all(|(index, byte)| {
            [8, 13, 18, 23].contains(&index)
                || byte.is_ascii_digit()
                || (b'a'..=b'f').contains(byte)
        })
        && bytes[14] == b'7'
        && matches!(bytes[19], b'8' | b'9' | b'a' | b'b');
    valid.then_some(value).ok_or(CliError::InvalidInput)
}

fn validate_branch(value: &str) -> Result<(), CliError> {
    (!value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control))
        .then_some(())
        .ok_or(CliError::InvalidInput)
}

fn is_terminal_status(value: &str) -> bool {
    matches!(
        value,
        "completed"
            | "completed_no_findings"
            | "completed_with_unsupported"
            | "failed"
            | "cancelled"
            | "interrupted"
    )
}

fn emit_error(cli: &Cli, error: CliError) -> ExitClass {
    let safe = match error {
        CliError::InvalidInput => safe_error(
            "invalid_identifier",
            "input",
            false,
            "The identifier or branch does not match the required command contract.",
            "Use the documented typed v7 identifier and an explicit non-empty branch where required.",
        ),
        CliError::DaemonUnavailable => safe_error(
            "daemon_unavailable",
            "state",
            true,
            "The Rust daemon endpoint is unavailable.",
            "Run `promptectomy daemon` in another process.",
        ),
        CliError::Request => safe_error(
            "daemon_request_failed",
            "state",
            true,
            "The Rust daemon request failed.",
            "Check daemon lifecycle and endpoint metadata.",
        ),
        CliError::Output => safe_error(
            "output_failed",
            "internal",
            false,
            "The CLI could not write output.",
            "Retry in a valid terminal or file descriptor.",
        ),
        CliError::Core(error) => error,
    };
    emit(
        cli,
        &CliEnvelope {
            schema_version: SCHEMA_VERSION,
            cli_protocol_version: CLI_PROTOCOL_VERSION,
            daemon_protocol_version: PROTOCOL_VERSION,
            command: command_name(&cli.command),
            status: "error",
            data: None,
            error: Some(safe),
        },
    )
}

fn command_name(command: &Command) -> &'static str {
    match command {
        Command::Doctor => "doctor",
        Command::Status(_) => "status",
        Command::Watch(_) => "watch",
        Command::Report(_) => "report",
        Command::Cancel(_) => "cancel",
        Command::Daemon(_) => "daemon",
        Command::Gc(_) => "gc",
        Command::MigratePythonV2(_) => "migrate-python-v2",
        Command::Init(_) => "init",
        Command::Inspect(_) => "inspect",
        Command::Audit(_) => "audit",
        Command::Draft(_) => "draft",
        Command::Calls(_) => "calls",
        Command::Finding(_) => "finding",
        Command::Candidate(_) => "candidate",
        Command::Diff(_) => "diff",
        Command::Apply(_) => "apply",
        Command::Resume(_) => "resume",
        Command::Export(_) => "export",
        Command::Delete(_) => "delete",
        Command::Tui(_) => "tui",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn doctor_json_does_not_require_daemon() {
        let root = tempfile::tempdir().unwrap();
        let config = DaemonConfig::new(root.path());
        let envelope = doctor(&config).await.unwrap();
        assert_eq!(envelope.status, "ok");
        let data = envelope.data.unwrap();
        assert_eq!(data["local_api"]["daemon_reachable"], false);
        assert_eq!(data["local_api"]["loopback_tcp_default"], false);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn doctor_reports_invalid_metadata_without_exposing_endpoint_details() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().unwrap();
        let config = DaemonConfig::new(root.path());
        fs::write(config.metadata_path(), b"{}").unwrap();
        fs::set_permissions(config.metadata_path(), fs::Permissions::from_mode(0o600)).unwrap();
        let envelope = doctor(&config).await.unwrap();
        let local_api = &envelope.data.unwrap()["local_api"];
        assert_eq!(local_api["metadata_present"], true);
        assert_eq!(local_api["metadata_valid"], false);
        assert_eq!(local_api["metadata_error"], "endpoint_metadata_invalid");

        let redacted = redact_metadata(&EndpointMetadata {
            schema_version: SCHEMA_VERSION.to_owned(),
            protocol_version: PROTOCOL_VERSION.to_owned(),
            transport: "unix-domain-socket".to_owned(),
            private: true,
            socket_path: "/private/secret/path".to_owned(),
            token: "secret".to_owned(),
            host: "promptectomy.local".to_owned(),
            allowed_origins: vec!["http://localhost".to_owned()],
        });
        assert!(redacted.get("socket_path").is_none());
        assert!(redacted.get("host").is_none());
        assert!(redacted.get("token").is_none());
    }

    #[test]
    fn plain_and_no_color_flags_are_noninteractive_and_accepted() {
        let cli = Cli::try_parse_from(["promptectomy", "--plain", "--no-color", "doctor"]).unwrap();
        assert!(cli.plain);
        assert!(cli.no_color);
    }

    #[test]
    fn json_envelope_and_markdown_output_are_stable_and_sanitized() {
        let envelope = success("status", json!({"run_count": 1}));
        assert_eq!(
            serde_json::to_string(&envelope).unwrap(),
            format!(
                "{{\"schema_version\":\"{SCHEMA_VERSION}\",\"cli_protocol_version\":\"{CLI_PROTOCOL_VERSION}\",\"daemon_protocol_version\":\"{PROTOCOL_VERSION}\",\"command\":\"status\",\"status\":\"ok\",\"data\":{{\"run_count\":1}}}}"
            )
        );
        let markdown = CliEnvelope {
            schema_version: SCHEMA_VERSION,
            cli_protocol_version: CLI_PROTOCOL_VERSION,
            daemon_protocol_version: PROTOCOL_VERSION,
            command: "report",
            status: "ok",
            data: Some(json!({"content": "# Safe\n\u{1b}[31mred\u{1b}[0m\u{202e}"})),
            error: None,
        };
        assert_eq!(human(&markdown), "# Safe\nred");
    }

    #[tokio::test]
    async fn later_phase_commands_are_typed_unavailable() {
        let code = run_from(["promptectomy", "--json", "draft", "."]).await;
        assert_eq!(code, ExitClass::UnsupportedEvidence as i32);
        let candidate = "candidate_019f0000-0000-7000-8000-000000000001";
        let missing_branch = run_from(["promptectomy", "--json", "apply", candidate]).await;
        assert_eq!(missing_branch, ExitClass::InputContract as i32);
        let explicit_branch = run_from([
            "promptectomy",
            "--json",
            "apply",
            candidate,
            "--branch",
            "repair/test",
        ])
        .await;
        assert_eq!(explicit_branch, ExitClass::UnsupportedEvidence as i32);
    }

    #[test]
    fn exit_classes_match_contract_v2() {
        let cases = [
            ("input", ExitClass::InputContract),
            ("contract", ExitClass::InputContract),
            ("unsupported", ExitClass::UnsupportedEvidence),
            ("evidence", ExitClass::UnsupportedEvidence),
            ("policy", ExitClass::PolicyAuthority),
            ("authority", ExitClass::PolicyAuthority),
            ("acquisition", ExitClass::AcquisitionAdapterToolchain),
            ("adapter", ExitClass::AcquisitionAdapterToolchain),
            ("toolchain", ExitClass::AcquisitionAdapterToolchain),
            ("agent", ExitClass::AgentBudget),
            ("budget", ExitClass::AgentBudget),
            ("executor", ExitClass::ExecutorCandidateEvaluator),
            ("candidate", ExitClass::ExecutorCandidateEvaluator),
            ("evaluator", ExitClass::ExecutorCandidateEvaluator),
            ("cancelled", ExitClass::CancelledInterrupted),
            ("interrupted", ExitClass::CancelledInterrupted),
            ("state", ExitClass::StateStorageIntegrityInternal),
            ("storage", ExitClass::StateStorageIntegrityInternal),
            ("integrity", ExitClass::StateStorageIntegrityInternal),
            ("internal", ExitClass::StateStorageIntegrityInternal),
        ];
        assert_eq!(exit_for(None), ExitClass::Success);
        for (category, expected) in cases {
            let error = safe_error("test", category, false, "safe", "next");
            assert_eq!(exit_for(Some(&error)), expected, "category {category}");
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn cli_reconnects_after_daemon_restart_and_reads_durable_state() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        use promptectomy_core::{BudgetLedger, CleanupState, CoreStore};

        let root = tempfile::tempdir().unwrap();
        let config = DaemonConfig::new(root.path());
        fs::create_dir(config.state_path()).unwrap();
        fs::set_permissions(config.state_path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut store = CoreStore::open(&config.state_path()).unwrap();
        let run = store
            .create_run(&test_authority(), BudgetLedger::default())
            .unwrap();
        let run = store
            .mark_cleanup(&run.run_id, CleanupState::Completed)
            .unwrap();
        drop(store);

        let first = tokio::spawn(promptectomy_daemon::serve(config.clone()));
        let first_metadata = wait_for_daemon(&config).await;
        let source = root.path().join("python-v2.sqlite");
        fs::write(&source, b"source-must-not-change").unwrap();
        let migration_error = migrate_python_v2(
            &config,
            &MigrationArgs {
                database: source.clone(),
            },
        )
        .unwrap_err();
        match migration_error {
            CliError::Core(error) => assert_eq!(error.code, "writer_conflict"),
            other => panic!("unexpected migration error: {other}"),
        }
        assert_eq!(fs::read(&source).unwrap(), b"source-must-not-change");
        let listed = status(
            &config,
            &StatusArgs {
                run_id: Some(run.run_id.clone()),
            },
        )
        .await
        .unwrap();
        assert_eq!(listed.data.unwrap()["run_id"], run.run_id);
        for format in [ReportFormat::Json, ReportFormat::Md] {
            let report = report(
                &config,
                &ReportArgs {
                    run_id: run.run_id.clone(),
                    format,
                },
            )
            .await
            .unwrap();
            assert!(
                report.data.unwrap()["content"]
                    .as_str()
                    .unwrap()
                    .contains(&run.run_id)
            );
        }
        let gap = watch(
            &config,
            &WatchArgs {
                run_id: run.run_id.clone(),
                cursor: u64::MAX,
                once: true,
            },
        )
        .await
        .unwrap();
        assert_eq!(gap.error.as_ref().unwrap().code, "event_cursor_expired");
        assert_eq!(
            exit_for(gap.error.as_ref()),
            ExitClass::StateStorageIntegrityInternal
        );
        let watcher_config = config.clone();
        let watcher_run_id = run.run_id.clone();
        let watcher = tokio::spawn(async move {
            watch(
                &watcher_config,
                &WatchArgs {
                    run_id: watcher_run_id,
                    cursor: run.last_sequence,
                    once: false,
                },
            )
            .await
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        first.abort();
        let _ = first.await;
        tokio::time::sleep(Duration::from_millis(600)).await;
        let second = tokio::spawn(promptectomy_daemon::serve(config.clone()));
        let second_metadata = wait_for_daemon(&config).await;
        assert_ne!(first_metadata.token, second_metadata.token);
        let cancelled = post_empty(
            &config,
            "cancel",
            &format!("/v2/runs/{}/cancel", run.run_id),
        )
        .await
        .unwrap();
        assert_eq!(cancelled.data.unwrap()["status"], "cancelling");
        second.abort();
        let _ = second.await;
        let mut store = CoreStore::open(&config.state_path()).unwrap();
        let confirmed = store.confirm_cancelled(&run.run_id, true).unwrap();
        drop(store);
        let third = tokio::spawn(promptectomy_daemon::serve(config.clone()));
        let third_metadata = wait_for_daemon(&config).await;
        assert_ne!(second_metadata.token, third_metadata.token);
        let watch_output = tokio::time::timeout(Duration::from_secs(4), watcher)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(
            watch_output.data.unwrap()["next_cursor"],
            confirmed.last_sequence
        );
        let persisted = status(
            &config,
            &StatusArgs {
                run_id: Some(run.run_id),
            },
        )
        .await
        .unwrap();
        assert_eq!(persisted.data.unwrap()["status"], "cancelled");
        third.abort();
        let _ = third.await;
        let source_before = fs::read(&source).unwrap();
        let migration_error = migrate_python_v2(
            &config,
            &MigrationArgs {
                database: source.clone(),
            },
        )
        .unwrap_err();
        match migration_error {
            CliError::Core(error) => assert_eq!(error.code, "import_invalid"),
            other => panic!("unexpected migration error: {other}"),
        }
        assert_eq!(fs::read(source).unwrap(), source_before);
    }

    #[cfg(unix)]
    async fn wait_for_daemon(config: &DaemonConfig) -> EndpointMetadata {
        for _ in 0..400 {
            if let Ok(metadata) = read_metadata(config)
                && request(&metadata, "GET", "/v2/health", None)
                    .await
                    .is_ok_and(|response| response.status == 200)
            {
                return metadata;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("daemon did not become reachable");
    }

    #[cfg(unix)]
    fn test_authority() -> promptectomy_core::AuthorityManifest {
        use uuid::Uuid;

        let manifest = json!({
            "reads": ["selected_source_bytes"],
            "writes": ["tool_owned_state"],
            "commands": [],
            "executor": null,
            "network_destinations": [],
            "environment_names": [],
            "model": null,
            "budget": {
                "wall_ms": 1_000,
                "input_tokens": 100,
                "output_tokens": 100,
                "bytes": 1_000,
                "attempts": 5,
            },
            "egress_classes": [],
            "retention": {},
            "cancellation": "supervisor_verified",
            "cleanup": "tool_owned_state_only",
        });
        let digest = promptectomy_contracts::artifact_id(
            &promptectomy_contracts::canonical_json(&manifest).unwrap(),
        );
        let value = json!({
            "schema_uri": format!("{}authority.schema.json", promptectomy_contracts::SCHEMA_BASE),
            "schema_version": SCHEMA_VERSION,
            "authority_id": format!("auth_{}", Uuid::now_v7()),
            "subject_id": format!("action_snap_sha256_{}", "b".repeat(64)),
            "mode": "inspect",
            "manifest": manifest,
            "manifest_digest": digest,
            "approved_at": "2026-07-19T00:00:00.000000Z",
            "expires_at": "2027-07-19T00:00:00.000000Z",
            "approval_origin": "interactive_local",
            "revoked": false,
        });
        promptectomy_core::AuthorityManifest::from_contract_json(
            &format!("snap_sha256_{}", "b".repeat(64)),
            &serde_json::to_vec(&value).unwrap(),
        )
        .unwrap()
    }
}
