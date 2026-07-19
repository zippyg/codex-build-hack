use std::process::Stdio;
use std::time::Duration;

use promptectomy_protocol::{
    BudgetLimits, EndpointKind, HelloBody, MESSAGE_SCHEMA_VERSION, MessageBody, ProtocolLimits,
    ProtocolMessage, ReadyBody, ResultBody, ResultStatus, read_frame, write_frame,
};
use serde_json::{Value, json};
use tokio::io::{AsyncWriteExt, stderr, stdin, stdout};
use tokio::process::Command;

#[tokio::main]
async fn main() {
    if std::env::args_os()
        .nth(1)
        .is_some_and(|value| value == "--descendant")
    {
        tokio::time::sleep(Duration::from_secs(60)).await;
        return;
    }
    if run_adapter().await.is_err() {
        std::process::exit(90);
    }
}

async fn run_adapter() -> Result<(), Box<dyn std::error::Error>> {
    let limits = ProtocolLimits::default();
    let mut input = stdin();
    let mut output = stdout();

    let parent_hello = read_frame(&mut input, &limits).await?;
    if !matches!(parent_hello.body, MessageBody::Hello(_)) {
        return Err("expected hello".into());
    }
    let hello = ProtocolMessage::hello(
        "child_hello",
        HelloBody::new(
            EndpointKind::PythonAdapter,
            "synthetic-python-adapter",
            vec!["synthetic".to_owned()],
        ),
    );
    write_frame(&mut output, &limits, &hello).await?;

    let ready = read_frame(&mut input, &limits).await?;
    let MessageBody::Ready(ReadyBody { negotiated }) = ready.body else {
        return Err("expected ready".into());
    };
    let ready = ProtocolMessage {
        schema_version: MESSAGE_SCHEMA_VERSION.to_owned(),
        message_id: "child_ready".to_owned(),
        request_id: None,
        body: MessageBody::Ready(ReadyBody { negotiated }),
    };
    write_frame(&mut output, &limits, &ready).await?;

    let request = read_frame(&mut input, &limits).await?;
    let request_id = request.request_id.clone().ok_or("missing request id")?;
    let MessageBody::Request(body) = request.body else {
        return Err("expected request".into());
    };
    let mode = request_mode(&body.payload)?;

    match mode {
        "success" => send_result(&mut output, &limits, request_id, json!({"ok": true})).await?,
        "marker" => {
            tokio::fs::write("spawned.marker", b"spawned").await?;
            send_result(&mut output, &limits, request_id, json!({"ok": true})).await?;
        }
        "environment" => {
            let cwd = std::env::current_dir()?.to_string_lossy().into_owned();
            send_result(
                &mut output,
                &limits,
                request_id,
                json!({
                    "cwd": cwd,
                    "user_present": std::env::var_os("USER").is_some(),
                    "home_present": std::env::var_os("HOME").is_some(),
                    "path_present": std::env::var_os("PATH").is_some(),
                    "openai_key_present": std::env::var_os("OPENAI_API_KEY").is_some(),
                }),
            )
            .await?;
        }
        "oversize" => {
            output.write_all(&2_048_u32.to_be_bytes()).await?;
            output.flush().await?;
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
        "malformed" => {
            output.write_all(&1_u32.to_be_bytes()).await?;
            output.write_all(b"{").await?;
            output.flush().await?;
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
        "nonzero" => {
            stderr()
                .write_all(b"host /private/path\x1b[31m\xe2\x80\xaesecret\n")
                .await?;
            stderr().flush().await?;
            std::process::exit(23);
        }
        "signal" => terminate_by_signal(),
        "timeout" => tokio::time::sleep(Duration::from_secs(60)).await,
        "stderr_oversize" => {
            stderr().write_all(&vec![b'x'; 4_096]).await?;
            stderr().flush().await?;
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
        "orphan" => {
            let child = Command::new(std::env::current_exe()?)
                .arg("--descendant")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?;
            tokio::fs::write(
                "descendant.pid",
                child.id().ok_or("missing child pid")?.to_string(),
            )
            .await?;
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
        _ => return Err("unknown mode".into()),
    }
    Ok(())
}

#[cfg(unix)]
fn terminate_by_signal() -> ! {
    use rustix::process::{Signal, getpid, kill_process};

    kill_process(getpid(), Signal::KILL).expect("synthetic signal must terminate the child");
    unreachable!("SIGKILL returned without terminating the child");
}

#[cfg(not(unix))]
fn terminate_by_signal() -> ! {
    std::process::exit(24)
}

fn request_mode(payload: &Value) -> Result<&str, &'static str> {
    payload
        .get("mode")
        .and_then(Value::as_str)
        .ok_or("missing mode")
}

async fn send_result<W>(
    output: &mut W,
    limits: &ProtocolLimits,
    request_id: String,
    payload: Value,
) -> Result<(), Box<dyn std::error::Error>>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let response = ProtocolMessage {
        schema_version: MESSAGE_SCHEMA_VERSION.to_owned(),
        message_id: "child_result".to_owned(),
        request_id: Some(request_id),
        body: MessageBody::Result(ResultBody {
            status: ResultStatus::Completed,
            payload,
            artifact_refs: Vec::new(),
            budgets_used: BudgetLimits::default(),
            diagnostics: Vec::new(),
        }),
    };
    write_frame(output, limits, &response).await?;
    Ok(())
}
