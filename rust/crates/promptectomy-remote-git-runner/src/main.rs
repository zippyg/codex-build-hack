#![forbid(unsafe_code)]

use std::process::ExitCode;

use promptectomy_remote_git_runner::{execute, write_failure, write_success};

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let exit = match execute().await {
        Ok(result) => match write_success(&result) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            let _ = write_failure(&error);
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    };
    std::future::pending::<()>().await;
    exit
}
