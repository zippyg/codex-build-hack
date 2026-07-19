#[tokio::main]
async fn main() {
    let code = promptectomy_cli::run_from(std::env::args_os()).await;
    std::process::exit(code);
}
