use promptectomy_daemon::{DaemonConfig, default_config, serve};

#[tokio::main]
async fn main() {
    let config =
        std::env::var_os("PROMPTECTOMY_DAEMON_DIR").map_or_else(default_config, DaemonConfig::new);
    if serve(config).await.is_err() {
        eprintln!("promptectomy-daemon: private local service failed");
        std::process::exit(9);
    }
}
