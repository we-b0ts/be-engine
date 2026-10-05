//! Standalone online recording app; runtime policy lives in the library owner.
use anyhow::Result;
use clap::Parser;
use traffic_e2e::online_recording::{OnlineRecordingOptions, run};

#[derive(Parser)]
#[command(name = "recording-online", version = traffic_e2e::BINARY_VERSION)]
struct Cli {
    #[command(flatten)]
    options: OnlineRecordingOptions,
}

fn main() -> Result<()> {
    let mut cli = Cli::parse();
    let key = cli.options.initialize_storage()?;
    // Initialize the encryption environment before logging/runtime starts threads.
    unsafe {
        std::env::set_var("TRAFFIC_E2E_ENCRYPTION_KEY_B64", key);
    }
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    tokio::runtime::Runtime::new()?.block_on(run(cli.options))
}
