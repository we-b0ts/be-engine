use std::path::PathBuf;

use clap::Parser;
use tracing_subscriber::EnvFilter;
use traffic_recorder_proxy::{AppConfig, AppState};

#[derive(Debug, Parser)]
#[command(author, version, about)]
struct Cli {
    #[arg(short, long, default_value = "config.example.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .init();

    let cli = Cli::parse();
    let config = AppConfig::load(&cli.config)?;
    let state = AppState::new(config).await?;
    state.run().await
}
