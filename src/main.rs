use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;
use traffic_recorder_proxy::{AppConfig, AppState, MysqlReplayConfig, run_mysql_replay};

#[derive(Debug, Parser)]
#[command(author, version, about)]
struct Cli {
    #[arg(short, long, default_value = "recorder.example.toml")]
    config: PathBuf,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    Replay(ReplayArgs),
}

#[derive(Debug, Parser)]
struct ReplayArgs {
    #[arg(long)]
    case: PathBuf,

    #[arg(long, default_value = "127.0.0.153:15353")]
    dns_listen: SocketAddr,

    #[arg(long, default_value = "127.0.0.1:15001")]
    tcp_listen: SocketAddr,

    #[arg(long, default_value = "198.18.0.0/15")]
    fake_cidr: String,

    #[arg(long)]
    report: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .init();

    let cli = Cli::parse();
    if let Some(Command::Replay(args)) = cli.command {
        return run_mysql_replay(MysqlReplayConfig {
            case_dir: args.case,
            dns_listen: args.dns_listen,
            tcp_listen: args.tcp_listen,
            fake_cidr: args.fake_cidr,
            report_path: args.report,
        })
        .await;
    }

    let config = AppConfig::load(&cli.config)?;
    let state = AppState::new(config).await?;
    state.run().await
}
