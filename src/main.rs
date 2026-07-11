use std::net::SocketAddr;
use std::path::PathBuf;
use std::{env, io};

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;
use traffic_recorder_proxy::{
    AppConfig, AppState, MysqlReplayControlConfig, ReplayConfig, run_mysql_replay_control,
    run_replay,
};

#[derive(Debug, Parser)]
#[command(author, version, about)]
struct Cli {
    #[arg(short, long, default_value = "config/recorder.example.toml")]
    config: PathBuf,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    Replay(ReplayArgs),
    ReplayControl(ReplayControlArgs),
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

    #[arg(long)]
    session: Option<PathBuf>,

    #[arg(long)]
    control_socket: Option<PathBuf>,

    #[arg(long)]
    ca_cert: Option<PathBuf>,

    #[arg(long)]
    ca_key: Option<PathBuf>,

    #[arg(long = "http-ignore-query-param")]
    http_ignore_query_params: Vec<String>,
}

#[derive(Debug, Parser)]
struct ReplayControlArgs {
    #[arg(long, env = "TRP_REPLAY_SESSION")]
    session: Option<PathBuf>,

    #[command(subcommand)]
    command: ReplayControlCommand,
}

#[derive(Debug, Subcommand)]
enum ReplayControlCommand {
    WaitReady,
    Status,
    Cases,
    Begin {
        case_id: String,
    },
    End {
        case_id: String,
        #[arg(long)]
        fail_on_dirty: bool,
    },
    Report {
        #[arg(long)]
        fail_on_dirty: bool,
    },
    Stop,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .init();

    let cli = Cli::parse();
    match cli.command {
        Some(Command::Replay(args)) => {
            return run_replay(ReplayConfig {
                case_dir: args.case,
                dns_listen: args.dns_listen,
                tcp_listen: args.tcp_listen,
                fake_cidr: args.fake_cidr,
                report_path: args.report,
                session_path: args.session,
                control_socket_path: args.control_socket,
                ca_cert_path: args.ca_cert,
                ca_key_path: args.ca_key,
                http_ignore_query_params: args.http_ignore_query_params,
            })
            .await;
        }
        Some(Command::ReplayControl(args)) => {
            let response = run_mysql_replay_control(replay_control_config(args)?).await?;
            serde_json::to_writer_pretty(io::stdout(), &response)?;
            println!();
            return Ok(());
        }
        None => {}
    }

    let config = AppConfig::load(&cli.config)?;
    let state = AppState::new(config).await?;
    state.run().await
}

fn replay_control_config(args: ReplayControlArgs) -> anyhow::Result<MysqlReplayControlConfig> {
    let session_path = args.session.unwrap_or_else(default_replay_session_path);
    let (command, case_id, fail_on_dirty) = match args.command {
        ReplayControlCommand::WaitReady => ("wait_ready".to_string(), None, false),
        ReplayControlCommand::Status => ("status".to_string(), None, false),
        ReplayControlCommand::Cases => ("cases".to_string(), None, false),
        ReplayControlCommand::Begin { case_id } => ("begin".to_string(), Some(case_id), false),
        ReplayControlCommand::End {
            case_id,
            fail_on_dirty,
        } => ("end".to_string(), Some(case_id), fail_on_dirty),
        ReplayControlCommand::Report { fail_on_dirty } => {
            ("report".to_string(), None, fail_on_dirty)
        }
        ReplayControlCommand::Stop => ("stop".to_string(), None, false),
    };
    Ok(MysqlReplayControlConfig {
        session_path,
        command,
        case_id,
        fail_on_dirty,
    })
}

fn default_replay_session_path() -> PathBuf {
    env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".replay")
        .join("session.json")
}
