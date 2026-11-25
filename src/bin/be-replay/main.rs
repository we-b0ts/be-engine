use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

mod event_session;
mod handoff;
mod project_init;
mod round;
mod startup;

#[derive(Debug, Parser)]
#[command(
    name = "be-replay",
    author,
    version = traffic_e2e::BINARY_VERSION,
    about = "Verify backend rewrites against recorded Source events",
    subcommand_required = true,
    arg_required_else_help = true
)]
struct Cli {
    /// Default log filter when RUST_LOG is not set.
    #[arg(
        long,
        global = true,
        env = "TRAFFIC_E2E_LOG_LEVEL",
        default_value = "info",
        value_name = "FILTER"
    )]
    log_level: String,
    /// Pretty-print JSON for human inspection; compact JSON is the default.
    #[arg(long, global = true)]
    pretty: bool,
    /// Target repository root.
    #[arg(long, default_value = ".")]
    target_root: PathBuf,
    /// Select a sealed Source recording for a run or evidence query.
    #[arg(long, global = true)]
    recording_run_id: Option<String>,
    #[command(subcommand)]
    command: RewriteCommand,
}

#[derive(Debug, Subcommand)]
enum RewriteCommand {
    /// Initialize one target repository for a backend rewrite.
    Init(project_init::ProjectInitArgs),
    /// Inspect or update target startup environment and mount inputs.
    Startup(startup::StartupArgs),
    #[command(flatten)]
    Source(event_session::SourceCommand),
}

#[tokio::main]
async fn main() -> ExitCode {
    traffic_e2e::initialize_application();
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let cli = Cli::parse();
    let log_filter = match log_filter(&cli.log_level) {
        Ok(filter) => filter,
        Err(error) => {
            report_error(&error);
            return ExitCode::FAILURE;
        }
    };
    tracing_subscriber::fmt()
        .with_env_filter(log_filter)
        .with_writer(std::io::stderr)
        .init();
    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            report_error(&error);
            ExitCode::FAILURE
        }
    }
}

fn log_filter(default_filter: &str) -> Result<EnvFilter> {
    if std::env::var_os("RUST_LOG").is_some() {
        Ok(EnvFilter::try_from_default_env()?)
    } else {
        Ok(EnvFilter::try_new(default_filter)?)
    }
}

fn report_error(error: &anyhow::Error) {
    eprintln!("Error: {error:?}");
}

async fn run(cli: Cli) -> Result<()> {
    let Cli {
        target_root,
        recording_run_id,
        command,
        pretty,
        ..
    } = cli;
    match command {
        RewriteCommand::Init(args) => project_init::run(target_root, args, pretty).await,
        RewriteCommand::Startup(args) => startup::run(target_root, args, pretty),
        RewriteCommand::Source(command) => {
            event_session::run(target_root, recording_run_id, command, pretty).await
        }
    }
}

fn write_json(mut writer: impl Write, value: &impl serde::Serialize, pretty: bool) -> Result<()> {
    if pretty {
        serde_json::to_writer_pretty(&mut writer, value)?;
    } else {
        serde_json::to_writer(&mut writer, value)?;
    }
    writeln!(writer)?;
    Ok(())
}

fn print_json(value: &impl serde::Serialize, pretty: bool) -> Result<()> {
    write_json(std::io::stdout(), value, pretty)
}

#[cfg(test)]
mod tests;
