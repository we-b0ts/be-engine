use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Subcommand};

mod comparison;
mod project;
mod recorder;
mod replay;

#[derive(Debug, Args)]
pub(super) struct ConfigArgs {
    /// Target repository root containing .traffic-e2e.
    #[arg(long, default_value = ".", global = true)]
    target_root: PathBuf,
    #[command(subcommand)]
    command: ConfigCommand,
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// Create or update .traffic-e2e/recorder.toml.
    Recorder(recorder::RecorderArgs),
    /// Configure dependency replay and response rules inherited by comparison.
    Replay(replay::ReplayArgs),
    /// Configure additional comparison-only response rules.
    Comparison(comparison::ComparisonArgs),
    /// Create .traffic-e2e/project.yaml from repository conventions.
    Project(project::ProjectArgs),
}

pub(super) fn run(args: ConfigArgs) -> Result<()> {
    match args.command {
        ConfigCommand::Recorder(command) => recorder::run(args.target_root, command),
        ConfigCommand::Replay(command) => replay::run(args.target_root, command),
        ConfigCommand::Comparison(command) => comparison::run(args.target_root, command),
        ConfigCommand::Project(command) => project::run(args.target_root, command),
    }
}

pub(super) fn print_json(value: &impl serde::Serialize) -> Result<()> {
    serde_json::to_writer_pretty(std::io::stdout(), value)?;
    println!();
    Ok(())
}
