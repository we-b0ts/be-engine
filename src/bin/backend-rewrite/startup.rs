use std::path::PathBuf;

use anyhow::{Result, ensure};
use clap::{Args, Subcommand};
use traffic_e2e::{
    StartupConfig, StartupUpdateOptions, refresh_startup_snapshot, status_startup_snapshot,
    update_startup_snapshot,
};

#[derive(Debug, Args)]
pub(super) struct StartupArgs {
    #[command(subcommand)]
    command: StartupCommand,
}

#[derive(Debug, Subcommand)]
enum StartupCommand {
    /// Replace the complete startup declaration and capture a matching snapshot.
    Update(StartupUpdateArgs),
    /// Recapture the configured startup paths and environment without changing project.yaml.
    Refresh,
    /// Show bounded snapshot metadata without exposing environment values.
    Status,
}

#[derive(Debug, Args)]
struct StartupUpdateArgs {
    /// Acknowledge that the supplied mounts and environment names replace the complete declaration.
    #[arg(long)]
    replace: bool,
    /// Source-compatible absolute file or directory to copy and mount read-only.
    #[arg(long = "mount", value_name = "ABSOLUTE_PATH")]
    mounts: Vec<PathBuf>,
    /// Application-owned environment variable captured from the configured source container.
    #[arg(long = "environment", value_name = "NAME")]
    environment: Vec<String>,
    /// Application-owned environment variable that receives target.port.
    #[arg(long, value_name = "NAME")]
    target_port_env: Option<String>,
    /// Application-owned environment variable that receives the Replay CA path.
    #[arg(long, value_name = "NAME")]
    replay_ca_env: Option<String>,
}

pub(super) fn run(target_root: PathBuf, args: StartupArgs, pretty: bool) -> Result<()> {
    match args.command {
        StartupCommand::Update(args) => {
            ensure!(
                args.replace,
                "startup update requires --replace because it replaces the complete declaration"
            );
            super::print_json(
                &update_startup_snapshot(StartupUpdateOptions {
                    target_root,
                    config: StartupConfig {
                        mounts: args.mounts,
                        environment_from_source: args.environment,
                        port_environment: args.target_port_env,
                        replay_ca_environment: args.replay_ca_env,
                    },
                })?,
                pretty,
            )
        }
        StartupCommand::Refresh => {
            super::print_json(&refresh_startup_snapshot(&target_root)?, pretty)
        }
        StartupCommand::Status => {
            super::print_json(&status_startup_snapshot(&target_root)?, pretty)
        }
    }
}
