use std::io::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Result, ensure};
use clap::{Args, Parser, Subcommand};
use traffic_e2e::{
    RewriteRepairCancelOptions, RewriteReplayRetryOptions, StartupSnapshotRecaptureOptions,
    cancel_misrouted_rewrite_repair, recapture_startup_snapshot,
    retry_rewrite_replay_after_out_of_band_run,
};

#[derive(Debug, Parser)]
#[command(
    name = "backend-rewrite-admin",
    author,
    version = traffic_e2e::BINARY_VERSION,
    about = "Perform explicit administrator-owned backend rewrite repairs",
    subcommand_required = true,
    arg_required_else_help = true
)]
struct Cli {
    /// Target repository root.
    #[arg(long, default_value = ".")]
    target_root: PathBuf,
    /// Pretty-print JSON for human inspection.
    #[arg(long, global = true)]
    pretty: bool,
    #[command(subcommand)]
    command: AdminCommand,
}

#[derive(Debug, Subcommand)]
enum AdminCommand {
    /// Repair immutable startup inputs after an explicit project declaration change.
    Startup(StartupArgs),
    /// Repair administrator-confirmed coordinator routing mistakes.
    Repair(RepairArgs),
}

#[derive(Debug, Args)]
struct RepairArgs {
    #[command(subcommand)]
    command: RepairCommand,
}

#[derive(Debug, Subcommand)]
enum RepairCommand {
    /// Return a misrouted source-change repair to target implementation.
    Cancel(RepairCancelArgs),
    /// Re-arm coordinator Replay after a confirmed out-of-band focused run.
    RetryReplay(RepairRetryReplayArgs),
}

#[derive(Debug, Args)]
struct RepairCancelArgs {
    /// Exact coordinator-issued repair identifier.
    repair_id: String,
    /// Human-readable reason for the administrator action.
    #[arg(long)]
    reason: String,
    /// Confirm that this repair was routed by mistake.
    #[arg(long)]
    confirm_misroute: bool,
}

#[derive(Debug, Args)]
struct RepairRetryReplayArgs {
    /// Exact active API selector.
    #[arg(long)]
    api: String,
    /// Failed focused attempt still owned by the coordinator.
    #[arg(long)]
    failed_attempt: u64,
    /// Newer passing focused attempt started outside the coordinator.
    #[arg(long)]
    out_of_band_attempt: u64,
    /// Human-readable reason for the administrator action.
    #[arg(long)]
    reason: String,
    /// Confirm that the newer focused attempt was run outside the coordinator.
    #[arg(long)]
    confirm_out_of_band_run: bool,
}

#[derive(Debug, Args)]
struct StartupArgs {
    #[command(subcommand)]
    command: StartupCommand,
}

#[derive(Debug, Subcommand)]
enum StartupCommand {
    /// Recapture the exact startup declaration currently stored in project.yaml.
    Recapture(StartupRecaptureArgs),
}

#[derive(Debug, Args)]
struct StartupRecaptureArgs {
    /// Confirm replacement of the existing local startup snapshot.
    #[arg(long)]
    confirm_replace: bool,
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _ = writeln!(std::io::stderr(), "Error: {error:?}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        AdminCommand::Startup(args) => match args.command {
            StartupCommand::Recapture(args) => {
                ensure!(
                    args.confirm_replace,
                    "startup recapture requires --confirm-replace"
                );
                let result = recapture_startup_snapshot(StartupSnapshotRecaptureOptions {
                    target_root: cli.target_root,
                })?;
                if cli.pretty {
                    serde_json::to_writer_pretty(std::io::stdout(), &result)?;
                } else {
                    serde_json::to_writer(std::io::stdout(), &result)?;
                }
                println!();
                Ok(())
            }
        },
        AdminCommand::Repair(args) => match args.command {
            RepairCommand::Cancel(args) => {
                let result = cancel_misrouted_rewrite_repair(RewriteRepairCancelOptions {
                    target_root: cli.target_root,
                    repair_id: args.repair_id,
                    reason: args.reason,
                    confirm_misroute: args.confirm_misroute,
                })?;
                if cli.pretty {
                    serde_json::to_writer_pretty(std::io::stdout(), &result)?;
                } else {
                    serde_json::to_writer(std::io::stdout(), &result)?;
                }
                println!();
                Ok(())
            }
            RepairCommand::RetryReplay(args) => {
                let result =
                    retry_rewrite_replay_after_out_of_band_run(RewriteReplayRetryOptions {
                        target_root: cli.target_root,
                        api: args.api,
                        failed_attempt: args.failed_attempt,
                        out_of_band_attempt: args.out_of_band_attempt,
                        reason: args.reason,
                        confirm_out_of_band_run: args.confirm_out_of_band_run,
                    })?;
                if cli.pretty {
                    serde_json::to_writer_pretty(std::io::stdout(), &result)?;
                } else {
                    serde_json::to_writer(std::io::stdout(), &result)?;
                }
                println!();
                Ok(())
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recapture_requires_explicit_confirmation() {
        let cli = Cli::try_parse_from(["backend-rewrite-admin", "startup", "recapture"]).unwrap();

        let error = run(cli).unwrap_err();

        assert!(error.to_string().contains("--confirm-replace"));
    }

    #[test]
    fn repair_cancel_requires_explicit_confirmation() {
        let cli = Cli::try_parse_from([
            "backend-rewrite-admin",
            "repair",
            "cancel",
            "repair-current",
            "--reason",
            "misrouted comparison issue",
        ])
        .unwrap();

        let error = run(cli).unwrap_err();

        assert!(error.to_string().contains("--confirm-misroute"));
    }

    #[test]
    fn replay_retry_requires_explicit_confirmation() {
        let cli = Cli::try_parse_from([
            "backend-rewrite-admin",
            "repair",
            "retry-replay",
            "--api",
            "MOTAN /rpc/example",
            "--failed-attempt",
            "12",
            "--out-of-band-attempt",
            "13",
            "--reason",
            "focused Replay was run outside the coordinator",
        ])
        .unwrap();

        let error = run(cli).unwrap_err();

        assert!(error.to_string().contains("--confirm-out-of-band-run"));
    }
}
