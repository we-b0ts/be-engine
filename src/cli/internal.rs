use std::num::NonZeroU64;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use clap::{Args, Subcommand};
use traffic_e2e::{
    ManagedRecordingInputCompletion, ManagedRecordingInputOptions, RecordingApi,
    drive_managed_recording_input, execute_rewrite_recording_worker,
};

use super::{record, record_comparison};

const MANAGED_COMPARISON_FINAL_QUIET_PERIOD: Duration = Duration::from_secs(3);

#[derive(Debug, Args)]
pub(super) struct InternalArgs {
    #[command(subcommand)]
    command: InternalCommand,
}

#[derive(Debug, Subcommand)]
enum InternalCommand {
    /// Run the recorder process inside the managed recorder runtime.
    RecorderRun(record::RecordArgs),
    /// Capture comparison responses inside the managed comparison runtime.
    ComparisonRun(record_comparison::RecordComparisonArgs),
    /// Hold configured background Redis reads at one run-local value.
    CacheSnapshotRun(super::cache_snapshot::CacheSnapshotRunArgs),
    /// Drive coordinator-owned request templates through a managed recording gateway.
    RecordingInput(RecordingInputArgs),
    /// Run one detached rewrite recording action owned by the coordinator.
    #[command(hide = true)]
    RewriteRecordingWorker(RewriteRecordingWorkerArgs),
}

#[derive(Debug, Args)]
struct RecordingInputArgs {
    #[arg(long)]
    case_source: PathBuf,
    /// Restrict input discovery to the corresponding recorded API directories.
    #[arg(long = "api")]
    recording_apis: Vec<RecordingApi>,
    #[arg(long)]
    origin: String,
    #[arg(long)]
    motan_upstream: Option<String>,
    #[arg(long, default_value = "30")]
    request_timeout_seconds: NonZeroU64,
    /// Notify a managed comparison after every finite request template is consumed.
    #[arg(long)]
    completion_control_socket: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct RewriteRecordingWorkerArgs {
    #[arg(long)]
    target_root: PathBuf,
    action_id: String,
}

pub(super) async fn run(args: InternalArgs) -> Result<()> {
    match args.command {
        InternalCommand::RecorderRun(args) => record::run(args).await,
        InternalCommand::ComparisonRun(args) => record_comparison::run(args).await,
        InternalCommand::CacheSnapshotRun(args) => super::cache_snapshot::run(args).await,
        InternalCommand::RecordingInput(args) => {
            let report = drive_managed_recording_input(ManagedRecordingInputOptions {
                case_source: args.case_source,
                recording_apis: args.recording_apis,
                origin: args.origin,
                motan_upstream: args.motan_upstream,
                request_timeout: Duration::from_secs(args.request_timeout_seconds.get()),
                completion: args.completion_control_socket.map(|control_socket| {
                    ManagedRecordingInputCompletion {
                        control_socket,
                        quiet_period: MANAGED_COMPARISON_FINAL_QUIET_PERIOD,
                    }
                }),
            })
            .await?;
            super::output::stdout_line(format_args!("{}", serde_json::to_string_pretty(&report)?))
        }
        InternalCommand::RewriteRecordingWorker(args) => {
            let report =
                execute_rewrite_recording_worker(args.target_root, &args.action_id).await?;
            super::output::stdout_line(format_args!("{}", serde_json::to_string_pretty(&report)?))
        }
    }
}
