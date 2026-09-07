use std::num::NonZeroU64;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use clap::{Args, Subcommand, ValueEnum};
use traffic_e2e::{
    ManagedRecordingInputCompletion, ManagedRecordingInputOptions, ProcessOutputCaptureSide,
    ProcessOutputObservation, RecordingApi, capture_project_process_outputs,
    capture_project_process_outputs_for_observation, drive_managed_recording_input,
    execute_rewrite_operation, execute_rewrite_recording_worker,
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
    /// Capture configured process-owned files before a managed container exits.
    ProcessOutputCapture(ProcessOutputCaptureArgs),
    /// Run one detached rewrite recording action owned by the coordinator.
    #[command(hide = true)]
    RewriteRecordingWorker(RewriteRecordingWorkerArgs),
    #[command(hide = true)]
    RewriteOperationWorker(RewriteRecordingWorkerArgs),
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
    /// Override the finite comparison quiet period after the last request.
    #[arg(long)]
    completion_quiet_period_ms: Option<NonZeroU64>,
}

#[derive(Debug, Args)]
struct RewriteRecordingWorkerArgs {
    #[arg(long)]
    target_root: PathBuf,
    action_id: String,
}

#[derive(Debug, Args)]
struct ProcessOutputCaptureArgs {
    #[arg(long)]
    target_root: PathBuf,
    #[arg(long)]
    container: String,
    #[arg(long, value_enum)]
    side: ProcessOutputCaptureSideArg,
    #[arg(long, value_enum)]
    observation: Option<ProcessOutputObservationArg>,
    #[arg(long)]
    output_root: PathBuf,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ProcessOutputCaptureSideArg {
    Source,
    Target,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ProcessOutputObservationArg {
    BeforeShutdown,
    Comparison,
}

impl From<ProcessOutputObservationArg> for ProcessOutputObservation {
    fn from(value: ProcessOutputObservationArg) -> Self {
        match value {
            ProcessOutputObservationArg::BeforeShutdown => Self::BeforeShutdown,
            ProcessOutputObservationArg::Comparison => Self::Comparison,
        }
    }
}

impl From<ProcessOutputCaptureSideArg> for ProcessOutputCaptureSide {
    fn from(value: ProcessOutputCaptureSideArg) -> Self {
        match value {
            ProcessOutputCaptureSideArg::Source => Self::Source,
            ProcessOutputCaptureSideArg::Target => Self::Target,
        }
    }
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
                        quiet_period: managed_comparison_quiet_period(
                            args.completion_quiet_period_ms,
                        ),
                    }
                }),
            })
            .await?;
            super::output::stdout_line(format_args!("{}", serde_json::to_string_pretty(&report)?))
        }
        InternalCommand::ProcessOutputCapture(args) => {
            let report = match args.observation {
                Some(observation) => capture_project_process_outputs_for_observation(
                    &args.target_root,
                    &args.container,
                    args.side.into(),
                    observation.into(),
                    &args.output_root,
                )?,
                None => capture_project_process_outputs(
                    &args.target_root,
                    &args.container,
                    args.side.into(),
                    &args.output_root,
                )?,
            };
            super::output::stdout_line(format_args!("{}", serde_json::to_string(&report)?))
        }
        InternalCommand::RewriteOperationWorker(args) => {
            let report = execute_rewrite_operation(args.target_root, &args.action_id).await?;
            super::output::stdout_line(format_args!("{}", serde_json::to_string(&report)?))
        }
        InternalCommand::RewriteRecordingWorker(args) => {
            let report =
                execute_rewrite_recording_worker(args.target_root, &args.action_id).await?;
            super::output::stdout_line(format_args!("{}", serde_json::to_string_pretty(&report)?))
        }
    }
}

fn managed_comparison_quiet_period(override_ms: Option<NonZeroU64>) -> Duration {
    override_ms
        .map(|value| Duration::from_millis(value.get()))
        .unwrap_or(MANAGED_COMPARISON_FINAL_QUIET_PERIOD)
        .max(MANAGED_COMPARISON_FINAL_QUIET_PERIOD)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_output_flush_never_shortens_the_comparison_final_quiet_period() {
        assert_eq!(
            managed_comparison_quiet_period(None),
            MANAGED_COMPARISON_FINAL_QUIET_PERIOD
        );
        assert_eq!(
            managed_comparison_quiet_period(NonZeroU64::new(1)),
            MANAGED_COMPARISON_FINAL_QUIET_PERIOD
        );
        assert_eq!(
            managed_comparison_quiet_period(NonZeroU64::new(15_000)),
            Duration::from_secs(15)
        );
    }
}
