use std::num::NonZeroU64;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use clap::{Args, Subcommand};
use traffic_e2e::{ManagedRecordingInputOptions, drive_managed_recording_input};

use super::{record, record_comparison};

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
    /// Drive coordinator-owned request templates through a managed recording gateway.
    RecordingInput(RecordingInputArgs),
}

#[derive(Debug, Args)]
struct RecordingInputArgs {
    #[arg(long)]
    case_source: PathBuf,
    #[arg(long)]
    origin: String,
    #[arg(long, default_value = "30")]
    request_timeout_seconds: NonZeroU64,
}

pub(super) async fn run(args: InternalArgs) -> Result<()> {
    match args.command {
        InternalCommand::RecorderRun(args) => record::run(args).await,
        InternalCommand::ComparisonRun(args) => record_comparison::run(args).await,
        InternalCommand::RecordingInput(args) => {
            let report = drive_managed_recording_input(ManagedRecordingInputOptions {
                case_source: args.case_source,
                origin: args.origin,
                request_timeout: Duration::from_secs(args.request_timeout_seconds.get()),
            })
            .await?;
            super::output::stdout_line(format_args!("{}", serde_json::to_string_pretty(&report)?))
        }
    }
}
