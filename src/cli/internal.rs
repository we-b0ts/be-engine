use anyhow::Result;
use clap::{Args, Subcommand};

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
}

pub(super) async fn run(args: InternalArgs) -> Result<()> {
    match args.command {
        InternalCommand::RecorderRun(args) => record::run(args).await,
        InternalCommand::ComparisonRun(args) => record_comparison::run(args).await,
    }
}
