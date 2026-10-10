use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Subcommand};
use traffic_e2e::execute_rewrite_operation;

use super::record;

#[derive(Debug, Args)]
pub(super) struct InternalArgs {
    #[command(subcommand)]
    command: InternalCommand,
}

#[derive(Debug, Subcommand)]
enum InternalCommand {
    /// Run the recorder process inside the managed recorder runtime.
    RecorderRun(record::RecordArgs),
    #[command(hide = true)]
    RewriteOperationWorker(RewriteOperationWorkerArgs),
}

#[derive(Debug, Args)]
struct RewriteOperationWorkerArgs {
    #[arg(long)]
    target_root: PathBuf,
    action_id: String,
}

pub(super) async fn run(args: InternalArgs) -> Result<()> {
    match args.command {
        InternalCommand::RecorderRun(args) => record::run(args).await,
        InternalCommand::RewriteOperationWorker(args) => {
            let report = execute_rewrite_operation(args.target_root, &args.action_id).await?;
            super::output::stdout_line(format_args!("{}", serde_json::to_string(&report)?))
        }
    }
}
