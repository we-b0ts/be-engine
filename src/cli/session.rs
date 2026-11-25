use std::path::PathBuf;

use anyhow::{Result, ensure};
use clap::Args;
use traffic_e2e::{E2eEventSessionOptions, run_e2e_event_session};

#[derive(Debug, Args)]
pub(super) struct RunSessionArgs {
    #[arg(long, default_value = ".")]
    target_root: PathBuf,
    #[arg(long)]
    recording_root: PathBuf,
    #[arg(long)]
    run_key: Option<String>,
}

pub(super) async fn run(args: RunSessionArgs) -> Result<()> {
    let result = run_e2e_event_session(E2eEventSessionOptions {
        target_root: args.target_root,
        recording_root: args.recording_root,
        run_key: args.run_key,
    })
    .await?;
    println!("{}", serde_json::to_string_pretty(&result)?);
    ensure!(result.passed, "Source session Replay failed");
    Ok(())
}
