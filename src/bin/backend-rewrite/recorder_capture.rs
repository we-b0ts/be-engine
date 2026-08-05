use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Subcommand};
use traffic_e2e::{
    RewriteContext, RewriteRecorderCapturePlanOptions, apply_rewrite_recorder_capture,
    plan_rewrite_recorder_capture,
};

#[derive(Debug, Args)]
pub(super) struct RecorderCaptureArgs {
    #[command(subcommand)]
    command: RecorderCaptureCommand,
}

#[derive(Debug, Subcommand)]
enum RecorderCaptureCommand {
    /// Resolve a source-proven backend endpoint and preview its capture rule.
    Plan(RecorderCapturePlanArgs),
    /// Atomically apply the persisted plan and park its API for one consolidated recording.
    Apply(RecorderCaptureApplyArgs),
}

#[derive(Debug, Args)]
struct RecorderCapturePlanArgs {
    /// Current issue evidence id returned by rewrite evidence.
    #[arg(long)]
    evidence_id: String,
    /// Source-proven backend hostname, optionally with its port.
    #[arg(long)]
    endpoint: String,
    /// Single-line source file/symbol proof that the API consumes this backend.
    #[arg(long)]
    source_evidence: String,
}

#[derive(Debug, Args)]
struct RecorderCaptureApplyArgs {
    plan_id: String,
}

pub(super) fn run(target_root: PathBuf, args: RecorderCaptureArgs, pretty: bool) -> Result<()> {
    match args.command {
        RecorderCaptureCommand::Plan(args) => super::print_json(
            &plan_rewrite_recorder_capture(
                RewriteContext { target_root },
                RewriteRecorderCapturePlanOptions {
                    evidence_id: args.evidence_id,
                    endpoint: args.endpoint,
                    source_evidence: args.source_evidence,
                },
            )?,
            pretty,
        ),
        RecorderCaptureCommand::Apply(args) => super::print_json(
            &apply_rewrite_recorder_capture(RewriteContext { target_root }, &args.plan_id)?,
            pretty,
        ),
    }
}
