use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Subcommand};
use traffic_e2e::{
    HttpResponseRewriteRuleConfig, RewriteContext, RewriteHttpResponseCapturePlanOptions,
    RewriteRecorderCapturePlanOptions, apply_rewrite_recorder_capture,
    plan_rewrite_http_response_capture, plan_rewrite_recorder_capture,
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
    /// Preview a JSON URL acquisition rule from recorded response and source evidence.
    PlanHttpResponse(HttpResponsePlanArgs),
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
struct HttpResponsePlanArgs {
    #[arg(long)]
    evidence_id: String,
    #[arg(long)]
    case_id: String,
    #[arg(long)]
    response_id: String,
    #[arg(long)]
    name: String,
    #[arg(long)]
    authority: String,
    #[arg(long)]
    method: String,
    /// Whole-segment * matches one level; trailing ** matches one or more levels.
    #[arg(long)]
    path_pattern: String,
    /// JSON pointer to an HTTP(S) URL. Repeat for multiple fields.
    #[arg(long = "pointer", required = true)]
    pointers: Vec<String>,
    /// Source file/symbol proof that this API consumes the selected upstream URL field.
    #[arg(long, env = "BACKEND_REWRITE_SOURCE_EVIDENCE", hide_env_values = true)]
    source_evidence: String,
}

#[derive(Debug, Args)]
struct RecorderCaptureApplyArgs {
    plan_id: String,
}

pub(super) fn run(target_root: PathBuf, args: RecorderCaptureArgs, pretty: bool) -> Result<()> {
    match args.command {
        RecorderCaptureCommand::PlanHttpResponse(args) => super::print_json(
            &plan_rewrite_http_response_capture(
                RewriteContext { target_root },
                RewriteHttpResponseCapturePlanOptions {
                    evidence_id: args.evidence_id,
                    case_id: args.case_id,
                    response_id: args.response_id,
                    source_evidence: args.source_evidence,
                    rule: HttpResponseRewriteRuleConfig {
                        name: args.name,
                        authorities: vec![args.authority],
                        methods: vec![args.method],
                        path: String::new(),
                        path_pattern: Some(args.path_pattern),
                        pointers: args.pointers,
                        status_codes: Vec::new(),
                        content_types: Vec::new(),
                        plugin: None,
                    },
                },
            )?,
            pretty,
        ),
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
