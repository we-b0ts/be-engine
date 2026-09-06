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
    /// Upstream authority (domain, optionally with port). May repeat across rules.
    #[arg(long)]
    name: String,
    /// HTTP method and path, e.g. 'GET /sandboxes/*'. * is one level; trailing ** is one or more.
    #[arg(long)]
    path_pattern: String,
    /// One JSON pointer to an HTTP(S) URL. Use separate rules for other fields.
    #[arg(long)]
    pointer: String,
    /// Confirm that source path construction and existing rules were checked.
    #[arg(long)]
    pattern_checked: bool,
    /// Brief note about URL consumption and the exact or wildcard path choice.
    #[arg(long, env = "BACKEND_REWRITE_SOURCE_EVIDENCE", hide_env_values = true)]
    source_evidence: Option<String>,
}

#[derive(Debug, Args)]
struct RecorderCaptureApplyArgs {
    plan_id: String,
}

pub(super) fn run(target_root: PathBuf, args: RecorderCaptureArgs, pretty: bool) -> Result<()> {
    match args.command {
        RecorderCaptureCommand::PlanHttpResponse(args) => {
            let (method, path) = args.path_pattern.split_once(' ').ok_or_else(|| {
                anyhow::anyhow!("path-pattern must contain METHOD /path, e.g. GET /sandboxes/*")
            })?;
            super::print_json(
                &plan_rewrite_http_response_capture(
                    RewriteContext { target_root },
                    RewriteHttpResponseCapturePlanOptions {
                        evidence_id: args.evidence_id,
                        case_id: args.case_id,
                        response_id: args.response_id,
                        source_evidence: args.source_evidence.unwrap_or_default(),
                        pattern_checked: args.pattern_checked,
                        rule: HttpResponseRewriteRuleConfig {
                            name: args.name.clone(),
                            authorities: vec![args.name],
                            methods: vec![method.into()],
                            path: String::new(),
                            path_pattern: Some(path.into()),
                            pointers: vec![args.pointer],
                            status_codes: Vec::new(),
                            content_types: Vec::new(),
                            plugin: None,
                            source_evidence: String::new(),
                        },
                    },
                )?,
                pretty,
            )
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        args: RecorderCaptureArgs,
    }

    #[test]
    fn http_path_review_is_accessible_before_confirmation_or_source_note() {
        let mut argv = vec![
            "test",
            "plan-http-response",
            "--evidence-id",
            "evidence-1",
            "--case-id",
            "case-1",
            "--response-id",
            "response-1",
            "--name",
            "cs.example",
            "--path-pattern",
            "GET /sandboxes/123",
            "--pointer",
            "/base_url",
        ];
        let parsed = Cli::try_parse_from(&argv).unwrap();
        let RecorderCaptureCommand::PlanHttpResponse(args) = parsed.args.command else {
            panic!("expected HTTP planner")
        };
        assert!(!args.pattern_checked);
        argv.extend([
            "--pattern-checked",
            "--source-evidence",
            "sandbox ID varies; read base_url",
        ]);
        let parsed = Cli::try_parse_from(argv).unwrap();
        let RecorderCaptureCommand::PlanHttpResponse(args) = parsed.args.command else {
            panic!("expected HTTP planner")
        };
        assert!(args.pattern_checked);
        assert_eq!(
            args.source_evidence.as_deref(),
            Some("sandbox ID varies; read base_url")
        );
    }
}
