use std::path::PathBuf;

use anyhow::{Result, ensure};
use clap::{Args, Subcommand};
use traffic_e2e::{RewriteReviewOptions, RewriteWorkScope};

#[derive(Debug, Args)]
pub(super) struct ReviewArgs {
    #[command(subcommand)]
    command: ReviewCommand,
}

#[derive(Debug, Subcommand)]
enum ReviewCommand {
    /// Review an assigned worker worktree, or the integrated target when omitted.
    Check {
        #[arg(long)]
        worktree: Option<PathBuf>,
        #[arg(long, conflicts_with = "process_output")]
        api: Option<String>,
        #[arg(long)]
        process_output: Option<String>,
        /// JSON document containing spawn ownership and code evidence.
        #[arg(long)]
        evidence: Option<PathBuf>,
    },
    /// Read the current integrated findings without advancing the workflow.
    Show,
    /// Route a current quality finding to its original API/process-output worker.
    Rework {
        #[arg(long, env = "BACKEND_REWRITE_REVIEW_FINDING")]
        finding: String,
        /// api:METHOD /path or process-output:ID, selected after checking ownership.
        #[arg(long, env = "BACKEND_REWRITE_REVIEW_OWNER")]
        owner: String,
    },
}

pub(super) fn run(root: PathBuf, args: ReviewArgs, pretty: bool) -> Result<()> {
    match args.command {
        ReviewCommand::Check {
            worktree,
            api,
            process_output,
            evidence,
        } => {
            let scope = api
                .map(|api| RewriteWorkScope::Api { api })
                .or_else(|| process_output.map(|id| RewriteWorkScope::ProcessOutput { id }));
            ensure!(
                worktree.is_some() == scope.is_some(),
                "--worktree requires exactly one --api or --process-output; omit all three for integrated review"
            );
            let report = traffic_e2e::check_rewrite_review(RewriteReviewOptions {
                target_root: root,
                worktree,
                scope,
                evidence,
            })?;
            super::print_json(&report, pretty)
        }
        ReviewCommand::Show => super::print_json(&traffic_e2e::show_rewrite_review(root)?, pretty),
        ReviewCommand::Rework { finding, owner } => {
            let scope = if let Some(api) = owner.strip_prefix("api:") {
                RewriteWorkScope::Api { api: api.into() }
            } else if let Some(id) = owner.strip_prefix("process-output:") {
                RewriteWorkScope::ProcessOutput { id: id.into() }
            } else {
                anyhow::bail!("owner must be api:METHOD /path or process-output:ID");
            };
            super::print_json(
                &traffic_e2e::rework_rewrite_review(root, &finding, scope)?,
                pretty,
            )
        }
    }
}
