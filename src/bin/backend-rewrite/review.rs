use std::path::PathBuf;

use anyhow::{Result, ensure};
use clap::{Args, Subcommand};
use traffic_e2e::{RewriteReviewOptions, RewriteWorkScope};

#[cfg(test)]
mod tests;

#[derive(Debug, Args)]
pub(super) struct ReviewArgs {
    #[command(subcommand)]
    command: ReviewCommand,
}

#[derive(Debug, Subcommand)]
enum ReviewCommand {
    /// Run all source, isolation, and engine-standard quality checks before delivery.
    Check {
        #[arg(long, env = "BACKEND_REWRITE_REVIEW_WORKTREE")]
        worktree: PathBuf,
        /// Check an integration candidate instead of a registered worker delivery.
        #[arg(long)]
        integration: bool,
        #[arg(
            long,
            conflicts_with = "process_output",
            required_unless_present_any = ["integration", "process_output"]
        )]
        api: Option<String>,
        #[arg(long)]
        process_output: Option<String>,
        /// Accepted worker handoff; pair with its scope for an integration delivery.
        #[arg(long, requires = "integration")]
        handoff_id: Option<String>,
        /// JSON document containing spawn ownership and code evidence.
        #[arg(long)]
        evidence: Option<PathBuf>,
        /// Confirm one production-source-proven domain occurrence; repeat per location.
        #[arg(
            long,
            value_name = "TARGET_FILE:LINE:COLUMN=SOURCE_REPOSITORY@REVISION:SOURCE_FILE:LINE:COLUMN"
        )]
        hardcode_ai_verified: Vec<String>,
    },
    /// Admit a published global integration report without rerunning its checks.
    Accept {
        #[arg(long, env = "BACKEND_REWRITE_REVIEW_REPORT")]
        report: PathBuf,
    },
    /// Read the current integrated findings without advancing the workflow.
    Show,
    /// Route a current quality finding to its original API/process-output worker.
    Rework {
        /// Failed unpublished integration report; omit to use current canonical findings.
        #[arg(long)]
        report: Option<PathBuf>,
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
            integration,
            api,
            process_output,
            handoff_id,
            evidence,
            hardcode_ai_verified,
        } => {
            let scope = api
                .map(|api| RewriteWorkScope::Api { api })
                .or_else(|| process_output.map(|id| RewriteWorkScope::ProcessOutput { id }));
            ensure!(
                !integration || scope.is_some() == handoff_id.is_some(),
                "integration review requires both a work-item selector and --handoff-id, or neither for a global candidate"
            );
            let report = traffic_e2e::check_rewrite_review(RewriteReviewOptions {
                target_root: root,
                worktree: Some(worktree),
                integration,
                scope,
                handoff_id,
                evidence,
                hardcode_ai_verified,
            })?;
            super::print_json(&report, pretty)
        }
        ReviewCommand::Accept { report } => {
            super::print_json(&traffic_e2e::accept_rewrite_review(root, report)?, pretty)
        }
        ReviewCommand::Show => super::print_json(&traffic_e2e::show_rewrite_review(root)?, pretty),
        ReviewCommand::Rework {
            finding,
            owner,
            report,
        } => {
            let scope = if let Some(api) = owner.strip_prefix("api:") {
                RewriteWorkScope::Api { api: api.into() }
            } else if let Some(id) = owner.strip_prefix("process-output:") {
                RewriteWorkScope::ProcessOutput { id: id.into() }
            } else {
                anyhow::bail!("owner must be api:METHOD /path or process-output:ID");
            };
            super::print_json(
                &traffic_e2e::rework_rewrite_review_with_report(root, &finding, scope, report)?,
                pretty,
            )
        }
    }
}
