use std::path::PathBuf;

use anyhow::{Result, ensure};
use clap::{Args, Subcommand};
use traffic_e2e::{RewriteIntegrationBatchOptions, RewriteReviewOptions, RewriteWorkScope};

#[cfg(test)]
mod tests;

#[derive(Debug, Args)]
pub(super) struct ReviewArgs {
    #[command(subcommand)]
    command: ReviewCommand,
}

#[derive(Debug, Subcommand)]
enum ReviewCommand {
    /// Export selected accepted handoffs and their complete candidate review command.
    Batch {
        #[arg(long, env = "BACKEND_REWRITE_REVIEW_WORKTREE")]
        worktree: PathBuf,
        /// Exact routes selected by the coordinator; repeat for each batch member.
        #[arg(long, required = true, value_parser = super::parse_api_scope)]
        api: Vec<String>,
    },
    /// Check final source/quality; outside pre-revalidation, succeed without code checks.
    Check {
        #[arg(long, env = "BACKEND_REWRITE_REVIEW_WORKTREE")]
        worktree: PathBuf,
        /// Check an integration candidate instead of a registered worker delivery.
        #[arg(long)]
        integration: bool,
        /// Bind final source/isolation review and agent-owned quality before full revalidation.
        /// This automatically selects global integration review.
        #[arg(long, conflicts_with_all = ["api", "handoff_id", "batch_handoffs"])]
        pre_revalidation: bool,
        /// Report the configured tool only after it passed on the final committed
        /// candidate. This command records the agent's result without running it.
        #[arg(
            long,
            requires = "pre_revalidation",
            required_if_eq("pre_revalidation", "true")
        )]
        quality_check: Option<String>,
        #[arg(
            long,
            required_unless_present_any = ["integration", "pre_revalidation"],
            value_parser = super::parse_api_scope
        )]
        api: Option<String>,
        /// Accepted worker handoff; pair with its scope for an integration delivery.
        #[arg(long, requires = "integration")]
        handoff_id: Option<String>,
        /// Engine-exported integration batch file; legacy nonempty JSON arrays of
        /// API {scope, handoff_id} entries are also supported. Include at least one
        /// handoff_ready item; integrated items may be retained in the batch.
        /// Review checks the whole candidate. For receipt refresh only, omit this
        /// option and all scope/handoff selectors, then use review accept.
        #[arg(long, requires = "integration", conflicts_with_all = ["api", "handoff_id"])]
        batch_handoffs: Option<PathBuf>,
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
    /// Route a current quality finding to its original API worker.
    Rework {
        /// Failed unpublished integration report; omit to use current canonical findings.
        #[arg(long)]
        report: Option<PathBuf>,
        #[arg(long, env = "BACKEND_REWRITE_REVIEW_FINDING")]
        finding: String,
        /// api:/path, selected after checking ownership.
        #[arg(long, env = "BACKEND_REWRITE_REVIEW_OWNER")]
        owner: String,
    },
}

pub(super) fn run(root: PathBuf, args: ReviewArgs, pretty: bool) -> Result<()> {
    match args.command {
        ReviewCommand::Batch { worktree, api } => super::print_json(
            &traffic_e2e::export_rewrite_integration_batch(RewriteIntegrationBatchOptions {
                target_root: root,
                worktree,
                apis: api,
            })?,
            pretty,
        ),
        ReviewCommand::Check {
            worktree,
            integration,
            pre_revalidation,
            quality_check,
            api,
            handoff_id,
            batch_handoffs,
            evidence,
            hardcode_ai_verified,
        } => {
            let scope = api.map(|api| RewriteWorkScope::Api { api });
            let integration = integration || pre_revalidation;
            ensure!(
                !integration || scope.is_some() == handoff_id.is_some(),
                "integration review requires both a work-item selector and --handoff-id, or neither for a global candidate"
            );
            let options = RewriteReviewOptions {
                target_root: root,
                worktree: Some(worktree),
                integration,
                quality_check,
                scope,
                handoff_id,
                evidence,
                hardcode_ai_verified,
            };
            let report = if pre_revalidation {
                traffic_e2e::check_rewrite_pre_revalidation(options)?
            } else if let Some(path) = batch_handoffs {
                traffic_e2e::check_rewrite_review_batch_file(options, &path)?
            } else {
                traffic_e2e::check_rewrite_review(options)?
            };
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
                RewriteWorkScope::Api {
                    api: super::parse_api_scope(api)?,
                }
            } else {
                anyhow::bail!("owner must be api:/path");
            };
            super::print_json(
                &traffic_e2e::rework_rewrite_review_with_report(root, &finding, scope, report)?,
                pretty,
            )
        }
    }
}
