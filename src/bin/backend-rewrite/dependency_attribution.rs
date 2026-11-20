//! Explicit implementer claims and independent repository-analyst submissions.
use anyhow::Result;
use clap::{Args, Subcommand};
use std::path::PathBuf;
use traffic_e2e::dependency_attribution_api_information;
use traffic_e2e::{
    AttributionCommandOptions, RewriteContext, apply_dependency_attribution, claim_foreign_unused,
    dependency_attribution_context_page, dependency_attribution_group,
};
use traffic_e2e::{
    dependency_attribution_batch_information, dependency_attribution_candidates,
    dependency_attribution_hypotheses, dependency_attribution_rules,
    dependency_attribution_source_information, dependency_attribution_target,
    investigate_unmatched_dependency, resolve_target_investigation, retry_dependency_batch,
    verify_dependency_obligation,
};

#[derive(Debug, Args)]
pub(super) struct DependencyAttributionArgs {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Show Source attribution work for the read-only repository analyst.
    Context {
        #[arg(long, default_value_t = 0)]
        offset: usize,
    },
    /// Page exact Source exchange identities for one unattributed group.
    Group {
        #[arg(long)]
        group: String,
        #[arg(long)]
        inventory: String,
        #[arg(long)]
        revision: u64,
        #[arg(long, default_value_t = 0)]
        offset: usize,
    },
    /// Inspect the complete effective task/lifecycle rule groups for proof binding.
    Rules,
    /// Inspect whole-run verification separately from focused API acceptance.
    Batch {
        #[arg(long, default_value_t = 0)]
        offset: usize,
    },
    /// Read one bounded pointer from an authenticated actual Target request, including run-owned I/O.
    Target {
        #[arg(long)]
        session: String,
        #[arg(long)]
        observation: String,
        #[arg(long)]
        pointer: String,
    },
    /// Admit a fresh complete-run retry after diagnosing a failed actual batch.
    RetryBatch {
        #[arg(long)]
        reason: String,
    },
    /// Page every persisted probe of a candidate, including failed and rejected attempts.
    Hypotheses {
        #[arg(long)]
        api: String,
        #[arg(long)]
        method: String,
        #[arg(long)]
        candidate: String,
        #[arg(long)]
        attempt: u64,
        #[arg(long, default_value_t = 0)]
        offset: usize,
    },
    /// Page Source resource/operation candidates for an authenticated Target request.
    Candidates {
        #[arg(long)]
        investigation: String,
        #[arg(long)]
        target_observation: String,
        #[arg(long)]
        revision: u64,
        #[arg(long, default_value_t = 0)]
        offset: usize,
    },
    /// Show exact API gates, hypothesis groups, attribution work and origin obligations.
    Show {
        #[arg(long)]
        api: String,
        #[arg(long, default_value_t = 0)]
        offset: usize,
    },
    /// Submit current API exclusion evidence for concrete unused occurrences.
    Claim {
        #[arg(long)]
        file: PathBuf,
    },
    /// Investigate independent unmatched Target requests, including zero Source candidates.
    Investigate {
        #[arg(long)]
        file: PathBuf,
    },
    /// Publish the current API implementer's diagnosis of its missing/unmatched traffic.
    Resolve {
        #[arg(long)]
        file: PathBuf,
    },
    /// Verify an origin API obligation against its genuine current execution.
    Verify { obligation_id: String },
    /// Inspect one authenticated original Source identity without exposing payloads.
    Source {
        #[arg(long)]
        exchange_id: String,
    },
    /// Atomically publish independently proved owners and original-owner obligations.
    Apply {
        #[arg(long)]
        file: PathBuf,
    },
}

pub(super) fn run(
    target_root: PathBuf,
    args: DependencyAttributionArgs,
    pretty: bool,
) -> Result<()> {
    match args.command {
        Command::Batch { offset } => super::print_json(
            &dependency_attribution_batch_information(RewriteContext { target_root }, offset)?,
            pretty,
        ),
        Command::Target {
            session,
            observation,
            pointer,
        } => super::print_json(
            &dependency_attribution_target(
                RewriteContext { target_root },
                &session,
                &observation,
                &pointer,
            )?,
            pretty,
        ),
        Command::RetryBatch { reason } => super::print_json(
            &retry_dependency_batch(RewriteContext { target_root }, &reason)?,
            pretty,
        ),
        Command::Hypotheses {
            api,
            method,
            candidate,
            attempt,
            offset,
        } => super::print_json(
            &dependency_attribution_hypotheses(
                RewriteContext { target_root },
                &api,
                &method,
                &candidate,
                attempt,
                offset,
            )?,
            pretty,
        ),
        Command::Rules => super::print_json(
            &dependency_attribution_rules(RewriteContext { target_root })?,
            pretty,
        ),
        Command::Candidates {
            investigation,
            target_observation,
            revision,
            offset,
        } => super::print_json(
            &dependency_attribution_candidates(
                RewriteContext { target_root },
                &investigation,
                &target_observation,
                revision,
                offset,
            )?,
            pretty,
        ),
        Command::Context { offset } => super::print_json(
            &dependency_attribution_context_page(RewriteContext { target_root }, offset)?,
            pretty,
        ),
        Command::Group {
            group,
            inventory,
            revision,
            offset,
        } => super::print_json(
            &dependency_attribution_group(
                RewriteContext { target_root },
                &group,
                &inventory,
                revision,
                offset,
            )?,
            pretty,
        ),
        Command::Show { api, offset } => super::print_json(
            &dependency_attribution_api_information(RewriteContext { target_root }, &api, offset)?,
            pretty,
        ),
        Command::Claim { file } => super::print_json(
            &claim_foreign_unused(AttributionCommandOptions { target_root, file })?,
            pretty,
        ),
        Command::Investigate { file } => super::print_json(
            &investigate_unmatched_dependency(AttributionCommandOptions { target_root, file })?,
            pretty,
        ),
        Command::Resolve { file } => super::print_json(
            &resolve_target_investigation(AttributionCommandOptions { target_root, file })?,
            pretty,
        ),
        Command::Verify { obligation_id } => super::print_json(
            &verify_dependency_obligation(RewriteContext { target_root }, &obligation_id)?,
            pretty,
        ),
        Command::Source { exchange_id } => super::print_json(
            &dependency_attribution_source_information(
                RewriteContext { target_root },
                &exchange_id,
            )?,
            pretty,
        ),
        Command::Apply { file } => super::print_json(
            &apply_dependency_attribution(AttributionCommandOptions { target_root, file })?,
            pretty,
        ),
    }
}
