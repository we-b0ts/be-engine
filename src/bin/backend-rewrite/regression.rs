use anyhow::Result;
use clap::{Args, Subcommand};
use std::path::PathBuf;
use traffic_e2e::{RewriteRegressionBeginOptions, begin_rewrite_regression};

#[derive(Debug, Args)]
pub(super) struct RegressionArgs {
    #[command(subcommand)]
    command: RegressionCommand,
}

#[derive(Debug, Subcommand)]
enum RegressionCommand {
    /// Confirm a purpose, enter a new work branch, and begin fresh verification.
    Begin {
        /// Required attestation of explicit user authorization for this new round.
        #[arg(long, required = true)]
        approve_new_regression: bool,
        /// Record new live traffic before Replay; otherwise reuse the selected recording.
        #[arg(long)]
        record_new_traffic: bool,
        #[command(flatten)]
        runtime: super::purpose::SessionRuntimeArgs,
    },
}

pub(super) fn run(target_root: PathBuf, args: RegressionArgs, pretty: bool) -> Result<()> {
    match args.command {
        RegressionCommand::Begin {
            approve_new_regression,
            record_new_traffic,
            runtime,
        } => super::print_json(
            &begin_rewrite_regression(RewriteRegressionBeginOptions {
                target_root,
                caller_approved: approve_new_regression,
                record_new_traffic,
                active_agent_count: runtime.active_agent_count,
                runtime_query: runtime.query(),
            })?,
            pretty,
        ),
    }
}

#[cfg(test)]
mod tests {
    use crate::Cli;
    use clap::Parser;

    #[test]
    fn both_purposes_require_explicit_user_approval() {
        assert!(Cli::try_parse_from(["backend-rewrite", "regression", "begin"]).is_err());
        assert!(
            Cli::try_parse_from([
                "backend-rewrite",
                "regression",
                "begin",
                "--runtime-query-command",
                "ListAgents",
                "--runtime-query-at",
                "2026-09-12T09:00:00Z"
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "backend-rewrite",
                "regression",
                "begin",
                "--approve-new-regression",
                "--active-agent-count",
                "0",
                "--runtime-query-command",
                "ListAgents",
                "--runtime-query-at",
                "2026-09-12T09:00:00Z"
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "backend-rewrite",
                "regression",
                "begin",
                "--approve-new-regression",
                "--runtime-query-command",
                "ListAgents"
            ])
            .is_err()
        );
    }
}
