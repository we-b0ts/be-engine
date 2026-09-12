use anyhow::Result;
use clap::{Args, Subcommand};
use std::path::PathBuf;
use traffic_e2e::{
    RewriteRegressionBeginOptions, RewriteWorkerMissingQuery, begin_rewrite_regression,
};

#[derive(Debug, Args)]
pub(super) struct RegressionArgs {
    #[command(subcommand)]
    command: RegressionCommand,
}

#[derive(Debug, Subcommand)]
enum RegressionCommand {
    /// Archive the old round and review/replay the selected recording afresh.
    Begin {
        /// Required attestation of explicit user authorization for this new round.
        #[arg(long, required = true)]
        approve_new_regression: bool,
        /// Actual runtime query confirming all old workers/experts are stopped or absent.
        #[arg(long, requires = "runtime_query_at")]
        runtime_query_command: Option<String>,
        /// RFC 3339 time with timezone when that query was executed.
        #[arg(long, requires = "runtime_query_command")]
        runtime_query_at: Option<String>,
    },
}

pub(super) fn run(target_root: PathBuf, args: RegressionArgs, pretty: bool) -> Result<()> {
    match args.command {
        RegressionCommand::Begin {
            approve_new_regression,
            runtime_query_command,
            runtime_query_at,
        } => super::print_json(
            &begin_rewrite_regression(RewriteRegressionBeginOptions {
                target_root,
                caller_approved: approve_new_regression,
                runtime_query: runtime_query_command.zip(runtime_query_at).map(
                    |(api_or_command, queried_at)| RewriteWorkerMissingQuery {
                        api_or_command,
                        queried_at,
                    },
                ),
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
    fn begin_requires_user_approval_even_with_runtime_evidence() {
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
                "--approve-new-regression"
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
