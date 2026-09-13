//! Purpose confirmation is the coordinator's only entry operation on pr_base.
use anyhow::Result;
use clap::{Args, Subcommand, ValueEnum};
use std::path::PathBuf;
use traffic_e2e::{RewriteRegressionBeginOptions, begin_rewrite_regression};

#[derive(Debug, Args)]
pub(super) struct PurposeArgs {
    #[command(subcommand)]
    command: PurposeCommand,
}

#[derive(Debug, Subcommand)]
enum PurposeCommand {
    /// Confirm the user's purpose and let the engine enter a new work branch.
    Confirm {
        #[arg(long, value_enum)]
        purpose: Purpose,
        /// Attest that the user explicitly requested or approved this purpose.
        #[arg(long, required = true)]
        user_approved: bool,
        #[command(flatten)]
        runtime: SessionRuntimeArgs,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Purpose {
    Replay,
    Record,
}

pub(super) fn run(target_root: PathBuf, args: PurposeArgs, pretty: bool) -> Result<()> {
    match args.command {
        PurposeCommand::Confirm {
            purpose,
            user_approved,
            runtime,
        } => super::print_json(
            &begin_rewrite_regression(RewriteRegressionBeginOptions {
                target_root,
                caller_approved: user_approved,
                record_new_traffic: matches!(purpose, Purpose::Record),
                active_agent_count: runtime.active_agent_count,
                runtime_query: runtime.query(),
            })?,
            pretty,
        ),
    }
}

/// Facts reported from an actual query of the caller's current agent runtime.
#[derive(Debug, Args)]
pub(super) struct SessionRuntimeArgs {
    /// Active child sessions/agents of this coordinator; exclude self, peers and stored bindings.
    #[arg(long, env = "BACKEND_REWRITE_SESSION_ACTIVE_AGENT_COUNT")]
    pub active_agent_count: usize,
    /// Actual API/command queried for the current coordinator session.
    #[arg(long, env = "BACKEND_REWRITE_SESSION_QUERY_COMMAND")]
    runtime_query_command: String,
    /// Actual query time, RFC 3339 including timezone.
    #[arg(long, env = "BACKEND_REWRITE_SESSION_QUERY_AT")]
    runtime_query_at: String,
}

impl SessionRuntimeArgs {
    pub(super) fn query(&self) -> traffic_e2e::RewriteWorkerMissingQuery {
        traffic_e2e::RewriteWorkerMissingQuery {
            api_or_command: self.runtime_query_command.clone(),
            queried_at: self.runtime_query_at.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::Cli;
    use clap::Parser;
    #[test]
    fn confirmation_requires_purpose_authorization_and_real_session_query_fields() {
        for purpose in ["replay", "record"] {
            let argv = [
                "backend-rewrite",
                "purpose",
                "confirm",
                "--purpose",
                purpose,
                "--user-approved",
                "--active-agent-count",
                "0",
                "--runtime-query-command",
                "ListAgents",
                "--runtime-query-at",
                "2026-09-12T09:00:00Z",
            ];
            assert!(Cli::try_parse_from(argv).is_ok());
            assert!(Cli::try_parse_from(&argv[..6]).is_err());
        }
        assert!(
            Cli::try_parse_from(["backend-rewrite", "purpose", "confirm", "--user-approved"])
                .is_err()
        );
    }
}
