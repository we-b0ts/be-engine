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
    /// Start a user-approved regression using a completed recording.
    Confirm {
        #[arg(long, value_enum, default_value = "replay", hide = true)]
        purpose: Purpose,
        /// Attest that the user explicitly requested or approved this regression.
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
    use super::*;
    use crate::{Cli, RewriteCommand};
    use clap::Parser;
    #[test]
    fn confirmation_defaults_to_replay_and_requires_authorization_and_session_query() {
        let mut argv = vec!["backend-rewrite", "purpose", "confirm"];
        let approval_and_query = [
            "--user-approved",
            "--active-agent-count",
            "0",
            "--runtime-query-command",
            "ListAgents",
            "--runtime-query-at",
            "2026-09-12T09:00:00Z",
        ];
        argv.extend(approval_and_query);
        assert!(matches!(
            Cli::try_parse_from(&argv).unwrap().command,
            RewriteCommand::Purpose(PurposeArgs {
                command: PurposeCommand::Confirm {
                    purpose: Purpose::Replay,
                    ..
                }
            })
        ));
        assert!(Cli::try_parse_from(&argv[..4]).is_err());
        argv.remove(3);
        assert!(Cli::try_parse_from(&argv).is_err());
        for purpose in ["replay", "record"] {
            let mut argv = vec![
                "backend-rewrite",
                "purpose",
                "confirm",
                "--purpose",
                purpose,
            ];
            argv.extend(approval_and_query);
            assert!(Cli::try_parse_from(&argv).is_ok());
        }
    }
}
