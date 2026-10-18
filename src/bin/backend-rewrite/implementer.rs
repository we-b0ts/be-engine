//! CLI adapter for reusable implementation slots; workflow decisions stay in the engine.
use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Subcommand};
use traffic_e2e::{
    ImplementerConfirmOptions, ImplementerDelivery, ImplementerHandoffOptions,
    ImplementerReassignOptions, ImplementerReplaceRuntimeOptions, ImplementerReportOptions,
};

#[derive(Debug, Args)]
pub(super) struct ImplementerArgs {
    #[command(subcommand)]
    command: ImplementerCommand,
}

#[derive(Debug, Subcommand)]
enum ImplementerCommand {
    /// Replace a runtime-confirmed missing worker session, preserving its checkout and pending APIs.
    ReplaceRuntime {
        #[arg(long)]
        slot: usize,
        #[arg(long)]
        previous_agent_handle: String,
        #[arg(long, env = "BACKEND_REWRITE_SUBAGENT_HANDLE", hide_env_values = true)]
        agent_handle: String,
        #[arg(long)]
        reason: String,
        #[arg(long)]
        runtime_query_command: String,
        #[arg(long)]
        runtime_query_at: String,
    },
    /// Confirm the exact same-group API batch assigned to a stable implementer slot.
    Confirm {
        #[arg(long)]
        slot: usize,
        #[arg(long)]
        group: String,
        #[arg(long)]
        dispatch_id: String,
        #[arg(long, env = "BACKEND_REWRITE_SUBAGENT_HANDLE", hide_env_values = true)]
        agent_handle: String,
    },
    /// Report one API's actual runtime activity with its original dispatch and lease.
    Report {
        #[arg(long)]
        slot: usize,
        #[arg(long, env = "BACKEND_REWRITE_IMPLEMENTER_API", value_parser = super::parse_api_scope)]
        api: String,
        #[arg(long, env = "BACKEND_REWRITE_IMPLEMENTER_DISPATCH_ID")]
        dispatch_id: String,
        #[arg(long, env = "BACKEND_REWRITE_IMPLEMENTER_LEASE_GENERATION")]
        lease_generation: u64,
        #[arg(long, env = "BACKEND_REWRITE_SUBAGENT_HANDLE", hide_env_values = true)]
        agent_handle: String,
        #[arg(long, env = "BACKEND_REWRITE_WORKER_ACTIVITY", value_parser = ["running", "queued", "idle"])]
        activity: String,
    },
    /// Atomically admit a completed subset of API deliveries; unrelated tasks remain assigned.
    Handoff {
        #[arg(long)]
        slot: usize,
        #[arg(long, env = "BACKEND_REWRITE_SUBAGENT_HANDLE", hide_env_values = true)]
        agent_handle: String,
        /// JSON array of {api, dispatch_id, lease_generation, handoff_id, review_report}.
        #[arg(long)]
        deliveries: PathBuf,
    },
    /// Explicitly move a group without changing any active assignment.
    Reassign {
        #[arg(long)]
        group: String,
        #[arg(long)]
        slot: usize,
        #[arg(long)]
        reason: String,
    },
}

impl ImplementerArgs {
    fn run(self, target_root: PathBuf, pretty: bool) -> Result<()> {
        let response = match self.command {
            ImplementerCommand::ReplaceRuntime {
                slot,
                previous_agent_handle,
                agent_handle,
                reason,
                runtime_query_command,
                runtime_query_at,
            } => traffic_e2e::replace_rewrite_implementer_runtime(
                ImplementerReplaceRuntimeOptions {
                    target_root,
                    slot_id: slot,
                    previous_agent_handle,
                    agent_handle,
                    reason,
                    runtime_query: traffic_e2e::RewriteWorkerMissingQuery {
                        api_or_command: runtime_query_command,
                        queried_at: runtime_query_at,
                    },
                },
            )?,
            ImplementerCommand::Confirm {
                slot,
                group,
                dispatch_id,
                agent_handle,
            } => traffic_e2e::confirm_rewrite_implementer(ImplementerConfirmOptions {
                target_root,
                slot_id: slot,
                group_id: group,
                dispatch_id,
                agent_handle,
            })?,
            ImplementerCommand::Report {
                slot,
                api,
                dispatch_id,
                lease_generation,
                agent_handle,
                activity,
            } => traffic_e2e::report_rewrite_implementer(ImplementerReportOptions {
                target_root,
                slot_id: slot,
                api,
                dispatch_id,
                lease_generation,
                agent_handle,
                activity: activity.parse()?,
            })?,
            ImplementerCommand::Handoff {
                slot,
                agent_handle,
                deliveries,
            } => {
                let deliveries: Vec<ImplementerDelivery> =
                    serde_json::from_slice(&std::fs::read(deliveries)?)?;
                traffic_e2e::handoff_rewrite_implementer(ImplementerHandoffOptions {
                    target_root,
                    slot_id: slot,
                    agent_handle,
                    deliveries,
                })?
            }
            ImplementerCommand::Reassign {
                group,
                slot,
                reason,
            } => traffic_e2e::reassign_rewrite_implementer(ImplementerReassignOptions {
                target_root,
                slot_id: slot,
                group_id: group,
                reason,
            })?,
        };
        super::print_json(&response, pretty)
    }
}

pub(super) fn run(root: PathBuf, args: ImplementerArgs, pretty: bool) -> Result<()> {
    args.run(root, pretty)
}

#[cfg(test)]
mod tests {
    use super::super::Cli;
    use clap::Parser;

    #[test]
    fn real_cli_accepts_pool_commands_and_requires_fenced_reports() {
        for args in [
            vec![
                "test",
                "implementer",
                "confirm",
                "--slot",
                "0",
                "--group",
                "auth",
                "--dispatch-id",
                "batch",
                "--agent-handle",
                "runtime",
            ],
            vec![
                "test",
                "implementer",
                "report",
                "--slot",
                "0",
                "--api",
                "/auth/*",
                "--dispatch-id",
                "api-dispatch",
                "--lease-generation",
                "3",
                "--agent-handle",
                "runtime",
                "--activity",
                "running",
            ],
            vec![
                "test",
                "implementer",
                "handoff",
                "--slot",
                "0",
                "--agent-handle",
                "runtime",
                "--deliveries",
                "/tmp/deliveries.json",
            ],
            vec![
                "test",
                "implementer",
                "reassign",
                "--slot",
                "1",
                "--group",
                "auth",
                "--reason",
                "future affinity",
            ],
            vec![
                "test",
                "implementer",
                "replace-runtime",
                "--slot",
                "0",
                "--previous-agent-handle",
                "old",
                "--agent-handle",
                "new",
                "--reason",
                "runtime confirmed missing",
                "--runtime-query-command",
                "ListAgents",
                "--runtime-query-at",
                "2026-10-18T00:00:00Z",
            ],
        ] {
            assert!(Cli::try_parse_from(&args).is_ok(), "{args:?}");
        }
        assert!(
            Cli::try_parse_from([
                "test",
                "implementer",
                "report",
                "--slot",
                "0",
                "--api",
                "/auth",
                "--agent-handle",
                "runtime",
                "--activity",
                "running"
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "test",
                "implementer",
                "report",
                "--slot",
                "0",
                "--api",
                "GET /auth",
                "--dispatch-id",
                "api",
                "--lease-generation",
                "1",
                "--agent-handle",
                "runtime",
                "--activity",
                "running"
            ])
            .is_err()
        );
    }
}
