use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Subcommand};
use traffic_e2e::{RewriteExpertDeliveryOptions, RewriteExpertOptions};

#[derive(Debug, Args)]
pub(super) struct ExpertArgs {
    #[command(subcommand)]
    command: ExpertCommand,
}

#[derive(Debug, Subcommand)]
enum ExpertCommand {
    /// Reserve the returned overdue APIs as one diagnostic batch before dispatch.
    Prepare {
        expert_id: String,
        #[arg(long = "api", required = true)]
        apis: Vec<traffic_e2e::RewriteApiSelector>,
    },
    /// Confirm the one accepted diagnostic task, including a queued task.
    Confirm(ExpertIdentity),
    /// After the API passes, acknowledge the expert has ended or was never spawned.
    Close {
        expert_id: String,
        #[arg(long, env = "BACKEND_REWRITE_EXPERT_HANDLE", hide_env_values = true)]
        agent_handle: Option<String>,
    },
    /// Acknowledge that the expert report was forwarded to the API implementer.
    Delivered {
        #[command(flatten)]
        identity: ExpertIdentity,
        #[arg(long)]
        api: traffic_e2e::RewriteApiSelector,
        #[arg(long, env = "BACKEND_REWRITE_EXPERT_REPORT_ID", hide_env_values = true)]
        report_id: String,
        #[arg(
            long,
            env = "BACKEND_REWRITE_EXPERT_RECIPIENT_HANDLE",
            hide_env_values = true
        )]
        recipient_handle: String,
    },
}

#[derive(Debug, Args)]
struct ExpertIdentity {
    expert_id: String,
    #[arg(long, env = "BACKEND_REWRITE_EXPERT_HANDLE", hide_env_values = true)]
    agent_handle: String,
}

impl ExpertIdentity {
    fn options(self, target_root: PathBuf) -> RewriteExpertOptions {
        RewriteExpertOptions {
            target_root,
            expert_id: self.expert_id,
            agent_handle: self.agent_handle,
        }
    }
}

pub(super) fn run(root: PathBuf, args: ExpertArgs, pretty: bool) -> Result<()> {
    let result = match args.command {
        ExpertCommand::Prepare { expert_id, apis } => {
            traffic_e2e::prepare_rewrite_expert(traffic_e2e::RewriteExpertPrepareOptions {
                target_root: root,
                expert_id,
                apis: apis.into_iter().map(|api| api.to_string()).collect(),
            })?
        }
        ExpertCommand::Confirm(identity) => {
            traffic_e2e::confirm_rewrite_expert(identity.options(root))?
        }
        ExpertCommand::Close {
            expert_id,
            agent_handle,
        } => traffic_e2e::close_rewrite_expert(traffic_e2e::RewriteExpertCloseOptions {
            target_root: root,
            expert_id,
            agent_handle,
        })?,
        ExpertCommand::Delivered {
            identity,
            api,
            report_id,
            recipient_handle,
        } => traffic_e2e::report_rewrite_expert_delivery(RewriteExpertDeliveryOptions {
            expert: identity.options(root),
            api: api.to_string(),
            report_id,
            recipient_handle,
        })?,
    };
    super::print_json(&result, pretty)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn expert_cli_preserves_batch_api_arguments_and_requires_delivery_recipient() {
        let cli = crate::Cli::try_parse_from([
            "backend-rewrite",
            "expert",
            "prepare",
            "batch-1",
            "--api",
            "/api/a",
            "--api",
            "/api/b",
        ])
        .unwrap();
        let crate::RewriteCommand::Expert(args) = cli.command else {
            panic!("expert CLI");
        };
        let ExpertCommand::Prepare { apis, .. } = args.command else {
            panic!("prepare CLI");
        };
        assert_eq!(
            apis.iter().map(ToString::to_string).collect::<Vec<_>>(),
            ["/api/a", "/api/b"]
        );
        assert!(
            crate::Cli::try_parse_from([
                "backend-rewrite",
                "expert",
                "delivered",
                "batch-1",
                "--agent-handle",
                "expert",
                "--api",
                "/api/a",
                "--report-id",
                "report-1",
            ])
            .is_err()
        );
        let cli = crate::Cli::try_parse_from([
            "backend-rewrite",
            "expert",
            "delivered",
            "batch-1",
            "--agent-handle",
            "expert",
            "--api",
            "/api/a",
            "--report-id",
            "report-1",
            "--recipient-handle",
            "implementer-a",
        ])
        .unwrap();
        let crate::RewriteCommand::Expert(args) = cli.command else {
            panic!("expert CLI");
        };
        assert!(matches!(args.command, ExpertCommand::Delivered { .. }));
    }
}
