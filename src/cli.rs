use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

mod diagnose;
mod workflow;

#[derive(Debug, Parser)]
#[command(
    name = "traffic-e2e",
    author,
    version,
    about = "Record, replay, and verify traffic-based E2E contracts",
    subcommand_required = true,
    arg_required_else_help = true
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Generate and validate the target repository's traffic E2E configuration.
    Init(workflow::InitArgs),
    /// Persist one canonical static or dynamic API case group.
    Prepare(workflow::PrepareArgs),
    /// Run one API's complete focused case group.
    RunApi(workflow::RunApiArgs),
    /// Run one complete regression round.
    Run(workflow::ContextArgs),
    /// Show generated traffic E2E progress and active run state.
    Status(workflow::ContextArgs),
    /// Recover a previously interrupted traffic E2E run.
    Recover(workflow::ContextArgs),
    /// Abort an active traffic E2E run and preserve its diagnostics.
    Abort(workflow::ContextArgs),
    /// Access low-level recorder, replay, grouping, and policy commands.
    Diagnose(diagnose::DiagnoseArgs),
}

pub(crate) async fn run() -> Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .init();

    match Cli::parse().command {
        Command::Init(args) => workflow::run(workflow::WorkflowCommand::Init(args)).await,
        Command::Prepare(args) => workflow::run(workflow::WorkflowCommand::Prepare(args)).await,
        Command::RunApi(args) => workflow::run(workflow::WorkflowCommand::RunApi(args)).await,
        Command::Run(args) => workflow::run(workflow::WorkflowCommand::Run(args)).await,
        Command::Status(args) => workflow::run(workflow::WorkflowCommand::Status(args)).await,
        Command::Recover(args) => workflow::run(workflow::WorkflowCommand::Recover(args)).await,
        Command::Abort(args) => workflow::run(workflow::WorkflowCommand::Abort(args)).await,
        Command::Diagnose(args) => diagnose::run(args).await,
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn command_model_satisfies_clap_invariants() {
        Cli::command().debug_assert();
    }

    #[test]
    fn exposes_workflow_commands_at_the_top_level() {
        let command = Cli::command();
        let names = command
            .get_subcommands()
            .map(|subcommand| subcommand.get_name())
            .collect::<Vec<_>>();

        assert_eq!(
            names,
            [
                "init", "prepare", "run-api", "run", "status", "recover", "abort", "diagnose"
            ]
        );
    }

    #[test]
    fn nests_low_level_commands_under_diagnose() {
        let parsed = Cli::try_parse_from([
            "traffic-e2e",
            "diagnose",
            "replay-policy",
            "validate",
            "--policy",
            ".traffic-e2e/replay.yaml",
        ])
        .unwrap();

        assert!(matches!(parsed.command, Command::Diagnose(_)));
    }

    #[test]
    fn rejects_the_removed_e2e_run_facade_shape() {
        assert!(Cli::try_parse_from(["traffic-e2e", "e2e-run", "status"]).is_err());
    }
}
