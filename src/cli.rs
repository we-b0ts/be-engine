use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

mod compare;
mod diagnose;
mod interception;
mod output;
mod record;
mod replay;
mod signal;
mod target;
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
    /// Default recorder log filter when RUST_LOG is not set.
    #[arg(
        long,
        global = true,
        env = "TRAFFIC_E2E_LOG_LEVEL",
        default_value = "info",
        value_name = "FILTER"
    )]
    log_level: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Mirror matched HTTP requests to baseline and candidate services and record both responses.
    Compare(compare::CompareArgs),
    /// Run the recorder with fixed-user local interception.
    Record(record::RecordArgs),
    /// Run a managed replay session with fixed-user local interception.
    Replay(replay::ReplayArgs),
    /// Execute a prebuilt target command as the fixed interception user.
    Target(target::TargetArgs),
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
    let cli = Cli::parse();
    let log_filter = if std::env::var_os("RUST_LOG").is_some() {
        EnvFilter::try_from_default_env()?
    } else {
        EnvFilter::try_new(&cli.log_level)?
    };
    tracing_subscriber::fmt()
        .with_env_filter(log_filter)
        .with_writer(output::TracingWriter)
        .init();

    match cli.command {
        Command::Compare(args) => compare::run(args).await,
        Command::Record(args) => record::run(args).await,
        Command::Replay(args) => replay::run(args).await,
        Command::Target(args) => target::run(args).await,
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

pub(crate) fn report_error(error: &anyhow::Error) {
    output::stderr_line(format_args!("Error: {error:?}"));
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
    fn exposes_public_commands_at_the_top_level() {
        let command = Cli::command();
        let names = command
            .get_subcommands()
            .map(|subcommand| subcommand.get_name())
            .collect::<Vec<_>>();

        assert_eq!(
            names,
            [
                "compare", "record", "replay", "target", "init", "prepare", "run-api", "run",
                "status", "recover", "abort", "diagnose"
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

    #[test]
    fn accepts_a_global_log_filter() {
        let parsed = Cli::try_parse_from([
            "traffic-e2e",
            "--log-level",
            "warn",
            "record",
            "--config",
            "recorder.toml",
        ])
        .unwrap();

        assert_eq!(parsed.log_level, "warn");
    }
}
