use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

mod cache_snapshot;
mod compare;
mod config;
mod diagnose;
mod interception;
mod internal;
mod output;
mod platform;
mod record;
mod record_comparison;
mod recording;
mod replay;
mod signal;
mod target;
mod workflow;

#[derive(Debug, Parser)]
#[command(
    name = "traffic-e2e",
    author,
    version = traffic_e2e::BINARY_VERSION,
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
    /// Record source traffic through the repository's managed recording configuration.
    Record(platform::RecordArgs),
    /// Record source and target responses through the managed comparison runtime.
    RecordComparison(platform::RecordComparisonArgs),
    /// Compare a finalized comparison recording with replay response rules.
    Compare(compare::CompareArgs),
    /// Wait for and inspect managed recording lifecycle state.
    Recording(recording::RecordingArgs),
    /// Run a managed replay session with fixed-user local interception.
    Replay(replay::ReplayArgs),
    /// Execute a prebuilt target command as the fixed interception user.
    Target(target::TargetArgs),
    /// Initialize and maintain target repository traffic E2E configuration.
    Config(config::ConfigArgs),
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
    /// Runtime-only process entrypoints used by managed containers.
    #[command(hide = true)]
    Internal(internal::InternalArgs),
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
        Command::RecordComparison(args) => platform::run_record_comparison(args).await,
        Command::Compare(args) => compare::run(args).await,
        Command::Record(args) => platform::run_record(args).await,
        Command::Recording(args) => recording::run(args).await,
        Command::Replay(args) => replay::run(args).await,
        Command::Target(args) => target::run(args).await,
        Command::Config(args) => config::run(args),
        Command::Prepare(args) => workflow::run(workflow::WorkflowCommand::Prepare(args)).await,
        Command::RunApi(args) => workflow::run(workflow::WorkflowCommand::RunApi(args)).await,
        Command::Run(args) => workflow::run(workflow::WorkflowCommand::Run(args)).await,
        Command::Status(args) => workflow::run(workflow::WorkflowCommand::Status(args)).await,
        Command::Recover(args) => workflow::run(workflow::WorkflowCommand::Recover(args)).await,
        Command::Abort(args) => workflow::run(workflow::WorkflowCommand::Abort(args)).await,
        Command::Diagnose(args) => diagnose::run(args).await,
        Command::Internal(args) => internal::run(args).await,
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
        let command = Cli::command();
        command.clone().debug_assert();
        assert_eq!(command.get_version(), Some(traffic_e2e::BINARY_VERSION));
    }

    #[test]
    fn exposes_public_commands_at_the_top_level() {
        let command = Cli::command();
        let names = command
            .get_subcommands()
            .filter(|subcommand| !subcommand.is_hide_set())
            .map(|subcommand| subcommand.get_name())
            .collect::<Vec<_>>();

        assert_eq!(
            names,
            [
                "record",
                "record-comparison",
                "compare",
                "recording",
                "replay",
                "target",
                "config",
                "prepare",
                "run-api",
                "run",
                "status",
                "recover",
                "abort",
                "diagnose"
            ]
        );
    }

    #[test]
    fn rejects_rewrite_commands_owned_by_the_backend_rewrite_binary() {
        assert!(Cli::try_parse_from(["traffic-e2e", "rewrite", "next"]).is_err());
    }

    #[test]
    fn exposes_repository_configuration_at_the_top_level() {
        let parsed = Cli::try_parse_from([
            "traffic-e2e",
            "config",
            "init",
            "--source-container",
            "source",
        ])
        .unwrap();

        assert!(matches!(parsed.command, Command::Config(_)));
    }

    #[test]
    fn rejects_the_removed_e2e_run_facade_shape() {
        assert!(Cli::try_parse_from(["traffic-e2e", "e2e-run", "status"]).is_err());
    }

    #[test]
    fn rejects_removed_platform_and_split_initialization_commands() {
        assert!(Cli::try_parse_from(["traffic-e2e", "platform", "record"]).is_err());
        assert!(Cli::try_parse_from(["traffic-e2e", "config", "recorder", "init"]).is_err());
        assert!(Cli::try_parse_from(["traffic-e2e", "config", "replay", "init"]).is_err());
        assert!(
            Cli::try_parse_from([
                "traffic-e2e",
                "config",
                "project",
                "init",
                "--source-container",
                "source",
            ])
            .is_err()
        );
    }

    #[test]
    fn compare_does_not_accept_recording_or_interception_options() {
        assert!(
            Cli::try_parse_from(["traffic-e2e", "compare", "run", "--policy", "replay.yaml",])
                .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "traffic-e2e",
                "compare",
                "run",
                "--policy",
                "replay.yaml",
                "--intercept",
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "traffic-e2e",
                "config",
                "comparison",
                "plan",
                "response-rule",
                "--kind",
                "counter",
                "--source-evidence",
                "src/user.rs:load live follower count",
                "--source-example",
                "100",
                "--target-example",
                "101",
                "--api",
                "GET /api/users/show",
                "--json-pointer",
                "/followers_count",
                "--comparison-run",
                "comparison-run",
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "traffic-e2e",
                "config",
                "replay",
                "plan",
                "response-rule",
                "--kind",
                "counter",
                "--api",
                "GET /api/users/show",
                "--json-pointer",
                "/followers_count",
                "--comparison-run",
                "comparison-run",
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "traffic-e2e",
                "config",
                "comparison",
                "plan",
                "response-rule",
                "--kind",
                "dynamic",
                "--api",
                "GET /api/token",
                "--json-pointer",
                "/token",
                "--comparison-run",
                "comparison-run",
            ])
            .is_err()
        );
    }

    #[test]
    fn exposes_action_first_config_strategy_commands() {
        assert!(
            Cli::try_parse_from([
                "traffic-e2e",
                "config",
                "recorder",
                "plan",
                "allowed-unused-http-hosts",
                "--host",
                "config.example.test",
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "traffic-e2e",
                "config",
                "recorder",
                "plan",
                "breeze-resource-capture",
                "--resource",
                "usercounter",
                "--source-revision",
                "abc123",
                "--evidence",
                "src/UserCounter.java:load uses usercounter",
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "traffic-e2e",
                "config",
                "replay",
                "plan",
                "response-rule",
                "--kind",
                "dynamic",
                "--dynamic-mechanism",
                "uuid",
                "--source-evidence",
                "src/token.rs:issue_token",
                "--source-example",
                "<redacted source UUID>",
                "--target-example",
                "<redacted target UUID>",
                "--api",
                "GET /api/token",
                "--json-pointer",
                "/token",
                "--case-source",
                "recordings/run/rule",
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "traffic-e2e",
                "config",
                "replay",
                "plan",
                "response-rule",
                "--kind",
                "dynamic",
                "--dynamic-mechanism",
                "uuid",
                "--source-evidence",
                "src/token.rs:issue_token",
                "--source-example",
                "<redacted source UUID>",
                "--target-example",
                "<redacted target UUID>",
                "--api",
                "GET /api/token",
                "--json-pointer",
                "/token",
                "--comparison-run",
                "comparison-run",
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "traffic-e2e",
                "config",
                "replay",
                "plan",
                "response-rule",
                "--kind",
                "dynamic",
                "--dynamic-mechanism",
                "uuid",
                "--source-evidence",
                "src/token.rs:issue_token",
                "--source-example",
                "<redacted source UUID>",
                "--target-example",
                "<redacted target UUID>",
                "--api",
                "GET /api/token",
                "--json-pointer",
                "/token",
                "--comparison-run",
                "comparison-run",
                "--case-source",
                "recordings/run/rule",
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "traffic-e2e",
                "config",
                "replay",
                "plan",
                "response-rule",
                "--kind",
                "dynamic",
                "--api",
                "GET /api/token",
                "--json-pointer",
                "/token",
                "--comparison-run",
                "comparison-run",
            ])
            .is_err()
        );
    }

    #[test]
    fn rejects_removed_configuration_entrypoints() {
        assert!(Cli::try_parse_from(["traffic-e2e", "init"]).is_err());
        assert!(Cli::try_parse_from(["traffic-e2e", "diagnose", "recorder-config"]).is_err());
        assert!(Cli::try_parse_from(["traffic-e2e", "diagnose", "replay-policy"]).is_err());
    }

    #[test]
    fn accepts_a_global_log_filter() {
        let parsed = Cli::try_parse_from([
            "traffic-e2e",
            "--log-level",
            "warn",
            "record",
            "--target-root",
            ".",
        ])
        .unwrap();

        assert_eq!(parsed.log_level, "warn");
    }
}
