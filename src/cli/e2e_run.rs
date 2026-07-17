use std::path::PathBuf;

use anyhow::{Result, ensure};
use clap::{Args, Subcommand};
use traffic_recorder_proxy::{
    E2eRunContext, E2eRunInitOptions, E2eRunPrepareOptions, abort_e2e_run, initialize_e2e_run,
    prepare_e2e_run, recover_e2e_run, run_e2e_api, run_e2e_round, status_e2e_run,
};

#[derive(Debug, Args)]
pub(super) struct E2eRunArgs {
    #[command(subcommand)]
    command: E2eRunCommand,
}

#[derive(Debug, Subcommand)]
enum E2eRunCommand {
    /// Generate and validate the target repository's migration configuration.
    Init(InitArgs),
    Prepare(PrepareArgs),
    RunApi(RunApiArgs),
    Run(ContextArgs),
    Status(ContextArgs),
    Abort(ContextArgs),
    Recover(ContextArgs),
}

#[derive(Debug, Args)]
struct InitArgs {
    /// Target repository root.
    #[arg(long, default_value = ".")]
    target_root: PathBuf,
    /// Executable target facade providing start, status, e2e, and stop.
    #[arg(long)]
    project_cli: PathBuf,
    /// Replay policy with expected responses restricted to assertions.
    #[arg(long)]
    replay_policy: PathBuf,
    /// Confirmed branch that migration pull requests target.
    #[arg(long)]
    integration_branch: String,
    /// Managed recorder configuration; requires --recording-rule.
    #[arg(long, requires = "recording_rule")]
    recorder_config: Option<PathBuf>,
    /// Managed recording rule; requires --recorder-config.
    #[arg(long, requires = "recorder_config")]
    recording_rule: Option<String>,
    /// Replace an existing generated .migration/e2e.yaml.
    #[arg(long)]
    force: bool,
}

#[derive(Debug, Clone, Args)]
struct ContextArgs {
    #[arg(long, default_value = ".")]
    target_root: PathBuf,
    #[arg(long)]
    case_source: PathBuf,
    #[arg(long)]
    run_key: Option<String>,
}

#[derive(Debug, Args)]
struct PrepareArgs {
    #[command(flatten)]
    context: ContextArgs,
    #[arg(long)]
    case_dir: PathBuf,
    #[arg(long)]
    method: String,
    #[arg(long)]
    source_route: String,
    #[arg(long)]
    pattern: Option<String>,
    #[arg(long)]
    source_revision: String,
}

#[derive(Debug, Args)]
struct RunApiArgs {
    #[command(flatten)]
    context: ContextArgs,
    #[arg(long)]
    api: String,
}

pub(super) async fn run(args: E2eRunArgs) -> Result<()> {
    match args.command {
        E2eRunCommand::Init(args) => print_json(&initialize_e2e_run(E2eRunInitOptions {
            target_root: args.target_root,
            project_cli: args.project_cli,
            replay_policy: args.replay_policy,
            integration_branch: args.integration_branch,
            recorder_config: args.recorder_config,
            recording_rule: args.recording_rule,
            force: args.force,
        })?),
        E2eRunCommand::Prepare(args) => {
            let report = prepare_e2e_run(E2eRunPrepareOptions {
                context: context(args.context),
                case_dir: args.case_dir,
                method: args.method,
                source_route: args.source_route,
                pattern: args.pattern,
                source_revision: args.source_revision,
            })?;
            print_json(&report)
        }
        E2eRunCommand::RunApi(args) => {
            let report = run_e2e_api(context(args.context), &args.api).await?;
            print_json(&report)?;
            ensure!(
                report.successful,
                "focused API replay finished with status {}",
                report.status
            );
            Ok(())
        }
        E2eRunCommand::Run(args) => {
            let report = run_e2e_round(context(args)).await?;
            print_json(&report)?;
            ensure!(
                report.successful,
                "E2E run finished with status {}",
                report.status
            );
            Ok(())
        }
        E2eRunCommand::Status(args) => print_json(&status_e2e_run(context(args))?),
        E2eRunCommand::Abort(args) => print_json(&abort_e2e_run(context(args)).await?),
        E2eRunCommand::Recover(args) => print_json(&recover_e2e_run(context(args)).await?),
    }
}

fn context(args: ContextArgs) -> E2eRunContext {
    E2eRunContext {
        target_root: args.target_root,
        case_source: args.case_source,
        run_key: args.run_key,
    }
}

fn print_json(value: &impl serde::Serialize) -> Result<()> {
    serde_json::to_writer_pretty(std::io::stdout(), value)?;
    println!();
    Ok(())
}
