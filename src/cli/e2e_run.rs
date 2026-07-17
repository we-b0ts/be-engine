use std::path::PathBuf;

use anyhow::{Result, ensure};
use clap::{Args, Subcommand};
use traffic_recorder_proxy::{
    E2eRunContext, E2eRunPrepareOptions, abort_e2e_run, prepare_e2e_run, recover_e2e_run,
    run_e2e_api, run_e2e_round, status_e2e_run,
};

#[derive(Debug, Args)]
pub(super) struct E2eRunArgs {
    #[command(subcommand)]
    command: E2eRunCommand,
}

#[derive(Debug, Subcommand)]
enum E2eRunCommand {
    Prepare(PrepareArgs),
    RunApi(RunApiArgs),
    Run(ContextArgs),
    Status(ContextArgs),
    Abort(ContextArgs),
    Recover(ContextArgs),
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
