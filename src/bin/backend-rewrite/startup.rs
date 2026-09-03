use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use traffic_e2e::{
    ensure_startup_environment, ensure_startup_mount, import_startup_environment,
    list_startup_environment, list_startup_mounts, remove_startup_environment,
    startup_environment_equals, startup_environment_exists, startup_mount_exists,
    validate_startup_environment,
};

#[derive(Debug, Args)]
pub(super) struct StartupArgs {
    #[command(subcommand)]
    command: StartupCommand,
}

#[derive(Debug, Subcommand)]
enum StartupCommand {
    /// Manage the ignored project-level target.env file without displaying values.
    Env(StartupEnvArgs),
    /// Inspect or add source-compatible startup mounts.
    Mount(StartupMountArgs),
}

#[derive(Debug, Args)]
struct StartupEnvArgs {
    #[command(subcommand)]
    command: StartupEnvCommand,
}

#[derive(Debug, Subcommand)]
enum StartupEnvCommand {
    /// List configured variable names without their values.
    List,
    /// Report whether one variable exists without displaying its value.
    Exists(StartupEnvNameArgs),
    /// Compare one value with the same-named caller environment variable.
    Equals(StartupEnvValueArgs),
    /// Create or update one value from the same-named caller environment variable.
    Ensure(StartupEnvValueArgs),
    /// Remove one variable without displaying its previous value.
    Remove(StartupEnvNameArgs),
    /// Merge a dotenv file into target.env without displaying values.
    Import(StartupEnvImportArgs),
    /// Validate target.env and list only its variable names.
    Validate,
}

#[derive(Debug, Args)]
struct StartupEnvNameArgs {
    name: String,
}

#[derive(Debug, Args)]
struct StartupEnvValueArgs {
    name: String,
    /// Caller environment variable containing the candidate value; defaults to NAME.
    #[arg(long, value_name = "CALLER_NAME")]
    from_env: Option<String>,
}

#[derive(Debug, Args)]
struct StartupEnvImportArgs {
    #[arg(value_name = "PATH")]
    env_file: PathBuf,
}

#[derive(Debug, Args)]
struct StartupMountArgs {
    #[command(subcommand)]
    command: StartupMountCommand,
}

#[derive(Debug, Subcommand)]
enum StartupMountCommand {
    /// List captured startup mount paths and access modes.
    List,
    /// Report whether one absolute startup path is captured.
    Exists(StartupMountPathArgs),
    /// Capture one missing absolute path from the configured stopped source container.
    Ensure(StartupMountPathArgs),
}

#[derive(Debug, Args)]
struct StartupMountPathArgs {
    #[arg(value_name = "ABSOLUTE_PATH")]
    path: PathBuf,
}

pub(super) fn run(target_root: PathBuf, args: StartupArgs, pretty: bool) -> Result<()> {
    match args.command {
        StartupCommand::Env(args) => match args.command {
            StartupEnvCommand::List => {
                super::print_json(&list_startup_environment(&target_root)?, pretty)
            }
            StartupEnvCommand::Exists(args) => super::print_json(
                &startup_environment_exists(&target_root, &args.name)?,
                pretty,
            ),
            StartupEnvCommand::Equals(args) => {
                let value = caller_value(&args)?;
                super::print_json(
                    &startup_environment_equals(&target_root, &args.name, &value)?,
                    pretty,
                )
            }
            StartupEnvCommand::Ensure(args) => {
                let value = caller_value(&args)?;
                super::print_json(
                    &ensure_startup_environment(&target_root, &args.name, &value)?,
                    pretty,
                )
            }
            StartupEnvCommand::Remove(args) => super::print_json(
                &remove_startup_environment(&target_root, &args.name)?,
                pretty,
            ),
            StartupEnvCommand::Import(args) => super::print_json(
                &import_startup_environment(&target_root, &args.env_file)?,
                pretty,
            ),
            StartupEnvCommand::Validate => {
                super::print_json(&validate_startup_environment(&target_root)?, pretty)
            }
        },
        StartupCommand::Mount(args) => match args.command {
            StartupMountCommand::List => {
                super::print_json(&list_startup_mounts(&target_root)?, pretty)
            }
            StartupMountCommand::Exists(args) => {
                super::print_json(&startup_mount_exists(&target_root, &args.path)?, pretty)
            }
            StartupMountCommand::Ensure(args) => {
                super::print_json(&ensure_startup_mount(&target_root, &args.path)?, pretty)
            }
        },
    }
}

fn caller_value(args: &StartupEnvValueArgs) -> Result<String> {
    let source = args.from_env.as_deref().unwrap_or(&args.name);
    std::env::var(source).with_context(|| {
        format!("caller environment variable {source:?} is required; its value is never printed")
    })
}
