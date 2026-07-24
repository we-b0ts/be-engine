use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Subcommand};
use traffic_e2e::initialize_standard_e2e_project;

#[derive(Debug, Args)]
pub(super) struct ProjectArgs {
    #[command(subcommand)]
    command: ProjectCommand,
}

#[derive(Debug, Subcommand)]
enum ProjectCommand {
    /// Create the conventional .traffic-e2e/project.yaml.
    Init,
}

pub(super) fn run(target_root: PathBuf, args: ProjectArgs) -> Result<()> {
    match args.command {
        ProjectCommand::Init => super::print_json(&initialize_standard_e2e_project(target_root)?),
    }
}
