use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Subcommand};
use traffic_e2e::initialize_standard_e2e_project_with_force;

#[derive(Debug, Args)]
pub(super) struct ProjectArgs {
    #[command(subcommand)]
    command: ProjectCommand,
}

#[derive(Debug, Subcommand)]
enum ProjectCommand {
    /// Create the conventional .traffic-e2e/project.yaml.
    Init {
        /// Replace an obsolete generated project configuration.
        #[arg(long)]
        force: bool,
    },
}

pub(super) fn run(target_root: PathBuf, args: ProjectArgs) -> Result<()> {
    match args.command {
        ProjectCommand::Init { force } => super::print_json(
            &initialize_standard_e2e_project_with_force(target_root, force)?,
        ),
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        project: ProjectArgs,
    }

    #[test]
    fn accepts_explicit_force_only_for_project_init() {
        let parsed = TestCli::try_parse_from(["test", "init", "--force"]).unwrap();
        assert!(matches!(
            parsed.project.command,
            ProjectCommand::Init { force: true }
        ));
    }
}
