use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Subcommand};
use traffic_e2e::{
    RepositoryAnalysisApplyOptions, RepositoryAnalysisContextOptions, apply_repository_analysis,
    repository_analysis_context,
};

#[derive(Debug, Args)]
pub(super) struct RepositoryAnalysisArgs {
    #[command(subcommand)]
    command: RepositoryAnalysisCommand,
}

#[derive(Debug, Subcommand)]
enum RepositoryAnalysisCommand {
    /// Show the current canonical routes requiring source-backed grouping.
    Context,
    /// Apply a complete incremental grouping for the exact returned analysis batch.
    Apply {
        batch_id: String,
        #[arg(
            long,
            env = "BACKEND_REWRITE_REPOSITORY_ANALYSIS_FILE",
            hide_env_values = true
        )]
        file: PathBuf,
    },
}

pub(super) fn run(root: PathBuf, args: RepositoryAnalysisArgs, pretty: bool) -> Result<()> {
    match args.command {
        RepositoryAnalysisCommand::Context => super::print_json(
            &repository_analysis_context(RepositoryAnalysisContextOptions { target_root: root })?,
            pretty,
        ),
        RepositoryAnalysisCommand::Apply { batch_id, file } => super::print_json(
            &apply_repository_analysis(RepositoryAnalysisApplyOptions {
                target_root: root,
                batch_id,
                file,
            })?,
            pretty,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn context_and_file_apply_are_real_distinct_commands() {
        let cli = crate::Cli::try_parse_from(["backend-rewrite", "repository-analysis", "context"])
            .unwrap();
        let crate::RewriteCommand::RepositoryAnalysis(args) = cli.command else {
            panic!("repository analysis command");
        };
        assert!(matches!(args.command, RepositoryAnalysisCommand::Context));
        let cli = crate::Cli::try_parse_from([
            "backend-rewrite",
            "repository-analysis",
            "apply",
            "batch-1",
            "--file",
            "analysis.json",
        ])
        .unwrap();
        let crate::RewriteCommand::RepositoryAnalysis(args) = cli.command else {
            panic!("repository analysis command");
        };
        let RepositoryAnalysisCommand::Apply { batch_id, file } = args.command else {
            panic!("apply command");
        };
        assert_eq!(batch_id, "batch-1");
        assert_eq!(file, PathBuf::from("analysis.json"));
        assert!(
            crate::Cli::try_parse_from(["backend-rewrite", "repository-analysis", "apply"])
                .is_err()
        );
        assert!(
            crate::Cli::try_parse_from([
                "backend-rewrite",
                "repository-analysis",
                "apply",
                "batch-1"
            ])
            .is_err()
        );
    }
}
