use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use clap::Args;
use traffic_e2e::{AppConfig, run_compare};

#[derive(Debug, Args)]
pub(super) struct CompareArgs {
    /// Compare-mode TOML configuration.
    #[arg(long)]
    config: PathBuf,
    /// Explicit 14-digit UTC compare run identifier.
    #[arg(long, value_parser = parse_run_id)]
    run_id: Option<String>,
}

pub(super) async fn run(args: CompareArgs) -> Result<()> {
    ensure!(
        args.config.is_file(),
        "compare config not found: {}",
        args.config.display()
    );
    let config = AppConfig::load_compare(&args.config)
        .with_context(|| format!("failed to load compare config {}", args.config.display()))?;
    run_compare(config, args.run_id).await
}

fn parse_run_id(value: &str) -> std::result::Result<String, String> {
    if value.len() == 14
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && chrono::NaiveDateTime::parse_from_str(value, "%Y%m%d%H%M%S").is_ok()
    {
        Ok(value.to_string())
    } else {
        Err("run ID must contain exactly 14 ASCII digits (YYYYMMDDHHMMSS)".to_string())
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        compare: CompareArgs,
    }

    #[test]
    fn parses_compare_arguments_without_policy() {
        let parsed = TestCli::try_parse_from([
            "test",
            "--config",
            "compare.toml",
            "--run-id",
            "20260722153045",
        ])
        .unwrap();
        assert_eq!(parsed.compare.run_id.as_deref(), Some("20260722153045"));
        assert!(
            TestCli::try_parse_from([
                "test",
                "--config",
                "compare.toml",
                "--policy",
                "replay.yaml",
            ])
            .is_err()
        );
    }
}
