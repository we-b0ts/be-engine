use std::num::NonZeroU64;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use clap::Args;
use traffic_e2e::{
    AppConfig, ComparisonRecordingRunOptions, RecordingApi, run_comparison_recording_with_options,
};

#[derive(Debug, Args)]
pub(super) struct RecordComparisonArgs {
    /// Recorder TOML configuration containing a [comparison_recording] section.
    #[arg(long)]
    config: PathBuf,
    /// Explicit 14-digit UTC comparison recording run identifier.
    #[arg(long, value_parser = parse_run_id)]
    run_id: Option<String>,
    /// Stop cleanly after both upstreams have been ready for this many seconds.
    #[arg(long, default_value = "60")]
    duration_seconds: NonZeroU64,
    /// Capture the source baseline again after the candidate for this run.
    #[arg(long)]
    baseline_recheck: bool,
    /// Record only this API for the current run; repeat for multiple METHOD/path selectors.
    #[arg(long = "api", value_name = "METHOD PATH_OR_PATTERN")]
    apis: Vec<RecordingApi>,
    /// Override the case limit for every API in this run.
    #[arg(long, value_name = "N")]
    case_limit: Option<NonZeroUsize>,
}

pub(super) async fn run(args: RecordComparisonArgs) -> Result<()> {
    ensure!(
        args.config.is_file(),
        "comparison recording config not found: {}",
        args.config.display()
    );
    let mut config = AppConfig::load_comparison_recording(&args.config).with_context(|| {
        format!(
            "failed to load comparison recording config {}",
            args.config.display()
        )
    })?;
    if let Some(case_limit) = args.case_limit {
        config.override_case_limits_for_run(case_limit);
    }
    if args.baseline_recheck {
        config
            .comparison_recording
            .as_mut()
            .expect("comparison recording config was validated")
            .baseline_recheck = true;
    }
    run_comparison_recording_with_options(
        config,
        ComparisonRecordingRunOptions {
            run_id: args.run_id,
            duration: Some(Duration::from_secs(args.duration_seconds.get())),
            recording_apis: args.apis,
        },
    )
    .await
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
        record_comparison: RecordComparisonArgs,
    }

    #[test]
    fn parses_record_comparison_arguments_without_policy() {
        let parsed = TestCli::try_parse_from([
            "test",
            "--config",
            "recorder.toml",
            "--run-id",
            "20260722153045",
            "--duration-seconds",
            "60",
            "--baseline-recheck",
            "--api",
            "GET /api/users/*",
            "--case-limit",
            "250",
        ])
        .unwrap();
        assert_eq!(
            parsed.record_comparison.run_id.as_deref(),
            Some("20260722153045")
        );
        assert_eq!(parsed.record_comparison.duration_seconds.get(), 60);
        assert!(parsed.record_comparison.baseline_recheck);
        assert_eq!(
            parsed.record_comparison.apis[0].to_string(),
            "GET /api/users/*"
        );
        assert_eq!(
            parsed.record_comparison.case_limit.map(NonZeroUsize::get),
            Some(250)
        );
        assert!(
            TestCli::try_parse_from([
                "test",
                "--config",
                "recorder.toml",
                "--policy",
                "replay.yaml",
            ])
            .is_err()
        );
        assert!(
            TestCli::try_parse_from(["test", "--config", "recorder.toml", "--intercept",]).is_err()
        );
        assert!(
            TestCli::try_parse_from([
                "test",
                "--config",
                "recorder.toml",
                "--duration-seconds",
                "0",
            ])
            .is_err()
        );
        assert!(
            TestCli::try_parse_from(["test", "--config", "recorder.toml", "--case-limit", "0",])
                .is_err()
        );

        let defaults = TestCli::try_parse_from(["test", "--config", "recorder.toml"]).unwrap();
        assert_eq!(defaults.record_comparison.duration_seconds.get(), 60);
    }
}
