use std::num::{NonZeroU64, NonZeroUsize};
use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use traffic_e2e::{
    ManagedRecordingOperation, ManagedRecordingOptions, RecordingApi, run_managed_recording,
};

#[derive(Debug, Clone, Args)]
pub(super) struct RecordArgs {
    /// Target repository containing .traffic-e2e/project.yaml.
    #[arg(long, default_value = ".")]
    target_root: PathBuf,
    /// Explicit 14-digit UTC run identifier. A current UTC identifier is generated when omitted.
    #[arg(long, value_parser = parse_run_id)]
    run_id: Option<String>,
    /// Stop cleanly after readiness has held for this many seconds.
    #[arg(long, default_value = "60")]
    duration_seconds: NonZeroU64,
    /// Record only this API; repeat for multiple METHOD/path selectors.
    #[arg(long = "api", value_name = "METHOD PATH_OR_PATTERN")]
    apis: Vec<RecordingApi>,
    /// Override the per-API case limit for every selected API.
    #[arg(long = "per-api-case-limit", value_name = "N")]
    per_api_case_limit: Option<NonZeroUsize>,
}

#[derive(Debug, Args)]
pub(super) struct RecordComparisonArgs {
    #[command(flatten)]
    run: RecordArgs,
    /// Capture the source response again after the candidate response.
    #[arg(long)]
    baseline_recheck: bool,
}

pub(super) async fn run_record(args: RecordArgs) -> Result<()> {
    run(options(args, ManagedRecordingOperation::Record, false)).await
}

pub(super) async fn run_record_comparison(args: RecordComparisonArgs) -> Result<()> {
    run(options(
        args.run,
        ManagedRecordingOperation::RecordComparison,
        args.baseline_recheck,
    ))
    .await
}

async fn run(options: ManagedRecordingOptions) -> Result<()> {
    let report = run_managed_recording(options).await?;
    serde_json::to_writer_pretty(std::io::stdout(), &report)?;
    println!();
    Ok(())
}

fn options(
    args: RecordArgs,
    operation: ManagedRecordingOperation,
    baseline_recheck: bool,
) -> ManagedRecordingOptions {
    ManagedRecordingOptions {
        target_root: args.target_root,
        operation,
        run_id: args.run_id,
        duration_seconds: args.duration_seconds,
        baseline_recheck,
        apis: args.apis,
        per_api_case_limit: args.per_api_case_limit,
        request_source: None,
    }
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
    struct RecordCli {
        #[command(flatten)]
        record: RecordArgs,
    }

    #[derive(Parser)]
    struct ComparisonCli {
        #[command(flatten)]
        comparison: RecordComparisonArgs,
    }

    #[test]
    fn parses_managed_record_and_comparison_commands() {
        let record = RecordCli::try_parse_from([
            "test",
            "--duration-seconds",
            "60",
            "--api",
            "GET /api/users/*",
        ])
        .unwrap();
        assert_eq!(record.record.duration_seconds.get(), 60);

        let comparison = ComparisonCli::try_parse_from(["test", "--baseline-recheck"]).unwrap();
        assert!(comparison.comparison.baseline_recheck);
    }

    #[test]
    fn rejects_zero_duration() {
        assert!(RecordCli::try_parse_from(["test", "--duration-seconds", "0"]).is_err());
    }
}
