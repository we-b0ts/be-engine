use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use clap::Args;
use traffic_e2e::{ComparisonVerificationOptions, verify_comparison_recording};

#[derive(Debug, Args)]
pub(super) struct CompareArgs {
    /// Finalized comparison recording run directory.
    #[arg(value_name = "COMPARISON_RECORDING_RUN")]
    case_source: PathBuf,
    /// Verification YAML whose response_rules define allowed response differences.
    #[arg(long)]
    policy: PathBuf,
    /// JSON report path. Defaults to comparison-report.json in the run directory.
    #[arg(long)]
    report: Option<PathBuf>,
}

pub(super) async fn run(args: CompareArgs) -> Result<()> {
    ensure!(
        args.case_source.is_dir(),
        "comparison recording run not found: {}",
        args.case_source.display()
    );
    ensure!(
        args.policy.is_file(),
        "verification policy not found: {}",
        args.policy.display()
    );
    let policy = args
        .policy
        .canonicalize()
        .with_context(|| format!("failed to resolve policy {}", args.policy.display()))?;
    let report_path = args
        .report
        .unwrap_or_else(|| args.case_source.join("comparison-report.json"));
    let report = verify_comparison_recording(ComparisonVerificationOptions {
        case_source: args.case_source,
        policy,
        report: report_path,
    })?;
    let summary = serde_json::json!({
        "complete": report.complete,
        "passed": report.passed,
        "counts": &report.counts,
        "apis": &report.apis,
        "representative_difference": &report.representative_difference,
        "representative_policy_mismatch": &report.representative_policy_mismatch,
    });
    super::output::stdout_line(format_args!("{}", serde_json::to_string_pretty(&summary)?))?;
    ensure!(
        report.passed,
        "comparison recording verification failed; see {}",
        report.report_path
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[derive(Debug, Parser)]
    struct TestCli {
        #[command(flatten)]
        compare: CompareArgs,
    }

    #[test]
    fn requires_only_recording_source_and_policy() {
        let parsed = TestCli::try_parse_from([
            "test",
            "artifacts/comparison-recordings/20260722160000",
            "--policy",
            ".traffic-e2e/verification.yaml",
        ])
        .unwrap();

        assert!(parsed.compare.report.is_none());
        assert!(
            TestCli::try_parse_from([
                "test",
                "artifacts/comparison-recordings/20260722160000",
                "--policy",
                ".traffic-e2e/verification.yaml",
                "--intercept",
            ])
            .is_err()
        );
    }
}
