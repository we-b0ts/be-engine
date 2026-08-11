use std::num::NonZeroU64;
use std::num::NonZeroUsize;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use clap::Args;
use tracing::info;
use traffic_e2e::{
    AppConfig, ComparisonRecordingRunOptions, ComparisonSourceMatch, RecordingApi,
    run_comparison_recording_with_options, validate_replay_policy,
};

#[derive(Debug, Args)]
pub(super) struct RecordComparisonArgs {
    /// Recorder TOML configuration containing a [comparison_recording] section.
    #[arg(long)]
    config: PathBuf,
    /// Verification policy. Defaults to verification.yaml next to the recorder config.
    #[arg(long)]
    policy: Option<PathBuf>,
    /// Runtime-only candidate origin selected by the managed comparison network.
    #[arg(long)]
    candidate_upstream: Option<String>,
    /// Runtime-only Motan candidate endpoint selected by the managed comparison network.
    #[arg(long)]
    candidate_motan_upstream: Option<String>,
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
    /// Override the per-API case limit for this run.
    #[arg(long = "per-api-case-limit", value_name = "N")]
    per_api_case_limit: Option<NonZeroUsize>,
    /// Publish comparison readiness on this Unix socket for the managed runtime.
    #[arg(long)]
    control_socket: Option<PathBuf>,
}

pub(super) async fn run(args: RecordComparisonArgs) -> Result<()> {
    ensure!(
        args.config.is_file(),
        "comparison recording config not found: {}",
        args.config.display()
    );
    let mut config = AppConfig::load_comparison_recording_with_candidates(
        &args.config,
        args.candidate_upstream.as_deref(),
        args.candidate_motan_upstream.as_deref(),
    )
    .with_context(|| {
        format!(
            "failed to load comparison recording config {}",
            args.config.display()
        )
    })?;
    let policy_path = args
        .policy
        .unwrap_or_else(|| args.config.with_file_name("verification.yaml"));
    ensure!(
        policy_path.is_file(),
        "comparison verification policy not found: {}",
        policy_path.display()
    );
    if let Some(per_api_case_limit) = args.per_api_case_limit {
        config.override_per_api_case_limit_for_run(per_api_case_limit);
    }
    config
        .comparison_recording
        .as_mut()
        .expect("comparison recording config was validated")
        .max_in_flight = 1;
    let decision = configure_baseline_recheck(&mut config, &policy_path, args.baseline_recheck)?;
    info!(
        policy = %policy_path.display(),
        source_match = ?decision.source_match,
        baseline_recheck = decision.enabled,
        reason = decision.reason,
        "comparison recording policy resolved"
    );
    run_comparison_recording_with_options(
        config,
        ComparisonRecordingRunOptions {
            run_id: args.run_id,
            duration: Some(Duration::from_secs(args.duration_seconds.get())),
            recording_apis: args.apis,
            control_socket: args.control_socket,
        },
    )
    .await
}

#[derive(Debug)]
struct BaselineRecheckDecision {
    source_match: ComparisonSourceMatch,
    enabled: bool,
    reason: &'static str,
}

fn configure_baseline_recheck(
    config: &mut AppConfig,
    policy_path: &Path,
    explicitly_enabled: bool,
) -> Result<BaselineRecheckDecision> {
    let policy = validate_replay_policy(policy_path)?;
    ensure!(
        policy.runner_owned_response_assertions,
        "comparison recording requires verification policy version 2"
    );
    let comparison = config
        .comparison_recording
        .as_mut()
        .expect("comparison recording config was validated");
    let configured = comparison.baseline_recheck;
    let policy_required = policy.comparison.source_match == ComparisonSourceMatch::BeforeOrAfter;
    comparison.baseline_recheck = configured || explicitly_enabled || policy_required;
    let reason = if policy_required {
        "source_match_before_or_after"
    } else if explicitly_enabled {
        "command_line"
    } else if configured {
        "recorder_config"
    } else {
        "disabled"
    };
    Ok(BaselineRecheckDecision {
        source_match: policy.comparison.source_match,
        enabled: comparison.baseline_recheck,
        reason,
    })
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
    use std::fs;

    use clap::Parser;
    use tempfile::tempdir;

    use super::*;

    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        record_comparison: RecordComparisonArgs,
    }

    #[test]
    fn parses_record_comparison_arguments_and_optional_policy() {
        let parsed = TestCli::try_parse_from([
            "test",
            "--config",
            "recorder.toml",
            "--policy",
            "verification.yaml",
            "--candidate-upstream",
            "http://172.30.0.2:8080",
            "--candidate-motan-upstream",
            "172.30.0.2:8002",
            "--run-id",
            "20260722153045",
            "--duration-seconds",
            "60",
            "--baseline-recheck",
            "--api",
            "GET /api/users/*",
            "--per-api-case-limit",
            "250",
            "--control-socket",
            "comparison.sock",
        ])
        .unwrap();
        assert_eq!(
            parsed.record_comparison.run_id.as_deref(),
            Some("20260722153045")
        );
        assert_eq!(
            parsed.record_comparison.policy.as_deref(),
            Some(Path::new("verification.yaml"))
        );
        assert_eq!(
            parsed.record_comparison.candidate_upstream.as_deref(),
            Some("http://172.30.0.2:8080")
        );
        assert_eq!(
            parsed.record_comparison.candidate_motan_upstream.as_deref(),
            Some("172.30.0.2:8002")
        );
        assert_eq!(parsed.record_comparison.duration_seconds.get(), 60);
        assert_eq!(
            parsed.record_comparison.control_socket.as_deref(),
            Some(Path::new("comparison.sock"))
        );
        assert!(parsed.record_comparison.baseline_recheck);
        assert_eq!(
            parsed.record_comparison.apis[0].to_string(),
            "GET /api/users/*"
        );
        assert_eq!(
            parsed
                .record_comparison
                .per_api_case_limit
                .map(NonZeroUsize::get),
            Some(250)
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
            TestCli::try_parse_from([
                "test",
                "--config",
                "recorder.toml",
                "--per-api-case-limit",
                "0",
            ])
            .is_err()
        );

        let defaults = TestCli::try_parse_from(["test", "--config", "recorder.toml"]).unwrap();
        assert_eq!(defaults.record_comparison.duration_seconds.get(), 60);
        assert!(defaults.record_comparison.policy.is_none());
    }

    #[test]
    fn before_or_after_policy_enables_baseline_recheck() {
        let temp = tempdir().unwrap();
        let policy = temp.path().join("verification.yaml");
        fs::write(
            &policy,
            "version: 2\nexpected_response: assertions_only\nrules: []\nresponse_rules:\n  comparison:\n    source_match: before_or_after\n",
        )
        .unwrap();
        let mut config = AppConfig::load_comparison_recording(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("config/recorder.example.toml"),
        )
        .unwrap();

        let decision = configure_baseline_recheck(&mut config, &policy, false).unwrap();

        assert!(decision.enabled);
        assert_eq!(decision.source_match, ComparisonSourceMatch::BeforeOrAfter);
        assert_eq!(decision.reason, "source_match_before_or_after");
        assert!(
            config
                .comparison_recording
                .as_ref()
                .unwrap()
                .baseline_recheck
        );
    }

    #[test]
    fn before_policy_keeps_recheck_optional() {
        let temp = tempdir().unwrap();
        let policy = temp.path().join("verification.yaml");
        fs::write(
            &policy,
            "version: 2\nexpected_response: assertions_only\nrules: []\n",
        )
        .unwrap();
        let load_config = || {
            AppConfig::load_comparison_recording(
                Path::new(env!("CARGO_MANIFEST_DIR")).join("config/recorder.example.toml"),
            )
            .unwrap()
        };
        let mut disabled = load_config();
        let disabled_decision = configure_baseline_recheck(&mut disabled, &policy, false).unwrap();
        assert!(!disabled_decision.enabled);
        assert_eq!(disabled_decision.reason, "disabled");

        let mut enabled = load_config();
        let enabled_decision = configure_baseline_recheck(&mut enabled, &policy, true).unwrap();
        assert!(enabled_decision.enabled);
        assert_eq!(enabled_decision.reason, "command_line");
    }
}
