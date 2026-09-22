use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};

use super::verification::ComparisonVerificationReport;
use crate::verification_progress::{ApiObservation, LatestCounts, VerificationStage, load, write};

pub fn update_comparison_progress(
    report: &ComparisonVerificationReport,
    progress_path: &Path,
    recording_run_id: &str,
) -> Result<bool> {
    if !report.complete {
        return Ok(false);
    }
    let mut progress = load(progress_path, VerificationStage::Progress)?
        .context("standard recording progress is missing before comparison settlement")?;
    let requires_persistence = progress.requires_persistence();
    let applied = progress.settle_api_results(
        recording_run_id,
        chrono::Utc::now().to_rfc3339(),
        api_results(report)?,
    )?;
    if applied || requires_persistence {
        write(progress_path, &progress)?;
    }
    Ok(applied)
}

fn api_results(report: &ComparisonVerificationReport) -> Result<BTreeMap<String, ApiObservation>> {
    report
        .apis
        .iter()
        .map(|(api, result)| {
            Ok((
                api.clone(),
                ApiObservation {
                    cases: LatestCounts {
                        executed: u64::try_from(result.counts.total)
                            .context("comparison API case count exceeds u64")?,
                        passed: u64::try_from(result.counts.passed)
                            .context("comparison API passed count exceeds u64")?,
                    },
                    finalized: true,
                    passed: result.passed,
                    success_streak: None,
                },
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::comparison_recording::verification::{
        ComparisonVerificationApi, ComparisonVerificationApiCounts, ComparisonVerificationCounts,
    };
    use crate::replay::ComparisonSourceMatch;

    fn report(
        summary_fingerprint: &str,
        api: &str,
        passed: usize,
        failed: usize,
    ) -> ComparisonVerificationReport {
        let total = passed + failed;
        ComparisonVerificationReport {
            version: 5,
            kind: "comparison_recording_verification".to_string(),
            case_source: format!("/cases/{summary_fingerprint}"),
            recording_summary_path: format!(
                "/cases/{summary_fingerprint}/comparison-recording-run.json"
            ),
            recording_summary_fingerprint: summary_fingerprint.to_string(),
            expected_response: "assertions_only".to_string(),
            assertion_mode: "comparison_recording".to_string(),
            baseline_recheck: "optional_source_consistency".to_string(),
            source_match: ComparisonSourceMatch::Before,
            policy_path: "/target/.traffic-e2e/verification.yaml".to_string(),
            policy_fingerprint: "policy".to_string(),
            report_path: format!("/cases/{summary_fingerprint}/comparison-report.json"),
            complete: true,
            passed: failed == 0,
            counts: ComparisonVerificationCounts {
                total,
                passed,
                failed,
                apis_total: 1,
                apis_passed: usize::from(failed == 0),
                apis_failed: usize::from(failed > 0),
                ..ComparisonVerificationCounts::default()
            },
            apis: BTreeMap::from([(
                api.to_string(),
                ComparisonVerificationApi {
                    passed: failed == 0,
                    counts: ComparisonVerificationApiCounts {
                        total,
                        passed,
                        failed,
                        ..ComparisonVerificationApiCounts::default()
                    },
                },
            )]),
            representative_difference: None,
            representative_policy_mismatch: None,
            cases: Vec::new(),
        }
    }

    fn record_batch(path: &Path, key: &str, apis: &[(&str, u64)]) {
        crate::verification_progress::record_completed_batch(
            path,
            key,
            "2026-08-15T00:00:00Z".to_string(),
            apis.iter()
                .map(|(api, cases)| ((*api).to_string(), *cases))
                .collect(),
        )
        .unwrap();
    }

    #[test]
    fn comparison_settles_one_standard_batch_without_counting_another_run() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("progress.yaml");
        record_batch(&path, "standard-1", &[("GET /users", 100)]);

        assert!(
            update_comparison_progress(
                &report("comparison-1", "GET /users", 100, 0),
                &path,
                "standard-1",
            )
            .unwrap()
        );
        assert!(
            !update_comparison_progress(
                &report("comparison-2", "GET /users", 100, 0),
                &path,
                "standard-1",
            )
            .unwrap()
        );

        let progress = load(&path, VerificationStage::Progress).unwrap().unwrap();
        assert_eq!(progress.totals.runs.executed, 1);
        assert_eq!(progress.totals.runs.passed, 1);
        assert_eq!(progress.totals.cases.executed, 100);
        assert_eq!(progress.totals.cases.passed, 100);
        assert_eq!(progress.success_streak.runs, 1);
        assert_eq!(progress.success_streak.cases, 100);
        assert!(
            !std::fs::read_to_string(path)
                .unwrap()
                .contains("counted_runs:")
        );
        assert!(
            directory
                .path()
                .join("local/artifacts/progress/counted-runs.yaml")
                .is_file()
        );
    }

    #[test]
    fn comparison_does_not_settle_an_incomplete_report() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("progress.yaml");
        record_batch(&path, "standard-1", &[("GET /users", 100)]);
        let mut incomplete = report("comparison-1", "GET /users", 99, 1);
        incomplete.complete = false;

        assert!(!update_comparison_progress(&incomplete, &path, "standard-1").unwrap());

        let progress = load(&path, VerificationStage::Progress).unwrap().unwrap();
        assert_eq!(progress.totals.runs.executed, 1);
        assert_eq!(progress.totals.runs.passed, 0);
        assert_eq!(progress.success_streak.runs, 0);
    }

    #[test]
    fn failed_partial_comparison_preserves_the_standard_case_inventory() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("progress.yaml");
        record_batch(&path, "standard-1", &[("GET /users", 100)]);

        assert!(
            update_comparison_progress(
                &report("comparison-1", "GET /users", 9, 1),
                &path,
                "standard-1",
            )
            .unwrap()
        );

        let progress = load(&path, VerificationStage::Progress).unwrap().unwrap();
        let observation = &progress.counted_observations["standard-1"].observation;
        assert_eq!(observation.apis["GET /users"].cases.executed, 100);
        assert_eq!(observation.apis["GET /users"].cases.passed, 9);
        assert!(!observation.apis["GET /users"].passed);
    }

    #[test]
    fn passing_partial_comparison_cannot_settle_the_standard_batch() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("progress.yaml");
        record_batch(&path, "standard-1", &[("GET /users", 100)]);

        let error = update_comparison_progress(
            &report("comparison-1", "GET /users", 10, 0),
            &path,
            "standard-1",
        )
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("does not cover the standard recording case inventory")
        );
    }

    #[test]
    fn comparison_failure_then_success_does_not_reconnect_the_old_streak() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("progress.yaml");
        record_batch(&path, "standard-1", &[("GET /users", 100)]);
        update_comparison_progress(
            &report("comparison-1", "GET /users", 100, 0),
            &path,
            "standard-1",
        )
        .unwrap();
        record_batch(&path, "standard-2", &[("GET /users", 100)]);

        update_comparison_progress(
            &report("comparison-2", "GET /users", 99, 1),
            &path,
            "standard-2",
        )
        .unwrap();
        update_comparison_progress(
            &report("comparison-3", "GET /users", 100, 0),
            &path,
            "standard-2",
        )
        .unwrap();

        let progress = load(&path, VerificationStage::Progress).unwrap().unwrap();
        assert_eq!(progress.totals.runs.executed, 2);
        assert_eq!(progress.totals.runs.passed, 2);
        assert_eq!(progress.success_streak.runs, 1);
        assert_eq!(progress.success_streak.cases, 100);
    }

    #[test]
    fn per_api_comparisons_settle_one_multi_api_standard_batch() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("progress.yaml");
        record_batch(
            &path,
            "standard-1",
            &[("GET /rules", 12), ("POST /config", 394)],
        );

        update_comparison_progress(
            &report("comparison-1", "GET /rules", 12, 0),
            &path,
            "standard-1",
        )
        .unwrap();
        let partial = load(&path, VerificationStage::Progress).unwrap().unwrap();
        assert_eq!(partial.totals.runs.executed, 1);
        assert_eq!(partial.totals.runs.passed, 0);
        assert_eq!(partial.totals.cases.executed, 406);
        assert_eq!(partial.totals.cases.passed, 12);

        update_comparison_progress(
            &report("comparison-2", "POST /config", 394, 0),
            &path,
            "standard-1",
        )
        .unwrap();
        let complete = load(&path, VerificationStage::Progress).unwrap().unwrap();
        assert_eq!(complete.totals.runs.executed, 1);
        assert_eq!(complete.totals.runs.passed, 1);
        assert_eq!(complete.totals.cases.executed, 406);
        assert_eq!(complete.totals.cases.passed, 406);
    }
}
