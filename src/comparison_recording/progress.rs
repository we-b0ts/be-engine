use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Serialize;

use super::verification::{ComparisonVerificationApi, ComparisonVerificationReport};
use crate::verification_progress::{
    ApiObservation, LatestCounts, ProgressObservation, ProgressReport, VerificationStage,
    fingerprint, load, write,
};

pub fn update_comparison_progress(
    report: &ComparisonVerificationReport,
    progress_path: &Path,
) -> Result<bool> {
    if !report.complete {
        return Ok(false);
    }
    let mut progress = load(progress_path, VerificationStage::Comparison)?
        .unwrap_or_else(|| ProgressReport::new(VerificationStage::Comparison));
    let requires_persistence = progress.requires_persistence();
    let applied = progress.apply(observation(report)?)?;
    if applied || requires_persistence {
        write(progress_path, &progress)?;
    }
    Ok(applied)
}

fn observation(report: &ComparisonVerificationReport) -> Result<ProgressObservation> {
    let evidence = ComparisonEvidence {
        recording_summary_fingerprint: &report.recording_summary_fingerprint,
        policy_fingerprint: &report.policy_fingerprint,
        passed: report.passed,
        counts: &report.counts,
        apis: &report.apis,
    };
    Ok(ProgressObservation {
        key: report.recording_summary_fingerprint.clone(),
        evidence_fingerprint: fingerprint(&serde_json::to_vec(&evidence)?),
        finished_at: chrono::Utc::now().to_rfc3339(),
        apis: report
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
                        passed: result.passed,
                    },
                ))
            })
            .collect::<Result<BTreeMap<_, _>>>()?,
    })
}

#[derive(Serialize)]
struct ComparisonEvidence<'a> {
    recording_summary_fingerprint: &'a str,
    policy_fingerprint: &'a str,
    passed: bool,
    counts: &'a super::verification::ComparisonVerificationCounts,
    apis: &'a BTreeMap<String, ComparisonVerificationApi>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::comparison_recording::verification::{
        ComparisonVerificationApiCounts, ComparisonVerificationCounts,
    };
    use crate::replay::ComparisonSourceMatch;

    fn report(
        summary_fingerprint: &str,
        policy_fingerprint: &str,
        passed: usize,
        failed: usize,
    ) -> ComparisonVerificationReport {
        let total = passed + failed;
        ComparisonVerificationReport {
            version: 5,
            kind: "comparison_recording_verification".to_string(),
            case_source: "/cases".to_string(),
            recording_summary_path: "/cases/comparison-recording-run.json".to_string(),
            recording_summary_fingerprint: summary_fingerprint.to_string(),
            expected_response: "assertions_only".to_string(),
            assertion_mode: "comparison_recording".to_string(),
            baseline_recheck: "optional_source_consistency".to_string(),
            source_match: ComparisonSourceMatch::Before,
            policy_path: "/target/.traffic-e2e/verification.yaml".to_string(),
            policy_fingerprint: policy_fingerprint.to_string(),
            report_path: "/cases/comparison-report.json".to_string(),
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
                "GET /users".to_string(),
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

    #[test]
    fn updates_comparison_progress_after_each_complete_report() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("comparison-progress.yaml");

        update_comparison_progress(&report("run-1", "policy", 100, 0), &path).unwrap();
        update_comparison_progress(&report("run-2", "policy", 100, 0), &path).unwrap();

        let progress = load(&path, VerificationStage::Comparison).unwrap().unwrap();
        assert_eq!(progress.totals.runs.executed, 2);
        assert_eq!(progress.success_streak.runs, 2);
        assert_eq!(progress.success_streak.cases, 200);
        assert!(
            !std::fs::read_to_string(path)
                .unwrap()
                .contains("counted_runs:")
        );
        assert!(
            directory
                .path()
                .join("local/artifacts/progress/comparison-counted-runs.yaml")
                .is_file()
        );
    }

    #[test]
    fn does_not_count_incomplete_or_duplicate_reports() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("comparison-progress.yaml");
        let complete = report("run-1", "policy", 100, 0);
        let mut incomplete = report("run-2", "policy", 0, 1);
        incomplete.complete = false;

        assert!(update_comparison_progress(&complete, &path).unwrap());
        assert!(!update_comparison_progress(&complete, &path).unwrap());
        assert!(!update_comparison_progress(&incomplete, &path).unwrap());

        let progress = load(&path, VerificationStage::Comparison).unwrap().unwrap();
        assert_eq!(progress.totals.runs.executed, 1);
        assert_eq!(progress.success_streak.runs, 1);
    }

    #[test]
    fn rejects_reinterpreting_one_recording_with_another_policy() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("comparison-progress.yaml");

        update_comparison_progress(&report("run-1", "policy-1", 100, 0), &path).unwrap();
        update_comparison_progress(&report("run-2", "policy-1", 100, 0), &path).unwrap();
        assert!(!update_comparison_progress(&report("run-1", "policy-1", 100, 0), &path).unwrap());
        let error =
            update_comparison_progress(&report("run-1", "policy-2", 100, 0), &path).unwrap_err();

        assert!(error.to_string().contains("different evidence"));
        let progress = load(&path, VerificationStage::Comparison).unwrap().unwrap();
        assert_eq!(progress.totals.runs.executed, 2);
    }
}
