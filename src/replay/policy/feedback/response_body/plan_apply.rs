use std::collections::BTreeSet;
use std::fs;

use anyhow::{Context, Result, ensure};

use super::*;
use crate::comparison_recording::{ComparisonVerificationOptions, verify_comparison_recording};
use crate::config::edit::write_atomic;
use crate::replay::{ResponseAssertionOptions, assert_recorded_response};

impl ResponseBodyRulePlan {
    pub fn report(&self) -> &ResponseBodyRuleReport {
        &self.report
    }

    pub fn apply(self) -> Result<ResponseBodyRuleReport> {
        let current = fs::read_to_string(&self.policy_path).with_context(|| {
            format!(
                "failed to reread replay policy {}",
                self.policy_path.display()
            )
        })?;
        ensure!(
            current == self.original,
            "replay policy changed after planning; rerun plan before applying"
        );
        if self.report.changed {
            write_atomic(&self.policy_path, self.updated.as_bytes())?;
        }
        let mut report = self.report;
        let (body_reports, outcome) = match self.verification {
            ResponseBodyPlanVerification::Comparison { case_source } => {
                let verification = verify_comparison_recording(ComparisonVerificationOptions {
                    case_source,
                    policy: self.policy_path.clone(),
                    report: report.evidence_report.clone(),
                })?;
                let matching = verification
                    .cases
                    .iter()
                    .filter(|case| case.api == report.api)
                    .collect::<Vec<_>>();
                ensure!(
                    !matching.is_empty(),
                    "offline response-body verification contains no cases for {}",
                    report.api
                );
                let body_reports = matching
                    .iter()
                    .filter_map(|case| case.response.as_ref()?.body_diagnosis.clone())
                    .collect::<Vec<_>>();
                ensure!(
                    body_reports.len() == matching.len(),
                    "offline verification did not produce codec-aware body reports"
                );
                report.evidence_fingerprint = fingerprint(&read_regular(
                    &report.evidence_report,
                    "refreshed comparison report",
                )?);
                (
                    body_reports,
                    ResponseBodyRuleVerificationOutcome {
                        kind: ResponseBodyRuleEvidenceKind::Comparison,
                        complete: verification.complete,
                        passed: verification.passed,
                        cases: verification.counts.total,
                        failed: verification.counts.failed,
                    },
                )
            }
            ResponseBodyPlanVerification::FocusedE2e { cases } => {
                let mut body_reports = Vec::with_capacity(cases.len());
                let mut failed = 0usize;
                for case in &cases {
                    let assertion = assert_recorded_response(ResponseAssertionOptions {
                        case_id: case.case_id.clone(),
                        request: case.request.clone(),
                        expected_response: case.expected_response.clone(),
                        actual_response: case.actual_response.clone(),
                        policy: self.policy_path.clone(),
                    })?;
                    failed += usize::from(!assertion.passed);
                    if let Some(body) = assertion.body_diagnosis {
                        body_reports.push(body);
                    }
                }
                (
                    body_reports,
                    ResponseBodyRuleVerificationOutcome {
                        kind: ResponseBodyRuleEvidenceKind::FocusedE2e,
                        complete: true,
                        passed: failed == 0,
                        cases: cases.len(),
                        failed,
                    },
                )
            }
        };
        report.discovered_unordered_paths = body_reports
            .iter()
            .flat_map(|body| body.unordered_path_candidates.iter().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        report.discovered_unordered_joined_string_paths = body_reports
            .iter()
            .flat_map(|body| body.unordered_joined_string_candidates.iter().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        report.order_only = Some(body_reports.iter().all(|body| body.order_only));
        report.residual_difference_cases = outcome.failed;
        report.offline_verification = Some(outcome);
        report.policy_fingerprint = load_replay_policy(&self.policy_path)?.fingerprint;
        report.applied = true;
        Ok(report)
    }
}
