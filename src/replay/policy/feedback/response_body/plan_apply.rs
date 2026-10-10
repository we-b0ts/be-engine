use std::collections::BTreeSet;
use std::fs;

use anyhow::{Context, Result, ensure};

use super::*;
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
