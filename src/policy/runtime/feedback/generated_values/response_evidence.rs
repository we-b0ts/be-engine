//! Protected response observations shared by generated response rule planners.
use super::evidence::{Witnesses, read};
use super::*;
use crate::policy::runtime::pattern::path_pattern_matches;
use crate::primary_protocol::assertion::ResponseAssertionCaseReport;

fn matches(api: &str, method: &str, path: &str) -> bool {
    let (expected_method, pattern) = api.split_once(' ').unwrap_or((method, api));
    expected_method == method && path_pattern_matches(pattern, path)
}

pub(super) fn collect(
    evidence: &ResponseBodyRuleEvidence,
    api: &str,
    policy: &str,
    witnesses: &mut Witnesses,
) -> Result<Vec<ResponseAssertionCaseReport>> {
    let mut observations = Vec::new();
    match evidence {
        ResponseBodyRuleEvidence::FocusedE2e {
            assertion_report,
            aggregate_report,
        } => {
            let aggregate: super::super::evidence::AggregateEvidence =
                serde_json::from_slice(&read(aggregate_report.clone(), witnesses)?)?;
            let assertions: super::super::evidence::AssertionEvidence =
                serde_json::from_slice(&read(assertion_report.clone(), witnesses)?)?;
            ensure!(
                aggregate.complete
                    && aggregate.case_source == assertions.case_source
                    && assertions.expected_response == "assertions_only"
                    && assertions.assertion_mode == "runner_owned"
                    && assertions.policy_fingerprint.as_deref() == Some(policy),
                "response rule evidence is incomplete or uses a different policy/oracle"
            );
            for case in assertions.cases {
                let Some(summary) = case.response else {
                    continue;
                };
                if !matches(api, &summary.method, &summary.path) {
                    continue;
                }
                ensure!(
                    aggregate.selected_case_ids.contains(&case.case_id),
                    "response rule case is outside the completed replay scope"
                );
                let bytes = read(
                    summary
                        .detail_report
                        .context("response rule evidence requires its assertion detail")?,
                    witnesses,
                )?;
                ensure!(
                    Some(fingerprint(&bytes)) == summary.detail_fingerprint,
                    "response assertion detail changed"
                );
                let detail: ResponseAssertionCaseReport = serde_json::from_slice(&bytes)?;
                ensure!(
                    detail.case_id == case.case_id
                        && detail.method == summary.method
                        && detail.path == summary.path
                        && detail.policy_fingerprint == policy,
                    "response assertion detail has a different scope or policy"
                );
                observations.push(detail);
            }
        }
    }
    Ok(observations)
}
