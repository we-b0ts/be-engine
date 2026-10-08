//! Header-only proof does not require or reinterpret the response body's codec.
use super::evidence::{Witnesses, read};
use super::*;
use crate::replay::{
    ResponseAssertionCaseReport,
    policy::pattern::{path_pattern_matches, uri_path},
};
use serde_json::Value;
use std::collections::BTreeMap;

pub(super) fn validate(
    feedback: &ResponseHeaderDateRuleFeedback,
    policy: &str,
) -> Result<(usize, usize, Witnesses)> {
    let mut witnesses = Vec::new();
    let mut observations = Vec::new();
    match &feedback.evidence {
        ResponseBodyRuleEvidence::FocusedE2e {
            assertion_report,
            aggregate_report,
        } => {
            let aggregate: super::super::evidence::AggregateEvidence =
                serde_json::from_slice(&read(aggregate_report.clone(), &mut witnesses)?)?;
            let assertions: super::super::evidence::AssertionEvidence =
                serde_json::from_slice(&read(assertion_report.clone(), &mut witnesses)?)?;
            ensure!(
                aggregate.complete
                    && aggregate.case_source == assertions.case_source
                    && assertions.expected_response == "assertions_only"
                    && assertions.policy_fingerprint.as_deref() == Some(policy),
                "header date evidence is incomplete or uses a different policy/oracle"
            );
            for case in assertions.cases {
                let Some(summary) = case.response else {
                    continue;
                };
                if !path_pattern_matches(&feedback.api, &summary.path) {
                    continue;
                }
                ensure!(
                    aggregate.selected_case_ids.contains(&case.case_id),
                    "header date case is outside the completed replay scope"
                );
                let bytes = read(
                    summary
                        .detail_report
                        .context("header date evidence requires its assertion detail")?,
                    &mut witnesses,
                )?;
                ensure!(
                    Some(fingerprint(&bytes)) == summary.detail_fingerprint,
                    "header assertion detail changed"
                );
                let detail: ResponseAssertionCaseReport = serde_json::from_slice(&bytes)?;
                ensure!(
                    detail.case_id == case.case_id
                        && detail.path == summary.path
                        && detail.policy_fingerprint == policy,
                    "header assertion detail has a different scope or policy"
                );
                observations.push(detail);
            }
        }
        ResponseBodyRuleEvidence::Comparison { comparison_report } => {
            let report: crate::comparison_recording::ComparisonVerificationReport =
                serde_json::from_slice(&read(comparison_report.clone(), &mut witnesses)?)?;
            ensure!(
                report.complete
                    && report.policy_fingerprint == policy
                    && report.expected_response == "assertions_only",
                "header date comparison evidence is incomplete or stale"
            );
            for case in report.cases {
                let Some(response) = case.response else {
                    continue;
                };
                if !path_pattern_matches(&feedback.api, &response.path) {
                    continue;
                }
                ensure!(
                    case.source_change_pointers.is_empty(),
                    "source changes cannot authorize header dates"
                );
                observations.push(response);
            }
        }
    }
    let mut by_header = BTreeMap::<String, Vec<ResponseHeaderDateRule>>::new();
    for rule in &feedback.rules {
        by_header
            .entry(rule.header.to_ascii_lowercase())
            .or_default()
            .push(rule.clone());
    }
    let matching = observations.len();
    let mut differences = 0;
    for observation in observations {
        let request: Value =
            serde_json::from_slice(&read(observation.request_path.into(), &mut witnesses)?)?;
        ensure!(
            uri_path(request["uri"].as_str().unwrap_or_default()) == observation.path,
            "header request identity differs from assertion evidence"
        );
        let source_bytes = read(observation.expected_response_path.into(), &mut witnesses)?;
        let target_bytes = read(observation.actual_response_path.into(), &mut witnesses)?;
        ensure!(
            fingerprint(&source_bytes) == observation.expected_response_fingerprint
                && fingerprint(&target_bytes) == observation.actual_response_fingerprint,
            "header response evidence changed since assertion"
        );
        let source: Value = serde_json::from_slice(&source_bytes)?;
        let target: Value = serde_json::from_slice(&target_bytes)?;
        let times = crate::replay::assertion::RequestTimes {
            source: request["timestamp"]
                .as_str()
                .and_then(|time| time.parse().ok()),
            target: target["request_sent_at"]
                .as_str()
                .or_else(|| target["timestamp"].as_str())
                .and_then(|time| time.parse().ok()),
        };
        let source_headers: crate::recorder::HeaderMapSnapshot =
            serde_json::from_value(source["headers"].clone())?;
        let target_headers: crate::recorder::HeaderMapSnapshot =
            serde_json::from_value(target["headers"].clone())?;
        let mut changed = false;
        for (header, rules) in &by_header {
            let source_values = source_headers
                .get(header)
                .context("source header is absent")?;
            let target_values = target_headers
                .get(header)
                .context("target header is absent")?;
            ensure!(
                !source_values
                    .iter()
                    .chain(target_values)
                    .any(|value| value == "<redacted>"),
                "redacted headers cannot authorize a date rule"
            );
            ensure!(
                crate::replay::assertion::headers::date::compare(
                    source_values,
                    target_values,
                    rules,
                    times
                )?,
                "stable response header values differ"
            );
            changed |= source_values != target_values;
        }
        differences += usize::from(changed);
    }
    ensure!(
        matching > 0 && differences > 0,
        "header date planning requires a selected dynamic difference"
    );
    Ok((matching, differences, witnesses))
}
