use anyhow::Result;
use serde_json::{Value, json};

use super::issue;
use super::model::{RewriteIssue, RewriteIssueKind, RewriteIssueOwner};
use crate::{ComparisonVerificationClassification, ComparisonVerificationReport};

const ERROR_PREVIEW_CHARACTERS: usize = 1_024;

pub(super) fn from_report(
    api: &str,
    report: &ComparisonVerificationReport,
    target_fingerprint: String,
    attempt: u64,
) -> Result<RewriteIssue> {
    if !report.complete {
        return Ok(incomplete_issue(api, report, target_fingerprint, attempt));
    }

    let observation = report
        .representative_difference
        .as_ref()
        .map(serde_json::to_value)
        .transpose()?;
    let pointer = observation
        .as_ref()
        .and_then(|value| value.get("pointer"))
        .and_then(Value::as_str)
        .unwrap_or("<comparison>");
    let response_body_candidate = observation.as_ref().is_some_and(|value| {
        value
            .get("body_diagnosis")
            .is_some_and(|body| !body.is_null())
    });
    Ok(RewriteIssue {
        id: issue::id(api, "comparison", pointer),
        kind: RewriteIssueKind::Comparison,
        owner: if response_body_candidate {
            RewriteIssueOwner::SourceInvestigation
        } else {
            RewriteIssueOwner::TargetCode
        },
        summary: format!(
            "comparison has {} candidate difference(s) and {} inconclusive case(s)",
            report.counts.failed, report.counts.inconclusive
        ),
        pointer_pattern: (pointer != "<comparison>")
            .then(|| crate::e2e_run::response_pointer_pattern(pointer)),
        representative: None,
        egress_rejections: None,
        recorder_capture_diagnosis: None,
        response_diagnosis: None,
        possible_causes: if response_body_candidate {
            vec![
                "structured_response_body_order_candidate".to_string(),
                "source_contract_must_prove_order_is_irrelevant".to_string(),
            ]
        } else {
            vec![
                "target_behavior".to_string(),
                "intentional_source_nondeterminism".to_string(),
                "source_changed_during_comparison".to_string(),
                "verification_policy_gap".to_string(),
            ]
        },
        observed_target_fingerprint: target_fingerprint,
        attempt,
        comparison_observation: observation,
    })
}

fn incomplete_issue(
    api: &str,
    report: &ComparisonVerificationReport,
    target_fingerprint: String,
    attempt: u64,
) -> RewriteIssue {
    let representative = report
        .cases
        .iter()
        .find(|case| case.classification == ComparisonVerificationClassification::Unevaluable);
    let (error, error_truncated) = bounded_error(
        representative
            .and_then(|case| case.error.as_deref())
            .unwrap_or("comparison case was unevaluable without a reported cause"),
    );
    let observation = json!({
        "api": representative.map_or(api, |case| case.api.as_str()),
        "case_id": representative.map(|case| case.case_id.as_str()),
        "classification": "unevaluable",
        "error": error,
        "error_truncated": error_truncated,
        "counts": {
            "candidate_differences": report.counts.failed,
            "inconclusive": report.counts.inconclusive,
            "unevaluable": report.counts.unevaluable,
        },
    });
    RewriteIssue {
        id: issue::id(api, "comparison", "<unevaluable>"),
        kind: RewriteIssueKind::Comparison,
        owner: RewriteIssueOwner::TrafficE2eSystem,
        summary: format!(
            "comparison verification is incomplete: {} unevaluable case(s), {} candidate difference(s), and {} inconclusive case(s)",
            report.counts.unevaluable, report.counts.failed, report.counts.inconclusive
        ),
        pointer_pattern: None,
        representative: None,
        egress_rejections: None,
        recorder_capture_diagnosis: None,
        response_diagnosis: None,
        possible_causes: vec![
            "comparison_verification_capability_gap".to_string(),
            "replay_capability_gap".to_string(),
        ],
        observed_target_fingerprint: target_fingerprint,
        attempt,
        comparison_observation: Some(observation),
    }
}

fn bounded_error(error: &str) -> (String, bool) {
    let mut characters = error.chars();
    let preview = characters
        .by_ref()
        .take(ERROR_PREVIEW_CHARACTERS)
        .collect::<String>();
    (preview, characters.next().is_some())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::{ComparisonSourceMatch, ComparisonVerificationCase, ComparisonVerificationCounts};

    fn report() -> ComparisonVerificationReport {
        ComparisonVerificationReport {
            version: 5,
            kind: "comparison_recording_verification".to_string(),
            case_source: "/comparison".to_string(),
            recording_summary_path: "/comparison/summary.json".to_string(),
            recording_summary_fingerprint: "fnv1a64:summary".to_string(),
            expected_response: "assertions_only".to_string(),
            assertion_mode: "comparison_recording".to_string(),
            baseline_recheck: "optional_source_consistency".to_string(),
            source_match: ComparisonSourceMatch::Before,
            policy_path: "/target/.traffic-e2e/verification.yaml".to_string(),
            policy_fingerprint: "fnv1a64:policy".to_string(),
            report_path: "/comparison/report.json".to_string(),
            complete: false,
            passed: false,
            counts: ComparisonVerificationCounts {
                total: 47,
                failed: 14,
                unevaluable: 33,
                apis_total: 1,
                apis_failed: 1,
                ..ComparisonVerificationCounts::default()
            },
            apis: BTreeMap::new(),
            representative_difference: None,
            representative_policy_mismatch: None,
            cases: vec![ComparisonVerificationCase {
                case_id: "case-unevaluable".to_string(),
                case_dir: "/comparison/case-unevaluable".to_string(),
                api: "MOTAN /rpc/example".to_string(),
                classification: ComparisonVerificationClassification::Unevaluable,
                passed: false,
                response: None,
                baseline_recheck: None,
                response_after: None,
                matched_source: None,
                source_change_pointers: Vec::new(),
                candidate_only_pointers: Vec::new(),
                policy_mismatch_rule_ids: Vec::new(),
                error: Some("Hessian2 wildcard path does not select a list".to_string()),
            }],
        }
    }

    #[test]
    fn incomplete_comparison_is_a_bounded_traffic_system_issue() {
        let issue = from_report(
            "MOTAN /rpc/example",
            &report(),
            "fnv1a64:target".to_string(),
            4,
        )
        .unwrap();

        assert_eq!(issue.owner, RewriteIssueOwner::TrafficE2eSystem);
        assert!(issue.pointer_pattern.is_none());
        assert!(issue.summary.contains("33 unevaluable case(s)"));
        assert_eq!(
            issue
                .comparison_observation
                .as_ref()
                .unwrap()
                .pointer("/counts/unevaluable"),
            Some(&json!(33))
        );
        assert_eq!(
            issue.comparison_observation.as_ref().unwrap().get("error"),
            Some(&json!("Hessian2 wildcard path does not select a list"))
        );
    }
}
