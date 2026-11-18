//! Merge content findings into the API-owned response report.
use super::model::ResponseAssertionCaseReport;
use crate::policy::runtime::ResponseField;
use crate::value_contract::json::AnchorClocks;
use serde_json::Value;
use std::collections::BTreeSet;

pub(super) fn compare_json(
    source: &Value,
    target: &Value,
    fields: &[ResponseField],
    report: &mut ResponseAssertionCaseReport,
    clocks: AnchorClocks,
) -> Vec<ResponseField> {
    let mut jwt = super::jwt::JwtComparison::load(
        fields,
        std::path::Path::new(&report.policy_path),
        std::path::Path::new(&report.request_path),
        source,
        target,
    );
    let (applicable, result) = traffic_policy_content::json::compare_json(
        traffic_extensions::policies(),
        source,
        target,
        fields,
        clocks,
        &mut jwt,
    );
    report.differences.extend(result.differences);
    report
        .applied_generated_rule_ids
        .extend(result.applied_generated_rule_ids);
    report
        .applied_unordered_rule_ids
        .extend(result.applied_unordered_rule_ids);
    report
        .applied_unordered_joined_string_rule_ids
        .extend(result.applied_unordered_joined_string_rule_ids);
    report
        .unordered_joined_string_candidates
        .extend(result.unordered_joined_string_candidates);
    for ids in [
        &mut report.applied_generated_rule_ids,
        &mut report.applied_unordered_rule_ids,
        &mut report.applied_unordered_joined_string_rule_ids,
    ] {
        let mut seen = BTreeSet::new();
        ids.retain(|id| seen.insert(id.clone()));
    }
    applicable
}
