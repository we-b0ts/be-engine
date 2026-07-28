use std::collections::BTreeSet;

use serde::Deserialize;

use super::super::response::{ResponseRuleKind, ResponseRules, response_locations_overlap};

#[derive(Debug, Deserialize)]
pub(super) struct AssertionEvidence {
    pub(super) case_source: String,
    pub(super) expected_response: String,
    pub(super) assertion_mode: String,
    pub(super) policy_fingerprint: Option<String>,
    pub(super) cases: Vec<AssertionCaseEvidence>,
}

#[derive(Debug, Deserialize)]
pub(super) struct ComparisonEvidence {
    pub(super) version: u8,
    pub(super) kind: String,
    pub(super) expected_response: String,
    pub(super) assertion_mode: String,
    pub(super) baseline_recheck: String,
    pub(super) policy_fingerprint: String,
    pub(super) complete: bool,
    pub(super) cases: Vec<AssertionCaseEvidence>,
}

#[derive(Debug, Deserialize)]
pub(super) struct AssertionCaseEvidence {
    pub(super) case_id: String,
    #[serde(default)]
    pub(super) classification: Option<String>,
    #[serde(default)]
    pub(super) source_change_pointers: Vec<String>,
    #[serde(default)]
    pub(super) policy_mismatch_rule_ids: Vec<String>,
    pub(super) response: Option<ResponseCaseEvidence>,
}

#[derive(Debug, Deserialize)]
pub(super) struct ResponseCaseEvidence {
    pub(super) method: String,
    pub(super) path: String,
    pub(super) body_mode: String,
    pub(super) differences: Vec<DifferenceEvidence>,
    #[serde(default)]
    applied_dynamic_rule_ids: Vec<String>,
    #[serde(default)]
    dynamic_candidates: Vec<String>,
    #[serde(default)]
    applied_unordered_rule_ids: Vec<String>,
    #[serde(default)]
    unordered_candidates: Vec<String>,
}

impl ResponseCaseEvidence {
    pub(super) fn candidates(&self, kind: ResponseRuleKind) -> &[String] {
        match kind {
            ResponseRuleKind::Dynamic => &self.dynamic_candidates,
            ResponseRuleKind::Unordered => &self.unordered_candidates,
        }
    }

    pub(super) fn applied_rule_ids(&self, kind: ResponseRuleKind) -> &[String] {
        match kind {
            ResponseRuleKind::Dynamic => &self.applied_dynamic_rule_ids,
            ResponseRuleKind::Unordered => &self.applied_unordered_rule_ids,
        }
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct DifferenceEvidence {
    pub(super) pointer: String,
    pub(super) kind: String,
    pub(super) expected_type: Option<String>,
    pub(super) actual_type: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct AggregateEvidence {
    pub(super) case_source: String,
    pub(super) selected_case_ids: Vec<String>,
    pub(super) complete: bool,
    pub(super) dirty: bool,
}

pub(super) fn difference_supports_rule(
    kind: ResponseRuleKind,
    difference: &DifferenceEvidence,
    requested: &BTreeSet<String>,
) -> bool {
    if !requested.contains(&difference.pointer) {
        return false;
    }
    match kind {
        ResponseRuleKind::Dynamic => {
            difference.kind == "value_mismatch"
                && difference.expected_type == difference.actual_type
                && difference
                    .expected_type
                    .as_deref()
                    .is_some_and(|kind| matches!(kind, "string" | "number" | "boolean"))
        }
        ResponseRuleKind::Unordered => {
            difference.kind == "array_order_mismatch"
                && difference.expected_type.as_deref() == Some("array")
                && difference.actual_type.as_deref() == Some("array")
        }
    }
}

pub(super) fn response_rule_exists(
    rules: &ResponseRules,
    kind: ResponseRuleKind,
    api: &str,
    pointer: &str,
) -> bool {
    match kind {
        ResponseRuleKind::Dynamic => rules
            .dynamic
            .get(api)
            .is_some_and(|fields| fields.iter().any(|field| field.pointer == pointer)),
        ResponseRuleKind::Unordered => rules
            .unordered
            .get(api)
            .is_some_and(|pointers| pointers.iter().any(|candidate| candidate == pointer)),
    }
}

pub(super) fn source_change_overlaps(
    case: &AssertionCaseEvidence,
    requested: &BTreeSet<String>,
) -> bool {
    case.source_change_pointers.iter().any(|source| {
        requested
            .iter()
            .any(|pointer| response_locations_overlap(source, pointer))
    })
}
