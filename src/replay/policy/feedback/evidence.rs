use std::collections::BTreeSet;
use std::path::PathBuf;

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
    pub(super) matched_source: Option<String>,
    #[serde(default)]
    pub(super) source_change_pointers: Vec<String>,
    #[serde(default)]
    pub(super) policy_mismatch_rule_ids: Vec<String>,
    pub(super) response: Option<ResponseCaseEvidence>,
}

#[derive(Debug, Deserialize)]
pub(super) struct ResponseCaseEvidence {
    #[serde(default)]
    pub(super) method: String,
    #[serde(default)]
    pub(super) path: String,
    #[serde(default)]
    pub(super) body_mode: String,
    #[serde(default)]
    pub(super) differences: Vec<DifferenceEvidence>,
    #[serde(default)]
    pub(super) detail_report: Option<PathBuf>,
    #[serde(default)]
    pub(super) detail_fingerprint: Option<String>,
    #[serde(default)]
    applied_generated_rule_ids: Vec<String>,
    #[serde(default)]
    generated_scalar_candidates: Vec<String>,
    #[serde(default)]
    applied_unordered_rule_ids: Vec<String>,
    #[serde(default)]
    unordered_candidates: Vec<String>,
    #[serde(default)]
    applied_counter_rule_ids: Vec<String>,
}

impl ResponseCaseEvidence {
    pub(super) fn candidates(&self, kind: ResponseRuleKind) -> &[String] {
        match kind {
            kind if kind.is_generated() => &self.generated_scalar_candidates,
            ResponseRuleKind::Unordered => &self.unordered_candidates,
            ResponseRuleKind::Counter => &[],
            _ => unreachable!("all response rule kinds are covered"),
        }
    }

    pub(super) fn applied_rule_ids(&self, kind: ResponseRuleKind) -> &[String] {
        match kind {
            kind if kind.is_generated() => &self.applied_generated_rule_ids,
            ResponseRuleKind::Unordered => &self.applied_unordered_rule_ids,
            ResponseRuleKind::Counter => &self.applied_counter_rule_ids,
            _ => unreachable!("all response rule kinds are covered"),
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
        kind if kind.is_generated() => {
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
        ResponseRuleKind::Counter => {
            difference.kind == "value_mismatch"
                && difference.expected_type == difference.actual_type
                && difference
                    .expected_type
                    .as_deref()
                    .is_some_and(|kind| matches!(kind, "string" | "number"))
        }
        _ => unreachable!("all response rule kinds are covered"),
    }
}

pub(super) fn response_rule_exists(
    rules: &ResponseRules,
    kind: ResponseRuleKind,
    api: &str,
    pointer: &str,
) -> bool {
    let Some(api_rules) = rules.json.get(api) else {
        return false;
    };
    match kind {
        kind if kind.is_generated() => api_rules
            .generated_for_kind(kind)
            .is_some_and(|fields| fields.iter().any(|field| field.pointer == pointer)),
        ResponseRuleKind::Unordered => api_rules
            .unordered
            .iter()
            .any(|field| field.pointer == pointer),
        ResponseRuleKind::Counter => api_rules
            .counter
            .iter()
            .any(|field| field.pointer == pointer),
        _ => unreachable!("all response rule kinds are covered"),
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
