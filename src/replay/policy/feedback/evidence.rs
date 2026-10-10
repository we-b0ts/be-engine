use std::collections::BTreeSet;
use std::path::PathBuf;

use serde::Deserialize;

use super::super::response::{
    ResponseBodyCodec, ResponseRuleKind, ResponseRules, response_pointer_matches,
};
use crate::replay::JsonJoinedStringCandidate;
use crate::replay::ResponseGatewayProtocol;

#[derive(Debug, Deserialize)]
pub(super) struct AssertionEvidence {
    pub(super) version: u32,
    pub(super) case_source: String,
    pub(super) expected_response: String,
    pub(super) assertion_mode: String,
    pub(super) policy_fingerprint: Option<String>,
    pub(super) cases: Vec<AssertionCaseEvidence>,
}

#[derive(Debug, Deserialize)]
pub(super) struct AssertionCaseEvidence {
    pub(super) case_id: String,
    #[serde(default)]
    pub(super) passed: bool,
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
    pub(super) body_codec: ResponseBodyCodec,
    #[serde(default)]
    pub(super) gateway_protocol: Option<ResponseGatewayProtocol>,
    #[serde(default)]
    pub(super) differences: Vec<DifferenceEvidence>,
    #[serde(default)]
    pub(super) detail_report: Option<PathBuf>,
    #[serde(default)]
    pub(super) detail_fingerprint: Option<String>,
    #[serde(default)]
    pub(super) request: Option<PathBuf>,
    #[serde(default)]
    pub(super) expected_response: Option<PathBuf>,
    #[serde(default)]
    pub(super) actual_response: Option<PathBuf>,
    #[serde(default)]
    pub(super) policy_fingerprint: String,
    #[serde(default)]
    pub(super) difference_count: usize,
    #[serde(default)]
    applied_generated_rule_ids: Vec<String>,
    #[serde(default)]
    generated_scalar_candidates: Vec<String>,
    #[serde(default)]
    applied_unordered_rule_ids: Vec<String>,
    #[serde(default)]
    unordered_candidates: Vec<String>,
    #[serde(default)]
    unordered_joined_string_candidates: Vec<JsonJoinedStringCandidate>,
    #[serde(default)]
    applied_unordered_joined_string_rule_ids: Vec<String>,
}

impl ResponseCaseEvidence {
    pub(super) fn has_candidate(
        &self,
        kind: ResponseRuleKind,
        pointer: &str,
        separator: Option<&str>,
    ) -> bool {
        match kind {
            kind if kind.is_generated() => self
                .generated_scalar_candidates
                .iter()
                .any(|candidate| response_pointer_matches(pointer, candidate)),
            ResponseRuleKind::Unordered => self
                .unordered_candidates
                .iter()
                .any(|candidate| response_pointer_matches(pointer, candidate)),
            ResponseRuleKind::UnorderedJoinedString => self
                .unordered_joined_string_candidates
                .iter()
                .any(|candidate| {
                    response_pointer_matches(pointer, &candidate.pointer)
                        && separator.is_some_and(|separator| candidate.separator == separator)
                }),
            _ => unreachable!("all response rule kinds are covered"),
        }
    }

    pub(super) fn applied_rule_ids(&self, kind: ResponseRuleKind) -> &[String] {
        match kind {
            kind if kind.is_generated() => &self.applied_generated_rule_ids,
            ResponseRuleKind::Unordered => &self.applied_unordered_rule_ids,
            ResponseRuleKind::UnorderedJoinedString => {
                &self.applied_unordered_joined_string_rule_ids
            }
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
    if !requested
        .iter()
        .any(|pointer| response_pointer_matches(pointer, &difference.pointer))
    {
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
        ResponseRuleKind::UnorderedJoinedString => {
            difference.kind == "value_mismatch"
                && difference.expected_type.as_deref() == Some("string")
                && difference.actual_type.as_deref() == Some("string")
        }
        _ => unreachable!("all response rule kinds are covered"),
    }
}

pub(super) fn response_rule_exists(
    rules: &ResponseRules,
    kind: ResponseRuleKind,
    api: &str,
    pointer: &str,
    separator: Option<&str>,
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
        ResponseRuleKind::UnorderedJoinedString => {
            api_rules.unordered_joined_string.iter().any(|field| {
                field.pointer == pointer
                    && separator.is_some_and(|separator| field.separator == separator)
            })
        }
        _ => unreachable!("all response rule kinds are covered"),
    }
}
