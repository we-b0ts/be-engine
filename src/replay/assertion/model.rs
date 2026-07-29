use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::replay::policy::{ResponseField, ResponseRuleKind};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResponseBodyMode {
    Unknown,
    JsonStructural,
    ExactBytes,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResponseDifferenceKind {
    StatusMismatch,
    ValueMismatch,
    TypeMismatch,
    MissingActual,
    UnexpectedActual,
    ArrayLengthMismatch,
    ArrayOrderMismatch,
    ExactBodyMismatch,
    DynamicFieldNotScalar,
    UnorderedFieldNotArray,
    UnorderedArrayContentMismatch,
    CounterFieldUnsupportedType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseDifference {
    pub pointer: String,
    pub kind: ResponseDifferenceKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual_status: Option<u16>,
}

impl ResponseDifference {
    pub(super) fn status(expected: u16, actual: u16) -> Self {
        Self {
            pointer: "$status".to_string(),
            kind: ResponseDifferenceKind::StatusMismatch,
            expected_type: None,
            actual_type: None,
            expected_status: Some(expected),
            actual_status: Some(actual),
        }
    }

    pub(super) fn exact_body_mismatch() -> Self {
        Self {
            pointer: "$body".to_string(),
            kind: ResponseDifferenceKind::ExactBodyMismatch,
            expected_type: None,
            actual_type: None,
            expected_status: None,
            actual_status: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseAssertionCaseReport {
    pub version: u8,
    pub case_id: String,
    pub method: String,
    pub path: String,
    pub policy_path: String,
    pub policy_fingerprint: String,
    pub expected_response_path: String,
    pub expected_response_fingerprint: String,
    pub actual_response_path: String,
    pub actual_response_fingerprint: String,
    pub body_mode: ResponseBodyMode,
    pub differences: Vec<ResponseDifference>,
    pub applied_dynamic_rule_ids: Vec<String>,
    pub unused_applicable_dynamic_rule_ids: Vec<String>,
    pub dynamic_candidates: Vec<String>,
    pub applied_unordered_rule_ids: Vec<String>,
    pub unused_applicable_unordered_rule_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub applied_counter_rule_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unused_applicable_counter_rule_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unobserved_response_rule_ids: Vec<String>,
    pub unordered_candidates: Vec<String>,
    pub passed: bool,
}

impl ResponseAssertionCaseReport {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        case_id: String,
        method: String,
        path: String,
        policy_path: String,
        policy_fingerprint: String,
        expected_response_path: String,
        expected_response_fingerprint: String,
        actual_response_path: String,
        actual_response_fingerprint: String,
    ) -> Self {
        Self {
            version: 1,
            case_id,
            method,
            path,
            policy_path,
            policy_fingerprint,
            expected_response_path,
            expected_response_fingerprint,
            actual_response_path,
            actual_response_fingerprint,
            body_mode: ResponseBodyMode::Unknown,
            differences: Vec::new(),
            applied_dynamic_rule_ids: Vec::new(),
            unused_applicable_dynamic_rule_ids: Vec::new(),
            dynamic_candidates: Vec::new(),
            applied_unordered_rule_ids: Vec::new(),
            unused_applicable_unordered_rule_ids: Vec::new(),
            applied_counter_rule_ids: Vec::new(),
            unused_applicable_counter_rule_ids: Vec::new(),
            unobserved_response_rule_ids: Vec::new(),
            unordered_candidates: Vec::new(),
            passed: false,
        }
    }

    pub(super) fn finish(&mut self, applicable: &[ResponseField], unobserved: &[ResponseField]) {
        let applied_dynamic = self
            .applied_dynamic_rule_ids
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        self.unused_applicable_dynamic_rule_ids = applicable
            .iter()
            .filter(|field| field.kind == ResponseRuleKind::Dynamic)
            .filter(|field| !applied_dynamic.contains(&field.id))
            .map(|field| field.id.clone())
            .collect();
        let applied_unordered = self
            .applied_unordered_rule_ids
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        self.unused_applicable_unordered_rule_ids = applicable
            .iter()
            .filter(|field| field.kind == ResponseRuleKind::Unordered)
            .filter(|field| !applied_unordered.contains(&field.id))
            .map(|field| field.id.clone())
            .collect();
        let applied_counter = self
            .applied_counter_rule_ids
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        self.unused_applicable_counter_rule_ids = applicable
            .iter()
            .filter(|field| field.kind == ResponseRuleKind::Counter)
            .filter(|field| !applied_counter.contains(&field.id))
            .map(|field| field.id.clone())
            .collect();
        self.unobserved_response_rule_ids =
            unobserved.iter().map(|field| field.id.clone()).collect();
        self.dynamic_candidates = self
            .differences
            .iter()
            .filter(|difference| {
                difference.kind == ResponseDifferenceKind::ValueMismatch
                    && difference.expected_type == difference.actual_type
                    && difference
                        .expected_type
                        .as_deref()
                        .is_some_and(|kind| matches!(kind, "string" | "number" | "boolean"))
            })
            .map(|difference| difference.pointer.clone())
            .collect();
        self.unordered_candidates = self
            .differences
            .iter()
            .filter(|difference| difference.kind == ResponseDifferenceKind::ArrayOrderMismatch)
            .map(|difference| difference.pointer.clone())
            .collect();
        self.passed = self.differences.is_empty()
            && self.unused_applicable_dynamic_rule_ids.is_empty()
            && self.unused_applicable_unordered_rule_ids.is_empty()
            && self.unused_applicable_counter_rule_ids.is_empty();
    }
}

pub(crate) fn unobserved_response_rule_ids<'a>(
    reports: impl IntoIterator<Item = &'a ResponseAssertionCaseReport>,
) -> Vec<String> {
    let reports = reports.into_iter().collect::<Vec<_>>();
    let applied = reports
        .iter()
        .flat_map(|report| {
            report
                .applied_dynamic_rule_ids
                .iter()
                .chain(&report.applied_unordered_rule_ids)
                .chain(&report.applied_counter_rule_ids)
        })
        .collect::<BTreeSet<_>>();
    reports
        .iter()
        .flat_map(|report| &report.unobserved_response_rule_ids)
        .filter(|rule_id| !applied.contains(rule_id))
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}
