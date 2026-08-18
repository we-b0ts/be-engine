use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::replay::policy::{
    Hessian2ValuePath, MotanBodyProtocol, ProtobufFieldPath, ResponseField, ResponseRuleKind,
};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResponseBodyMode {
    Unknown,
    JsonStructural,
    MotanProtobuf,
    MotanHessian2,
    ExactBytes,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MotanBodyAssertionReport {
    pub rule_kind: String,
    pub protocol: MotanBodyProtocol,
    pub envelope: String,
    pub configured: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protocol_candidates: Vec<MotanBodyProtocol>,
    pub unordered_path_candidates: Vec<MotanUnorderedPathCandidate>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unordered_joined_string_candidates: Vec<Hessian2JoinedStringCandidate>,
    pub differences: Vec<MotanBodyDifference>,
    pub order_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(untagged)]
pub enum MotanUnorderedPathCandidate {
    Protobuf(ProtobufFieldPathCandidate),
    Hessian2(Hessian2ValuePathCandidate),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(untagged)]
pub enum MotanBodyDifference {
    Protobuf(ProtobufBodyDifference),
    Hessian2(Hessian2BodyDifference),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ProtobufBodyDifferenceKind {
    RepeatedFieldOrderMismatch,
    OccurrenceCountMismatch,
    WireTypeMismatch,
    ValueMismatch,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProtobufBodyDifference {
    pub field_path: ProtobufFieldPath,
    pub display_path: String,
    pub kind: ProtobufBodyDifferenceKind,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProtobufFieldPathCandidate {
    pub field_path: ProtobufFieldPath,
    pub display_path: String,
}

impl From<ProtobufFieldPath> for ProtobufFieldPathCandidate {
    fn from(field_path: ProtobufFieldPath) -> Self {
        let display_path = field_path.display_path();
        Self {
            field_path,
            display_path,
        }
    }
}

impl From<ProtobufFieldPath> for MotanUnorderedPathCandidate {
    fn from(field_path: ProtobufFieldPath) -> Self {
        Self::Protobuf(field_path.into())
    }
}

impl From<ProtobufBodyDifference> for MotanBodyDifference {
    fn from(difference: ProtobufBodyDifference) -> Self {
        Self::Protobuf(difference)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Hessian2ValuePathCandidate {
    pub value_path: Hessian2ValuePath,
    pub display_path: String,
}

impl From<Hessian2ValuePath> for Hessian2ValuePathCandidate {
    fn from(value_path: Hessian2ValuePath) -> Self {
        let display_path = value_path.display_path();
        Self {
            value_path,
            display_path,
        }
    }
}

impl From<Hessian2ValuePath> for MotanUnorderedPathCandidate {
    fn from(value_path: Hessian2ValuePath) -> Self {
        Self::Hessian2(value_path.into())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Hessian2JoinedStringCandidate {
    pub value_path: Hessian2ValuePath,
    pub display_path: String,
    pub separator: String,
}

impl From<(Hessian2ValuePath, String)> for Hessian2JoinedStringCandidate {
    fn from((value_path, separator): (Hessian2ValuePath, String)) -> Self {
        let display_path = value_path.display_path();
        Self {
            value_path,
            display_path,
            separator,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Hessian2BodyDifferenceKind {
    ListOrderMismatch,
    ListLengthMismatch,
    TypeMismatch,
    ValueMismatch,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Hessian2BodyDifference {
    pub value_path: Hessian2ValuePath,
    pub display_path: String,
    pub kind: Hessian2BodyDifferenceKind,
}

impl From<Hessian2BodyDifference> for MotanBodyDifference {
    fn from(difference: Hessian2BodyDifference) -> Self {
        Self::Hessian2(difference)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ResponseDifferenceKind {
    ResponseUnavailable,
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
    pub applied_motan_rule_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unused_applicable_motan_rule_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub motan: Option<MotanBodyAssertionReport>,
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
            applied_motan_rule_ids: Vec::new(),
            unused_applicable_motan_rule_ids: Vec::new(),
            motan: None,
            unordered_candidates: Vec::new(),
            passed: false,
        }
    }

    pub(super) fn finish(&mut self, applicable: &[ResponseField], applicable_motan: &[String]) {
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
        let applied_motan = self
            .applied_motan_rule_ids
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        self.unused_applicable_motan_rule_ids = applicable_motan
            .iter()
            .filter(|rule_id| !applied_motan.contains(*rule_id))
            .cloned()
            .collect();
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
            && self.unused_applicable_counter_rule_ids.is_empty()
            && self.unused_applicable_motan_rule_ids.is_empty();
    }
}
