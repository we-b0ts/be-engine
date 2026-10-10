use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::replay::policy::{
    Hessian2ValuePath, ProtobufFieldPath, ResponseBodyCodec, ResponseField, ResponseRuleKind,
};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResponseGatewayProtocol {
    Http,
    Motan1,
    Motan2,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResponseBodyAssertionReport {
    pub codec: ResponseBodyCodec,
    pub envelope: String,
    pub configured: bool,
    /// Whether this structured comparison determined the response verdict.
    /// False means the codec was decoded only to provide diagnostic evidence.
    #[serde(default)]
    pub used_for_verdict: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub codec_candidates: Vec<ResponseBodyCodec>,
    pub unordered_path_candidates: Vec<ResponseBodyUnorderedPathCandidate>,
    #[serde(default)]
    pub unordered_joined_string_candidates: Vec<ResponseBodyJoinedStringCandidate>,
    pub differences: Vec<ResponseBodyDifferenceDetail>,
    /// Whether applying every mechanically discovered candidate would make the
    /// decoded protocol bodies equal. This is evidence coverage, not proof
    /// that the source contract permits ignoring order.
    pub candidates_explain_all_differences: bool,
    /// Whether configured collection rules already make the decoded bodies
    /// equal. Joined-string candidates are deliberately excluded until a rule
    /// with source proof selects their separator.
    pub order_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(untagged)]
pub enum ResponseBodyUnorderedPathCandidate {
    Protobuf(ProtobufFieldPathCandidate),
    Hessian2(Hessian2ValuePathCandidate),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(untagged)]
pub enum ResponseBodyJoinedStringCandidate {
    Protobuf(ProtobufJoinedStringCandidate),
    Hessian2(Hessian2JoinedStringCandidate),
}

impl ResponseBodyJoinedStringCandidate {
    pub fn separator(&self) -> &str {
        match self {
            Self::Protobuf(candidate) => &candidate.separator,
            Self::Hessian2(candidate) => &candidate.separator,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(untagged)]
pub enum ResponseBodyDifferenceDetail {
    Protobuf(ProtobufBodyDifference),
    Hessian2(Hessian2BodyDifference),
    Docx(DocxBodyDifference),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum DocxBodyDifferenceKind {
    EntrySetMismatch,
    EntryValueMismatch,
    TimestampMismatch,
    TimestampInvalid,
    TimestampOutsideRequestWindow,
    TimestampDeltaMismatch,
    TimeReferenceMissing,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct DocxBodyDifference {
    pub part: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub element: Option<String>,
    pub kind: DocxBodyDifferenceKind,
}

impl From<DocxBodyDifference> for ResponseBodyDifferenceDetail {
    fn from(difference: DocxBodyDifference) -> Self {
        Self::Docx(difference)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ProtobufBodyDifferenceKind {
    RepeatedFieldOrderMismatch,
    JoinedStringOrderMismatch,
    OccurrenceCountMismatch,
    WireTypeMismatch,
    ValueMismatch,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProtobufJoinedStringCandidate {
    pub field_path: ProtobufFieldPath,
    pub display_path: String,
    pub separator: String,
}

impl From<(ProtobufFieldPath, String)> for ProtobufJoinedStringCandidate {
    fn from((field_path, separator): (ProtobufFieldPath, String)) -> Self {
        let display_path = field_path.display_path();
        Self {
            field_path,
            display_path,
            separator,
        }
    }
}

impl From<(ProtobufFieldPath, String)> for ResponseBodyJoinedStringCandidate {
    fn from(candidate: (ProtobufFieldPath, String)) -> Self {
        Self::Protobuf(candidate.into())
    }
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

impl From<ProtobufFieldPath> for ResponseBodyUnorderedPathCandidate {
    fn from(field_path: ProtobufFieldPath) -> Self {
        Self::Protobuf(field_path.into())
    }
}

impl From<ProtobufBodyDifference> for ResponseBodyDifferenceDetail {
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

impl From<Hessian2ValuePath> for ResponseBodyUnorderedPathCandidate {
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

impl From<(Hessian2ValuePath, String)> for ResponseBodyJoinedStringCandidate {
    fn from(candidate: (Hessian2ValuePath, String)) -> Self {
        Self::Hessian2(candidate.into())
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

impl From<Hessian2BodyDifference> for ResponseBodyDifferenceDetail {
    fn from(difference: Hessian2BodyDifference) -> Self {
        Self::Hessian2(difference)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ResponseDifferenceKind {
    JwtInvalid,
    JwtAlgorithmMismatch,
    JwtSignatureInvalid,
    JwtClaimsMismatch,
    JwtTimeMismatch,
    JwtNonceMismatch,
    JwtUrlMismatch,
    JwtExpiryMismatch,
    JwtSigningKeyUnavailable,
    ResponseUnavailable,
    StatusMismatch,
    HeaderMissingActual,
    HeaderUnexpectedActual,
    HeaderValueMismatch,
    SseObservationMismatch,
    SseStreamEndMismatch,
    GatewayMetadataMismatch,
    ValueMismatch,
    TypeMismatch,
    MissingActual,
    UnexpectedActual,
    ArrayLengthMismatch,
    ArrayOrderMismatch,
    ExactBodyMismatch,
    GeneratedFieldNotScalar,
    TimeFieldInvalid,
    TimeReferenceMissing,
    TimestampOutsideRequestWindow,
    DurationDeltaMismatch,
    UnorderedFieldNotArray,
    UnorderedArrayContentMismatch,
    UnorderedJoinedStringFieldNotString,
    UnorderedJoinedStringContentMismatch,
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

    pub(super) fn header(name: &str, kind: ResponseDifferenceKind) -> Self {
        debug_assert!(matches!(
            kind,
            ResponseDifferenceKind::HeaderMissingActual
                | ResponseDifferenceKind::HeaderUnexpectedActual
                | ResponseDifferenceKind::HeaderValueMismatch
        ));
        Self {
            pointer: format!("$headers/{name}"),
            kind,
            expected_type: None,
            actual_type: None,
            expected_status: None,
            actual_status: None,
        }
    }

    pub(super) fn body_value_mismatch() -> Self {
        Self {
            pointer: "$body".to_string(),
            kind: ResponseDifferenceKind::ValueMismatch,
            expected_type: None,
            actual_type: None,
            expected_status: None,
            actual_status: None,
        }
    }

    pub(super) fn gateway_metadata_mismatch() -> Self {
        Self {
            pointer: "$metadata".to_string(),
            kind: ResponseDifferenceKind::GatewayMetadataMismatch,
            expected_type: None,
            actual_type: None,
            expected_status: None,
            actual_status: None,
        }
    }

    pub(super) fn body_type_mismatch(expected: &str, actual: &str) -> Self {
        Self {
            pointer: "$body".to_string(),
            kind: ResponseDifferenceKind::TypeMismatch,
            expected_type: Some(expected.to_string()),
            actual_type: Some(actual.to_string()),
            expected_status: None,
            actual_status: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseAssertionCaseReport {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub applied_header_rule_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unused_applicable_header_rule_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub header_date_candidates: Vec<super::headers::date::ResponseHeaderDateCandidate>,
    pub version: u8,
    pub case_id: String,
    pub method: String,
    pub path: String,
    pub request_path: String,
    pub policy_path: String,
    pub policy_fingerprint: String,
    pub expected_response_path: String,
    pub expected_response_fingerprint: String,
    pub actual_response_path: String,
    pub actual_response_fingerprint: String,
    pub gateway_protocol: ResponseGatewayProtocol,
    pub body_codec: ResponseBodyCodec,
    pub differences: Vec<ResponseDifference>,
    pub applied_generated_rule_ids: Vec<String>,
    pub unused_applicable_generated_rule_ids: Vec<String>,
    pub generated_scalar_candidates: Vec<String>,
    pub applied_unordered_rule_ids: Vec<String>,
    pub unused_applicable_unordered_rule_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub applied_unordered_joined_string_rule_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unused_applicable_unordered_joined_string_rule_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub applied_body_rule_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unused_applicable_body_rule_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_diagnosis: Option<ResponseBodyAssertionReport>,
    pub unordered_candidates: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unordered_joined_string_candidates: Vec<JsonJoinedStringCandidate>,
    pub passed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct JsonJoinedStringCandidate {
    pub pointer: String,
    pub separator: String,
}

impl ResponseAssertionCaseReport {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        case_id: String,
        method: String,
        path: String,
        gateway_protocol: ResponseGatewayProtocol,
        request_path: String,
        policy_path: String,
        policy_fingerprint: String,
        expected_response_path: String,
        expected_response_fingerprint: String,
        actual_response_path: String,
        actual_response_fingerprint: String,
    ) -> Self {
        Self {
            version: 3,
            applied_header_rule_ids: Vec::new(),
            unused_applicable_header_rule_ids: Vec::new(),
            header_date_candidates: Vec::new(),
            case_id,
            method,
            path,
            request_path,
            policy_path,
            policy_fingerprint,
            expected_response_path,
            expected_response_fingerprint,
            actual_response_path,
            actual_response_fingerprint,
            gateway_protocol,
            body_codec: ResponseBodyCodec::Unknown,
            differences: Vec::new(),
            applied_generated_rule_ids: Vec::new(),
            unused_applicable_generated_rule_ids: Vec::new(),
            generated_scalar_candidates: Vec::new(),
            applied_unordered_rule_ids: Vec::new(),
            unused_applicable_unordered_rule_ids: Vec::new(),
            applied_unordered_joined_string_rule_ids: Vec::new(),
            unused_applicable_unordered_joined_string_rule_ids: Vec::new(),
            applied_body_rule_ids: Vec::new(),
            unused_applicable_body_rule_ids: Vec::new(),
            body_diagnosis: None,
            unordered_candidates: Vec::new(),
            unordered_joined_string_candidates: Vec::new(),
            passed: false,
        }
    }

    pub(super) fn finish(&mut self, applicable: &[ResponseField], applicable_body: &[String]) {
        let applied_generated = self
            .applied_generated_rule_ids
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        self.unused_applicable_generated_rule_ids = applicable
            .iter()
            .filter(|field| field.kind.is_generated())
            .filter(|field| !applied_generated.contains(&field.id))
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
        let applied_joined_string = self
            .applied_unordered_joined_string_rule_ids
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        self.unused_applicable_unordered_joined_string_rule_ids = applicable
            .iter()
            .filter(|field| field.kind == ResponseRuleKind::UnorderedJoinedString)
            .filter(|field| !applied_joined_string.contains(&field.id))
            .map(|field| field.id.clone())
            .collect();
        let applied_body = self
            .applied_body_rule_ids
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        self.unused_applicable_body_rule_ids = applicable_body
            .iter()
            .filter(|rule_id| !applied_body.contains(*rule_id))
            .cloned()
            .collect();
        self.generated_scalar_candidates = self
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
        self.unordered_joined_string_candidates.sort();
        self.unordered_joined_string_candidates.dedup();
        self.passed = self.differences.is_empty()
            && self.unused_applicable_header_rule_ids.is_empty()
            && self.unused_applicable_generated_rule_ids.is_empty()
            && self.unused_applicable_unordered_rule_ids.is_empty()
            && self
                .unused_applicable_unordered_joined_string_rule_ids
                .is_empty()
            && self.unused_applicable_body_rule_ids.is_empty();
    }
}
