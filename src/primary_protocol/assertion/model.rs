use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::policy::runtime::{ResponseBodyCodec, ResponseField, ResponseRuleKind};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResponseGatewayProtocol {
    Http,
    Motan1,
    Motan2,
}

pub use traffic_policy_content::model::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseAssertionCaseReport {
    /// Private runner-to-replay constraints; never persist generated tokens in reports.
    #[serde(skip)]
    pub(crate) identity_pairs: Vec<crate::value_contract::identities::IdentityPair>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub applied_header_rule_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unused_applicable_header_rule_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub header_date_candidates: Vec<super::headers::date::ResponseHeaderDateCandidate>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub header_jwt_candidates: Vec<super::headers::HeaderJwtCandidate>,
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
    /// Replay verified the business exchange without observing Target's heartbeat close.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub fast_heartbeat_tail_skipped: bool,
    pub unordered_candidates: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unordered_joined_string_candidates: Vec<JsonJoinedStringCandidate>,
    pub passed: bool,
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
            identity_pairs: Vec::new(),
            applied_header_rule_ids: Vec::new(),
            unused_applicable_header_rule_ids: Vec::new(),
            header_date_candidates: Vec::new(),
            header_jwt_candidates: Vec::new(),
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
            fast_heartbeat_tail_skipped: false,
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
