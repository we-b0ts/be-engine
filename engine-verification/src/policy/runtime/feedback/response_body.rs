//! Historical response-body plan DTOs and the retired authoring rejection.
use super::super::response::{
    DocxTimestampRule, ResponseBodyCodec, ResponseBodyJoinedStringPath, ResponseBodyUnorderedPath,
};
use crate::primary_protocol::assertion::{
    ResponseBodyJoinedStringCandidate, ResponseBodyUnorderedPathCandidate,
};
use anyhow::Result;
use serde::Serialize;
use std::path::PathBuf;
#[derive(Debug, Clone)]
pub struct ResponseBodyRuleFeedback {
    pub policy_path: PathBuf,
    pub api: String,
    pub codec: ResponseBodyCodec,
    pub unordered_paths: Vec<ResponseBodyUnorderedPath>,
    pub unordered_joined_string_paths: Vec<ResponseBodyJoinedStringPath>,
    pub docx_timestamps: Vec<DocxTimestampRule>,
    pub evidence: ResponseBodyRuleEvidence,
}

#[derive(Debug, Clone)]
pub enum ResponseBodyRuleEvidence {
    FocusedE2e {
        assertion_report: PathBuf,
        aggregate_report: PathBuf,
    },
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseBodyRuleEvidenceKind {
    FocusedE2e,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResponseBodyRuleVerificationOutcome {
    pub kind: ResponseBodyRuleEvidenceKind,
    pub complete: bool,
    pub passed: bool,
    pub cases: usize,
    pub failed: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResponseBodyRuleReport {
    pub policy: PathBuf,
    pub policy_fingerprint: String,
    pub evidence_kind: ResponseBodyRuleEvidenceKind,
    pub evidence_report: PathBuf,
    pub evidence_fingerprint: String,
    pub api: String,
    pub rule_id: String,
    pub codec: ResponseBodyCodec,
    pub matching_cases: usize,
    pub selected_difference_cases: usize,
    pub residual_difference_cases: usize,
    pub discovered_unordered_paths: Vec<ResponseBodyUnorderedPathCandidate>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub discovered_unordered_joined_string_paths: Vec<ResponseBodyJoinedStringCandidate>,
    pub effective_unordered_paths: Vec<ResponseBodyUnorderedPath>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub effective_unordered_joined_string_paths: Vec<ResponseBodyJoinedStringPath>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub discovered_docx_timestamps: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub effective_docx_timestamps: Vec<DocxTimestampRule>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offline_verification: Option<ResponseBodyRuleVerificationOutcome>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order_only: Option<bool>,
    pub changed: bool,
    pub applied: bool,
    pub diff: String,
}

pub struct ResponseBodyRulePlan {
    report: ResponseBodyRuleReport,
}
impl ResponseBodyRulePlan {
    pub fn report(&self) -> &ResponseBodyRuleReport {
        &self.report
    }
    pub fn apply(self) -> Result<ResponseBodyRuleReport> {
        Err(crate::policy::legacy_authoring_error())
    }
}
pub fn plan_response_body_rule(
    _feedback: ResponseBodyRuleFeedback,
) -> Result<ResponseBodyRulePlan> {
    Err(crate::policy::legacy_authoring_error())
}
