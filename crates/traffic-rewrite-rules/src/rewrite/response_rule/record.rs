//! Construct persisted response rule proposals from already admitted evidence.
use super::rule_kind;
use anyhow::{Context, Result};
use serde_json::Value;
use traffic_engine::{
    DocxTimestampRule, ResponseBodyCodec, ResponseBodyJoinedStringPath, ResponseBodyUnorderedPath,
    ResponseRuleKind, execution_identity as fingerprint,
};
use traffic_rewrite_model::rewrite::model::{
    RewriteIssue, RewriteResponseBodyRuleSpec, RewriteRulePlanRecord, RewriteState,
};

#[derive(Debug, Clone)]
pub struct RewriteRulePlanOptions {
    pub response_jwts: Vec<crate::ResponseJwtRule>,
    pub header_dates: Vec<crate::ResponseHeaderDateRule>,
    pub dynamic_value: Option<crate::DynamicValueRule>,
    pub mysql_time: Option<crate::DynamicValueMysqlTimeRule>,
    pub redis_time: Option<crate::DynamicValueRedisTimeRule>,
    pub dependency_request: Option<Value>,
    pub evidence_id: String,
    pub jwt: Option<crate::rewrite::jwt_plan::JwtRulePlanOptions>,
    pub body_codec: ResponseBodyCodec,
    pub kind: Option<ResponseRuleKind>,
    pub time: Option<crate::ResponseTimeRule>,
    pub json_pointer: Option<String>,
    pub source_evidence: Option<String>,
    pub source_example: Option<String>,
    pub target_example: Option<String>,
    pub separator: Option<String>,
    pub unordered_paths: Vec<ResponseBodyUnorderedPath>,
    pub unordered_joined_string_paths: Vec<ResponseBodyJoinedStringPath>,
    pub docx_timestamps: Vec<DocxTimestampRule>,
}

pub fn json(
    state: &RewriteState,
    issue: &RewriteIssue,
    kind: ResponseRuleKind,
    options: RewriteRulePlanOptions,
) -> Result<RewriteRulePlanRecord> {
    let pointer = options
        .json_pointer
        .or_else(|| issue.representative.as_ref().map(|r| r.pointer.clone()))
        .context("rule plan requires a representative JSON Pointer")?;
    Ok(RewriteRulePlanRecord {
        unified: None,
        generated_witnesses: Vec::new(),
        response_jwts: Vec::new(),
        header_dates: Vec::new(),
        dynamic_value: None,
        mysql_time: None,
        redis_time: None,
        dependency_request: None,
        id: format!(
            "plan-{}",
            fingerprint::id(&[
                &state.workflow_id,
                &issue.id,
                &format!("{kind:?}"),
                &pointer,
                &options.evidence_id,
            ])
            .trim_start_matches("fnv1a64:")
        ),
        issue_id: issue.id.clone(),
        kind: rule_kind(kind).to_string(),
        json_pointer: pointer,
        time: options.time,
        source_evidence: options.source_evidence,
        source_example: options.source_example,
        target_example: options.target_example,
        separator: options.separator,
        response_body: None,
        jwt: None,
        evidence_id: options.evidence_id,
    })
}

pub fn body(
    state: &RewriteState,
    issue: &RewriteIssue,
    options: RewriteRulePlanOptions,
) -> Result<RewriteRulePlanRecord> {
    let spec = RewriteResponseBodyRuleSpec {
        codec: options.body_codec,
        unordered_paths: options.unordered_paths,
        unordered_joined_string_paths: options.unordered_joined_string_paths,
        docx_timestamps: options.docx_timestamps,
    };
    let spec_json = serde_json::to_string(&spec)?;
    Ok(RewriteRulePlanRecord {
        unified: None,
        generated_witnesses: Vec::new(),
        response_jwts: Vec::new(),
        header_dates: Vec::new(),
        dynamic_value: None,
        mysql_time: None,
        redis_time: None,
        dependency_request: None,
        id: format!(
            "plan-{}",
            fingerprint::id(&[
                &state.workflow_id,
                &issue.id,
                "response_body",
                &spec_json,
                &options.evidence_id,
            ])
            .trim_start_matches("fnv1a64:")
        ),
        issue_id: issue.id.clone(),
        kind: "response_body".to_string(),
        json_pointer: String::new(),
        time: None,
        source_evidence: None,
        source_example: None,
        target_example: None,
        separator: None,
        response_body: Some(spec),
        jwt: None,
        evidence_id: options.evidence_id,
    })
}
