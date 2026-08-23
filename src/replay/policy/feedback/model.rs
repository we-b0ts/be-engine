use std::path::PathBuf;

use serde::Serialize;

use super::super::response::ResponseRuleKind;

#[derive(Debug, Clone)]
pub struct ResponseRuleFeedback {
    pub policy_path: PathBuf,
    pub kind: ResponseRuleKind,
    pub api: String,
    pub json_pointers: Vec<String>,
    pub source_evidence: Option<String>,
    pub source_example: Option<String>,
    pub target_example: Option<String>,
    pub separator: Option<String>,
    pub assertion_report: PathBuf,
    pub aggregate_report: PathBuf,
}

#[derive(Debug, Clone)]
pub struct ComparisonResponseRuleFeedback {
    pub policy_path: PathBuf,
    pub kind: ResponseRuleKind,
    pub api: String,
    pub json_pointers: Vec<String>,
    pub source_evidence: Option<String>,
    pub source_example: Option<String>,
    pub target_example: Option<String>,
    pub separator: Option<String>,
    pub comparison_report: PathBuf,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResponseRuleReport {
    pub policy: PathBuf,
    pub policy_fingerprint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assertion_report: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assertion_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aggregate_report: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aggregate_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comparison_report: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comparison_fingerprint: Option<String>,
    pub kind: ResponseRuleKind,
    pub api: String,
    pub json_pointers: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_evidence: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_example: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_example: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub separator: Option<String>,
    pub matching_cases: usize,
    pub selected_difference_cases: usize,
    pub unselected_difference_pointers: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aggregate_dirty: Option<bool>,
    pub changed: bool,
    pub applied: bool,
    pub added_rule_ids: Vec<String>,
    pub diff: String,
}
