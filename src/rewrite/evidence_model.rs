use serde::Serialize;
use serde_json::Value;

use super::model::RewriteCommandSpec;

#[derive(Debug, Clone, Serialize)]
pub struct RewriteApplicableRulePlanner {
    pub kind: String,
    pub capability: String,
    pub evidence_id: String,
    pub command: RewriteCommandSpec,
}

#[derive(Debug, Clone, Serialize)]
pub struct RewriteRuleHint {
    pub capability: String,
    pub rule: String,
    pub hint: String,
    pub help: RewriteCommandSpec,
}

#[derive(Debug, Clone, Serialize)]
pub struct RewriteEvidenceReport {
    pub schema_version: u32,
    pub evidence_id: String,
    pub issue_id: String,
    pub query: String,
    pub facts: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub applicable_rule_planners: Vec<RewriteApplicableRulePlanner>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rule_hints: Vec<RewriteRuleHint>,
    pub does_not_prove: Vec<String>,
    pub next_step: String,
}
