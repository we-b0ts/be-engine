use serde::Serialize;
use serde_json::Value;

use super::model::{RewriteCommandSpec, RewriteEvidenceCommand, RewriteWorkerDispatchView};

/// Current assignment metadata. Excluded from diagnostic evidence hashing so unrelated
/// coordinator revisions and activity observations cannot invalidate evidence.
#[derive(Debug, Clone, Serialize)]
pub struct RewriteEvidenceContext {
    pub target_root: std::path::PathBuf,
    pub workflow_id: String,
    pub revision: u64,
    pub recording_run_id: String,
    pub require_comparison: bool,
    pub worker: RewriteWorkerDispatchView,
    pub review: crate::rewrite::review::ReviewContext,
}

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<Box<RewriteEvidenceContext>>,
    pub evidence_id: String,
    pub issue_id: String,
    pub query: String,
    pub facts: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub queries: Vec<RewriteEvidenceCommand>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub applicable_rule_planners: Vec<RewriteApplicableRulePlanner>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rule_hints: Vec<RewriteRuleHint>,
    pub does_not_prove: Vec<String>,
    pub next_step: String,
}
