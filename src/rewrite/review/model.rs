use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::rewrite::{RewriteCommandSpec, RewriteWorkScope};

pub const RULE_VERSION: &str = "target-source-review-v3";

#[derive(Debug, Clone)]
pub struct RewriteReviewOptions {
    pub target_root: PathBuf,
    pub worktree: Option<PathBuf>,
    pub scope: Option<RewriteWorkScope>,
    pub evidence: Option<PathBuf>,
    pub integration: bool,
    pub handoff_id: Option<String>,
    pub hardcode_ai_verified: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewAssignment {
    pub worktree: PathBuf,
    pub base_revision: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewRework {
    pub target_fingerprint: String,
    pub findings: BTreeMap<String, ReviewFinding>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewStatus {
    Passed,
    ChangesRequired,
    EvidenceRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewRule {
    FileLines,
    // Retained for deserializing historical reports; the scanner no longer emits it.
    JsonValue,
    SpawnOwnership,
    RustSyntax,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewFinding {
    pub id: String,
    pub file: PathBuf,
    pub line: usize,
    pub column: usize,
    pub rule: ReviewRule,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpawnOwnership {
    Startup,
    Request,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewCodeEvidence {
    pub file: PathBuf,
    pub line: usize,
    pub fact: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpawnEvidence {
    pub finding_id: String,
    pub ownership: SpawnOwnership,
    pub startup_entry: Option<ReviewCodeEvidence>,
    pub call_chain: Vec<ReviewCodeEvidence>,
    pub request_path_review: String,
    pub task_lifecycle: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewEvidence {
    pub spawns: Vec<SpawnEvidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewriteReviewReport {
    pub schema_version: u32,
    pub rules_version: String,
    pub workflow_id: String,
    pub dispatch_id: Option<String>,
    pub scope: Option<RewriteWorkScope>,
    pub worktree: PathBuf,
    pub base_revision: String,
    pub head_revision: String,
    pub target_fingerprint: String,
    pub status: ReviewStatus,
    pub files: BTreeMap<PathBuf, String>,
    pub findings: Vec<ReviewFinding>,
    pub evidence: ReviewEvidence,
    pub evidence_files: BTreeMap<PathBuf, String>,
    pub report_path: PathBuf,
    pub next_step: String,
    #[serde(default)]
    pub required_gates: Vec<String>,
    #[serde(default)]
    pub quality: Option<crate::rewrite::quality::QualityReport>,
    #[serde(default)]
    pub validation: Option<ReviewValidation>,
    #[serde(default)]
    pub integration: Option<IntegrationReview>,
    #[serde(default)]
    pub hardcode_ai_verified: Vec<String>,
    #[serde(default)]
    pub accepted_target_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewValidation {
    pub canonical_root: PathBuf,
    pub recording_run_id: String,
    pub code_fingerprint: String,
    pub context_fingerprint: String,
    pub scan_base_revision: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationReview {
    pub canonical_base_revision: String,
    pub canonical_base_fingerprint: String,
    pub handoff_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReviewContext {
    pub assignment: Option<ReviewAssignment>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rework: Option<ReviewRework>,
    pub check: RewriteCommandSpec,
    pub integrated_findings: RewriteCommandSpec,
}
