use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
};
use uuid::Uuid;

use super::super::verification_obligations::{
    ScopeObligation, VerificationImpact, VerificationScope,
};
use crate::dependency::attribution::{AttributionProof, DependencyOwner};

pub const SCHEMA: &str = "dependency-attribution/v3";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::rewrite) struct ReviewLedger {
    pub revision: u64,
    pub recording_run_id: Option<String>,
    pub source_inventory_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub case_defaults_identity: Option<String>,
    pub unresolved_source_exchange_ids: BTreeSet<Uuid>,
    pub claims: BTreeMap<String, ForeignUnusedClaim>,
    pub investigations: BTreeMap<String, super::investigations::TargetInvestigation>,
    pub decisions: super::decisions::DecisionSet,
    pub decision_history: super::decisions::DecisionHistory,
    pub obligations: BTreeMap<String, ScopeObligation>,
    pub receipts: BTreeMap<String, AcceptanceReceipt>,
    pub batch_receipt: Option<BatchAcceptanceReceipt>,
    pub batch_failure: Option<BatchFailure>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_receipt: Option<WorkflowAcceptanceReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_failure: Option<WorkflowFailure>,
    pub required_method_apis: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::rewrite) struct WorkflowAcceptanceReceipt {
    pub completion_scope: WorkflowCompletionScope,
    pub workflow_id: String,
    pub policy_fingerprint: String,
    pub review_context: String,
    pub review_receipt_identity: String,
    pub projections: BTreeMap<PathBuf, WorkflowArtifactIdentity>,
    pub actual: BatchAcceptanceReceipt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::rewrite) struct WorkflowArtifactIdentity {
    pub sha256: String,
    pub stamp: crate::dependency_index::FileStamp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::rewrite) enum WorkflowCompletionScope {
    WorkflowContracts,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::rewrite) struct WorkflowFailure {
    pub recording_run_id: String,
    pub source_inventory_id: String,
    pub replay_identity: String,
    pub attribution_snapshot: String,
    pub policy_fingerprint: String,
    pub method_apis: BTreeSet<String>,
    pub results: Vec<crate::E2eApiRunResult>,
    pub evidence_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::rewrite) struct BatchAcceptanceReceipt {
    pub engine_fingerprint: String,
    pub recording_run_id: String,
    pub source_revision: String,
    pub source_inventory_id: String,
    pub replay_identity: String,
    pub attribution_snapshot: String,
    pub session_id: String,
    pub report_path: PathBuf,
    pub report_sha256: String,
    pub report_stamp: crate::dependency_index::FileStamp,
    pub selected_case_ids: BTreeSet<String>,
    pub covered_method_apis: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::rewrite) struct BatchFailure {
    pub recording_run_id: String,
    pub source_inventory_id: String,
    pub replay_identity: String,
    pub attribution_snapshot: String,
    pub result: crate::E2eRunResult,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForeignUnusedClaim {
    pub id: String,
    pub api: String,
    pub method_api: String,
    pub recording_run_id: String,
    pub source_revision: String,
    pub source_inventory_id: String,
    pub attempt: u64,
    pub execution_identity: String,
    pub report_sha256: String,
    pub source_exchange_ids: BTreeSet<Uuid>,
    #[serde(default)]
    pub exclusion: Option<AttributionProof>,
    #[serde(default)]
    pub reason: String,
    pub status: ClaimStatus,
    pub rejection: Option<ClaimRejection>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimRejection {
    pub claim_id: String,
    pub proof: AttributionProof,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimStatus {
    Pending,
    Proved,
    Rejected,
    Unresolved,
    /// Historical API request investigation replaced by a newer real attempt.
    Superseded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForeignUnusedSubmission {
    pub schema: String,
    pub api: String,
    pub evidence_id: String,
    pub source_exchange_ids: BTreeSet<Uuid>,
    /// Optional historical diagnosis; an implementer need not prove exclusion.
    #[serde(default)]
    pub exclusion: Option<AttributionProof>,
    #[serde(default)]
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AttributionReviewContext {
    pub schema: &'static str,
    pub work_type: &'static str,
    pub workflow_id: String,
    pub recording_run_id: String,
    pub source_revision: String,
    pub source_inventory_id: String,
    pub revision: u64,
    pub assignment_id: String,
    pub claims: Vec<ForeignUnusedClaim>,
    pub task_groups: BTreeMap<String, Vec<String>>,
    pub evidence_commands: Vec<crate::rewrite::RewriteCommandSpec>,
    pub effective_policy_fingerprint: String,
    pub rule_groups: Vec<serde_json::Value>,
    pub rule_planning: serde_json::Value,
    pub unattributed_exchange_ids: BTreeSet<Uuid>,
    pub obligations: Vec<ScopeObligation>,
    pub next_step: &'static str,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttributionSubmission {
    pub schema: String,
    pub assignment_id: String,
    pub expected_revision: u64,
    pub recording_run_id: String,
    pub source_revision: String,
    pub source_inventory_id: String,
    pub decisions: Vec<ProposedAttribution>,
    pub investigation_resolutions: Vec<super::investigations::InvestigationResolution>,
    pub unresolved_claim_ids: BTreeSet<String>,
    pub claim_rejections: Vec<ClaimRejection>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProposedAttribution {
    pub claim_ids: BTreeSet<String>,
    pub source_exchange_ids: BTreeSet<Uuid>,
    pub source_task: String,
    pub owner: DependencyOwner,
    pub proof: AttributionProof,
    pub impact: VerificationImpact,
    /// Original API or task needing new evidence; never inferred from the victim.
    pub obligation_scope: VerificationScope,
    pub missing_evidence: Option<String>,
    pub rule_binding: AttributionRuleBinding,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttributionRuleBinding {
    pub policy_fingerprint: String,
    pub rule_ids: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptanceReceipt {
    pub engine_fingerprint: String,
    pub verdict: String,
    pub api: String,
    pub method_api: String,
    pub recording_run_id: String,
    pub source_revision: String,
    pub source_inventory_id: String,
    pub attempt: u64,
    pub session_id: String,
    pub report_sha256: String,
    pub execution_identity: String,
    pub proof_ids: BTreeSet<String>,
    pub excluded_unused: BTreeSet<Uuid>,
    pub batch_verified: bool,
}

#[derive(Debug, Clone)]
pub struct AttributionCommandOptions {
    pub target_root: PathBuf,
    pub file: PathBuf,
}
