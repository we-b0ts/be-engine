use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, path::PathBuf};
pub use traffic_rewrite_model::rewrite::model::*;
use uuid::Uuid;

use crate::dependency::attribution::AttributionProof;

pub use traffic_rewrite_model::rewrite::dependency_review::model::SCHEMA;

pub use traffic_rewrite_model::rewrite::dependency_review::model::ReviewLedger;

pub use traffic_rewrite_model::rewrite::dependency_review::model::WorkflowAcceptanceReceipt;

pub use traffic_rewrite_model::rewrite::dependency_review::model::WorkflowArtifactIdentity;

pub use traffic_rewrite_model::rewrite::dependency_review::model::WorkflowCompletionScope;

pub use traffic_rewrite_model::rewrite::dependency_review::model::WorkflowFailure;

pub use traffic_rewrite_model::rewrite::dependency_review::model::BatchAcceptanceReceipt;

pub use traffic_rewrite_model::rewrite::dependency_review::model::ForeignUnusedClaim;

pub use traffic_rewrite_model::rewrite::dependency_review::model::ClaimRejection;

pub use traffic_rewrite_model::rewrite::dependency_review::model::ClaimStatus;

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

pub use traffic_rewrite_model::rewrite::dependency_review::model::AttributionReviewContext;

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
    pub investigation_resolutions: Vec<InvestigationResolution>,
    pub unresolved_claim_ids: BTreeSet<String>,
    pub claim_rejections: Vec<ClaimRejection>,
}

pub use traffic_rewrite_model::rewrite::dependency_review::model::{
    AttributionRuleBinding, ProposedAttribution,
};

pub use traffic_rewrite_model::rewrite::dependency_review::model::AcceptanceReceipt;

#[derive(Debug, Clone)]
pub struct AttributionCommandOptions {
    pub target_root: PathBuf,
    pub file: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetInvestigationSubmission {
    pub schema: String,
    pub api: String,
    pub evidence_id: String,
    pub target_observation_ids: BTreeSet<String>,
    pub reason: String,
}

pub use traffic_rewrite_model::rewrite::dependency_review::investigations::TargetInvestigation;

pub use traffic_rewrite_model::rewrite::dependency_review::investigations::InvestigationOutcome;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvestigationResolution {
    pub investigation_id: String,
    pub outcome: InvestigationOutcome,
    pub source_task: String,
    pub proof: AttributionProof,
    pub origin_scope: traffic_rewrite_model::rewrite::verification_obligations::VerificationScope,
    pub reason: String,
}
