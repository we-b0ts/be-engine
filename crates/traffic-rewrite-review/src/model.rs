use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::RewriteWorkScope;

pub const RULE_VERSION: &str = "target-source-review-v5";

#[derive(Debug, Clone)]
pub struct RewriteReviewOptions {
    pub target_root: PathBuf,
    pub worktree: Option<PathBuf>,
    pub scope: Option<RewriteWorkScope>,
    pub evidence: Option<PathBuf>,
    pub integration: bool,
    /// Confirms the agent passed this tool on the final committed candidate.
    pub quality_check: Option<String>,
    pub handoff_id: Option<String>,
    pub hardcode_ai_verified: Vec<String>,
}

pub use traffic_rewrite_model::rewrite::review::model::ReviewAssignment;

pub use traffic_rewrite_model::rewrite::review::model::ReviewRework;

pub use traffic_rewrite_model::rewrite::review::model::ReviewStatus;

pub use traffic_rewrite_model::rewrite::review::model::ReviewRule;

pub use traffic_rewrite_model::rewrite::review::model::ReviewFinding;

pub use traffic_rewrite_model::rewrite::review::model::SpawnOwnership;

pub use traffic_rewrite_model::rewrite::review::model::ReviewEvidence;

pub use traffic_rewrite_model::rewrite::review::model::RewriteReviewReport;

pub use traffic_rewrite_model::rewrite::review::model::ReviewValidation;

pub use traffic_rewrite_model::rewrite::review::model::IntegrationReview;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrationHandoffSelection {
    pub scope: RewriteWorkScope,
    pub handoff_id: String,
}

pub use traffic_rewrite_model::rewrite::review::model::IntegrationHandoffReview;

#[derive(Debug, Clone, Serialize)]
pub struct DeliveryContext {
    pub assignment: Option<ReviewAssignment>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_repairs: Option<ReviewRework>,
}
