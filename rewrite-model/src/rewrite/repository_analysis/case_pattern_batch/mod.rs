use crate::rewrite::*;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CasePatternAnalysisCommit {
    pub workflow_id: String,
    pub recording_run_id: String,
    pub batch_id: String,
    pub submission_revision: String,
    pub publication: Option<Publication>,
}

/// Persist the accepted result's identity before changing either project file.
/// Both writes can then be retried by comparing their before and after revisions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Publication {
    pub context: RepositoryAnalysisContext,
    pub policy_after: String,
    pub catalog_after: String,
}
