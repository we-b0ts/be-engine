use crate::rewrite::*;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegressionOrigin {
    pub previous_workflow_id: String,
    pub started_at: String,
    pub pr_base: String,
    pub base_revision: String,
    pub base_fingerprint: String,
    pub user_approved: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_query: Option<super::RewriteWorkerMissingQuery>,
    #[serde(default)]
    pub record_new_traffic: bool,
    #[serde(default)]
    pub superseded_recording_run_id: Option<String>,
    #[serde(default)]
    pub active_session_agent_count: Option<usize>,
    #[serde(default)]
    pub session_runtime_query: Option<super::RewriteWorkerMissingQuery>,
}
