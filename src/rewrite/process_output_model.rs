use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::model::RewriteIssue;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RewriteWorkScope {
    Api { api: String },
    ProcessOutput { id: String },
}

impl RewriteWorkScope {
    pub(super) fn binding_key(&self) -> String {
        match self {
            Self::Api { api } => api.clone(),
            Self::ProcessOutput { id } => format!("process_output:{id}"),
        }
    }

    pub(super) fn label(&self) -> String {
        match self {
            Self::Api { api } => format!("API {api}"),
            Self::ProcessOutput { id } => format!("process output {id}"),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RewriteProcessOutputStatus {
    #[default]
    Pending,
    ImplementationRequired,
    RevalidationPending,
    Complete,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewriteProcessOutputProgress {
    pub id: String,
    #[serde(default)]
    pub status: RewriteProcessOutputStatus,
    #[serde(default)]
    pub attempts: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_target_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issue: Option<RewriteIssue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct RewriteProcessOutputEvidence {
    pub root: PathBuf,
    pub target_fingerprint: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(super) struct RewriteProcessOutputState {
    #[serde(default)]
    pub inventory: Vec<RewriteProcessOutputProgress>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_target_evidence: Option<RewriteProcessOutputEvidence>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RewriteProcessOutputInventoryView {
    pub total: usize,
    pub completed: usize,
    pub pending: usize,
    pub implementation_required: usize,
    pub revalidation_pending: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_output: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RewriteProcessOutputInventoryDetails {
    #[serde(flatten)]
    pub summary: RewriteProcessOutputInventoryView,
    pub items: Vec<RewriteProcessOutputProgress>,
}
