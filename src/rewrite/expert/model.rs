use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::rewrite::{RewriteCommandSpec, RewriteWorkScope, RewriteWorkerDispatchView};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(in crate::rewrite) struct ExpertAssignment {
    pub id: String,
    pub apis: Vec<String>,
    pub prepared_at: String,
    pub agent_handle_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_handle: Option<String>,
    pub confirmed_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closed_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery: Option<ExpertDelivery>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(in crate::rewrite) struct ExpertDelivery {
    pub report_id: String,
    pub recipient_handle_fingerprint: String,
    pub delivered_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RewriteExpertState {
    NotDue,
    PrepareRequired,
    DispatchRequired,
    Confirmed,
    Delivered,
    CloseRequired,
    Closed,
}

#[derive(Debug, Clone, Serialize)]
pub struct RewriteExpertView {
    pub expert_id: String,
    pub role: &'static str,
    pub state: RewriteExpertState,
    pub apis: Vec<RewriteExpertApiView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_handle_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_handle: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub closed_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RewriteExpertApiView {
    pub work_scope: RewriteWorkScope,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub implementer: Option<RewriteWorkerDispatchView>,
    pub implementer_handle_fingerprint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_bound_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_integrated_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_integrated_commit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eligible_after: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub worktree: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report_id: Option<String>,
    pub commands: RewriteExpertApiCommands,
}

#[derive(Debug, Clone, Serialize)]
pub struct RewriteExpertApiCommands {
    pub evidence: RewriteCommandSpec,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report_delivered: Option<RewriteCommandSpec>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RewriteExpertCommands {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prepare: Option<RewriteCommandSpec>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirm_expert: Option<RewriteCommandSpec>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub close_expert: Option<RewriteCommandSpec>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RewriteExpertInventoryItem {
    #[serde(flatten)]
    pub expert: RewriteExpertView,
    pub commands: RewriteExpertCommands,
}

#[derive(Debug, Clone)]
pub struct RewriteExpertOptions {
    pub target_root: PathBuf,
    pub expert_id: String,
    pub agent_handle: String,
}

#[derive(Debug, Clone)]
pub struct RewriteExpertDeliveryOptions {
    pub expert: RewriteExpertOptions,
    pub api: String,
    pub report_id: String,
    pub recipient_handle: String,
}

#[derive(Debug, Clone)]
pub struct RewriteExpertPrepareOptions {
    pub target_root: PathBuf,
    pub expert_id: String,
    pub apis: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct RewriteExpertCloseOptions {
    pub target_root: PathBuf,
    pub expert_id: String,
    pub agent_handle: Option<String>,
}
