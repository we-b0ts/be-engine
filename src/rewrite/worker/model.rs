use serde::{Deserialize, Serialize};

use super::super::model::RewriteCommandSpec;
use super::super::work_scope::RewriteWorkScope;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(in crate::rewrite) struct RewriteWorkerBinding {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_handle: Option<String>,
    pub agent_handle_fingerprint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_name: Option<String>,
    pub confirmed_dispatch_id: String,
    /// Initial timer baseline; resumes and empty handoffs never reset it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_bound_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_integrated_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_integrated_commit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expert: Option<super::super::expert::model::ExpertAssignment>,
    #[serde(default)]
    pub transfer_generation: u64,
    #[serde(default)]
    pub rework_generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_transfer: Option<RewriteWorkerTransferRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observation: Option<RewriteWorkerObservation>,
    #[serde(default)]
    pub review_assignment: Option<crate::rewrite::review::ReviewAssignment>,
    #[serde(default)]
    pub review_report: Option<crate::rewrite::review::RewriteReviewReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(in crate::rewrite) struct RewriteWorkerTransferRecord {
    pub previous_agent_handle_fingerprint: String,
    pub reason: String,
    pub transferred_at: String,
    // Every transfer before runtime-query authorization required user approval.
    #[serde(default)]
    pub authorization: RewriteWorkerTransferAuthorization,
}

/// Coordinator attestation of either user approval or an actual runtime query.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "basis", rename_all = "snake_case", deny_unknown_fields)]
pub(in crate::rewrite) enum RewriteWorkerTransferAuthorization {
    #[default]
    UserApproved,
    RuntimeApiConfirmedMissing {
        query: RewriteWorkerMissingQuery,
    },
}

/// An executed runtime query covering the exact previous worker handle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RewriteWorkerMissingQuery {
    pub api_or_command: String,
    /// RFC 3339 time when the coordinator actually queried the runtime.
    pub queried_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RewriteWorkerDispatchState {
    DispatchRequired,
    ResumeRequired,
    Confirmed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RewriteWorkerBlockingReason {
    WorkerDispatchUnconfirmed,
}

#[derive(Debug, Clone, Serialize)]
pub struct RewriteWorkerDispatchView {
    pub binding_id: String,
    pub dispatch_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_handle: Option<String>,
    pub work_scope: RewriteWorkScope,
    pub state: RewriteWorkerDispatchState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_bound_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_integrated_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_integrated_commit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocking_reason: Option<RewriteWorkerBlockingReason>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_api: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_name: Option<String>,
}

/// Facts reported by the state-machine coordinator from its actual task runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RewriteWorkerActivity {
    Running,
    Queued,
    Idle,
    HandoffReady,
    Integrated,
    ReworkRequired,
}

impl std::str::FromStr for RewriteWorkerActivity {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "running" => Ok(Self::Running),
            "queued" => Ok(Self::Queued),
            "idle" => Ok(Self::Idle),
            "handoff_ready" => Ok(Self::HandoffReady),
            "integrated" => Ok(Self::Integrated),
            "rework_required" => Ok(Self::ReworkRequired),
            _ => anyhow::bail!(
                "worker activity must be running, queued, idle, handoff_ready, integrated, or rework_required"
            ),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(in crate::rewrite) struct RewriteWorkerObservation {
    pub dispatch_id: String,
    pub recording_run_id: String,
    pub activity: RewriteWorkerActivity,
    pub observed_at: String,
    #[serde(default)]
    pub coordinator_reported: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handoff_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrated_target_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RewriteWorkerCoverageState {
    DispatchRequired,
    ResumeRequired,
    StatusRequired,
    Running,
    IntegrationRequired,
    VerificationRequired,
}

#[derive(Debug, Clone, Serialize)]
pub struct RewriteWorkerInventoryItem {
    #[serde(flatten)]
    pub worker: RewriteWorkerDispatchView,
    pub coverage: RewriteWorkerCoverageState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handoff_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delivery_commit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub worker_worktree: Option<std::path::PathBuf>,
    pub commands: RewriteWorkerInventoryCommands,
}

#[derive(Debug, Clone, Serialize)]
pub struct RewriteWorkerInventoryCommands {
    pub status: RewriteCommandSpec,
    pub report_worker: RewriteCommandSpec,
}
