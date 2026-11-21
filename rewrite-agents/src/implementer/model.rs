use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::RewriteWorkerActivity;

pub use traffic_rewrite_model::rewrite::implementer::model::ImplementerPool;

pub use traffic_rewrite_model::rewrite::implementer::model::ImplementerRuntimeReplacement;

pub use traffic_rewrite_model::rewrite::implementer::model::ImplementerTask;

pub use traffic_rewrite_model::rewrite::implementer::model::ImplementerDispatch;

pub use traffic_rewrite_model::rewrite::implementer::model::ImplementerSlotView;

pub use traffic_rewrite_model::rewrite::implementer::model::ImplementerPoolView;

#[derive(Debug, Clone)]
pub struct ImplementerConfirmOptions {
    pub target_root: PathBuf,
    pub slot_id: usize,
    pub group_id: String,
    /// Exact batch identity returned by the engine, including every API dispatch.
    pub dispatch_id: String,
    pub agent_handle: String,
}

#[derive(Debug, Clone)]
pub struct ImplementerReportOptions {
    pub target_root: PathBuf,
    pub slot_id: usize,
    pub api: String,
    pub dispatch_id: String,
    pub lease_generation: u64,
    pub agent_handle: String,
    pub activity: RewriteWorkerActivity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImplementerDelivery {
    pub api: String,
    pub dispatch_id: String,
    pub lease_generation: u64,
    pub handoff_id: String,
    #[serde(default)]
    pub review_report: PathBuf,
    /// Commit frozen by engine admission; source review is a final-stage concern.
    #[serde(default)]
    pub delivery_commit: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ImplementerHandoffOptions {
    pub target_root: PathBuf,
    pub slot_id: usize,
    pub agent_handle: String,
    pub deliveries: Vec<ImplementerDelivery>,
}

#[derive(Debug, Clone)]
pub struct ImplementerReassignOptions {
    pub target_root: PathBuf,
    pub group_id: String,
    pub slot_id: usize,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct ImplementerReplaceRuntimeOptions {
    pub target_root: PathBuf,
    pub slot_id: usize,
    pub previous_agent_handle: String,
    pub agent_handle: String,
    pub reason: String,
    pub runtime_query: crate::RewriteWorkerMissingQuery,
}
