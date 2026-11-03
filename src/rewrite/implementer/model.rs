use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::rewrite::{RewriteCommandSpec, RewriteWorkerActivity};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImplementerPool {
    pub effective_max_implementers: usize,
    #[serde(default)]
    pub next_group_slot: usize,
    #[serde(default)]
    pub group_slots: BTreeMap<String, usize>,
    #[serde(default)]
    pub slots: BTreeMap<usize, ImplementerSlot>,
}

impl ImplementerPool {
    pub fn new(max_implementers: usize) -> Self {
        Self {
            effective_max_implementers: max_implementers,
            next_group_slot: 0,
            group_slots: BTreeMap::new(),
            slots: (0..max_implementers)
                .map(|id| (id, ImplementerSlot::default()))
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ImplementerSlot {
    pub agent_handle: Option<String>,
    #[serde(default)]
    pub generation: u64,
    #[serde(default)]
    pub tasks: BTreeMap<String, ImplementerTask>,
    pub current_api: Option<String>,
    pub observed_at: Option<String>,
    #[serde(default)]
    pub confirmed_batches: BTreeSet<String>,
    #[serde(default)]
    pub last_runtime_replacement: Option<ImplementerRuntimeReplacement>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImplementerRuntimeReplacement {
    pub previous_handle: String,
    pub new_handle: String,
    pub reason: String,
    pub runtime_query: crate::rewrite::RewriteWorkerMissingQuery,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImplementerTask {
    pub api: String,
    pub group_id: String,
    pub recording_run_id: String,
    pub dispatch_id: String,
    pub lease_generation: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImplementerDispatch {
    pub slot_id: usize,
    pub name: String,
    pub worktree: PathBuf,
    pub agent_handle: Option<String>,
    pub group_id: String,
    pub dispatch_id: String,
    pub lease_generation: u64,
    pub apis: Vec<ImplementerTask>,
    pub current_api: Option<String>,
    pub pending_api_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImplementerSlotView {
    pub slot_id: usize,
    pub name: String,
    pub worktree: PathBuf,
    pub agent_handle: Option<String>,
    pub current_api: Option<String>,
    pub developing_api_count: usize,
    pub pending_api_count: usize,
    pub queued_api_count: usize,
    pub state: String,
    pub groups: Vec<String>,
    pub tasks: Vec<ImplementerTask>,
    pub observed_at: Option<String>,
    pub report: RewriteCommandSpec,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImplementerPoolView {
    pub configured_max_implementers: usize,
    pub effective_max_implementers: usize,
    pub group_slots: BTreeMap<String, usize>,
    pub slots: Vec<ImplementerSlotView>,
}

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
    pub runtime_query: crate::rewrite::RewriteWorkerMissingQuery,
}
