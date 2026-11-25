use crate::rewrite::*;
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImplementerTask {
    pub api: String,
    pub group_id: String,
    pub recording_run_id: String,
    pub dispatch_id: String,
    pub lease_generation: u64,
}

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

#[derive(Debug, Clone, Serialize)]
pub struct ImplementerPoolView {
    pub configured_max_implementers: usize,
    pub effective_max_implementers: usize,
    pub group_slots: BTreeMap<String, usize>,
    pub slots: Vec<ImplementerSlotView>,
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

impl ImplementerPool {
    pub const DEFAULT_CAPACITY: usize = 16;

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
