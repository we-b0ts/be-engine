use super::*;
use crate::dependency::observation::SemanticInventory;
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchReconciliation {
    pub schema: String,
    pub session_id: String,
    pub source_inventory_id: String,
    pub recording_run_id: String,
    pub recording_run_epoch: Uuid,
    pub process_epochs: Vec<Uuid>,
    pub dependency_attribution_snapshot: Option<String>,
    pub complete_source_scope: bool,
    pub source_capture_complete: bool,
    pub execution_complete: bool,
    pub required_cases: BTreeSet<String>,
    pub selected_cases: BTreeSet<String>,
    pub source_inventory: SemanticInventory,
    pub unused_run_dependencies: BTreeMap<String, usize>,
    pub actual_unmatched_or_unsafe: usize,
    pub provisional_hypotheses_used: bool,
    pub startup_phase_complete: bool,
    pub dependency_inventory_verified: bool,
}

mod validation;
pub use validation::validate_completed_receipt_with;
