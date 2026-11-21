use crate::rewrite::*;
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetInvestigation {
    pub id: String,
    pub kind: String,
    pub api: String,
    pub method_api: String,
    pub recording_run_id: String,
    pub source_revision: String,
    pub source_inventory_id: String,
    pub attempt: u64,
    pub session_id: String,
    pub report_sha256: String,
    pub target_observations: BTreeMap<String, Value>,
    #[serde(skip)]
    pub candidate_discovery: BTreeMap<String, Value>,
    pub reason: String,
    pub status: ClaimStatus,
    pub resolution: Option<InvestigationOutcome>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvestigationOutcome {
    ValueRule,
    TargetImplementation,
    CrossScope,
    MissingCapture,
    Unresolved,
}
