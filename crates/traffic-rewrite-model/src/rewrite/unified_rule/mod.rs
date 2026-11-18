pub mod attribution;
pub use attribution::*;
pub mod manifest;
pub use manifest::*;
pub mod preflight;
pub use preflight::*;
pub mod source_proof;
use crate::rewrite::*;
pub use source_proof::*;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedRulePlanRecord {
    #[serde(default)]
    pub apply_started: bool,
    pub policy: PathBuf,
    pub original: String,
    pub updated: String,
    pub identity: manifest::ExecutionIdentity,
    pub artifacts: Vec<manifest::Artifact>,
    pub preflight: preflight::Preflight,
    pub rule_ids: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub replaced_rules: Vec<PolicyRule>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub replace_sections: BTreeSet<String>,
    pub source_proofs: source_proof::SourceProofSnapshot,
    #[serde(default)]
    pub target_replay_drift_at_plan: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_validation_started: Option<SystemTime>,
}
