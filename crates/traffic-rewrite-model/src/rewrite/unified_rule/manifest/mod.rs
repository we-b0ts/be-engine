use crate::rewrite::*;
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Artifact {
    pub path: PathBuf,
    pub sha256: String,
    pub length: u64,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub inputs: BTreeMap<PathBuf, crate::dependency_index::FileStamp>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "scope", content = "identity", rename_all = "snake_case")]
pub enum ExecutionIdentity {
    ApiIssue(ApiExecutionIdentity),
    Batch(BatchExecutionIdentity),
    Attribution(super::attribution::Identity),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApiExecutionIdentity {
    pub workflow: String,
    pub recording_run: String,
    pub api: String,
    pub group: String,
    pub source_revision: String,
    pub case_inventory: String,
    pub case_source: PathBuf,
    pub attempt: u64,
    pub target_inputs: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allows_target_drift: bool,
    pub engine: String,
    #[serde(default)]
    pub recorded_replay: Option<String>,
    #[serde(default)]
    pub recorded_engine: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BatchExecutionIdentity {
    pub workflow: String,
    pub proof_revision: u64,
    pub evidence: crate::e2e_run::BatchRuleEvidence,
}
