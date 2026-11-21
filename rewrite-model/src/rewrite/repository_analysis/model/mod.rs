use crate::rewrite::*;
/// The adopted project catalog. Runtime ownership belongs to the workflow pool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepositoryAnalysisSnapshot {
    pub catalog_revision: String,
    pub api_groups: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepositoryAnalysisContext {
    pub schema_version: u32,
    pub workflow_id: String,
    pub recording_run_id: String,
    pub source_revision: String,
    /// Internal scope retained for retry fencing, not part of the analyst input.
    #[serde(skip)]
    pub scope: Vec<String>,
    pub pending_apis: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub case_patterns: Option<CasePatternContext>,
    pub batch_id: String,
    pub catalog_path: PathBuf,
    /// Read the existing groups from catalog_path using this revision fence.
    pub catalog_revision: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CasePatternContext {
    pub candidates: Vec<String>,
    pub grouping_enabled: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub only_apis: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skipped_apis: Vec<String>,
    pub policy_revision: String,
    pub project_revision: String,
}
