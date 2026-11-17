use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub(super) const SCHEMA_VERSION: u32 = 1;

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

#[derive(Debug, Clone)]
pub struct RepositoryAnalysisContextOptions {
    pub target_root: PathBuf,
}

#[derive(Debug, Clone)]
pub struct RepositoryAnalysisApplyOptions {
    pub target_root: PathBuf,
    pub batch_id: String,
    pub file: PathBuf,
}

/// Incremental analysis: existing group definitions and route assignments are immutable.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AnalysisSubmission {
    pub schema_version: u32,
    pub catalog_revision: String,
    pub assignments: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub case_patterns: Option<BTreeMap<String, Option<String>>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CatalogDocument {
    pub api_groups: BTreeMap<String, String>,
}
