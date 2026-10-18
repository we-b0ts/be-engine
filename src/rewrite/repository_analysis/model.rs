use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub(super) const SCHEMA_VERSION: u32 = 1;

/// Source-backed grouping metadata, independent of a workflow's implementer slots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryAnalysisGroup {
    pub summary: String,
    pub source_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub shared_modules: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub write_hotspots: Vec<String>,
}

/// The adopted project catalog. Runtime ownership belongs to the workflow pool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryAnalysisSnapshot {
    pub catalog_revision: String,
    pub groups: BTreeMap<String, RepositoryAnalysisGroup>,
    pub api_groups: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RepositoryAnalysisContext {
    pub schema_version: u32,
    pub workflow_id: String,
    pub recording_run_id: String,
    pub source_revision: String,
    /// Complete selected canonical route scope; HTTP methods are grouped together.
    pub scope: Vec<String>,
    pub pending_apis: Vec<String>,
    pub batch_id: String,
    pub catalog_path: PathBuf,
    pub catalog: RepositoryAnalysisSnapshot,
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
    #[serde(default)]
    pub groups: BTreeMap<String, RepositoryAnalysisGroup>,
    pub assignments: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CatalogDocument {
    pub schema_version: u32,
    pub groups: BTreeMap<String, RepositoryAnalysisGroup>,
    pub api_groups: BTreeMap<String, String>,
    /// Lets a retry finish adopting a catalog committed before the state save.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_applied: Option<AppliedAnalysis>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AppliedAnalysis {
    pub batch_id: String,
    pub submission_digest: String,
    pub scope_digest: String,
}
