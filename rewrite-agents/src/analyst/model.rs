use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: u32 = 1;

pub use traffic_rewrite_model::rewrite::repository_analysis::model::RepositoryAnalysisSnapshot;

pub use traffic_rewrite_model::rewrite::repository_analysis::model::RepositoryAnalysisContext;

pub use traffic_rewrite_model::rewrite::repository_analysis::model::CasePatternContext;

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
pub struct AnalysisSubmission {
    pub schema_version: u32,
    pub catalog_revision: String,
    pub assignments: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub case_patterns: Option<BTreeMap<String, Option<String>>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogDocument {
    pub api_groups: BTreeMap<String, String>,
}
