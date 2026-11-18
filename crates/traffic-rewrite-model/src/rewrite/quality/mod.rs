use crate::rewrite::*;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityReport {
    pub schema_version: u8,
    // Historical receipts remain readable, but cannot pass stage admission.
    #[serde(default)]
    pub scope: Option<QualityScope>,
    pub policy_fingerprint: String,
    pub replay_isolation: ReplayIsolationReport,
    /// Tool the agent reports having passed on this final candidate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quality_check: Option<String>,
    // Historical command results remain readable but never grant admission.
    #[serde(default)]
    pub commands: Vec<QualityCommandReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityCommandReport {
    pub name: String,
    pub argv: Vec<String>,
    /// Candidate-relative execution directory; portable across Git worktrees.
    #[serde(default = "default_working_directory")]
    pub working_directory: PathBuf,
    pub status: QualityCommandStatus,
    pub exit_code: Option<i32>,
    pub log_path: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualityCommandStatus {
    Passed,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualityScope {
    Worker,
    Integration,
    PreRevalidation,
}
fn default_working_directory() -> PathBuf {
    PathBuf::from(".")
}
