use crate::rewrite::*;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayIsolationReport {
    pub schema_version: u8,
    pub gate: String,
    pub status: ReplayIsolationStatus,
    pub scanned_files: usize,
    pub scanned_added_lines: usize,
    pub violations: Vec<ReplayIsolationViolation>,
    pub omitted_violations: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayIsolationStatus {
    Passed,
    Failed,
}

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct ReplayIsolationViolation {
    pub file: PathBuf,
    pub line: usize,
    pub column: usize,
    pub rule: String,
    pub matched: String,
    pub reason: String,
    pub required_change: String,
}

impl ReplayIsolationReport {
    pub fn passed(&self) -> bool {
        self.schema_version == 2
            && self.gate == GATE_NAME
            && matches!(self.status, ReplayIsolationStatus::Passed)
            && self.violations.is_empty()
            && self.omitted_violations == 0
    }
}

const GATE_NAME: &str = "replay-isolation";
