//! Protocol-independent workflow phases, inventory progress and attempt deltas.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RewritePhase {
    RecordingRequired,
    ApiPending,
    ImplementationRequired,
    AwaitingRecordingRefresh,
    SystemRepairRequired,
    SliceComplete,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RewriteApiStatus {
    #[default]
    Pending,
    Active,
    ImplementationRequired,
    SystemRepairRequired,
    AwaitingRecordingRefresh,
    RevalidationPending,
    Complete,
    Skipped,
}

impl RewriteApiStatus {
    pub fn is_done(self) -> bool {
        matches!(self, Self::Complete | Self::Skipped)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewriteApiProgress {
    pub api: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_route: Option<String>,
    #[serde(default)]
    pub status: RewriteApiStatus,
    #[serde(default)]
    pub attempts: usize,
    #[serde(default)]
    pub e2e_current: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_target_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewriteAttemptDelta {
    pub previous_attempt: u64,
    pub current_attempt: u64,
    pub response_passed_delta: i64,
    pub response_nonpassing_delta: i64,
    pub improved: bool,
    pub regressed: bool,
}
