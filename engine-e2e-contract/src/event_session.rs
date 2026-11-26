use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone)]
pub struct E2eEventSessionOptions {
    pub target_root: PathBuf,
    pub recording_root: PathBuf,
    pub run_key: Option<String>,
    pub expected_target_commit: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct E2eEventSessionProgress {
    pub matched: usize,
    pub total: Option<usize>,
    pub last_sequence: Option<u64>,
    pub complete: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure: Option<Value>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum E2eEventSessionPhase {
    #[default]
    PreparingReplay,
    Building,
    StartingTarget,
    Replaying,
    Finalizing,
    Complete,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct E2eEventSessionApiProgress {
    pub verified: usize,
    pub total: Option<usize>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct E2eEventSessionCaseProgress {
    pub completed: u64,
    pub total: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct E2eEventSessionCounts {
    pub matched: usize,
    pub total: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct E2eEventSessionSequenceProgress {
    pub last_sequence: Option<u64>,
    pub complete: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct E2eEventSessionStatusProgress {
    pub phase: E2eEventSessionPhase,
    pub events: E2eEventSessionCounts,
    pub apis: E2eEventSessionApiProgress,
    #[serde(default)]
    pub cases: E2eEventSessionCaseProgress,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct E2eEventSessionResult {
    pub run_key: String,
    pub attempt_id: String,
    pub recording_root: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_commit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_inputs: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine_revision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_image_id: Option<String>,
    pub passed: bool,
    pub events: E2eEventSessionProgress,
    #[serde(default)]
    pub phase: E2eEventSessionPhase,
    #[serde(default)]
    pub apis: E2eEventSessionApiProgress,
    #[serde(default)]
    pub cases: E2eEventSessionCaseProgress,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub progress: PathBuf,
    pub report: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum E2eEventSessionState {
    NotStarted,
    Running,
    Interrupted,
    Failed,
    Passed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct E2eEventSessionStatus {
    pub state: E2eEventSessionState,
    pub progress: Option<E2eEventSessionStatusProgress>,
    pub attempt: Option<E2eEventSessionResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_events: Option<E2eEventSessionSequenceProgress>,
}
