//! Bounded diagnostic hypotheses accompanying value comparison.
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Candidate {
    pub case_id: String,
    pub candidate_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub attempt_id: String,
    pub pointer: String,
    pub command: String,
    pub draft_policy: Value,
    pub expected: Value,
    pub actual: Value,
    pub source_proof_required: bool,
    pub reason: String,
}
