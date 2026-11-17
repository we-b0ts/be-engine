//! Common candidate-attempt evidence and its final durability barrier.
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HypothesisContext {
    pub carrier: String,
    pub source_reference: Value,
    pub target_observation_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HypothesisAttempt {
    #[serde(flatten)]
    pub candidate: crate::value_contract::hypothesis::Candidate,
    pub carrier: String,
    pub source_reference: Value,
    pub target_observation_id: Option<String>,
    pub validation: String,
    pub status: String,
    pub validation_reason: String,
}
