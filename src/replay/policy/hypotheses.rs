//! Common candidate-attempt evidence and its final durability barrier.
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{ReplayPolicy, RequestRuleRuntime};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct HypothesisContext {
    pub carrier: String,
    pub source_reference: Value,
    pub target_observation_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct HypothesisAttempt {
    #[serde(flatten)]
    pub candidate: crate::value_contract::hypothesis::Candidate,
    pub carrier: String,
    pub source_reference: Value,
    pub target_observation_id: Option<String>,
    pub validation: String,
    pub status: String,
    pub validation_reason: String,
}

pub(crate) async fn await_durable<P: crate::replay::protocol_runtime::ReplayProtocolSet>(
    state: &tokio::sync::Mutex<crate::replay::RuntimeState<P>>,
) -> Result<()> {
    let owner = state
        .lock()
        .await
        .replay_policy
        .as_ref()
        .map(|policy| policy.contracts().clone());
    if let Some(owner) = owner {
        owner.await_hypotheses_durable().await?;
    }
    Ok(())
}
