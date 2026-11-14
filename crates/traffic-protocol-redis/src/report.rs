//! Native subscription identity carried by Source-bound report projections.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationIdentity {
    pub target: traffic_protocol::connection::Endpoint,
    pub database: i64,
    pub username: Option<String>,
    pub connection_id: Uuid,
    pub subscription_sequence: u64,
    pub kind: String,
    pub subject: Vec<u8>,
    pub subscription_proof: Value,
}

impl NotificationIdentity {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.subscription_sequence > 0,
            "invalid shared notification lane"
        );
        ensure!(
            matches!(self.kind.as_str(), "channel" | "pattern" | "shard_channel"),
            "invalid shared notification kind"
        );
        Ok(())
    }
}
