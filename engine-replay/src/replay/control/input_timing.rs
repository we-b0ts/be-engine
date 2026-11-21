use super::*;
use crate::interaction::replay::timing::{Advance, SocketIoTiming};
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Query {
    pub epoch: DateTime<Utc>,
    pub sequence: u64,
    pub completed: Vec<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events_ready: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closed_at: Option<DateTime<Utc>>,
}
mod client;
pub use client::connect;
