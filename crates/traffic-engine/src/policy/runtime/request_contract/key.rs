//! Historical key declaration and report schema.
mod config;
pub(crate) use config::{IdentityField, KeyContract, KeyFormat, Transform};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub(crate) struct KeyBindingReport {
    pub case_id: String,
    pub host: String,
    pub port: u16,
    pub database: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    pub source_fingerprint: String,
    pub target_fingerprint: String,
}
