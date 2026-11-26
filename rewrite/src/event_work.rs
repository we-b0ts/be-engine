//! Public contracts for grouping recorded APIs and limiting grouped dispatch.

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiGrouping {
    pub api: String,
    pub case_pattern: String,
    pub group: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiConfirmation {
    pub api: String,
    pub implemented: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub case_pattern: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
}

pub fn validate_max_implementers(max: usize) -> Result<()> {
    ensure!(
        (1..=16).contains(&max),
        "session supports 1 to 16 implementers"
    );
    Ok(())
}
