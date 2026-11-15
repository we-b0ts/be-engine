//! Application bindings for rule-owned derived-value delivery.
#[cfg(test)]
use super::json::AnchorClocks;
#[cfg(test)]
use crate::policy::CompiledRule;
#[cfg(test)]
use anyhow::Result;
#[cfg(test)]
use serde_json::Value;
pub(crate) use traffic_contract::delivery::{select, shift};

#[cfg(test)]
pub(crate) fn materialize(
    source: &Value,
    rules: &[&CompiledRule],
    clocks: AnchorClocks,
) -> Result<Value> {
    traffic_policy_execution::delivery::materialize(
        &super::execution_context(),
        source,
        rules,
        clocks,
    )
}

#[cfg(test)]
use super::time;
#[cfg(test)]
use crate::policy::{TimeAnchor, TimeContract, TimestampFormat};
#[cfg(test)]
use chrono::{DateTime, Utc};
#[cfg(test)]
mod tests;
