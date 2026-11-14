//! Application policy bindings for shared derived-value delivery.
use super::json::AnchorClocks;
use crate::policy::CompiledRule;
use anyhow::Result;
use serde_json::Value;

pub(crate) use traffic_contract::delivery::{select, shift, value_quantum};

pub(crate) fn materialize(
    source: &Value,
    rules: &[&CompiledRule],
    clocks: AnchorClocks,
) -> Result<Value> {
    let fields = rules
        .iter()
        .flat_map(|rule| {
            rule.delivery_time.iter().map(move |(pointer, contract)| {
                traffic_contract::delivery::TimeField {
                    rule_id: &rule.rule.id,
                    pointer,
                    contract,
                }
            })
        })
        .collect::<Vec<_>>();
    traffic_contract::delivery::materialize(source, &fields, clocks, &super::json::PolicyMetadata)
}

#[cfg(test)]
use super::time;
#[cfg(test)]
use crate::policy::{TimeAnchor, TimeContract, TimestampFormat};
#[cfg(test)]
use chrono::{DateTime, Utc};
#[cfg(test)]
mod tests;
