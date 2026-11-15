//! Compatibility entrypoints for Source-selected registered value semantics.
#[cfg(test)]
use crate::policy::{FieldContract, TimePolicy};
#[cfg(test)]
use crate::policy::{TimeAnchor, TimestampFormat};
#[cfg(test)]
use anyhow::Result;
#[cfg(test)]
use serde_json::Value;

pub(crate) const RULE_ID: &str = "builtin.time";

#[cfg(test)]
fn facts(settings: &TimePolicy) -> traffic_value::Value {
    serde_json::from_value(serde_json::json!({"settings":{"time":settings}}))
        .expect("time settings are serializable logical values")
}

#[cfg(test)]
pub(crate) fn contract(source: &Value, settings: &TimePolicy) -> Option<FieldContract> {
    let source = serde_json::from_value(source.clone()).ok()?;
    let inferred = traffic_extensions::policies()
        .infer(&source, &facts(settings))
        .ok()??;
    traffic_policy_value::inference::contract(inferred)
        .ok()
        .filter(|contract| matches!(contract, FieldContract::Time { .. }))
}

#[cfg(test)]
pub(crate) fn source_fields(
    source: &traffic_value::Value,
    settings: &TimePolicy,
) -> Result<Vec<traffic_policy_value::inference::InferredField>> {
    traffic_policy_value::inference::fields(
        traffic_extensions::policies(),
        source,
        &facts(settings),
    )
}

#[cfg(test)]
pub(crate) fn fields(
    source: &Value,
    settings: &TimePolicy,
) -> Result<Vec<(String, FieldContract)>> {
    Ok(
        source_fields(&serde_json::from_value(source.clone())?, settings)?
            .into_iter()
            .map(|field| (field.pointer, field.contract))
            .collect(),
    )
}

#[cfg(test)]
pub(crate) use traffic_policy_value::fields::pointer_pattern;

#[cfg(test)]
mod tests;
