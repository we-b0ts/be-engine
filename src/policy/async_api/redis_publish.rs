//! A successful terminal PUBLISH selected by its channel and JSON message.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

use super::{AsyncRedisResponse, Endpoint};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AsyncRedisPublishEnd {
    pub operation: String,
    pub channel: String,
    #[serde(deserialize_with = "super::super::strict_map::unique_map")]
    pub when_message: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "AsyncRedisResponse::is_any")]
    pub when_response: AsyncRedisResponse,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<Endpoint>,
}

pub(super) fn validate(end: &mut AsyncRedisPublishEnd) -> Result<()> {
    ensure!(
        end.operation.eq_ignore_ascii_case("PUBLISH"),
        "async Redis channel completion requires PUBLISH"
    );
    end.operation.make_ascii_uppercase();
    ensure!(
        end.when_response.is_any(),
        "async Redis PUBLISH requires a successful integer reply; nil is not a PUBLISH result"
    );
    ensure!(
        !end.channel.trim().is_empty()
            && end.channel.len() <= 1024
            && !end.channel.contains('*')
            && !end.channel.chars().any(char::is_control),
        "async Redis PUBLISH channel requires a bounded exact name without wildcards or controls"
    );
    ensure!(
        (1..=32).contains(&end.when_message.len()),
        "async Redis PUBLISH completion requires 1..32 message conditions"
    );
    for (pointer, value) in &end.when_message {
        super::super::validate_pointer(pointer, false)?;
        ensure!(
            !value.is_array() && !value.is_object() && value.to_string().len() <= 4096,
            "async Redis PUBLISH message conditions require bounded literal JSON scalars"
        );
    }
    ensure!(
        end.database.is_none_or(|database| database >= 0),
        "async Redis database must be nonnegative"
    );
    if let Some(endpoint) = &end.endpoint {
        endpoint.validate()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
