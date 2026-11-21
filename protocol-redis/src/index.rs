//! RESP command lookup identities are independent of storage locations.
use anyhow::{Context, Result};
use serde_json::Value;
use sha2::{Digest, Sha256};
use traffic_protocol::evidence::index::{IndexEndpoint, LookupProjection};

pub fn key(host: &str, port: u16, database: i64, command: &str, args: &[Vec<u8>]) -> String {
    format!(
        "{:x}",
        Sha256::digest(
            serde_json::to_vec(&(
                host.trim_end_matches('.').to_ascii_lowercase(),
                port,
                database,
                command.to_ascii_uppercase(),
                args
            ))
            .unwrap()
        )
    )
}
pub fn endpoint(event: &Value) -> Option<IndexEndpoint> {
    Some(IndexEndpoint {
        host: event["target_host"]
            .as_str()?
            .trim_end_matches('.')
            .to_ascii_lowercase(),
        port: u16::try_from(event["target_port"].as_u64()?).ok()?,
        protocol: "redis".into(),
    })
}
pub fn lookup(event: &Value) -> Result<Option<LookupProjection>> {
    let tag = event["event_type"].as_str().unwrap_or_default();
    if !matches!(tag, "redis_exchange" | "redis_pub_sub_push") {
        return Ok(None);
    }
    let connection = event["connection_id"]
        .as_str()
        .context("Redis connection identity missing")?
        .to_owned();
    let key = if tag == "redis_exchange" {
        let args = event["args"]
            .as_array()
            .context("Redis arguments missing")?
            .iter()
            .map(|value| {
                // Indexing retains incomplete records; execution still rejects them.
                let mut value = value.clone();
                value["truncated"] = false.into();
                serde_json::from_value::<crate::recorded::RecordedCapture>(value)?.decode()
            })
            .collect::<Result<Vec<_>>>()?;
        Some(key(
            event["target_host"]
                .as_str()
                .context("Redis host missing")?,
            u16::try_from(
                event["target_port"]
                    .as_u64()
                    .context("Redis port missing")?,
            )?,
            event["database"]
                .as_i64()
                .context("Redis database missing")?,
            event["command"].as_str().context("Redis command missing")?,
            &args,
        ))
    } else {
        None
    };
    Ok(Some(LookupProjection {
        index: "redis".into(),
        key,
        connection: Some(connection),
        summary: Value::Null,
    }))
}
