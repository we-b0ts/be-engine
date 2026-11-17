//! Application assembly for built-in protocol state and native connection drivers.
pub mod auto_protocol;
pub mod http;
pub use http::contracts::{
    multipart_witness_matches as http_multipart_witness_matches,
    source_witness as http_source_witness, validate_witness as http_validate_witness,
    witness_metadata_matches as http_witness_metadata_matches, witness_value as http_witness_value,
};
pub use http::cross_case as http_cross_case;
pub use http::cross_case::HttpCrossCaseSelector;
pub use http::diagnosis as http_request_diagnosis;
pub use traffic_protocol_redis::key_selector::RedisValueKeySelector;
pub type RedisUnorderedField = traffic_protocol_redis::bindings::LegacyValueLocation<
    traffic_policy_schema::response::ProtobufFieldPath,
    traffic_policy_schema::response::ProtobufRepeatedElementType,
>;
pub type RedisUnorderedSelector =
    traffic_protocol_redis::bindings::LegacyUnorderedSelector<RedisUnorderedField>;
pub use traffic_protocol_redis::request_identity::request_fingerprint as redis_request_fingerprint;
pub mod redis_value {}
pub fn normalize_redis_expiration(
    command: &str,
    source: &[Vec<u8>],
    target: &[Vec<u8>],
    clocks: traffic_contract::time::ClockPair,
) -> anyhow::Result<Option<Vec<Vec<u8>>>> {
    traffic_protocol_redis::expiration::normalize(
        command,
        source,
        target,
        crate::value_contract::time::DEFAULT_TOLERANCE,
        |scale| {
            let (source, target) = clocks.require()?;
            Ok(if scale == 1000 {
                (source.timestamp_millis(), target.timestamp_millis())
            } else {
                (source.timestamp(), target.timestamp())
            })
        },
    )
}
pub mod mysql;
pub fn mysql_source_witness(
    event: &serde_json::Value,
    surface: crate::policy::Surface,
) -> anyhow::Result<Vec<u8>> {
    traffic_protocol_mysql::witness::source_payload(event, surface.dependency_side()?)
}
pub fn mysql_witness_sql_value(
    raw: &[u8],
    surface: crate::policy::Surface,
    database: Option<&str>,
    index: usize,
) -> anyhow::Result<Option<serde_json::Value>> {
    let mut value = traffic_protocol_mysql::witness::sql_value(
        raw,
        surface.dependency_side()?,
        database,
        index,
    )?;
    if let Some(value) = &mut value
        && let Some(text) = value["value"].as_str()
        && let Some(codec) =
            crate::value_codec::try_recognize(text.as_bytes(), &traffic_value::Value::Null)?
        && let Ok(decoded) = codec.decode(text.as_bytes())
        && (decoded.logical.is_object() || decoded.logical.is_array())
    {
        value["json"] = decoded.logical;
    }
    Ok(value)
}
pub mod runtime;

pub mod report;
pub mod source;
#[allow(non_upper_case_globals)]
impl ReplayProtocol {
    pub const Mysql: Self = Self::new(traffic_protocol::ProtocolId::new("mysql"));
    pub const Http: Self = Self::new(traffic_protocol::ProtocolId::new("http"));
    pub const Https: Self = Self::new(traffic_protocol::ProtocolId::new("https"));
    pub const Redis: Self = Self::new(traffic_protocol::ProtocolId::new("redis"));

    pub fn resolve(value: &str, providers: &crate::protocols::DependencyProviders) -> Result<Self> {
        let known = [
            Self::Auto,
            Self::Mysql,
            Self::Http,
            Self::Https,
            Self::Redis,
        ];
        known
            .into_iter()
            .find(|protocol| protocol.id().as_str() == value)
            .or_else(|| {
                providers
                    .registrations()
                    .iter()
                    .find(|entry| entry.kind.as_str() == value)
                    .map(|entry| Self::registered(entry.kind))
            })
            .context("dependency protocol has no registered implementation")
    }
}

/// Historical snapshot plans require a stateful capability beyond finite native Replay.
pub fn inspect_case_source_snapshot_overlay(
    _case_source: &Path,
    _policy: &Path,
    _rule_name: &str,
) -> Result<crate::replay::report::command::CommandSnapshotOverlayReport> {
    anyhow::bail!("Redis snapshot overlays require an installed native snapshot capability")
}

use crate::replay::ReplayProtocol;
use anyhow::{Context, Result};
use std::path::Path;
