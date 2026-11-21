//! Persisted legacy carrier selectors, independent of semantic policy implementations.
pub use crate::key_selector::RedisValueKeySelector;
use crate::recorded::RecordedExchange;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "codec", rename_all = "snake_case", deny_unknown_fields)]
pub enum LegacyValueLocation<P, E> {
    Json {
        pointer: String,
    },
    Protobuf {
        field_path: P,
        element_type: E,
        display_path: String,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LegacyUnorderedSelector<F> {
    pub host: String,
    pub port: u16,
    pub key: RedisValueKeySelector,
    pub field: F,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedisSharedReadSelector {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    pub read: RedisSharedRead,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedisSharedRead {
    pub command: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database: Option<i64>,
    pub key: RedisValueKeySelector,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash_field: Option<RedisValueKeySelector>,
}

impl RedisSharedReadSelector {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.host.is_none() && self.port.is_none()
                || self
                    .host
                    .as_ref()
                    .is_some_and(|host| !host.trim().is_empty() && !host.contains(['*', '/', ' ']))
                    && self.port.is_some_and(|port| port > 0),
            "finite Redis sharing requires an exact host and port"
        );
        self.read.validate()
    }
    pub fn matches(&self, record: &RecordedExchange, args: &[Vec<u8>]) -> bool {
        self.host.as_ref().is_none_or(|host| {
            traffic_protocol::observation::normalize_host(host)
                == traffic_protocol::observation::normalize_host(&record.target_host)
        }) && self.port.is_none_or(|port| port == record.target_port)
            && self.read.matches(record, args)
    }
}

impl RedisSharedRead {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            matches!(self.command.as_str(), "GET" | "HGET"),
            "finite Redis sharing supports GET and HGET"
        );
        ensure!(
            self.database.is_none_or(|database| database >= 0),
            "Redis database must be nonnegative"
        );
        self.key.validate()?;
        ensure!(
            (self.command == "HGET") == self.hash_field.is_some(),
            "HGET requires hash_field; GET cannot select hash_field"
        );
        if let Some(field) = &self.hash_field {
            field.validate()?;
        }
        Ok(())
    }
    fn matches(&self, record: &RecordedExchange, args: &[Vec<u8>]) -> bool {
        record.command.eq_ignore_ascii_case(&self.command)
            && self
                .database
                .is_none_or(|database| record.database == database)
            && args.len() == if self.command == "HGET" { 2 } else { 1 }
            && self.key.matches(&args[0])
            && self
                .hash_field
                .as_ref()
                .is_none_or(|field| field.matches(&args[1]))
    }
    pub fn overlaps(&self, other: &Self) -> bool {
        self.command == other.command
            && self
                .database
                .zip(other.database)
                .is_none_or(|(left, right)| left == right)
            && self.key.overlaps(&other.key)
            && match (&self.hash_field, &other.hash_field) {
                (Some(a), Some(b)) => a.overlaps(b),
                (None, None) => true,
                _ => false,
            }
    }
}
