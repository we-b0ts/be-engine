//! Physical finite-read sharing. JSON content belongs to the global strategy.
use super::{RecordedExchange, key_selector::RedisValueKeySelector};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedisSharedReadSelector {
    pub host: String,
    pub port: u16,
    pub read: RedisSharedRead,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedisSharedRead {
    pub command: String,
    #[serde(default)]
    pub database: i64,
    pub key: RedisValueKeySelector,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash_field: Option<RedisValueKeySelector>,
}

impl RedisSharedReadSelector {
    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            !self.host.trim().is_empty() && !self.host.contains(['*', '/', ' ']) && self.port > 0,
            "finite Redis sharing requires an exact host and port"
        );
        self.read.validate()
    }
    pub(in crate::replay::redis) fn matches(
        &self,
        record: &RecordedExchange,
        args: &[Vec<u8>],
    ) -> bool {
        super::normalize_host(&self.host) == super::normalize_host(&record.target_host)
            && self.port == record.target_port
            && self.read.matches(record, args)
    }
}

impl RedisSharedRead {
    pub(in crate::replay) fn validate(&self) -> Result<()> {
        ensure!(
            matches!(self.command.as_str(), "GET" | "HGET"),
            "finite Redis sharing supports GET and HGET"
        );
        ensure!(self.database >= 0, "Redis database must be nonnegative");
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
            && record.database == self.database
            && args.len() == if self.command == "HGET" { 2 } else { 1 }
            && self.key.matches(&args[0])
            && self
                .hash_field
                .as_ref()
                .is_none_or(|field| field.matches(&args[1]))
    }
    pub(in crate::replay) fn overlaps(&self, other: &Self) -> bool {
        self.command == other.command
            && self.database == other.database
            && self.key.overlaps(&other.key)
            && match (&self.hash_field, &other.hash_field) {
                (Some(a), Some(b)) => a.overlaps(b),
                (None, None) => true,
                _ => false,
            }
    }
}
