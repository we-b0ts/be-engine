//! Exact dependency selection and explicit response timestamp semantics.
use super::super::{RecordedExchange, key_selector::RedisValueKeySelector};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedisTimeShiftSelector {
    pub host: String,
    pub port: u16,
    pub read: RedisTimeShiftRead,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedisTimeShiftRead {
    pub command: String,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub database: i64,
    pub key: RedisValueKeySelector,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash_field: Option<RedisValueKeySelector>,
    pub response_json: BTreeMap<String, RelativeTimeField>,
}
fn is_zero(value: &i64) -> bool {
    *value == 0
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelativeTimeField {
    pub time: RelativeTime,
    pub format: RedisTimestampFormat,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelativeTime {
    PreserveRelative,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum RedisTimestampFormat {
    UnixSeconds,
    UnixMilliseconds,
}

impl RedisTimeShiftSelector {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.host.trim().is_empty() && !self.host.contains(['*', '/', ' ']) && self.port > 0,
            "time-shift requires an exact Redis host and port"
        );
        self.read.validate()
    }
    pub(in crate::replay::redis) fn matches(
        &self,
        record: &RecordedExchange,
        args: &[Vec<u8>],
    ) -> bool {
        super::super::normalize_host(&self.host)
            == super::super::normalize_host(&record.target_host)
            && self.port == record.target_port
            && self.read.matches(record, args)
    }
}

impl RedisTimeShiftRead {
    pub(in crate::replay) fn validate(&self) -> Result<()> {
        ensure!(
            matches!(self.command.as_str(), "GET" | "HGET"),
            "Redis time-shift supports GET and HGET bulk JSON responses"
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
        ensure!(
            !self.response_json.is_empty() && self.response_json.len() <= 32,
            "time-shift requires 1..32 JSON timestamp fields"
        );
        let paths: Vec<_> = self.response_json.keys().collect();
        for (i, path) in paths.iter().enumerate() {
            ensure!(
                path.len() <= 1024 && path.starts_with('/'),
                "time-shift requires an exact non-root JSON Pointer"
            );
            // Reject malformed escapes and wildcard syntax rather than guessing a location.
            for segment in path[1..].split('/') {
                ensure!(
                    segment != "*",
                    "time-shift JSON Pointers do not expand wildcards"
                );
                let mut chars = segment.chars();
                while let Some(c) = chars.next() {
                    if c == '~' {
                        ensure!(
                            matches!(chars.next(), Some('0' | '1')),
                            "invalid JSON Pointer escape"
                        );
                    }
                }
            }
            ensure!(
                paths[..i].iter().all(|p| !pointer_overlap(p, path)),
                "overlapping time-shift JSON Pointers"
            );
        }
        Ok(())
    }
    pub(super) fn matches(&self, record: &RecordedExchange, args: &[Vec<u8>]) -> bool {
        record.command.eq_ignore_ascii_case(&self.command)
            && record.database == self.database
            && args.len() == if self.command == "HGET" { 2 } else { 1 }
            && self.key.matches(&args[0])
            && self.hash_field.as_ref().is_none_or(|f| f.matches(&args[1]))
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
            && self
                .response_json
                .keys()
                .any(|a| other.response_json.keys().any(|b| pointer_overlap(a, b)))
    }
}
fn pointer_overlap(a: &str, b: &str) -> bool {
    a == b
        || a.strip_prefix(b).is_some_and(|s| s.starts_with('/'))
        || b.strip_prefix(a).is_some_and(|s| s.starts_with('/'))
}
