//! Historical test-data DTOs only; converted to current global JSON declarations.
use crate::replay::RedisValueKeySelector;
use anyhow::Result;
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
    Rfc3339,
}

impl RedisTimeShiftRead {
    pub(in crate::replay) fn shared(&self) -> crate::replay::redis::shared_read::RedisSharedRead {
        crate::replay::redis::shared_read::RedisSharedRead {
            command: self.command.clone(),
            database: self.database,
            key: self.key.clone(),
            hash_field: self.hash_field.clone(),
        }
    }
    pub(in crate::replay) fn validate(&self) -> Result<()> {
        self.shared().validate()
    }
}
impl RedisTimeShiftSelector {
    pub(in crate::replay) fn shared(
        &self,
    ) -> crate::replay::redis::shared_read::RedisSharedReadSelector {
        crate::replay::redis::shared_read::RedisSharedReadSelector {
            host: self.host.clone(),
            port: self.port,
            read: self.read.shared(),
        }
    }
}
#[derive(Clone)]
pub(crate) struct RedisTimeShiftFeedback {
    pub policy_path: std::path::PathBuf,
    #[allow(dead_code)]
    pub case_source: std::path::PathBuf,
    #[allow(dead_code)]
    pub replay_report_path: std::path::PathBuf,
    pub rule_id: String,
    pub selector: RedisTimeShiftSelector,
    pub source_evidence: String,
}
