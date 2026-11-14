//! Physical finite-read sharing. JSON content belongs to the global strategy.
use super::{RecordedExchange, key_selector::RedisValueKeySelector};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

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
    pub(crate) fn validate(&self) -> Result<()> {
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
    pub(in crate::replay::redis) fn matches(
        &self,
        record: &RecordedExchange,
        args: &[Vec<u8>],
    ) -> bool {
        self.host.as_ref().is_none_or(|host| {
            super::normalize_host(host) == super::normalize_host(&record.native.target_host)
        }) && self
            .port
            .is_none_or(|port| port == record.native.target_port)
            && self.read.matches(record, args)
    }
}

impl RedisSharedRead {
    pub(in crate::replay) fn validate(&self) -> Result<()> {
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
        record.native.command.eq_ignore_ascii_case(&self.command)
            && self
                .database
                .is_none_or(|database| record.native.database == database)
            && args.len() == if self.command == "HGET" { 2 } else { 1 }
            && self.key.matches(&args[0])
            && self
                .hash_field
                .as_ref()
                .is_none_or(|field| field.matches(&args[1]))
    }
    pub(in crate::replay) fn overlaps(&self, other: &Self) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn global_sharing_selects_keys_without_changing_physical_request_identity() {
        let selector: RedisSharedReadSelector = serde_json::from_value(json!({
            "read":{"command":"HGET","key":"token_v2","hash_field":"3061639762"}
        }))
        .unwrap();
        selector.validate().unwrap();
        let args = vec![b"token_v2".to_vec(), b"3061639762".to_vec()];
        let target = super::super::TargetKey {
            host: "cache.test".into(),
            port: 6379,
        };
        let original = super::super::cross_case::target_fingerprint(
            &target,
            2,
            1,
            Some("alice"),
            "HGET",
            &args,
        );
        for (host, port, database, username) in [
            ("other.test", 6379, 1, Some("alice")),
            ("cache.test", 6380, 1, Some("alice")),
            ("cache.test", 6379, 2, Some("alice")),
            ("cache.test", 6379, 1, Some("bob")),
        ] {
            let record: RecordedExchange = serde_json::from_value(json!({
                "connection_id":uuid::Uuid::new_v4(),"sequence":1,"target_host":host,"target_port":port,
                "database":database,"username":username,"resp_version":2,"command":"HGET","args":[],
                "response_kind":"bulk_string","response":{"encoding":"utf8","data":"$2\r\nok\r\n"},"duration_ms":0,"replay_safe":true
            })).unwrap();
            assert!(selector.matches(&record, &args));
            let target = super::super::TargetKey {
                host: host.into(),
                port,
            };
            assert_ne!(
                original,
                super::super::cross_case::target_fingerprint(
                    &target, 2, database, username, "HGET", &args
                )
            );
        }
        let mut scoped = selector;
        scoped.host = Some("cache.test".into());
        scoped.port = Some(6379);
        scoped.read.database = Some(1);
        assert!(scoped.read.overlaps(&RedisSharedRead {
            database: None,
            ..scoped.read.clone()
        }));
        assert!(!scoped.read.overlaps(&RedisSharedRead {
            database: Some(2),
            ..scoped.read.clone()
        }));
    }
}
