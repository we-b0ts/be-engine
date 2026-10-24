//! Physical Redis scalar formats; structured values use the global JSON strategy.
use super::GlobalField;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const GLOBAL_REDIS_ID: &str = "global.redis";

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedisPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database: Option<i64>,
    #[serde(default, deserialize_with = "super::strict_map::unique_map")]
    pub keys: BTreeMap<String, GlobalField>,
}

impl RedisPolicy {
    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            self.database.is_none_or(|value| value >= 0),
            "Redis database must be nonnegative"
        );
        ensure!(self.keys.len() <= 4096, "redis.keys exceeds 4096 entries");
        for (pattern, field) in &self.keys {
            ensure!(
                !pattern.is_empty()
                    && pattern.len() <= 1024
                    && pattern.bytes().filter(|byte| *byte == b'*').count() <= 1,
                "Redis key requires a nonempty bounded physical key or single-wildcard pattern"
            );
            field.validate()?;
            ensure!(
                matches!(
                    field,
                    GlobalField::Time { .. }
                        | GlobalField::Identity { .. }
                        | GlobalField::Duration { .. }
                ),
                "Redis scalar keys accept time, identity or duration; JSON protocols and arrays use json.fields"
            );
        }
        let keys = self.keys.iter().collect::<Vec<_>>();
        for (index, (left, field)) in keys.iter().enumerate() {
            for (right, other) in &keys[index + 1..] {
                ensure!(
                    !overlap(left, right) || field == other,
                    "overlapping Redis key patterns assign different formats"
                );
            }
        }
        Ok(())
    }

    pub(crate) fn field(&self, database: i64, key: &[u8]) -> Result<Option<&GlobalField>> {
        if self.database.is_some_and(|expected| expected != database) {
            return Ok(None);
        }
        let mut result = None;
        for (pattern, field) in &self.keys {
            if matches(pattern, key) {
                ensure!(
                    result.is_none_or(|prior| prior == field),
                    "overlapping Redis scalar formats disagree"
                );
                result = Some(field);
            }
        }
        Ok(result)
    }
}

fn matches(pattern: &str, value: &[u8]) -> bool {
    match pattern.split_once('*') {
        Some((prefix, suffix)) => {
            value.len() >= prefix.len() + suffix.len()
                && value.starts_with(prefix.as_bytes())
                && value.ends_with(suffix.as_bytes())
        }
        None => pattern.as_bytes() == value,
    }
}

fn overlap(left: &str, right: &str) -> bool {
    match (left.split_once('*'), right.split_once('*')) {
        (None, _) => matches(right, left.as_bytes()),
        (_, None) => matches(left, right.as_bytes()),
        (Some((lp, ls)), Some((rp, rs))) => {
            (lp.starts_with(rp) || rp.starts_with(lp)) && (ls.ends_with(rs) || rs.ends_with(ls))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalar_key_patterns_are_physical_bounded_and_unambiguous() {
        let policy: RedisPolicy = serde_yaml::from_str(
            "database: 0\nkeys:\n  'clock:*': {kind: time, formats: [unix_seconds]}\n",
        )
        .unwrap();
        policy.validate().unwrap();
        assert!(policy.field(0, b"clock:record").unwrap().is_some());
        assert!(policy.field(1, b"clock:record").unwrap().is_none());
        assert!(policy.field(0, b"other").unwrap().is_none());
        for invalid in [
            "keys: {'a*b*c': {kind: time, formats: [unix_seconds]}}",
            "keys: {'clock:*': {kind: time, formats: [unix_seconds]}, 'clock:item': {kind: identity, formats: [uuid]}}",
            "keys: {'clock': {kind: unordered}}",
        ] {
            assert!(match serde_yaml::from_str::<RedisPolicy>(invalid) {
                Ok(policy) => policy.validate().is_err(),
                Err(_) => true,
            });
        }
    }
}
