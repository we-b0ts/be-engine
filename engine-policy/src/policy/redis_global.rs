//! Redis key-segment identities and scalar value formats selected by physical keys.
use super::GlobalField;
use crate::policy::GlobalFieldRuntime;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const GLOBAL_REDIS_ID: &str = "global.redis";

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedisPolicy {
    #[serde(default, deserialize_with = "super::strict_map::unique_map")]
    pub keys: BTreeMap<String, GlobalField>,
    #[serde(
        default,
        skip_serializing_if = "BTreeMap::is_empty",
        deserialize_with = "super::strict_map::unique_map"
    )]
    pub key_identities: BTreeMap<String, GlobalField>,
}

pub struct RedisKeyIdentity<'a> {
    pub prefix: &'a str,
    pub suffix: &'a str,
    pub field: &'a GlobalField,
}

impl RedisPolicy {
    pub fn validate(&self) -> Result<()> {
        let identity_only = self
            .key_identities
            .keys()
            .filter(|pattern| !self.keys.contains_key(*pattern))
            .count();
        ensure!(
            self.keys.len() + identity_only <= 4096,
            "redis.keys exceeds 4096 entries"
        );
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
                    GlobalField::Policy(_)
                        | GlobalField::Time { .. }
                        | GlobalField::Identity { .. }
                        | GlobalField::Duration { .. }
                ),
                "Redis scalar keys accept registered policies and time, identity or duration formats"
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
        let identities = self.key_identities.iter().collect::<Vec<_>>();
        for (index, (pattern, field)) in identities.iter().enumerate() {
            traffic_policy_document::authoring::redis_keys::key_format::affixes(pattern)?;
            ensure!(
                matches!(field, GlobalField::Identity { .. }),
                "standalone Redis key_format requires an identity format"
            );
            field.validate()?;
            for (other, _) in &identities[index + 1..] {
                ensure!(
                    !overlap(pattern, other),
                    "Redis key identity patterns {pattern:?} and {other:?} overlap"
                );
            }
        }
        Ok(())
    }

    // Applicability comes from the recorded key. The identity is the complete
    // wildcard segment, including any prefix declared by its identity format.
    pub fn key_identity(&self, key: &[u8]) -> Option<RedisKeyIdentity<'_>> {
        self.key_identities.iter().find_map(|(pattern, field)| {
            let (prefix, suffix) = pattern.split_once('*')?;
            matches_affixes(prefix, suffix, key).then_some(RedisKeyIdentity {
                prefix,
                suffix,
                field,
            })
        })
    }

    #[allow(dead_code)]
    pub fn field(&self, key: &[u8]) -> Result<Option<&GlobalField>> {
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
        Some((prefix, suffix)) => matches_affixes(prefix, suffix, value),
        None => pattern.as_bytes() == value,
    }
}

fn matches_affixes(prefix: &str, suffix: &str, value: &[u8]) -> bool {
    value.len() >= prefix.len() + suffix.len()
        && value.starts_with(prefix.as_bytes())
        && value.ends_with(suffix.as_bytes())
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
        let policy: RedisPolicy =
            serde_yaml::from_str("keys:\n  'clock:*': {kind: time, formats: [unix_seconds]}\n")
                .unwrap();
        policy.validate().unwrap();
        assert!(policy.field(b"clock:record").unwrap().is_some());
        assert!(policy.field(b"other").unwrap().is_none());
        for invalid in [
            "database: 0\nkeys: {}",
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
