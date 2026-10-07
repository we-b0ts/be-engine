//! Redis request-value and response-time policy schema and overlap validation.
use super::config::{DependencyProtocol, ReplayDependencyRule, ReplayScope};
use crate::replay::redis::value::{
    RedisUnorderedField, RedisUnorderedSelector, RedisValueKeySelector,
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub(super) enum RedisSelector {
    Lock(RedisLockConfig),
    Value(RedisValueSelector),
    TimeShift(crate::replay::redis::time_shift::RedisTimeShiftRead),
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RedisLockConfig {
    pub lock: RedisLockField,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RedisLockField {
    pub key: RedisValueKeySelector,
    pub source_evidence: String,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RedisValueSelector {
    pub key: RedisValueKeySelector,
    pub unordered: Vec<RedisFieldRule>,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RedisFieldRule {
    pub field: RedisUnorderedField,
    pub source_evidence: String,
}
impl RedisSelector {
    pub(super) fn selectors(&self, rule: &ReplayDependencyRule) -> Vec<RedisUnorderedSelector> {
        let Self::Value(value) = self else {
            return Vec::new();
        };
        value
            .unordered
            .iter()
            .map(|f| RedisUnorderedSelector {
                host: rule.target.host.clone().unwrap_or_default(),
                port: rule.target.port.unwrap_or_default(),
                key: value.key.clone(),
                field: f.field.clone(),
            })
            .collect()
    }
}
pub(super) fn validate(rule: &ReplayDependencyRule) -> Result<()> {
    let redis = rule
        .redis
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Redis rule requires redis selector"))?;
    ensure!(
        rule.case_selector.is_none(),
        "Redis rules cannot select a case"
    );
    ensure!(
        rule.replay_scope == ReplayScope::Case || matches!(redis, RedisSelector::TimeShift(_)),
        "Redis recording_run scope requires a GET/HGET time-shift selector"
    );
    ensure!(
        rule.http.is_none() && rule.mysql.is_none() && rule.memcached.is_none(),
        "Redis rule cannot define another protocol selector"
    );
    if let RedisSelector::Lock(lock) = redis {
        crate::replay::redis::lock::RedisLockSelector {
            host: rule.target.host.clone().unwrap_or_default(),
            port: rule.target.port.unwrap_or_default(),
            key: lock.lock.key.clone(),
        }
        .validate()?;
        crate::config::process_owned_dependencies::validate_source_evidence(
            &lock.lock.source_evidence,
        )?;
        return Ok(());
    }
    if let RedisSelector::TimeShift(read) = redis {
        let selector = crate::replay::redis::time_shift::RedisTimeShiftSelector {
            host: rule.target.host.clone().unwrap_or_default(),
            port: rule.target.port.unwrap_or_default(),
            read: read.clone(),
        };
        selector.validate()?;
        if rule.replay_scope == ReplayScope::RecordingRun {
            crate::replay::redis::cross_case::exact_read(&selector)?;
        }
        return Ok(());
    }
    let RedisSelector::Value(value) = redis else {
        unreachable!()
    };
    ensure!(
        !value.unordered.is_empty() && value.unordered.len() <= 32,
        "Redis unordered requires 1..32 fields"
    );
    for selector in redis.selectors(rule) {
        selector.validate()?;
    }
    for (index, field) in value.unordered.iter().enumerate() {
        crate::config::process_owned_dependencies::validate_source_evidence(
            &field.source_evidence,
        )?;
        ensure!(
            value.unordered[..index]
                .iter()
                .all(|other| !field.field.overlaps(&other.field)),
            "Redis unordered fields overlap"
        );
    }
    Ok(())
}
pub(super) fn validate_overlaps(rules: &[ReplayDependencyRule]) -> Result<()> {
    for (i, rule) in rules.iter().enumerate() {
        if rule.protocol != DependencyProtocol::Redis {
            ensure!(rule.redis.is_none(), "non-Redis rule cannot contain redis");
            continue;
        }
        let Some(redis) = &rule.redis else {
            continue;
        };
        for other in &rules[..i] {
            let Some(other_redis) = &other.redis else {
                continue;
            };
            if rule.target.port != other.target.port
                || rule
                    .target
                    .host
                    .as_ref()
                    .zip(other.target.host.as_ref())
                    .is_none_or(|(a, b)| !a.eq_ignore_ascii_case(b))
            {
                continue;
            }
            if let (RedisSelector::Lock(a), RedisSelector::Lock(b)) = (redis, other_redis) {
                ensure!(
                    !a.lock.key.overlaps(&b.lock.key),
                    "Redis lock-token key selectors overlap between rules {:?} and {:?}",
                    rule.id,
                    other.id
                );
            }
            if let (RedisSelector::Lock(lock), RedisSelector::Value(value))
            | (RedisSelector::Value(value), RedisSelector::Lock(lock)) = (redis, other_redis)
            {
                ensure!(
                    !lock.lock.key.overlaps(&value.key),
                    "Redis lock-token and unordered value selectors overlap"
                );
            }
            if let (RedisSelector::TimeShift(a), RedisSelector::TimeShift(b)) = (redis, other_redis)
            {
                ensure!(
                    !a.overlaps(b),
                    "Redis time-shift response fields overlap between rules {:?} and {:?}",
                    rule.id,
                    other.id
                );
            }
            let (RedisSelector::Value(redis), RedisSelector::Value(other_redis)) =
                (redis, other_redis)
            else {
                continue;
            };
            if !redis.key.overlaps(&other_redis.key) {
                continue;
            }
            ensure!(
                !redis.unordered.iter().any(|a| other_redis
                    .unordered
                    .iter()
                    .any(|b| a.field.overlaps(&b.field))),
                "Redis unordered fields overlap between rules {:?} and {:?}",
                rule.id,
                other.id
            );
        }
    }
    Ok(())
}
